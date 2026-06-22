#include "source/extensions/filters/http/rate_limit_quota_apig/config_discovery_client.h"

#include <random>

#include "envoy/grpc/status.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/grpc/common.h"
#include "source/common/tracing/null_span_impl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

namespace {

constexpr absl::string_view kGetQuotaConfigMethodFullName =
    "envoy.service.rate_limit_quota_apig.v3.RateLimitQuotaConfigDiscoveryService.GetQuotaConfig";

constexpr absl::string_view kStreamMethodFullName =
    "envoy.service.rate_limit_quota_apig.v3.RateLimitQuotaConfigDiscoveryService.StreamRlQsConfigs";

constexpr absl::string_view kResourceTypeUrl =
    "type.googleapis.com/envoy.extensions.filters.http.rate_limit_quota_apig.v3."
    "RateLimitQuotaBucketSettings";

// Splits "{tenant}|{scope}" into the (tenant, scope) pair. Empty tenant or
// scope is reported as a parse failure.
bool splitSubscriptionKey(absl::string_view key, std::string& tenant, std::string& scope) {
  const auto pipe = key.find('|');
  if (pipe == absl::string_view::npos || pipe == 0 || pipe == key.size() - 1) {
    return false;
  }
  tenant = std::string(key.substr(0, pipe));
  scope = std::string(key.substr(pipe + 1));
  return true;
}

// Pick a jittered duration in [base * 0.8, base * 1.2]. Centered backoff
// avoids thundering-herd reconnects when many filter instances see the
// quota-server flap simultaneously.
std::chrono::milliseconds jitter(std::chrono::milliseconds base) {
  static thread_local std::mt19937 rng{std::random_device{}()};
  std::uniform_real_distribution<double> dist(0.8, 1.2);
  return std::chrono::milliseconds(static_cast<int64_t>(base.count() * dist(rng)));
}

} // namespace

ConfigDiscoveryClient::ConfigDiscoveryClient(Grpc::RawAsyncClientSharedPtr async_client,
                                             Event::Dispatcher& dispatcher,
                                             DynamicSettingsRegistrySharedPtr registry,
                                             std::chrono::milliseconds initial_backoff,
                                             std::chrono::milliseconds max_backoff,
                                             size_t subscribed_max_entries,
                                             std::chrono::milliseconds fetch_timeout,
                                             std::chrono::milliseconds negative_cache_ttl,
                                             std::chrono::milliseconds idle_eviction_ttl)
    : async_client_(std::move(async_client)), dispatcher_(dispatcher),
      registry_(std::move(registry)), initial_backoff_(initial_backoff),
      max_backoff_(max_backoff),
      // A 0 cap would make subscribeOnMain a no-op (every insert immediately
      // evicts itself), which is never what the caller wants. Clamp to 1
      // as a defensive floor; tests pass small values intentionally and the
      // production default is already 32K.
      subscribed_max_(subscribed_max_entries == 0 ? 1 : subscribed_max_entries),
      fetch_timeout_(fetch_timeout),
      negative_cache_ttl_(negative_cache_ttl),
      idle_eviction_ttl_(idle_eviction_ttl),
      service_method_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          std::string(kStreamMethodFullName))),
      get_quota_config_method_(Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
          std::string(kGetQuotaConfigMethodFullName))),
      current_backoff_(initial_backoff) {}

ConfigDiscoveryClient::~ConfigDiscoveryClient() {
  if (eviction_timer_) {
    eviction_timer_->disableTimer();
  }
  if (reconnect_timer_) {
    reconnect_timer_->disableTimer();
  }
  for (auto& [key, request] : inflight_raw_requests_) {
    if (request != nullptr) {
      request->cancel();
    }
  }
  inflight_raw_requests_.clear();
  for (auto& [key, callbacks] : inflight_requests_) {
    for (auto& cb : callbacks) {
      if (cb) {
        cb(false);
      }
    }
  }
  inflight_requests_.clear();
  if (stream_ != nullptr) {
    stream_->resetStream();
    stream_ = nullptr;
  }
}

void ConfigDiscoveryClient::start() {
  if (stream_ != nullptr) {
    return;
  }
  ENVOY_LOG(debug, "ConfigDiscoveryClient: opening RLQS Config DS stream");
  stream_ = async_client_->startRaw(
      service_method_.service()->full_name(), service_method_.name(), *this,
      Http::AsyncClient::StreamOptions().setBufferBodyForRetry(false));
  if (stream_ == nullptr) {
    ENVOY_LOG(warn, "ConfigDiscoveryClient: failed to open stream; will retry");
    scheduleReconnect();
    return;
  }
  if (stats_.stream_connect != nullptr) {
    stats_.stream_connect->inc();
  }
  // Successful open resets the backoff so a steady stream doesn't carry
  // forward an old large delay if it ever flaps again.
  current_backoff_ = initial_backoff_;
  sendRequest();
  // Spec § D-6 Subplan 4: snapshot the resources we just declared as
  // subscribed so the very next response (the server's full SOTW answer
  // to our initial / reconnect request) can be diffed for abandons. This
  // is the ONLY place we snapshot — see snapshotSubscribedForAbandon().
  snapshotSubscribedForAbandon();
}

void ConfigDiscoveryClient::subscribeFromWorker(absl::string_view tenant,
                                                absl::string_view scope) {
  // Worker context: copy the strings (string_views may be temporaries) and
  // bounce onto the main dispatcher. The subscribed_ map and the gRPC
  // stream are single-threaded on the main thread. weak_from_this guards
  // against a listener-drain race: TlsStore + filter shared_ptrs may all
  // drop between the post and the dispatcher iteration that runs it.
  std::string t(tenant);
  std::string s(scope);
  std::weak_ptr<ConfigDiscoveryClient> weak = weak_from_this();
  dispatcher_.post([weak, t = std::move(t), s = std::move(s)] {
    if (auto self = weak.lock()) {
      self->subscribeOnMain(t, s);
    }
  });
}

void ConfigDiscoveryClient::subscribeOnMain(absl::string_view tenant, absl::string_view scope) {
  std::string key = DynamicSettingsRegistry::makeKey(tenant, scope);
  if (auto it = subscribed_index_.find(key); it != subscribed_index_.end()) {
    // Touch: move to LRU front so the next overflow doesn't evict a key
    // a worker is actively observing.
    subscribed_lru_.splice(subscribed_lru_.begin(), subscribed_lru_, it->second);
    return;
  }
  // New subscription: insert at front, then evict overflow tail.
  subscribed_lru_.push_front(std::move(key));
  subscribed_index_[subscribed_lru_.front()] = subscribed_lru_.begin();
  while (subscribed_lru_.size() > subscribed_max_) {
    const std::string& evicted = subscribed_lru_.back();
    if (stats_.subscription_evicted != nullptr) {
      stats_.subscription_evicted->inc();
    }
    ENVOY_LOG(debug, "ConfigDiscoveryClient: evicting LRU subscription {} (cap={})", evicted,
              subscribed_max_);

    std::string evicted_tenant, evicted_scope;
    if (splitSubscriptionKey(evicted, evicted_tenant, evicted_scope)) {
      registry_->erase(evicted_tenant, evicted_scope);
    }
    cache_expiry_.erase(evicted);

    subscribed_index_.erase(evicted);
    subscribed_lru_.pop_back();
  }
  ENVOY_LOG(debug, "ConfigDiscoveryClient: subscribing to {}", subscribed_lru_.front());
  // Removed xDS DiscoveryRequest broadcast to prevent sending full LRU contents.
  // The client now uses unary fetchQuotaConfig for on-demand rule fetching.
}

void ConfigDiscoveryClient::sendRequest() {
  if (stream_ == nullptr) {
    return;
  }
  envoy::service::discovery::v3::DiscoveryRequest request;
  request.set_type_url(std::string(kResourceTypeUrl));
  request.set_version_info(last_version_info_);
  request.set_response_nonce(last_nonce_);
  // Iterate the LRU (any order — server treats this as a set, just as before).
  for (const auto& name : subscribed_lru_) {
    request.add_resource_names(name);
  }

  Buffer::InstancePtr buffer = std::make_unique<Buffer::OwnedImpl>();
  std::string serialized;
  if (!request.SerializeToString(&serialized)) {
    ENVOY_LOG(error, "ConfigDiscoveryClient: failed to serialize DiscoveryRequest");
    return;
  }
  buffer->add(serialized);
  stream_->sendMessageRaw(std::move(buffer), false);
}

void ConfigDiscoveryClient::snapshotSubscribedForAbandon() {
  // Capture the current subscription set as the SOTW window for the
  // immediately-following server response (spec § D-6 Subplan 4 abandon
  // scope). See the field docstring on last_sent_resource_names_ for why
  // this is intentionally NOT called from every sendRequest — only from
  // start() / reconnect so steady-state invalidation pushes (scoped to a
  // single resource) cannot false-erase the rest of the subscription set.
  last_sent_resource_names_.clear();
  last_sent_resource_names_.reserve(subscribed_lru_.size());
  for (const auto& name : subscribed_lru_) {
    last_sent_resource_names_.insert(name);
  }
}

bool ConfigDiscoveryClient::onReceiveMessageRaw(Buffer::InstancePtr&& response_buffer) {
  envoy::service::discovery::v3::DiscoveryResponse response;
  const std::string data = response_buffer->toString();
  if (!response.ParseFromString(data)) {
    ENVOY_LOG(warn, "ConfigDiscoveryClient: failed to parse DiscoveryResponse");
    if (stats_.response_parse_error != nullptr) {
      stats_.response_parse_error->inc();
    }
    return false;
  }
  if (stats_.response_received != nullptr) {
    stats_.response_received->inc();
  }
  last_version_info_ = response.version_info();
  last_nonce_ = response.nonce();

  // Group Anys by (tenant, scope) so a single response covering multiple
  // bindings (e.g. unsolicited push after multi-route invalidation) lands
  // correctly in the registry. Missing tags log WARN and skip the Any.
  absl::flat_hash_map<std::string, DynamicSettingsRegistry::SettingsList> grouped;
  for (const auto& any : response.resources()) {
    auto bs_mut = std::make_shared<RateLimitQuotaBucketSettings>();
    if (!any.UnpackTo(bs_mut.get())) {
      ENVOY_LOG(warn, "ConfigDiscoveryClient: failed to unpack BucketSettings from Any (type_url={})",
                any.type_url());
      if (stats_.settings_parse_error != nullptr) {
        stats_.settings_parse_error->inc();
      }
      continue;
    }
    std::string tenant, scope;
    if (!extractBindingFromSettings(*bs_mut, tenant, scope)) {
      // Without (tenant, scope) tags the filter can't index the entry.
      // Server must inject _tenant/_scope into bucket_id_builder; see
      // rlqs_config_ds.go injectBindingTags.
      if (stats_.settings_missing_binding_tag != nullptr) {
        stats_.settings_missing_binding_tag->inc();
      }
      continue;
    }
    const std::string key = DynamicSettingsRegistry::makeKey(tenant, scope);
    // Wrap with a precomputed bucket_id_builder string overlay so the
    // filter hot path can apply variant identity without re-traversing the
    // protobuf per request (see CachedBucketSettings doc in the registry).
    RateLimitQuotaBucketSettingsConstSharedPtr bs = bs_mut;
    grouped[key].push_back(wrapSettings(std::move(bs)));
  }

  // Apply the grouped updates (entries the server explicitly sent).
  for (auto& [key, list] : grouped) {
    std::string tenant, scope;
    if (splitSubscriptionKey(key, tenant, scope)) {
      registry_->update(tenant, scope, std::move(list));
    }
  }

  // Spec § D-6 Subplan 4 — confirmed-miss-omission AbandonAction.
  // For each resource_name we just asked for that did NOT come back in
  // the grouped response, treat as server-side abandon and drop the
  // local registry entry. This catches:
  //   - upstream config deletion that the server resolves on next
  //     resubscribe / reconnect
  //   - control-plane scope reshuffle (binding now resolves to a
  //     different (tenant, scope), so the old one becomes stale)
  // last_sent_resource_names_ was filled by the prior sendRequest()
  // and is empty for unsolicited invalidation pushes — see the field
  // docstring for why this is the correct correlation window.
  //
  // Known limitation: server's invalidation push for a DELETED config
  // (rlqs_config_ds.go:248-285) only emits Resources=[] without any
  // (tenant, scope) tag. That deletion is not detected here — fallback
  // paths handle it: (a) data-plane AbandonAction on next matching
  // request via RLQS Stream, (b) abandon detected on the next ACK that
  // includes the deleted key in resource_names. Full immediate-coverage
  // requires a server-side proto extension (e.g.
  // `abandoned_resource_names: repeated string` in DiscoveryResponse),
  // out of scope here.
  if (!last_sent_resource_names_.empty()) {
    for (const auto& key : last_sent_resource_names_) {
      if (grouped.contains(key)) {
        continue;
      }
      std::string tenant, scope;
      if (!splitSubscriptionKey(key, tenant, scope)) {
        continue;
      }
      // erase() is a silent no-op when the key has no registry entry
      // (e.g. abandon before first update). To avoid bumping the
      // counter on no-ops, peek at the registry first via lookup().
      if (registry_->lookup(tenant, scope).empty()) {
        continue;
      }
      registry_->erase(tenant, scope);
      cache_expiry_.erase(key);
      if (stats_.config_ds_abandon_applied != nullptr) {
        stats_.config_ds_abandon_applied->inc();
      }
      ENVOY_LOG(debug, "ConfigDiscoveryClient: SOTW abandon erased {}", key);
    }
    last_sent_resource_names_.clear();
  }

  // ACK the response. Per xDS SOTW the client must always respond with
  // version + nonce — server uses this for retry detection. Note we do NOT
  // re-snapshot last_sent_resource_names_ here: every steady-state response
  // (ACK reply or unsolicited invalidation push) compares against an empty
  // snapshot and therefore never erases. Only start() / reconnect repopulate
  // the snapshot. See last_sent_resource_names_ docstring for the rationale.
  sendRequest();
  return true;
}

bool ConfigDiscoveryClient::extractBindingFromSettings(const RateLimitQuotaBucketSettings& bs,
                                                      std::string& tenant,
                                                      std::string& scope) const {
  if (!bs.has_bucket_id_builder()) {
    ENVOY_LOG(warn, "ConfigDiscoveryClient: BucketSettings missing bucket_id_builder");
    return false;
  }
  const auto& m = bs.bucket_id_builder().bucket_id_builder();
  auto t_it = m.find("_tenant");
  auto s_it = m.find("_scope");
  if (t_it == m.end() || s_it == m.end()) {
    ENVOY_LOG(warn, "ConfigDiscoveryClient: BucketSettings missing _tenant/_scope tag");
    return false;
  }
  if (t_it->second.value_specifier_case() !=
      envoy::extensions::filters::http::rate_limit_quota_apig::v3::
          RateLimitQuotaBucketSettings_BucketIdBuilder_ValueBuilder::kStringValue) {
    return false;
  }
  if (s_it->second.value_specifier_case() !=
      envoy::extensions::filters::http::rate_limit_quota_apig::v3::
          RateLimitQuotaBucketSettings_BucketIdBuilder_ValueBuilder::kStringValue) {
    return false;
  }
  tenant = t_it->second.string_value();
  scope = s_it->second.string_value();
  return !tenant.empty() && !scope.empty();
}

void ConfigDiscoveryClient::onRemoteClose(Grpc::Status::GrpcStatus status,
                                          const std::string& message) {
  ENVOY_LOG(warn, "ConfigDiscoveryClient: stream closed status={} message='{}'; reconnecting",
            static_cast<int>(status), message);
  // Each remote close that triggers retry counts as one reconnect cycle.
  // start() will bump stream_connect on the next successful open, so the
  // pair (stream_connect, stream_reconnect) gives operators the connect /
  // disconnect ratio without double-counting.
  if (stats_.stream_reconnect != nullptr) {
    stats_.stream_reconnect->inc();
  }
  stream_ = nullptr;
  scheduleReconnect();
}

void ConfigDiscoveryClient::scheduleReconnect() {
  if (!reconnect_timer_) {
    std::weak_ptr<ConfigDiscoveryClient> weak = weak_from_this();
    reconnect_timer_ = dispatcher_.createTimer([weak] {
      if (auto self = weak.lock()) {
        self->onReconnectTimer();
      }
    });
  }
  reconnect_timer_->enableTimer(jitter(current_backoff_));
  // Double for next iteration, capped at max_backoff_.
  current_backoff_ = std::min(max_backoff_,
                              std::chrono::milliseconds(current_backoff_.count() * 2));
}

void ConfigDiscoveryClient::onReconnectTimer() {
  reconnect_timer_->disableTimer();
  start();
}

void ConfigDiscoveryClient::fetchQuotaConfig(absl::string_view tenant, absl::string_view scope, FetchQuotaConfigCallback cb) {
  // Ensure we execute on the main dispatcher where inflight_requests_ and cache_expiry_ are thread-safe.
  if (!dispatcher_.isThreadSafe()) {
    ENVOY_LOG(debug, "RLQS ConfigDS: fetchQuotaConfig cross-thread post tenant={} scope={}", tenant, scope);
    std::string t(tenant);
    std::string s(scope);
    // weak_from_this: same listener-drain protection as subscribeFromWorker.
    std::weak_ptr<ConfigDiscoveryClient> weak = weak_from_this();
    dispatcher_.post([weak, t = std::move(t), s = std::move(s), cb = std::move(cb)]() mutable {
      if (auto self = weak.lock()) {
        ENVOY_LOG_MISC(debug, "RLQS ConfigDS: fetchQuotaConfig post landed on main thread");
        self->fetchQuotaConfig(t, s, std::move(cb));
      } else if (cb) {
        ENVOY_LOG_MISC(warn, "RLQS ConfigDS: fetchQuotaConfig client destroyed before post executed, failing callback");
        cb(false);
      }
    });
    return;
  }

  // Beyond this point we rely on inflight_requests_ / cache_expiry_ being
  // mutated only on main; mirror the invariant explicitly the same way
  // DynamicSettingsRegistry::update / GlobalHotspotTracker::registerOnMain
  // do, so a regression that bypasses the post-bounce above gets a release-
  // build counter + log line rather than a silent data race.
  ENVOY_BUG(dispatcher_.isThreadSafe(),
            "ConfigDiscoveryClient::fetchQuotaConfig must run on the main dispatcher");

  std::string key = DynamicSettingsRegistry::makeKey(tenant, scope);

  // 0. Check negative cache (failed fetches) — skip the RPC entirely.
  auto neg_it = negative_cache_expiry_.find(key);
  if (neg_it != negative_cache_expiry_.end() &&
      dispatcher_.timeSource().monotonicTime() < neg_it->second) {
    if (stats_.negative_cache_hit) {
      stats_.negative_cache_hit->inc();
    }
    ENVOY_LOG(debug, "ConfigDiscoveryClient: negative cache hit for {}, skipping fetch", key);
    if (cb) cb(false);
    return;
  }

  // 1. Check TTL Cache
  auto expiry_it = cache_expiry_.find(key);
  if (expiry_it != cache_expiry_.end() && dispatcher_.timeSource().monotonicTime() < expiry_it->second) {
    ENVOY_LOG(debug, "RLQS ConfigDS: fetchQuotaConfig TTL cache hit key={}", key);
    touchAccessOnMain(key);
    if (cb) cb(true);
    return;
  }

  // 2. Check Singleflight (already in-flight)
  auto inflight_it = inflight_requests_.find(key);
  if (inflight_it != inflight_requests_.end()) {
    if (cb) inflight_it->second.push_back(std::move(cb));
    return;
  }

  // 3. New Fetch
  if (cb) {
    inflight_requests_[key].push_back(std::move(cb));
  } else {
    inflight_requests_[key] = {};
  }

  envoy::service::rate_limit_quota_apig::v3::GetQuotaConfigRequest req;
  req.set_tenant(std::string(tenant));
  req.set_scope(std::string(scope));

  Buffer::InstancePtr buffer = std::make_unique<Buffer::OwnedImpl>();
  std::string serialized;
  if (!req.SerializeToString(&serialized)) {
    ENVOY_LOG(error, "ConfigDiscoveryClient: failed to serialize GetQuotaConfigRequest");
    invokeAndClearInflight(key, false);
    return;
  }
  buffer->add(serialized);

  auto* request_cbs = new FetchQuotaConfigRequest(weak_from_this(), tenant, scope);

  if (get_quota_config_method_ == nullptr) {
    ENVOY_LOG(error, "ConfigDiscoveryClient: GetQuotaConfig method not found");
    invokeAndClearInflight(key, false);
    delete request_cbs;
    return;
  }

  auto request = async_client_->sendRaw(
      get_quota_config_method_->service()->full_name(), get_quota_config_method_->name(),
      std::move(buffer), *request_cbs, Tracing::NullSpan::instance(),
      Http::AsyncClient::RequestOptions().setTimeout(fetch_timeout_));
  
  if (request == nullptr) {
    ENVOY_LOG(warn, "RLQS ConfigDS: GetQuotaConfig RPC failed inline for key={}", key);
  } else {
    ENVOY_LOG(debug, "RLQS ConfigDS: GetQuotaConfig RPC dispatched for key={}", key);
    inflight_raw_requests_[key] = request;
  }
}

void ConfigDiscoveryClient::invokeAndClearInflight(const std::string& key, bool success) {
  inflight_raw_requests_.erase(key);
  auto it = inflight_requests_.find(key);
  if (it != inflight_requests_.end()) {
    auto callbacks = std::move(it->second);
    inflight_requests_.erase(it);
    ENVOY_LOG(debug, "RLQS ConfigDS: invoking {} inflight callbacks key={} success={}",
              callbacks.size(), key, success);
    for (auto& cb : callbacks) {
      if (cb) cb(success);
    }
  } else {
    ENVOY_LOG(warn, "RLQS ConfigDS: invokeAndClearInflight key={} success={} but no inflight entry found", key, success);
  }
}

void ConfigDiscoveryClient::onFetchQuotaConfigSuccess(const std::string& tenant, const std::string& scope, Buffer::InstancePtr&& response_buffer) {
  envoy::service::rate_limit_quota_apig::v3::GetQuotaConfigResponse response;
  std::string key = DynamicSettingsRegistry::makeKey(tenant, scope);
  ENVOY_LOG(debug, "ConfigDiscoveryClient: onFetchQuotaConfigSuccess for key={}, response_size={} bytes",
            key, response_buffer ? response_buffer->length() : 0);

  if (!response.ParseFromString(response_buffer->toString())) {
    ENVOY_LOG(warn, "ConfigDiscoveryClient: failed to parse GetQuotaConfigResponse for key={}", key);
    invokeAndClearInflight(key, false);
    return;
  }

  ENVOY_LOG(debug, "ConfigDiscoveryClient: parsed GetQuotaConfigResponse for key={}, settings_size={}",
            key, response.settings_size());

  // Update dynamic registry. Wrap each settings with a precomputed
  // bucket_id_builder string overlay so the filter hot path applies variant
  // identity without per-request proto reflection.
  DynamicSettingsRegistry::SettingsList list;
  list.reserve(response.settings_size());
  for (const auto& settings : response.settings()) {
    RateLimitQuotaBucketSettingsConstSharedPtr bs =
        std::make_shared<const RateLimitQuotaBucketSettings>(settings);
    list.push_back(wrapSettings(std::move(bs)));
  }
  registry_->update(tenant, scope, std::move(list));

  // Update TTL and clear any negative cache entry from a prior failure.
  negative_cache_expiry_.erase(key);
  cache_expiry_[key] = dispatcher_.timeSource().monotonicTime() + config_ttl_;
  touchAccessOnMain(key);

  // Add to LRU list to prevent repeated fetches. If the list is full, this will evict the oldest.
  subscribeOnMain(tenant, scope);

  invokeAndClearInflight(key, true);
}

void ConfigDiscoveryClient::onFetchQuotaConfigFailure(const std::string& tenant, const std::string& scope, Grpc::Status::GrpcStatus status, const std::string& message) {
  ENVOY_LOG(warn, "ConfigDiscoveryClient: getQuotaConfig failed for {}|{}: status={} message='{}'", tenant, scope, static_cast<int>(status), message);
  std::string key = DynamicSettingsRegistry::makeKey(tenant, scope);
  if (negative_cache_ttl_.count() > 0) {
    negative_cache_expiry_[key] =
        dispatcher_.timeSource().monotonicTime() + negative_cache_ttl_;
  }
  invokeAndClearInflight(key, false);
}

void ConfigDiscoveryClient::touchAccessFromWorker(absl::string_view tenant,
                                                   absl::string_view scope) {
  std::string t(tenant);
  std::string s(scope);
  std::weak_ptr<ConfigDiscoveryClient> weak = weak_from_this();
  dispatcher_.post([weak, t = std::move(t), s = std::move(s)] {
    if (auto self = weak.lock()) {
      self->touchAccessOnMain(DynamicSettingsRegistry::makeKey(t, s));
    }
  });
}

void ConfigDiscoveryClient::touchAccessOnMain(const std::string& key) {
  last_access_[key] = dispatcher_.timeSource().monotonicTime();
}

void ConfigDiscoveryClient::startEvictionTimer() {
  if (idle_eviction_ttl_.count() <= 0 || eviction_timer_) {
    return;
  }
  std::weak_ptr<ConfigDiscoveryClient> weak = weak_from_this();
  eviction_timer_ = dispatcher_.createTimer([weak] {
    if (auto self = weak.lock()) {
      self->runIdleEviction();
      self->eviction_timer_->enableTimer(std::chrono::seconds(10));
    }
  });
  eviction_timer_->enableTimer(std::chrono::seconds(10));
}

void ConfigDiscoveryClient::runIdleEviction() {
  if (last_access_.empty()) {
    return;
  }
  auto now = dispatcher_.timeSource().monotonicTime();
  std::vector<std::string> keys_to_evict;
  for (const auto& [key, last_access] : last_access_) {
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_access) >
        idle_eviction_ttl_) {
      keys_to_evict.push_back(key);
    }
  }
  if (keys_to_evict.empty()) {
    return;
  }
  for (const auto& key : keys_to_evict) {
    std::string tenant, scope;
    if (splitSubscriptionKey(key, tenant, scope)) {
      registry_->erase(tenant, scope);
    }
    cache_expiry_.erase(key);
    negative_cache_expiry_.erase(key);
    if (auto it = subscribed_index_.find(key); it != subscribed_index_.end()) {
      subscribed_lru_.erase(it->second);
      subscribed_index_.erase(it);
    }
    last_access_.erase(key);
    if (stats_.idle_eviction != nullptr) {
      stats_.idle_eviction->inc();
    }
  }
  ENVOY_LOG(info, "ConfigDiscoveryClient: idle eviction swept {} entries", keys_to_evict.size());
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
