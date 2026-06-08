#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.h"
#include "envoy/grpc/async_client.h"
#include "envoy/service/discovery/v3/discovery.pb.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.h"
#include "envoy/stats/stats.h"

#include "source/common/common/logger.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/dynamic_settings_registry.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"

#include <list>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

/**
 * ConfigDiscoveryClient is the filter-side bidi-stream client for the
 * RateLimitQuotaConfigDiscoveryService (spec § D-8). It runs on the main
 * thread, maintains a long-lived gRPC stream to the quota-server, and
 * pushes per-(tenant, scope) BucketSettings into the shared
 * DynamicSettingsRegistry that worker threads read at request time.
 *
 * Subscription model:
 *   - The filter calls subscribe(tenant, scope) the first time it observes
 *     a (tenant, scope) at request time. Workers cross-thread-safely via
 *     `subscribeFromWorker()`, which posts to the main dispatcher.
 *   - On the main thread, the client batches subscriptions into a single
 *     DiscoveryRequest with all known resource_names (SOTW xDS contract).
 *   - The server replies (or unsolicited-pushes after Pub/Sub invalidation)
 *     with Resources carrying self-identifying `_tenant`/`_scope`/`_dim`
 *     tags in `bucket_id_builder`, which the client uses to group the
 *     incoming Anys into per-(tenant, scope) lists for the registry.
 *
 * Lifecycle:
 *   - Owned by the FilterConfig / TLS scaffolding via shared_ptr. The
 *     destructor closes the stream and the reconnect timer.
 *   - Reconnect: onRemoteClose() schedules a retry with exponential
 *     backoff (1s → 30s) and jitter ±20%. On reconnect we resend the full
 *     subscription set; the server starts from scratch (no state).
 *
 * Failure modes:
 *   - Stream open failure: logged WARN; retried on the backoff timer.
 *   - Malformed response: each Any failing to unpack is logged WARN and
 *     skipped; valid Anys in the same response still update the registry.
 *   - Missing _tenant/_scope tags: logged WARN and the Any is skipped;
 *     a misconfigured server cannot poison the registry.
 */
// Minimal stats interface the ConfigDiscoveryClient needs. Decoupled from
// FilterConfig::RateLimitQuotaStats so unit tests don't have to construct
// the full POOL_COUNTER_PREFIX scope just to drive the client.
struct ConfigDiscoveryClientStats {
  Stats::Counter* stream_connect = nullptr;
  Stats::Counter* stream_reconnect = nullptr;
  Stats::Counter* response_received = nullptr;
  Stats::Counter* response_parse_error = nullptr;
  Stats::Counter* settings_parse_error = nullptr;
  Stats::Counter* settings_missing_binding_tag = nullptr;
  // Subscription LRU eviction counter — bumped when the subscribed_-
  // bound cap is exceeded and the least-recently-touched (tenant, scope)
  // is dropped to make room. Non-zero values mean the configured cap is
  // smaller than the working set; an alarm threshold should be a small
  // fraction of stream_connect so transient drops during a reconnect
  // (resubscribe + evict) don't fire false alerts.
  Stats::Counter* subscription_evicted = nullptr;
  // Spec § D-6 Subplan 4: confirmed-miss-omission abandon applied to the
  // local DynamicSettingsRegistry. Bumped once per registry entry erased
  // in response to a SOTW DiscoveryResponse that omitted a previously
  // subscribed resource_name. Non-zero is healthy churn (configs being
  // deleted upstream); a sustained high rate compared to response_received
  // suggests churn that may warrant configuration review.
  Stats::Counter* config_ds_abandon_applied = nullptr;
};

// enable_shared_from_this is load-bearing: subscribeFromWorker /
// fetchQuotaConfig post `[this]`-equivalent closures from worker context onto
// the main dispatcher; if a listener drain drops the TlsStore + every
// filter's shared_ptr between the post and the dispatcher iteration that
// runs it, the closure would dereference freed memory. weak_from_this() in
// the closure resurrects a strong ref iff the client is still alive,
// otherwise the closure is a no-op. Mirrors GlobalRateLimitClientImpl /
// GlobalHotspotTracker pattern.
class ConfigDiscoveryClient : public Grpc::RawAsyncStreamCallbacks,
                              public std::enable_shared_from_this<ConfigDiscoveryClient>,
                              public Logger::Loggable<Logger::Id::rate_limit_quota> {
public:
  // Default cap on distinct subscribed (tenant, scope) keys. Each ACK
  // re-sends the entire resource_names list (SOTW xDS contract), so an
  // unbounded set lets a high-churn worker fleet eventually hand the
  // server a megabytes-sized DiscoveryRequest. Cap is approximate; the
  // LRU evicts the least-recently-touched key when capacity is exceeded.
  //
  // Sized for multi-tenant gateway deployments: 500K covers up to
  // 50 tenants x 5K routes/tenant + 2x headroom for multi-dim variants.
  // At ~30 bytes/key this caps single-DiscoveryRequest payload at ~15 MB;
  // operators running this scale must also raise gRPC
  // `max_send/recv_message_length` accordingly. Phase 3 (delta-xDS) will
  // remove the full-resend pattern entirely.
  static constexpr size_t kDefaultSubscribedMaxEntries = 500000;

  ConfigDiscoveryClient(Grpc::RawAsyncClientSharedPtr async_client,
                        Event::Dispatcher& dispatcher,
                        DynamicSettingsRegistrySharedPtr registry,
                        std::chrono::milliseconds initial_backoff = std::chrono::seconds(1),
                        std::chrono::milliseconds max_backoff = std::chrono::seconds(30),
                        size_t subscribed_max_entries = kDefaultSubscribedMaxEntries);

  // setStats wires per-stream observability counters. Optional — when
  // unset, every helper short-circuits (nil counters), so tests that
  // don't care about metrics don't need to wire them.
  void setStats(ConfigDiscoveryClientStats stats) { stats_ = stats; }

  ~ConfigDiscoveryClient() override;

  // Subscribe to a (tenant, scope) binding. Thread-safe — workers post the
  // request onto the main dispatcher; the actual subscription update runs
  // on main. Idempotent: re-subscribing to an existing key is a no-op
  // (modulo a refresh DiscoveryRequest, which the server handles cheaply
  // via cache + version unchanged).
  void subscribeFromWorker(absl::string_view tenant, absl::string_view scope);

  // Main-thread-only variant for tests and the factory setup path.
  void subscribeOnMain(absl::string_view tenant, absl::string_view scope);

  // Open the stream and send the initial (possibly empty) DiscoveryRequest.
  // Idempotent; if the stream is already open, this is a no-op.
  void start();

  // ---- Grpc::RawAsyncStreamCallbacks ----
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
  void onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&&) override {}
  bool onReceiveMessageRaw(Buffer::InstancePtr&& response_buffer) override;
  void onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&&) override {}
  void onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& message) override;

  // Test hooks (exposed so unit tests can drive the client deterministically
  // without needing the gRPC machinery).
  size_t subscribedCountForTest() const { return subscribed_index_.size(); }
  const std::string& lastVersionInfoForTest() const { return last_version_info_; }
  const std::string& lastNonceForTest() const { return last_nonce_; }
  bool hasStreamForTest() const { return stream_ != nullptr; }
  // Returns subscribed keys in LRU order, most-recently-touched first. Used
  // by tests to assert the LRU eviction order without reaching into private
  // internals.
  std::vector<std::string> subscribedOrderForTest() const {
    return std::vector<std::string>(subscribed_lru_.begin(), subscribed_lru_.end());
  }
  
  void sendRequestForTest() { sendRequest(); }

  // Callback type for fetchQuotaConfig.
  using FetchQuotaConfigCallback = std::function<void(bool success)>;

  // Fetch a single quota config based on tenant and scope using the GetQuotaConfig unary RPC.
  // The callback is invoked when the response arrives (or fails). The result is parsed
  // and pushed into the DynamicSettingsRegistry automatically.
  void fetchQuotaConfig(absl::string_view tenant, absl::string_view scope, FetchQuotaConfigCallback cb);

  private:
  // Async gRPC callback object owned by the async_client_ until the response
  // arrives. Holds a weak_ptr — not a raw reference — to the parent client
  // because async_client_ is shared (`getOrCreateRawAsyncClient`) and may
  // outlive `*this`. Without the weak guard, an in-flight unary request that
  // completes after listener drain would fire onSuccessRaw / onFailure on a
  // freed parent. Same hazard as the recent worker→main post fixes; same
  // fix shape.
  class FetchQuotaConfigRequest : public Grpc::RawAsyncRequestCallbacks {
  public:
    FetchQuotaConfigRequest(std::weak_ptr<ConfigDiscoveryClient> parent_weak,
                            absl::string_view tenant, absl::string_view scope)
        : parent_weak_(std::move(parent_weak)), tenant_(tenant), scope_(scope) {}

    void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
    void onSuccessRaw(Buffer::InstancePtr&& response, Tracing::Span& /*span*/) override {
      if (auto parent = parent_weak_.lock()) {
        parent->onFetchQuotaConfigSuccess(tenant_, scope_, std::move(response));
      }
      delete this;
    }
    void onFailure(Grpc::Status::GrpcStatus status, const std::string& message,
                   Tracing::Span& /*span*/) override {
      if (auto parent = parent_weak_.lock()) {
        parent->onFetchQuotaConfigFailure(tenant_, scope_, status, message);
      }
      delete this;
    }

  private:
    std::weak_ptr<ConfigDiscoveryClient> parent_weak_;
    std::string tenant_;
    std::string scope_;
  };

  void invokeAndClearInflight(const std::string& key, bool success);
  void onFetchQuotaConfigSuccess(const std::string& tenant, const std::string& scope, Buffer::InstancePtr&& response);
  void onFetchQuotaConfigFailure(const std::string& tenant, const std::string& scope, Grpc::Status::GrpcStatus status, const std::string& message);

  // Build and send a DiscoveryRequest with the current subscription set
  // and the cached version_info / response_nonce for ACK. No-op when the
  // stream is not open.
  void sendRequest();

  // Capture subscribed_lru_ into last_sent_resource_names_ so the next
  // response can be diffed for confirmed-miss-omission abandons. Called
  // ONLY from start() (and therefore from onReconnectTimer via start) —
  // see the field docstring for the safety rationale.
  void snapshotSubscribedForAbandon();

  // Parse a single Resource Any, returning the (tenant, scope) extracted
  // from its bucket_id_builder tags. Logs WARN and returns false when the
  // tags are missing.
  bool extractBindingFromSettings(const RateLimitQuotaBucketSettings& bs, std::string& tenant,
                                  std::string& scope) const;

  // Reconnect timer callback. Calls start() and clears the backoff timer
  // so the next failure starts a fresh exponential ramp.
  void onReconnectTimer();

  // Schedule the next reconnect with exponential backoff + jitter. Caps at
  // max_backoff_; doubles current_backoff_ each call until cap.
  void scheduleReconnect();

  Grpc::RawAsyncClientSharedPtr async_client_;
  Event::Dispatcher& dispatcher_;
  DynamicSettingsRegistrySharedPtr registry_;
  const std::chrono::milliseconds initial_backoff_;
  const std::chrono::milliseconds max_backoff_;
  const size_t subscribed_max_;

  // Singleflight tracking for on-demand fetch. Maps `tenant|scope` to a list of callbacks.
  absl::flat_hash_map<std::string, std::vector<FetchQuotaConfigCallback>> inflight_requests_;

  // Tracks in-flight unary RPC handles so they can be cancelled on destruction.
  absl::flat_hash_map<std::string, Grpc::AsyncRequest*> inflight_raw_requests_;

  // TTL tracking for dynamically fetched configs. Maps `tenant|scope` to expiration time.
  absl::flat_hash_map<std::string, MonotonicTime> cache_expiry_;

  // Default TTL for dynamically fetched configs (5 minutes).
  const std::chrono::milliseconds config_ttl_{std::chrono::minutes(5)};

  const Protobuf::MethodDescriptor& service_method_;
  const Protobuf::MethodDescriptor* get_quota_config_method_;
  Grpc::RawAsyncStream* stream_{nullptr};

  // LRU of subscribed resource names ("{tenant}|{scope}"). The list keeps
  // most-recently-touched at front; `subscribed_index_` indexes into it
  // for O(1) lookup-and-touch. Mutated only on the main dispatcher.
  //
  // Why LRU: every ACK / nonce-bumping request resends the entire
  // resource_names set (SOTW), so an unbounded subscribed_ would let the
  // request payload grow with the worker's lifetime observation set. The
  // LRU bounds the request size at subscribed_max_ entries; evicting the
  // coldest (tenant, scope) just means the next request from that worker
  // observing that key will issue a fresh subscribe — same cost it paid
  // when it first observed the key. No correctness loss.
  std::list<std::string> subscribed_lru_;
  absl::flat_hash_map<std::string, std::list<std::string>::iterator> subscribed_index_;

  // Cached ACK state from the most recent DiscoveryResponse. Empty until
  // the first response arrives.
  std::string last_version_info_;
  std::string last_nonce_;

  // Snapshot of resource_names included in the most recent INITIAL or
  // RECONNECT DiscoveryRequest. Populated only by snapshotSubscribedForAbandon()
  // (called from start()); consumed and cleared at onReceiveMessageRaw() to
  // drive confirmed-miss-omission AbandonAction (spec § D-6 Subplan 4).
  //
  // Why only initial/reconnect: the server has two wire-indistinguishable
  // response shapes — (a) full SOTW answer to our request, (b) unsolicited
  // invalidation push scoped to one resource_name (rlqs_config_ds.go:248-285).
  // The ONLY moment we can be confident the response is a full SOTW is right
  // after we open the stream — a single resource_name omitted from that
  // first response unambiguously means "abandoned upstream while we were
  // disconnected". After that first response we clear the set and never
  // re-populate during the steady stream; an unsolicited push that arrives
  // mid-session would otherwise be diffed against the live subscription set
  // and false-erase every (tenant, scope) the push didn't mention.
  //
  // Coverage: catches stale entries left over from a previous filter
  // session / from server-side deletions that happened while the stream was
  // down. Does NOT catch mid-session deletions — those fall to (a) the
  // data-plane RLQS AbandonAction path (next matching request triggers
  // server.AbandonAction → filter erases via global_client_impl.cc:785-797),
  // (b) ExpiredAssignmentBehaviorTimeout. Full immediate coverage requires
  // a server-side proto extension (e.g. `abandoned_resource_names` field
  // on DiscoveryResponse), out of scope here.
  absl::flat_hash_set<std::string> last_sent_resource_names_;

  // Reconnect machinery.
  Event::TimerPtr reconnect_timer_;
  std::chrono::milliseconds current_backoff_;

  // Observability counters set by setStats(). Default is all-nullptr; every
  // increment site nil-checks each pointer so unwired tests pay no overhead.
  ConfigDiscoveryClientStats stats_{};
};

using ConfigDiscoveryClientSharedPtr = std::shared_ptr<ConfigDiscoveryClient>;

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
