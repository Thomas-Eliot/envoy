#pragma once
#include <atomic>
#include <memory>

#include "envoy/thread_local/thread_local.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"

#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.h"
#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.validate.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/registry/registry.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.validate.h"

#include "source/common/http/matching/data_impl.h"
#include "source/common/http/message_impl.h"
#include "source/common/matcher/matcher.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/global_client_impl.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/matcher.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/config_discovery_client.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/dynamic_settings_registry.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/sync_quota_checker.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/token_usage_extractor.h"
#include "source/extensions/matching/input_matchers/cel_matcher/config.h"

#include "re2/re2.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse;
using QuotaAssignmentAction = ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse::
    BucketAction::QuotaAssignmentAction;
// using FilterConfig =
//     envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig;
// using FilterConfigConstSharedPtr = std::shared_ptr<const FilterConfig>;
using RouteConfig = envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaOverride;

using DenyResponseSettings = ::envoy::extensions::filters::http::rate_limit_quota_apig::v3::
    RateLimitQuotaBucketSettings::DenyResponseSettings;

// Reserved BucketId keys. Single source of truth so a typo in one literal
// can't silently disable tenant routing, scope partitioning, or dimension
// dispatch. Mirrors server-side `QuotaDimension*` constants in
// `ratelimit-quota-server/src/config/config_impl.go`.
inline constexpr absl::string_view kBucketIdTenantKey = "_tenant";
inline constexpr absl::string_view kBucketIdScopeKey = "_scope";
inline constexpr absl::string_view kBucketIdDimKey = "_dim";
inline constexpr absl::string_view kBucketIdDimToken = "token";

// Per-worker MD5(route_name) cache held in a ThreadLocal slot on
// FilterConfig. Each worker thread owns its own map and is the sole reader
// / writer, so the hot path is lock-free — matches Envoy's thread model
// (main thread mutates control state, workers mutate their own TLS copies).
// Bounded by FilterConfig::kRouteNameMd5CacheCap.
struct RouteMd5Cache : public ThreadLocal::ThreadLocalObject {
  absl::flat_hash_map<std::string, std::string> cache;
};

/**
 * All local rate limit stats. @see stats_macros.h
 */
#define ALL_RATE_LIMIT_QUOTA_STATS(COUNTER)                                                        \
  COUNTER(rate_total)                                                                              \
  COUNTER(rate_limited)                                                                            \
  COUNTER(new_bucket_id)                                                                           \
  COUNTER(cold_path_sync_started)                                                                  \
  COUNTER(cold_path_sync_allowed)                                                                  \
  COUNTER(cold_path_sync_denied)                                                                   \
  COUNTER(cold_path_sync_error)                                                                    \
  COUNTER(no_sync_checker_upgrade)                                                                 \
  COUNTER(hotspot_access_recorded)                                                                 \
  COUNTER(degraded_sync_allowed)                                                                   \
  COUNTER(degraded_sync_denied)                                                                    \
  COUNTER(degraded_sync_error)                                                                     \
  COUNTER(degraded_sync_concurrency_allowed)                                                       \
  COUNTER(degraded_sync_concurrency_denied)                                                        \
  /* Token-dimension rules always round-trip to RLQS on every request                              \
   * (single-dim _dim:token), bypassing the local token-bucket / cold-hot /                        \
   * degradation paths. Per-request cost of an LLM token cannot be known                            \
   * before the upstream response, so any local approximation cannot deliver                       \
   * 100% accuracy. Started counts dispatches; allowed/denied count outcomes;                      \
   * error counts RPC failures (which fail-open per product spec). */                              \
  COUNTER(token_dim_sync_started)                                                                  \
  COUNTER(token_dim_sync_allowed)                                                                  \
  COUNTER(token_dim_sync_denied)                                                                   \
  COUNTER(token_dim_sync_error)                                                                    \
  /* Concurrency-variant breakdown for multi-dim token-dim rules — mirrors                         \
   * degraded_sync_concurrency_{allowed,denied}. Bumped only when the                              \
   * variant whose RPC just completed had concurrency_limit set, so                                \
   * operators can isolate "denied by token budget" from "denied by                                \
   * concurrency cap" inside the same rule. */                                                     \
  COUNTER(token_dim_sync_concurrency_allowed)                                                      \
  COUNTER(token_dim_sync_concurrency_denied)                                                       \
  COUNTER(tokens_consumed_total)                                                                   \
  COUNTER(tokens_consumed_input)                                                                   \
  COUNTER(tokens_consumed_output)                                                                  \
  COUNTER(tokens_consumed_cached)                                                                  \
  /* Tenant extraction outcome — bump exactly one per request that runs the                       \
   * tenant_key_source path. _unknown means all configured sources failed to                       \
   * yield a non-empty tenant; success means a non-_unknown value was found. */                    \
  COUNTER(tenant_extract_success)                                                                  \
  COUNTER(tenant_extract_unknown)                                                                  \
  /* FILTER_CHAIN_NAME RE2 didn't match the configured chain_name_pattern.                         \
   * High rate suggests a stale pattern or chain-name rename. */                                   \
  COUNTER(tenant_chain_regex_unmatched)                                                            \
  /* RLQS Config Discovery Service (spec § D-8) — observability for the                            \
   * dynamic BucketSettings push pipeline. Stream lifecycle + per-response                         \
   * outcomes; without these the only signal of pipeline trouble was logs. */                      \
  COUNTER(config_discovery_stream_connect)                                                         \
  COUNTER(config_discovery_stream_reconnect)                                                       \
  COUNTER(config_discovery_response_received)                                                      \
  COUNTER(config_discovery_response_parse_error)                                                   \
  COUNTER(config_discovery_settings_parse_error)                                                   \
  COUNTER(config_discovery_settings_missing_binding_tag)                                           \
  /* LRU eviction on the subscribed set inside the discovery client.                              \
   * Non-zero values mean the configured cap is below the working set;                            \
   * see ConfigDiscoveryClient::kDefaultSubscribedMaxEntries. */                                   \
  COUNTER(config_discovery_subscription_evicted)                                                   \
  /* Spec § D-6 Subplan 4: SOTW confirmed-miss-omission AbandonAction                              \
   * applied to the local DynamicSettingsRegistry. Bumped per registry                             \
   * entry erased after a DiscoveryResponse omitted a previously                                   \
   * subscribed resource_name. Healthy churn signal; sustained high                                 \
   * rate vs response_received warrants config review. */                                          \
  COUNTER(config_discovery_abandon_applied)                                                        \
  /* DynamicSettingsRegistry traffic — spec § D-7 multi-dim fan-out                                \
   * observability. Together with the variant counters below, operators see                        \
   * the warm-up curve (variants_missing initially → variants_cached steady). */                   \
  COUNTER(dynamic_registry_lookup_hit)                                                             \
  COUNTER(dynamic_registry_lookup_empty)                                                           \
  COUNTER(dynamic_variant_cached)                                                                  \
  COUNTER(dynamic_variant_missing)                                                                 \
  COUNTER(multi_dim_denied)                                                                        \
  /* AbandonAction received from server (data path). Distinguishes from                            \
   * cold-path bucket creation; high rate means the server is rejecting the                        \
   * filter's BucketIds (spec § D-6). */                                                           \
  COUNTER(abandon_action_received)                                                                 \
  /* T-EC-08 Top 5 Phase 1 — bucket cache publish observability. Counts                            \
   * every writeBucketsToTLS call so we can establish a baseline before the                        \
   * Phase 2 sharded refactor. */                                                                  \
  COUNTER(bucket_cache_publish_total)                                                              \
  /* B-1' debounce hit-rate. Bumped whenever scheduleWriteBucketsToTLS                              \
   * finds a publish already pending and short-circuits — semantically                              \
   * "this schedule call's mutation will be captured by the publish closure                        \
   * already in the dispatcher queue". The increment happens at the schedule                        \
   * site (not at the publish closure), so each pending-schedule produces                          \
   * exactly one increment regardless of how the closure is later                                   \
   * coalesced. Dashboard query: coalesced / (coalesced + total) ≈ batch                            \
   * ratio. Production target: > 0.9 under cold-start / config push.                               \
   * Sync-post test environments always see 0 here because the post                                 \
   * closure runs inline and resets publish_scheduled_ between schedules. */                       \
  COUNTER(bucket_cache_publish_coalesced)                                                          \
  /* T-EC-08 Top 5 Phase 1 — DynamicSettingsRegistry publish observability.                        \
   * Bumped once per snapshot republish (update / erase) so operators can                          \
   * watch server-push churn against the filter's COW cost before the same                         \
   * sharded refactor lands here. */                                                               \
  COUNTER(dynamic_registry_publish_total)

/**
 * Struct definition for all local rate limit stats. @see stats_macros.h
 */
struct RateLimitQuotaStats {
  ALL_RATE_LIMIT_QUOTA_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Possible async results for a limit call.
 */
enum class RateLimitStatus {
  // The request is not over limit.
  OK,
  // The request is over limit.
  OverLimit,
  // The rate limit service could not be queried.
  Error,
};

class FilterConfig {
public:
  FilterConfig(
      const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
          proto_config,
      const std::string& stats_prefix, Stats::Scope& scope,
      Server::Configuration::ServerFactoryContext& factory_context,
      const envoy::config::core::v3::Metadata& listener_metadata =
          envoy::config::core::v3::Metadata::default_instance());
  const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig
  config() const {
    return config_;
  }
  const Matcher::MatchTreeSharedPtr<Http::HttpMatchingData> matcher() const { return matcher_; }
  std::string domain() const { return domain_; }
  RateLimitQuotaStats& stats() const { return stats_; }
  bool extractAgentTokenUsage() const { return config_.extract_agent_token_usage(); }

  // B-5 publish-µs histogram. Lives at
  //   `<stats_prefix>.rate_limit_quota_apig.bucket_cache_publish_us`
  // — same prefix space as the existing `bucket_cache_publish_total`
  // counter so dashboards can graph rate alongside p50 / p99 latency
  // under one query. Created eagerly at FilterConfig construction so
  // the GlobalRateLimitClientImpl can wire it via setBucketCachePublishHistogram.
  Stats::Histogram& bucketCachePublishUsHistogram() const {
    return bucket_cache_publish_us_histogram_;
  }

  // P2 #10 — distribution of dirty shards copied per publish. Bucketed
  // count, no unit; values are in [0, K] where K is the configured shard
  // count. Operators watch p50 / p99 to validate sharding effectiveness:
  //   p50 close to 1 → spread is good, single-bucket mutations isolate
  //   p50 close to K → spread is bad, sharding gives no isolation
  // Recorded at the publish boundary inside writeBucketsToTLS, before
  // dirty_shards_ is cleared.
  Stats::Histogram& bucketCacheDirtyShardsHistogram() const {
    return bucket_cache_dirty_shards_histogram_;
  }

  // Round 2 #B — per-publish duration histogram for the
  // DynamicSettingsRegistry, symmetric with bucketCachePublishUsHistogram.
  // At 50 tenant × 5K BucketSettings, a single push can hit an unfortunate
  // hash distribution where one shard holds the long-tail; without this
  // histogram operators have no signal on registry publish latency.
  Stats::Histogram& dynamicRegistryPublishUsHistogram() const {
    return dynamic_registry_publish_us_histogram_;
  }

  // Round 3 #1 — full reporting-tick duration histogram (µs). At 5K-bucket
  // scale the buildReports walk is the dominant main-thread CPU item;
  // bucket_cache_publish_us only covers writeBucketsToTLS itself.
  // Operator runbook: p99 > reporting_interval/4 means main thread is at
  // risk of falling behind; consider raising reporting_interval via
  // RATELIMIT_QUOTA_REPORTING_INTERVAL_MS_OVERRIDE.
  Stats::Histogram& buildReportsUsHistogram() const {
    return build_reports_us_histogram_;
  }

  std::chrono::milliseconds reportingInterval() const { return reporting_interval_; }

  // env: RATELIMIT_QUOTA_REPORTING_INTERVAL_MS_OVERRIDE
  //
  // Operator escape hatch to override the proto-configured reporting_interval
  // without a CR / Pilot push. Designed for incident-time rebalancing — at
  // 50 listener × 5K dirty bucket / 100ms cadence the buildReports walk is the
  // largest single CPU item on the main thread (~5–10%). Doubling the
  // interval to 200ms cuts that load in half at the cost of doubling the
  // server-side burst-visibility window.
  //
  // Range clamp: [50ms, 5000ms]. Values below 50ms compress the dispatcher
  // queue and lose any aggregation benefit; values above 5s exceed the
  // server's stale-bucket eviction grace and risk apparent quota gaps. Out-
  // of-range or non-numeric values fall through to the proto value.
  //
  // Read once at process start (static local in
  // `effectiveRateLimitQuotaReportingIntervalMs`); env mutations after start
  // are ignored. Set this on listener pods only — the filter-config factory
  // on the main dispatcher reads it at the same point as the listener proto.
  static constexpr int64_t kRateLimitQuotaReportingIntervalMinMs = 50;
  static constexpr int64_t kRateLimitQuotaReportingIntervalMaxMs = 5000;

  // Resolve the effective reporting interval: env override (if valid) takes
  // precedence over `proto_value_ms`. `proto_value_ms` is the value already
  // pulled out of the FilterConfig proto via PROTOBUF_GET_MS_OR_DEFAULT — we
  // accept it as int64 to keep this helper free of proto includes.
  //
  // Production callers use the no-arg overload, which reads the env var
  // exactly once into a static-local cache (subsequent mutations ignored).
  // Tests should prefer `resolveReportingInterval` below — it takes the
  // env value as an explicit argument so tests can pin every resolution
  // case without fighting the one-shot cache.
  static std::chrono::milliseconds effectiveReportingIntervalMs(int64_t proto_value_ms);

  // Pure function: given an env-override value in ms (0 = unset/invalid)
  // and the proto-configured value in ms, return the effective interval.
  //  - env_override_ms == 0           → return proto_value_ms
  //  - env_override_ms in [50, 5000]  → return env_override_ms
  //  - env_override_ms otherwise      → log warn, return proto_value_ms
  // Logging: out-of-range values warn so operator typos surface in pod
  // logs rather than silently picking a clamp boundary.
  static std::chrono::milliseconds
  resolveReportingInterval(int64_t env_override_ms, int64_t proto_value_ms);

  const envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource& tenantKeySource() const {
    return config_.tenant_key_source();
  }

  // F-1.2 (perf plan): cached final values for tenant LISTENER_METADATA
  // lookup. Computed once at config load so the per-request path doesn't
  // construct two std::string temporaries (proto default vs. configured)
  // on every decodeHeaders call.
  const std::string& tenantMetadataNamespace() const { return tenant_metadata_namespace_; }
  const std::string& tenantMetadataField() const { return tenant_metadata_field_; }

  // Cached MD5-hex of route_name for the ROUTE_NAME scope path. Without this
  // cache, the default ScopeConfig (disable_route_name_hash=false) MD5s the
  // route name on every request — pure waste, since route names are stable
  // across the lifetime of this FilterConfig. Bounded to prevent unbounded
  // growth in pathological cases (e.g. regex-derived route names with
  // unbounded cardinality); once the cap is hit, further misses fall back
  // to per-request md5 and skip the cache write.
  //
  // Implementation: per-worker TLS slot, not a shared mutex-guarded map —
  // Envoy's threading guarantees that each worker is the sole reader and
  // writer of its own `RouteMd5Cache`, so the hot path takes zero locks.
  std::string cachedRouteNameMd5(absl::string_view route_name) const;

  // Listener-level metadata snapshot captured at filter-config creation time.
  // Spec § D-1 / § 7: LISTENER_METADATA tenant extraction reads from the
  // listener's static metadata (set in the Listener proto, e.g. by the gateway
  // operator), not per-request dynamicMetadata. The reference points into the
  // copy stored on this FilterConfig, whose lifetime spans the listener.
  const envoy::config::core::v3::Metadata& listenerMetadata() const { return listener_metadata_; }
  // RE2 is used in place of std::regex to (a) avoid catastrophic backtracking
  // on adversarial input — RE2 has guaranteed linear-time matching — and
  // (b) cut per-request CPU on hot path. The regex is compiled once at
  // listener load time; chainNamePatternRegex() returns the pre-compiled
  // engine for the request path to call PartialMatch with capture groups.
  const re2::RE2* chainNamePatternRegex() const { return chain_name_pattern_regex_.get(); }
  bool hasChainNamePattern() const { return chain_name_pattern_regex_ != nullptr; }

  // Cold/hot: cached at construction (proto `cold_hot_config.disabled` defaults to off when unset).
  bool coldHotSplitEnabled() const { return cold_hot_split_enabled_; }
  uint32_t hotspotThreshold() const { return hotspot_threshold_; }

  // True iff this listener uses the RLQS Config Discovery dynamic-loading
  // mode (spec § D-8). Single source of truth for code paths that branch on
  // dynamic vs. static. Internally delegates to `isDynamicModeProto` so the
  // FilterConfig ctor — which can't yet call non-static accessors on
  // `*this` — uses the same predicate as runtime callers; any future tweak
  // is a single-site change.
  bool isDynamicMode() const { return isDynamicModeProto(config_); }

  // Static form for use during member-initializer-list construction, when
  // `*this` isn't yet a complete object. Production callers should prefer
  // the non-static `isDynamicMode()` accessor.
  static bool isDynamicModeProto(
      const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
          proto_config) {
    return proto_config.has_rlqs_config_server();
  }

private:
  // Single source of truth for the stats namespace appended to the
  // listener-supplied prefix. Counter macros, histogram registration, and
  // any future gauge wiring must all anchor on `<prefix>.<finalPrefixSuffix>.<name>`
  // so dashboards see one consistent stat root.
  static constexpr const char* finalPrefixSuffix() { return ".rate_limit_quota_apig"; }
  static std::string makeFinalPrefix(const std::string& prefix) {
    return prefix + finalPrefixSuffix();
  }

  static RateLimitQuotaStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    const std::string final_prefix = makeFinalPrefix(prefix);
    return {ALL_RATE_LIMIT_QUOTA_STATS(POOL_COUNTER_PREFIX(scope, final_prefix))};
  }

private:
  envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig config_;
  const std::string domain_;
  mutable RateLimitQuotaStats stats_;
  // B-5 — `bucket_cache_publish_us` histogram. Held as a reference because
  // the Stats::Scope owns the histogram's lifetime; FilterConfig only pins
  // it via the named-stat registration. Recorded by GlobalRateLimitClientImpl
  // inside writeBucketsToTLS once setBucketCachePublishHistogram has wired
  // a pointer to this reference.
  Stats::Histogram& bucket_cache_publish_us_histogram_;
  // P2 #10 — `bucket_cache_dirty_shards_per_publish` histogram. Same scope
  // as the µs histogram above; recorded at the publish boundary inside
  // writeBucketsToTLS via setBucketCacheDirtyShardsHistogram.
  Stats::Histogram& bucket_cache_dirty_shards_histogram_;
  // Round 2 #B — `dynamic_registry_publish_us` histogram. Wired into
  // DynamicSettingsRegistry::setPublishUsHistogram from config.cc.
  Stats::Histogram& dynamic_registry_publish_us_histogram_;
  // Round 3 #1 — `bucket_cache_build_reports_us` histogram. Wired into
  // GlobalRateLimitClientImpl::setBuildReportsUsHistogram from config.cc.
  Stats::Histogram& build_reports_us_histogram_;
  const std::chrono::milliseconds reporting_interval_;
  const bool cold_hot_split_enabled_;
  const uint32_t hotspot_threshold_;
  Matcher::MatchTreeSharedPtr<Http::HttpMatchingData> matcher_ = nullptr;
  // Compiled at listener load. nullptr ⇔ no chain_name_pattern configured;
  // hasChainNamePattern() is the canonical guard the request path must check
  // before dereferencing the engine.
  std::unique_ptr<re2::RE2> chain_name_pattern_regex_;
  // Owning copy of the listener's static metadata captured from
  // FactoryContext::listenerMetadata() at filter-config creation. Copied (not
  // referenced) because the FactoryContext is not guaranteed to outlive this
  // object; the proto is small and only copied once per listener push.
  envoy::config::core::v3::Metadata listener_metadata_;
  // F-1.2: pre-resolved LISTENER_METADATA lookup keys (with spec D-1 defaults
  // already applied: "apig_tenant" / "tenant_id"). Stored as owning strings
  // because the source values come from `proto_config` which is value-copied
  // into config_.
  std::string tenant_metadata_namespace_;
  std::string tenant_metadata_field_;

  // Bounded cache for cachedRouteNameMd5. Route names per listener are
  // typically O(10²); the cap is a safety net for unbounded-cardinality
  // generators (regex-extracted names, header-derived scopes), not a
  // resource-pressure knob — pick a value high enough to never matter in
  // normal operation. The cap applies per-worker (each TLS slot has its own
  // map), so worst-case memory ≈ N_workers × cap × ~64 B = a few MB.
  static constexpr size_t kRouteNameMd5CacheCap = 4096;
  // TLS slot: each worker holds its own RouteMd5Cache instance, populated
  // lazily on first MD5 miss. set() at FilterConfig construction posts the
  // factory to every worker dispatcher; until a worker's slot is populated
  // (brief startup window), cachedRouteNameMd5 falls back to direct md5Hex.
  mutable ThreadLocal::TypedSlot<RouteMd5Cache> route_md5_tls_;
};
using FilterConfigConstSharedPtr = std::shared_ptr<const FilterConfig>;

class FilterConfigRoute : public Router::RouteSpecificFilterConfig {
public:
  FilterConfigRoute(const RouteConfig& config,
                    Server::Configuration::ServerFactoryContext& factory_context)
      : domain_(config.domain()) {
    if (config.has_bucket_matchers()) {
      RateLimitOnMatchActionContext context;
      Matcher::MatchTreeFactory<Http::HttpMatchingData, RateLimitOnMatchActionContext> factory(
          context, factory_context, visitor_);
      matcher_ = factory.create(config.bucket_matchers())();
    }
  }

  const Matcher::MatchTreeSharedPtr<Http::HttpMatchingData> matcher() const { return matcher_; }
  const std::string& domain() const { return domain_; }

private:
  // const xds::type::matcher::v3::Matcher matcher_;
  Matcher::MatchTreeSharedPtr<Http::HttpMatchingData> matcher_ = nullptr;
  RateLimitQuotaValidationVisitor visitor_ = {};
  const std::string domain_;
};

class RateLimitQuotaFilter : public Http::PassThroughFilter,
                             public AsyncQuotaCheckCallbacks,
                             public Logger::Loggable<Logger::Id::rate_limit_quota> {
public:
  RateLimitQuotaFilter(FilterConfigConstSharedPtr config,
                       Server::Configuration::FactoryContext& factory_context,
                       std::unique_ptr<RateLimitClient> local_client,
                       Grpc::GrpcServiceConfigWithHashKey config_with_hash_key,
                       std::shared_ptr<SyncQuotaChecker> sync_checker = nullptr,
                       DynamicSettingsRegistrySharedPtr dynamic_registry = nullptr,
                       ConfigDiscoveryClientSharedPtr config_discovery_client = nullptr)
      : config_(std::move(config)), config_with_hash_key_(config_with_hash_key),
        factory_context_(factory_context), matcher_(config_->matcher()),
        client_(std::move(local_client)),
        time_source_(
            factory_context.getServerFactoryContext().mainThreadDispatcher().timeSource()),
        sync_quota_checker_(sync_checker),
        dynamic_registry_(std::move(dynamic_registry)),
        config_discovery_client_(std::move(config_discovery_client)),
        token_usage_accumulator_(config_->extractAgentTokenUsage()) {}

  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool end_stream) override;
  // decodeHeaders returns StopIteration while a synchronous quota check (cold
  // path / degraded SyncCheck / token-dim sync) is in flight. For requests that
  // carry a body (end_stream=false on headers), the inherited
  // PassThroughFilter::decodeData returns Continue, which RESUMES iteration and
  // forwards the request upstream before the check resolves — so the server's
  // deny arrives too late and the request is never blocked. Hold the body /
  // trailers until the async callback calls continueDecoding().
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override;
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool end_stream) override;
  void onDestroy() override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks& callbacks) override {
    encoder_callbacks_ = &callbacks;
  }

  // AsyncQuotaCheckCallbacks implementation
  void onQuotaCheckComplete(bool allowed) override;
  void onQuotaCheckError() override;

  // Callback for when ConfigDiscoveryClient finishes fetching the quota config.
  void onQuotaConfigFetchComplete(bool success);

  // Perform request matching. It returns the generated bucket ids if the
  // matching succeeded, error status otherwise.
  absl::StatusOr<Matcher::ActionPtr> requestMatching(const Http::RequestHeaderMap& headers);

  Http::Matching::HttpMatchingDataImpl matchingData() {
    ASSERT(data_ptr_ != nullptr);
    return *data_ptr_;
  }

private:
  // Create the matcher factory and matcher.
  void createMatcher(const xds::type::matcher::v3::Matcher& matcher);

  Http::FilterHeadersStatus processCachedBucket(const DenyResponseSettings& deny_response_settings,
                                                const BucketId& bucket_id_proto,
                                                const RateLimitQuotaBucketSettings& bucket_settings);
  Http::FilterHeadersStatus processCachedBucket(const DenyResponseSettings& deny_response_settings,
                                                CachedBucket& cached_bucket);
  bool shouldAllowRequest(const CachedBucket& cached_bucket);

  // Single-dim token rules (BucketId carries `_dim:token`) bypass every local
  // path and round-trip to the RLQS server on every request. The local
  // token-bucket / cold-hot / degradation approximations cannot deliver 100%
  // accuracy when the per-request token cost is only known from the upstream
  // response. On RPC error/timeout the request fails open per product spec
  // (AI requests are expensive; degraded availability is worse than a brief
  // overshoot). Periodic reports still carry tokens_consumed against the
  // same cached bucket, so the server keeps an accurate consumption ledger.
  Http::FilterHeadersStatus
  dispatchTokenDimensionSync(const BucketId& bucket_id_proto,
                             const RateLimitQuotaBucketSettings& bucket_settings);

  // Clear the three "which sync mode is in flight" flags together. Called
  // when transitioning out of cold-path / degraded / token-dim sync — keeping
  // them in lock-step prevents a stale flag from misrouting the NEXT callback.
  void clearPendingSyncCheckFlags();

  // F-1.4: lazy builder for `deny_details_` + the dynamic-metadata bucket
  // logging struct. Previously both ran unconditionally on every request in
  // decodeHeaders (~15 small allocs per request). Now they fire only on the
  // deny path. Sync deny sites pass the local BucketId; async callbacks pass
  // the saved `cold_path_bucket_id_` (which is set before any async check).
  void buildDenyDetailsLazy(const BucketId& bucket_id_proto);

  // Spec § D-7 multi-dim fan-out. Returns engaged optional only when the
  // dynamic registry has a SettingsList for this (tenant, scope) AND every
  // dim's variant BucketId is already cached locally — i.e. the warm path
  // can issue an independent quota check per dim and return the first-deny
  // dim's deny_response. On a miss, returns nullopt so the caller falls
  // back to the existing single-dim path with the base BucketId; the
  // missing variants are registered via createBucket as a side effect so
  // the next request picks them up.
  absl::optional<Http::FilterHeadersStatus>
  tryDynamicMultiDimensionCheck(const BucketId& base_bucket_id_proto,
                                const RateLimitOnMatchAction& match_action);

  // Build the (tenant, scope) registry key from the base BucketId; returns
  // empty when either piece is missing (filter falls back to single-dim).
  std::pair<std::string, std::string>
  extractTenantScopeKey(const BucketId& base_bucket_id_proto) const;

  // Initiate async quota check for degradation mode.
  // Returns true if async check was started (request should be paused).
  bool initiateAsyncQuotaCheck(const CachedBucket& cached_bucket);

  // ---- Multi-dim 100% accurate dispatch state machine ---------------
  // Pending deduction record — same shape as the lambda-local struct in
  // the legacy multi-dim loop, hoisted to a member so the async resume
  // callbacks can walk it across StopIteration boundaries.
  struct MultiDimPendingDeduction {
    std::shared_ptr<CachedBucket> bucket;
    bool was_concurrency{false};
  };

  // Variant deferred to the Phase-2 (async SyncCheck) pass: a strict
  // request bucket in degraded mode, or a strict concurrency bucket whose
  // Phase-1 local CAS would have failed.
  struct DeferredSyncCheckVariant {
    BucketId id;
    std::shared_ptr<CachedBucket> cached;
    RateLimitQuotaBucketSettingsConstSharedPtr settings;
    bool is_concurrency{false};
  };

  // State carried across the multi-dim dispatch's async suspend points.
  // Lives only while a dispatch is in flight; created in Phase 1, drained
  // in Phase 2, destroyed on terminal commit / abort.
  struct MultiDimDispatchState {
    std::vector<MultiDimPendingDeduction> pending;
    std::vector<DeferredSyncCheckVariant> deferred;
    size_t deferred_cursor{0};
    DenyResponseSettings final_deny_response_settings; // from the variant that triggered DENY
    std::string deny_details;
    // True when any variant in this dispatch has `_dim:token`. Forces every
    // variant to defer to Phase 2 sync RPC (skipping local CAS / token
    // bucket entirely) and switches the RPC-error path from fail-closed
    // (strict default) to fail-open (operator product spec: AI requests
    // must not be blocked by RLQS degradation).
    bool token_dim_failopen{false};
  };

  // Active dispatch state; non-null only between Phase 1 entry and the
  // terminal continueDecoding / sendLocalReply. onQuotaCheck{Complete,
  // Error} branches on this pointer to route async callbacks back into
  // the multi-dim resume path instead of the single-dim legacy handler.
  std::unique_ptr<MultiDimDispatchState> multi_dim_state_;

  // Phase-1 → Phase-2 entry: fires the next deferred variant's
  // checkQuotaAsync. Drives the StopIteration/resume loop. Returns the
  // FilterHeadersStatus the caller should propagate (StopIteration when
  // an RPC is in flight, Continue when everything is done).
  Http::FilterHeadersStatus sendNextDeferredMultiDimSyncCheck();

  // Async-callback entry from onQuotaCheckComplete when multi_dim_state_
  // is set. Applies the just-allowed variant's local INC and advances
  // the cursor, then either fires the next SyncCheck (StopIteration) or
  // commits everything (continueDecoding).
  void resumeMultiDimAfterSyncCheck(bool allowed);

  // Async-callback entry from onQuotaCheckError. Rolls back pending +
  // primes the deny cache for the variant that errored, then sends a
  // deny response. Fail-closed for strict (no fallback_allow override).
  void abortMultiDimAfterError();

  // Rollback compensation shared between Phase-1 sync denies and Phase-2
  // async denies. Walks `pending` in reverse, refunding token buckets,
  // decrementing concurrency active_requests, and clawing back the
  // num_requests_allowed bumps recorded earlier.
  void rollbackMultiDimPending(std::vector<MultiDimPendingDeduction>& pending);
  // -------------------------------------------------------------------

  // Resolve and write the strict-mode deny cache for the bucket whose
  // SyncCheck round trip just completed. Re-fetches the live bucket via
  // client_->getBucket(pending_strict_bucket_id_hash_) so a TLS shard swap
  // between initiateAsyncQuotaCheck and the callback doesn't strand the
  // write on a detached old shared_ptr. Falls back to the captured
  // pending_strict_bucket_ when the re-fetch returns nullptr (bucket
  // evicted by abandon_action). Then resets all three pending strict
  // fields. No-op when not in strict mode.
  void primeStrictDenyCache(int64_t ttl_ns);

  // Token usage (wasm-go GetTokenUsage-compatible): JSON paths, SSE framing,
  // OpenAI /responses merge, incremental credit to QuotaUsage::tokens_consumed.
  void resetTokenUsageState();
  void creditPendingTokenUsageDelta();
  void processSseEventForTokens(absl::string_view raw_event);
  void appendSseBodyForTokens(absl::string_view chunk, bool end_stream);
  void appendJsonBodyForTokens(absl::string_view chunk, bool end_stream);

  FilterConfigConstSharedPtr config_;
  Grpc::GrpcServiceConfigWithHashKey config_with_hash_key_;
  Server::Configuration::FactoryContext& factory_context_;
  Http::StreamDecoderFilterCallbacks* callbacks_ = nullptr;
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_ = nullptr;
  RateLimitQuotaValidationVisitor visitor_ = {};
  Matcher::MatchTreeSharedPtr<Http::HttpMatchingData> matcher_ = nullptr;
  std::unique_ptr<Http::Matching::HttpMatchingDataImpl> data_ptr_ = nullptr;

  // Own a local, filter-specific client to provider functions needed by worker
  // threads.
  std::unique_ptr<RateLimitClient> client_;
  TimeSource& time_source_;

  // Optional synchronous quota checker for degradation mode.
  // When the bucket is in degraded mode, this checker is used to perform
  // synchronous quota checks instead of local token bucket consumption.
  std::shared_ptr<SyncQuotaChecker> sync_quota_checker_;

  // Dynamic per-(tenant, scope) BucketSettings pushed by the server via
  // StreamRlQsConfigs (spec § D-8). When non-null, runs the multi-dim quota
  // check on the warm path (spec § D-7); when null, falls back to the
  // static xDS bucket_matchers single-dim path. The discovery client and
  // registry are both optional — the filter remains functional without
  // either, matching the pre-Phase-1 behavior.
  DynamicSettingsRegistrySharedPtr dynamic_registry_;
  ConfigDiscoveryClientSharedPtr config_discovery_client_;

  // State for async quota config fetch
  bool waiting_for_quota_config_{false};
  BucketId pending_bucket_id_proto_;
  std::unique_ptr<RateLimitOnMatchAction> pending_match_action_;
  // Guard for the cross-thread fetchQuotaConfig callback. The callback fires
  // on the main thread (via ConfigDiscoveryClient) and posts back to this
  // filter's worker dispatcher. If the filter is destroyed before the posted
  // closure runs, the guard prevents use-after-free.
  std::shared_ptr<std::atomic<bool>> config_fetch_alive_guard_;

  // State for async quota check
  bool waiting_for_quota_check_{false};
  // Set for cold-path sync only; cleared before degradation-mode sync begins.
  bool cold_path_sync_check_pending_{false};
  // Set when dispatchTokenDimensionSync owns the in-flight SyncCheck. Routes
  // onQuotaCheckComplete / onQuotaCheckError into the token-dim handler
  // (fail-open on error) instead of the cold/degraded handlers (which use
  // operator-configured fallback policy).
  bool token_dim_sync_pending_{false};
  // BucketId for the token-dim sync in flight. Used by the deny path to call
  // buildDenyDetailsLazy with the correct ID. Separate from cold_path_bucket_id_
  // because the latter doubles as a "send one-off report on stream end" signal
  // that we don't need here — the periodic reporter owns reporting for the
  // already-cached bucket.
  BucketId token_dim_bucket_id_;
  std::shared_ptr<QuotaUsage> pending_quota_usage_;
  DenyResponseSettings pending_deny_settings_;
  std::string deny_details_{"quota_rate_limited"};

  // Strict-request 100% accuracy: snapshot of the cached bucket's
  // strict_request_mode flag captured at initiateAsyncQuotaCheck time.
  // Used by onQuotaCheckError to override fallback_allow_on_timeout with
  // fail-closed and to populate the bucket's deny_until_ns cache. False
  // for token / concurrency dimensions, preserving legacy behavior.
  bool pending_strict_request_mode_{false};
  // Captured shared_ptr to the cached bucket whose SyncCheck is in flight.
  // Held strictly as a fallback: if a TLS shard swap between initiate and
  // callback rebuilds the bucket, the canonical write target is the
  // currently-published bucket (re-fetched via client_->getBucket using
  // pending_strict_bucket_id_hash_ below); this snapshot is only used when
  // the re-fetch returns nullptr (e.g., abandon_action evicted the entry).
  std::shared_ptr<CachedBucket> pending_strict_bucket_;
  // Hash key of the strict bucket pending an async check. 0 = nothing
  // pending. Captured at initiateAsyncQuotaCheck so the callback can
  // re-resolve to the live bucket without re-deriving from the matcher.
  size_t pending_strict_bucket_id_hash_{0};

  // State for token tracking
  std::shared_ptr<QuotaUsage> pending_token_quota_usage_;
  BucketId cold_path_bucket_id_;
  bool response_is_json_{false};
  bool response_is_sse_{false};
  // Set in addition to response_is_json_ when content-type is
  // application/vnd.amazon.eventstream (Bedrock streaming). Routed through the
  // JSON path, which is binary-tolerant via extractUsageObject.
  bool response_is_aws_eventstream_{false};

  TokenUsageAccumulator token_usage_accumulator_;
  OpenAiResponseStreamMerger openai_response_stream_merger_;
  std::string sse_token_stream_buffer_;
  std::string json_token_response_buffer_;
  uint64_t last_token_credit_total_{0};
  uint64_t last_input_token_credit_{0};
  uint64_t last_output_token_credit_{0};
  uint64_t last_cached_token_credit_{0};

  // State for concurrency tracking
  bool concurrency_incremented_{false};
  bool is_concurrency_limit_pending_{false};
  std::shared_ptr<QuotaUsage> active_quota_usage_;

  // Multi-dim (spec § D-7) per-variant concurrency tracking. The single-dim
  // scalars above can only represent one CAS-incremented bucket. When a route
  // fans out into N variant BucketIds and more than one variant has a
  // concurrency_limit, every successful CAS must be remembered so onDestroy
  // can decrement them all. Without this, active_requests leaks monotonically
  // and the server's gauge-based concurrency check eventually denies every
  // request to the route.
  std::vector<std::shared_ptr<QuotaUsage>> multi_dim_active_quota_usages_;

  // SyncCheck latency tracking: set when an async check is initiated (cold or degraded).
  MonotonicTime sync_check_start_time_{};
  bool sync_check_timing_active_{false};

  // Set when a degraded SyncCheck was performed (not cold path).
  // Used to emit token-deviation warnings when actual tokens are later extracted.
  bool was_degraded_sync_{false};
  // Estimated token count deducted by SyncCheck (always 1 per request on the Envoy side;
  // actual avg_tokens_per_request is configured server-side).
  static constexpr uint64_t kSyncCheckTokenEstimate = 1;
};

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
