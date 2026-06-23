#include "source/extensions/filters/http/rate_limit_quota_apig/filter.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>

#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"
#include "envoy/matcher/matcher.h"
#include "envoy/stream_info/stream_info.h"
#include "envoy/type/v3/ratelimit_strategy.pb.h"

#include "source/common/common/hex.h"
#include "source/common/common/logger.h"
#include "source/common/http/matching/data_impl.h"
#include "source/common/matcher/matcher.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/matcher.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/time_utils.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/token_usage_extractor.h"

#include "source/common/json/json_loader.h"

#include "openssl/md5.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"

#include "absl/container/inlined_vector.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_cat.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

// Forward declaration — defined near appendJsonBodyForTokens below.
static std::string extractUsageObject(absl::string_view buf);

namespace {

// MD5(input) → 32-char lower-case hex. Used to bound the length of the
// route_name component of `_scope` when ScopeConfig.enable_route_name_hash is
// true, so user-defined route names of arbitrary length stay within the
// rate-limit service's Redis key length budget.
std::string md5Hex(absl::string_view input) {
  uint8_t digest[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const uint8_t*>(input.data()), input.size(), digest);
  return Hex::encode(digest, MD5_DIGEST_LENGTH);
}

Matcher::MatchTreeSharedPtr<Http::HttpMatchingData> createMatcher(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        config,
    Server::Configuration::ServerFactoryContext& context) {
  if (config.has_bucket_matchers()) {
    RateLimitQuotaValidationVisitor validation_visitor;
    RateLimitOnMatchActionContext action_factory_context;
    Matcher::MatchTreeFactory<::Envoy::Http::HttpMatchingData, RateLimitOnMatchActionContext>
        factory(action_factory_context, context, validation_visitor);
    return factory.create(config.bucket_matchers())();
  }
  // Allow matcher to not be set, to allow for cases where we only have route or
  // virtual host specific configurations.
  return {};
}
} // namespace

namespace {
constexpr std::chrono::milliseconds kDefaultSyncCheckTimeout{100};
constexpr bool kDefaultFallbackAllowOnTimeout = true;

using DegradationModeConfig =
    envoy::extensions::filters::http::rate_limit_quota_apig::v3::DegradationModeConfig;
using ColdHotSplitConfig =
    envoy::extensions::filters::http::rate_limit_quota_apig::v3::ColdHotSplitConfig;

std::chrono::milliseconds durationToMs(const google::protobuf::Duration& d) {
  return std::chrono::milliseconds(d.seconds() * 1000 + d.nanos() / 1000000);
}

bool readFallbackAllowOnTimeout(const DegradationModeConfig& dm) {
  if (dm.has_fallback_allow_on_timeout()) {
    return dm.fallback_allow_on_timeout().value();
  }
  return kDefaultFallbackAllowOnTimeout;
}

bool readColdFallbackAllowOnError(const ColdHotSplitConfig& ch) {
  if (ch.has_cold_fallback_allow_on_error()) {
    return ch.cold_fallback_allow_on_error().value();
  }
  return kDefaultFallbackAllowOnTimeout;
}

std::chrono::milliseconds coldPathTimeoutValue(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        cfg) {
  if (cfg.has_cold_hot_config() && cfg.cold_hot_config().has_cold_sync_timeout()) {
    const auto ms = durationToMs(cfg.cold_hot_config().cold_sync_timeout());
    // A zero Duration means the field was explicitly set but left at protobuf default.
    // Fall through to kDefaultSyncCheckTimeout rather than firing timers instantly.
    if (ms.count() > 0) {
      return ms;
    }
  }
  if (cfg.has_degradation_mode_config() && cfg.degradation_mode_config().has_sync_check_timeout()) {
    const auto ms = durationToMs(cfg.degradation_mode_config().sync_check_timeout());
    if (ms.count() > 0) {
      return ms;
    }
  }
  return kDefaultSyncCheckTimeout;
}

std::chrono::milliseconds degradationSyncTimeoutValue(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        cfg) {
  if (cfg.has_degradation_mode_config() && cfg.degradation_mode_config().has_sync_check_timeout()) {
    const auto ms = durationToMs(cfg.degradation_mode_config().sync_check_timeout());
    if (ms.count() > 0) {
      return ms;
    }
  }
  return kDefaultSyncCheckTimeout;
}

std::chrono::milliseconds configFetchTimeoutValue(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        cfg) {
  if (cfg.has_config_fetch_timeout()) {
    const auto& d = cfg.config_fetch_timeout();
    return std::chrono::milliseconds(d.seconds() * 1000 + d.nanos() / 1000000);
  }
  return std::chrono::milliseconds(2000);
}

bool coldPathErrorFallbackAllow(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        cfg) {
  if (cfg.has_cold_hot_config()) {
    return readColdFallbackAllowOnError(cfg.cold_hot_config());
  }
  if (cfg.has_degradation_mode_config()) {
    return readFallbackAllowOnTimeout(cfg.degradation_mode_config());
  }
  return kDefaultFallbackAllowOnTimeout;
}

bool degradationErrorFallbackAllow(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        cfg) {
  if (cfg.has_degradation_mode_config()) {
    return readFallbackAllowOnTimeout(cfg.degradation_mode_config());
  }
  return kDefaultFallbackAllowOnTimeout;
}

// A rule is "token dimension" iff its BucketId carries `_dim:token`. The
// server stamps this key via bucket_id_builder for single-dim token rules.
// We match the exact dimension marker rather than scanning BucketSettings,
// because the same identification is used by the server-side reporter to
// correlate the per-request SyncCheck with the eventual tokens_consumed
// figure in the periodic report.
bool isTokenDimensionBucket(const BucketId& bucket_id_proto) {
  auto it = bucket_id_proto.bucket().find(std::string(kBucketIdDimKey));
  return it != bucket_id_proto.bucket().end() && it->second == kBucketIdDimToken;
}

} // namespace

const char kBucketMetadataNamespace[] = "envoy.extensions.http_filters.rate_limit_quota.bucket";

// Cap buffered response bytes for token extraction (SSE / JSON accumulation).
constexpr size_t kMaxTokenStreamBufferBytes = 512 * 1024;

using envoy::type::v3::RateLimitStrategy;
using NoAssignmentBehavior = envoy::extensions::filters::http::rate_limit_quota_apig::v3::
    RateLimitQuotaBucketSettings::NoAssignmentBehavior;

namespace {

// Read RATELIMIT_QUOTA_REPORTING_INTERVAL_MS_OVERRIDE once at process start.
// Returns 0 when unset, non-numeric, or non-positive — the caller treats 0
// as "no override" and falls through to the proto value. Range clamping is
// applied later in resolveReportingInterval, so the cache here is just a
// faithful read of the operator's literal env value.
int64_t reportingIntervalEnvOverrideMs() {
  static const int64_t cached = []() -> int64_t {
    const char* env = std::getenv("RATELIMIT_QUOTA_REPORTING_INTERVAL_MS_OVERRIDE");
    if (env == nullptr) {
      return 0;
    }
    char* end = nullptr;
    const long parsed = std::strtol(env, &end, 10);
    if (end == env || parsed <= 0) {
      return 0;
    }
    return static_cast<int64_t>(parsed);
  }();
  return cached;
}

} // namespace

std::chrono::milliseconds
FilterConfig::resolveReportingInterval(int64_t env_override_ms, int64_t proto_value_ms) {
  if (env_override_ms == 0) {
    return std::chrono::milliseconds(proto_value_ms);
  }
  // Clamp to safe operating range. Out-of-range values fall back to the
  // proto value rather than silently picking a clamp boundary, which would
  // mask operator typos like RATELIMIT_QUOTA_REPORTING_INTERVAL_MS_OVERRIDE=10000000.
  if (env_override_ms < kRateLimitQuotaReportingIntervalMinMs ||
      env_override_ms > kRateLimitQuotaReportingIntervalMaxMs) {
    ENVOY_LOG_MISC(warn,
                   "RLQS reporting_interval env override {} ms outside [{}, {}], "
                   "ignoring; proto value {} ms used.",
                   env_override_ms, kRateLimitQuotaReportingIntervalMinMs,
                   kRateLimitQuotaReportingIntervalMaxMs, proto_value_ms);
    return std::chrono::milliseconds(proto_value_ms);
  }
  ENVOY_LOG_MISC(info,
                 "RLQS reporting_interval overridden via env: proto={} ms → {} ms",
                 proto_value_ms, env_override_ms);
  return std::chrono::milliseconds(env_override_ms);
}

std::chrono::milliseconds
FilterConfig::effectiveReportingIntervalMs(int64_t proto_value_ms) {
  return resolveReportingInterval(reportingIntervalEnvOverrideMs(), proto_value_ms);
}

std::string FilterConfig::cachedRouteNameMd5(absl::string_view route_name) const {
  // Per-worker TLS cache; this worker is the sole reader/writer of its slot,
  // so no synchronization is needed. The TLS slot is populated by the
  // factory passed to set() in the FilterConfig ctor — it can only return
  // empty during the brief startup window between FilterConfig construction
  // and the worker dispatcher processing the set() post.
  auto cache_ref = route_md5_tls_.get();
  if (!cache_ref.has_value()) {
    return md5Hex(route_name);
  }
  auto& cache = cache_ref->cache;
  // absl::flat_hash_map doesn't support heterogeneous lookup by default;
  // constructing the std::string key is unavoidable but typically fits SSO
  // for normal route names — far cheaper than the MD5 round it replaces.
  const std::string key(route_name);
  auto it = cache.find(key);
  if (it != cache.end()) {
    return it->second;
  }
  // Above the cap we silently fall back to per-request MD5 — correctness is
  // preserved, only the cache benefit is lost for new entries.
  std::string hash = md5Hex(route_name);
  if (cache.size() < kRouteNameMd5CacheCap) {
    cache.emplace(key, hash);
  }
  return hash;
}

bool FilterConfig::shouldTouchConfigAccess(absl::string_view tenant, absl::string_view scope,
                                           TimeSource& time_source) const {
  auto dedup_ref = config_access_dedup_tls_.get();
  if (!dedup_ref.has_value()) {
    return true;
  }
  auto& dedup = dedup_ref->last_touch;
  const std::string key = DynamicSettingsRegistry::makeKey(tenant, scope);
  auto now = time_source.monotonicTime();
  auto it = dedup.find(key);
  if (it != dedup.end() &&
      std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() <
          kConfigAccessTouchDedupSec) {
    return false;
  }
  if (dedup.size() >= kConfigAccessDedupCap && it == dedup.end()) {
    return true;
  }
  dedup[key] = now;
  return true;
}

FilterConfig::FilterConfig(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        proto_config,
    const std::string& stats_prefix, Stats::Scope& scope,
    Server::Configuration::ServerFactoryContext& factory_context,
    const envoy::config::core::v3::Metadata& listener_metadata)
    : config_(proto_config), domain_(proto_config.domain()),
      stats_(generateStats(stats_prefix, scope)),
      // Same prefix root as ALL_RATE_LIMIT_QUOTA_STATS counters
      // (`<stats_prefix>.rate_limit_quota_apig.<name>`) so the publish-µs
      // histogram graphs alongside its rate counter without a different
      // query namespace. Centralized via makeFinalPrefix so a future tweak
      // of the suffix updates counters and histograms in one place.
      bucket_cache_publish_us_histogram_(scope.histogramFromString(
          makeFinalPrefix(stats_prefix) + ".bucket_cache_publish_us",
          Stats::Histogram::Unit::Microseconds)),
      bucket_cache_dirty_shards_histogram_(scope.histogramFromString(
          makeFinalPrefix(stats_prefix) + ".bucket_cache_dirty_shards_per_publish",
          Stats::Histogram::Unit::Unspecified)),
      dynamic_registry_publish_us_histogram_(scope.histogramFromString(
          makeFinalPrefix(stats_prefix) + ".dynamic_registry_publish_us",
          Stats::Histogram::Unit::Microseconds)),
      build_reports_us_histogram_(scope.histogramFromString(
          makeFinalPrefix(stats_prefix) + ".bucket_cache_build_reports_us",
          Stats::Histogram::Unit::Microseconds)),
      reporting_interval_(FilterConfig::effectiveReportingIntervalMs(
          PROTOBUF_GET_MS_OR_DEFAULT(proto_config, reporting_interval, 1000))),
      // Dynamic-loading mode (rlqs_config_server configured) bypasses cold/hot
      // split: server-pushed BucketSettings make the cold-path sync RPC
      // redundant and adds main-thread load (spec § D-8 + Phase 0 perf plan).
      // Predicate routes through `isDynamicModeProto` so this ctor and the
      // runtime `isDynamicMode()` accessor stay in lock-step.
      cold_hot_split_enabled_(!(proto_config.has_cold_hot_config() &&
                                proto_config.cold_hot_config().disabled()) &&
                              !isDynamicModeProto(proto_config)),
      hotspot_threshold_((proto_config.has_cold_hot_config() &&
                          proto_config.cold_hot_config().hotspot_threshold() > 0)
                             ? proto_config.cold_hot_config().hotspot_threshold()
                             : 10),
      matcher_(createMatcher(proto_config, factory_context)),
      listener_metadata_(listener_metadata),
      // F-1.2: resolve LISTENER_METADATA lookup keys once at config load.
      // Spec D-1 defaults: "apig_tenant" / "tenant_id".
      tenant_metadata_namespace_(
          (proto_config.has_tenant_key_source() &&
           proto_config.tenant_key_source().has_tenant() &&
           !proto_config.tenant_key_source().tenant().metadata_namespace().empty())
              ? proto_config.tenant_key_source().tenant().metadata_namespace()
              : "apig_tenant"),
      tenant_metadata_field_(
          (proto_config.has_tenant_key_source() &&
           proto_config.tenant_key_source().has_tenant() &&
           !proto_config.tenant_key_source().tenant().metadata_field().empty())
              ? proto_config.tenant_key_source().tenant().metadata_field()
              : "tenant_id"),
      route_md5_tls_(factory_context.threadLocal()),
      config_access_dedup_tls_(factory_context.threadLocal()) {
  // Post the per-worker RouteMd5Cache factory. Each worker dispatcher will
  // run the lambda once when it processes the post; until then, the slot
  // returns empty and cachedRouteNameMd5 falls back to direct md5Hex.
  route_md5_tls_.set([](Event::Dispatcher&) { return std::make_shared<RouteMd5Cache>(); });
  config_access_dedup_tls_.set(
      [](Event::Dispatcher&) { return std::make_shared<ConfigAccessDedup>(); });

  if (proto_config.has_tenant_key_source() && proto_config.tenant_key_source().has_tenant()) {
    const auto& tenant_cfg = proto_config.tenant_key_source().tenant();
    if (!tenant_cfg.chain_name_pattern().empty()) {
      // Use RE2 (linear-time, no catastrophic backtracking) instead of
      // std::regex (ECMAScript engine, susceptible to ReDoS on adversarial
      // chain names). set_log_errors(false) suppresses the global re2 logger
      // — we surface the error with EnvoyException so listener load fails
      // loudly instead of accepting a silently-broken pattern.
      re2::RE2::Options options;
      options.set_log_errors(false);
      auto compiled = std::make_unique<re2::RE2>(tenant_cfg.chain_name_pattern(), options);
      if (!compiled->ok()) {
        throw EnvoyException(
            absl::StrCat("Invalid regex pattern for chain_name_pattern: ", compiled->error()));
      }
      chain_name_pattern_regex_ = std::move(compiled);
    }
  }
}

// Returns whether or not to allow a request based on the no-assignment-behavior.
// DENY_ALL → deny.
// token_bucket or requests_per_time_unit → deny (the fallback bucket must be
//   evaluated; returning allow here would bypass it entirely for the very first
//   request, which contradicts the operator's intent of having a local fallback).
// ALLOW_ALL or unset → allow.
bool noAssignmentBehaviorShouldAllow(const NoAssignmentBehavior& no_assignment_behavior) {
  const auto& strategy = no_assignment_behavior.fallback_rate_limit();
  switch (strategy.strategy_case()) {
  case RateLimitStrategy::kBlanketRule:
    return strategy.blanket_rule() != RateLimitStrategy::DENY_ALL;
  case RateLimitStrategy::kTokenBucket:
  case RateLimitStrategy::kRequestsPerTimeUnit:
    // A configured rate-limit fallback should be honoured: deny until the
    // bucket (created in createBucket) can be checked on the NEXT request.
    return false;
  default:
    return true;
  }
}

// Translate from the HttpStatus Code enum to the Envoy::Http::Code enum.
inline Envoy::Http::Code getDenyResponseCode(const DenyResponseSettings& settings) {
  if (!settings.has_http_status()) {
    return Envoy::Http::Code::TooManyRequests;
  }
  return static_cast<Envoy::Http::Code>(static_cast<uint64_t>(settings.http_status().code()));
}

inline std::function<void(Http::ResponseHeaderMap&)>
addDenyResponseHeadersCb(const DenyResponseSettings& settings) {
  if (settings.response_headers_to_add().empty())
    return nullptr;
  // Headers copied from settings for thread-safety.
  return [headers_to_add = settings.response_headers_to_add()](Http::ResponseHeaderMap& headers) {
    for (const envoy::config::core::v3::HeaderValueOption& header : headers_to_add) {
      headers.addCopy(Http::LowerCaseString(header.header().key()), header.header().value());
    }
  };
}

Http::FilterHeadersStatus sendDenyResponse(Http::StreamDecoderFilterCallbacks* cb,
                                           const DenyResponseSettings& settings,
                                           StreamInfo::ResponseFlag flag,
                                           absl::string_view details) {
  cb->sendLocalReply(getDenyResponseCode(settings), settings.http_body().value(),
                     addDenyResponseHeadersCb(settings), absl::nullopt, details);
  cb->streamInfo().setResponseFlag(flag);
  return Envoy::Http::FilterHeadersStatus::StopIteration;
}

void RateLimitQuotaFilter::buildDenyDetailsLazy(const BucketId& bucket_id_proto) {
  // Stream-level dynamic metadata, consumed by access logs via
  // `%DYNAMIC_METADATA(envoy.extensions.http_filters.rate_limit_quota.bucket)%`.
  ProtobufWkt::Struct bucket_log;
  auto* bucket_log_fields = bucket_log.mutable_fields();
  for (const auto& bucket : bucket_id_proto.bucket()) {
    (*bucket_log_fields)[bucket.first] = ValueUtil::stringValue(bucket.second);
  }
  callbacks_->streamInfo().setDynamicMetadata(kBucketMetadataNamespace, bucket_log);

  // `quota_rate_limited{k=v,...}` deny_details with stable key ordering so
  // operators can group log lines by exact bucket.
  std::vector<std::string> parts;
  parts.reserve(bucket_id_proto.bucket().size());
  for (const auto& bucket : bucket_id_proto.bucket()) {
    parts.push_back(absl::StrCat(bucket.first, "=", bucket.second));
  }
  std::sort(parts.begin(), parts.end());
  deny_details_ = parts.empty() ? "quota_rate_limited"
                                : absl::StrCat("quota_rate_limited{",
                                               absl::StrJoin(parts, ","), "}");
}

Http::FilterHeadersStatus RateLimitQuotaFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                              bool end_stream) {
  ENVOY_LOG(trace, "decodeHeaders: end_stream = {}", end_stream);

  config_->stats().rate_total_.inc();
  // First, perform the request matching.
  absl::StatusOr<Matcher::ActionPtr> match_result = requestMatching(headers);
  if (!match_result.ok()) {
    // When the request is not matched by any matchers, it is ALLOWED by default
    // (i.e., fail-open) and its quota usage will not be reported to RLQS
    // server.
    // TODO(tyxia) Add stats here and other places throughout the filter. e.g.
    // request allowed/denied, matching succeed/fail and so on.
    ENVOY_LOG(debug,
              "The request is not matched by any matchers: ", match_result.status().message());
    return Envoy::Http::FilterHeadersStatus::Continue;
  }

  // Second, generate the bucket id for this request based on match action when
  // the request matching succeeds.
  const RateLimitOnMatchAction& match_action =
      match_result.value()->getTyped<RateLimitOnMatchAction>();
  absl::StatusOr<BucketId> ret =
      match_action.generateBucketId(*data_ptr_, factory_context_, visitor_);
  if (!ret.ok()) {
    // When it failed to generate the bucket id for this specific request, the
    // request is ALLOWED by default (i.e., fail-open).
    ENVOY_LOG(debug, "Unable to generate the bucket id: {}", ret.status().message());
    return Envoy::Http::FilterHeadersStatus::Continue;
  }

  BucketId bucket_id_proto = *ret;

  if (config_->config().has_tenant_key_source()) {
    const auto& key_source = config_->tenantKeySource();
    
    // Extract tenant
    if (key_source.has_tenant()) {
      const auto& t_cfg = key_source.tenant();
      std::string tenant_id;

      {
        const auto& ns = config_->tenantMetadataNamespace();
        const auto& field = config_->tenantMetadataField();
        const auto& dynamic_meta = callbacks_->streamInfo().dynamicMetadata().filter_metadata();
        auto it = dynamic_meta.find(ns);
        if (it != dynamic_meta.end()) {
          const auto& fields = it->second.fields();
          auto f_it = fields.find(field);
          if (f_it != fields.end() &&
              f_it->second.kind_case() == ProtobufWkt::Value::kStringValue &&
              !f_it->second.string_value().empty()) {
            tenant_id = f_it->second.string_value();
            config_->stats().tenant_extract_dynamic_metadata_.inc();
          }
        }
      }

      if (tenant_id.empty()) {
        for (const auto& source_type : t_cfg.order()) {
        if (source_type == envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_TenantConfig_SourceType_LISTENER_METADATA) {
          // F-1.2: ns / field defaults pre-resolved at config load. Per-request
          // path is now a pure hashmap lookup with no std::string temporaries.
          const auto& ns = config_->tenantMetadataNamespace();
          const auto& field = config_->tenantMetadataField();

          // Spec § D-1 / § 7: tenant is read from the listener's static
          // metadata (set in the Listener proto by the gateway operator).
          // The snapshot is captured once at filter-config creation and
          // stored on FilterConfig; reading per-request is a plain hashmap
          // lookup with no per-request allocation.
          const auto& listener_meta = config_->listenerMetadata().filter_metadata();
          auto it = listener_meta.find(ns);
          if (it != listener_meta.end()) {
            const auto& fields = it->second.fields();
            auto f_it = fields.find(field);
            if (f_it != fields.end() && f_it->second.kind_case() == ProtobufWkt::Value::kStringValue) {
              tenant_id = f_it->second.string_value();
              break;
            }
          }
        } else if (source_type == envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_TenantConfig_SourceType_FILTER_CHAIN_NAME) {
          const std::string& chain_name = callbacks_->streamInfo().filterChainName();
          const re2::RE2* re = config_->chainNamePatternRegex();
          if (re != nullptr) {
            // RE2 capture-group extraction. The 1-based capture group index
            // mirrors std::regex semantics; group=0 (full match) is treated
            // as group=1 for backward compatibility with prior std::regex
            // configurations.
            const uint32_t group = t_cfg.capture_group() > 0 ? t_cfg.capture_group() : 1;
            const int n_groups = re->NumberOfCapturingGroups();
            if (n_groups > 0 && static_cast<int>(group) <= n_groups) {
              // Build argv pointing at the requested group only — earlier
              // groups are captured into discarded scratch slots so RE2 sees
              // a contiguous arg vector.
              //
              // F-1.3: InlinedVector<T, 4> keeps the scratch buffers on the
              // stack for capture_group <= 4 (the common case), eliminating
              // 3 heap allocations on the per-request tenant extraction path.
              absl::InlinedVector<re2::StringPiece, 4> scratch(group);
              absl::InlinedVector<re2::RE2::Arg, 4> args(group);
              absl::InlinedVector<re2::RE2::Arg*, 4> argv(group);
              for (uint32_t i = 0; i < group; ++i) {
                args[i] = re2::RE2::Arg(&scratch[i]);
                argv[i] = &args[i];
              }
              if (re2::RE2::PartialMatchN(chain_name, *re, argv.data(), group)) {
                tenant_id.assign(scratch[group - 1].data(), scratch[group - 1].size());
                if (!tenant_id.empty()) {
                  break;
                }
              } else {
                // Pattern compiled fine, capture group in range, but the
                // chain name didn't match — usually a stale chain_name_pattern
                // or a chain rename. Per-request counter so operators can
                // alarm on regression spikes vs. config rollouts.
                config_->stats().tenant_chain_regex_unmatched_.inc();
              }
            }
          }
        }
        }
      } // if (tenant_id.empty())

      // _tenant fallback: when no source resolves a value, write a sentinel
      // ("_unknown") instead of leaving the key absent. This keeps each
      // unmatched tenant's traffic in its own bucket — without the sentinel,
      // unmatched requests would all hash to the same (tenant-less) bucket
      // and silently merge across listeners, defeating multi-tenant isolation.
      // Server side treats "_unknown" as a normal tenant for accounting; a
      // global QuotaRule binding can attach a dedicated policy to it.
      if (tenant_id.empty()) {
        tenant_id = "_unknown";
        config_->stats().tenant_extract_unknown_.inc();
      } else {
        config_->stats().tenant_extract_success_.inc();
      }
      (*bucket_id_proto.mutable_bucket())[std::string(kBucketIdTenantKey)] = tenant_id;
    }

    // Extract scope
    auto evaluate_scope = [&](const auto& s_cfg) {
      std::string scope_value;
      std::string default_prefix;
      
      switch (s_cfg.type()) {
        case envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_ScopeConfig_ScopeType_ROUTE_NAME:
          default_prefix = "route:";
          if (callbacks_->route() && callbacks_->route()->routeEntry()) {
            scope_value = callbacks_->route()->routeEntry()->routeName();
            if (!scope_value.empty() && s_cfg.enable_route_name_hash()) {
              scope_value = config_->cachedRouteNameMd5(scope_value);
            }
          }
          break;
        case envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_ScopeConfig_ScopeType_VIRTUAL_HOST_NAME:
          default_prefix = "domain:";
          if (!headers.getHostValue().empty()) {
            scope_value = std::string(headers.getHostValue());
          }
          break;
        case envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_ScopeConfig_ScopeType_CLUSTER_NAME:
          default_prefix = "service:";
          if (callbacks_->route() && callbacks_->route()->routeEntry()) {
            scope_value = callbacks_->route()->routeEntry()->clusterName();
          }
          break;
        case envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_ScopeConfig_ScopeType_GLOBAL:
          default_prefix = "global:";
          scope_value = "_";
          break;
        case envoy::extensions::filters::http::rate_limit_quota_apig::v3::TenantKeySource_ScopeConfig_ScopeType_REQUEST_HEADER:
          default_prefix = "header:";
          if (!s_cfg.header_name().empty()) {
            auto header_val = headers.get(Http::LowerCaseString(s_cfg.header_name()));
            if (!header_val.empty()) {
              scope_value = std::string(header_val[0]->value().getStringView());
            }
          }
          break;
        default:
          break;
      }
      
      if (!scope_value.empty()) {
        const std::string prefix = s_cfg.prefix().empty() ? default_prefix : s_cfg.prefix();
        const std::string bkey =
            s_cfg.bucket_key().empty() ? std::string(kBucketIdScopeKey) : s_cfg.bucket_key();
        (*bucket_id_proto.mutable_bucket())[bkey] = prefix + scope_value;
      }
    };

    if (key_source.has_scope()) {
      evaluate_scope(key_source.scope());
    }
    for (const auto& s_cfg : key_source.additional_scopes()) {
      evaluate_scope(s_cfg);
    }
  }

  const size_t bucket_id = hashBucketId(bucket_id_proto);
  ENVOY_LOG(trace, "Generated the associated hashed bucket id: {} for bucket id proto:\n {}",
            bucket_id, bucket_id_proto.DebugString());

  // F-1.4: dynamic-metadata bucket logging + `deny_details_` string build
  // moved to `buildDenyDetailsLazy`, invoked only on the deny path. Most
  // requests don't deny, so the ~15 small allocations the eager build cost
  // on every request are saved. cold_path_bucket_id_ is saved at the cold
  // path entries (and read by encodeData / onQuotaCheck* callbacks), so
  // async deny paths can reconstruct the same logging output.

  // Settings needed if a cached bucket or default behavior decides to deny.
  const DenyResponseSettings& deny_response_settings =
      match_action.bucketSettings().deny_response_settings();

  // Token-dim short-circuit: single-dim `_dim:token` rules always sync-RPC
  // to RLQS (the per-request token cost is variable and only known after
  // the upstream response, so local approximation can't deliver 100%). Runs
  // before the multi-dim / cold-hot / local-bucket paths so none of their
  // local-approximation logic ever applies to a token rule. Multi-dim rules
  // that *include* a token variant are out of scope here — only the base
  // BucketId is inspected, and multi-dim BucketIds carry no `_dim` until
  // tryDynamicMultiDimensionCheck overlays the per-variant key.
  if (isTokenDimensionBucket(bucket_id_proto)) {
    return dispatchTokenDimensionSync(bucket_id_proto, match_action.bucketSettings());
  }

  // Spec § D-7 multi-dim warm path. Runs only when the dynamic registry has
  // a SettingsList for this (tenant, scope) AND every variant BucketId is
  // already cached locally. On a cache miss for any variant we fall through
  // to the single-dim path (with side effect: missing variants are registered
  // via createBucket inside the helper so the next request picks them up).
  if (auto multi_dim_status = tryDynamicMultiDimensionCheck(bucket_id_proto, match_action);
      multi_dim_status.has_value()) {
    return *multi_dim_status;
  }

  // Dynamic multi-dim mode must never create ghost base buckets — base
  // BucketIds that carry _tenant/_scope but no _dim overlay. When
  // tryDynamicMultiDimensionCheck returns nullopt (registry miss or empty
  // variant list), evict any stale ghost entry and fail-open so the request
  // passes through while the server pushes the real per-dim settings.
  if (config_->isDynamicMode() && isMultiDimGhostBaseBucket(bucket_id_proto)) {
    evictGhostBaseBucketIfPresent(bucket_id_proto);
    return continueMultiDimWarmupWithoutBaseBucket(bucket_id_proto);
  }

  std::shared_ptr<CachedBucket> cached_bucket = client_->getBucket(bucket_id);
  if (cached_bucket) {
    // Update last access time
    std::chrono::nanoseconds now = nowMonotonicNsTyped(callbacks_->dispatcher().timeSource());
    cached_bucket->quota_usage->time_of_last_access.store(now, std::memory_order_relaxed);

    // Save quota_usage for token consumption during encodeData (wasm-compatible JSON/SSE parse).
    pending_token_quota_usage_ = cached_bucket->quota_usage;
    resetTokenUsageState();

    // Found the cached bucket entry.
    return processCachedBucket(deny_response_settings, *cached_bucket);
  }

  // Cold / hot split: process-wide frequency on GlobalRateLimitClientImpl (disabled via
  // cold_hot_config.disabled); thresholds cached on FilterConfig.
  const auto& top_config = config_->config();
  bool should_create_bucket = true;
  if (config_->coldHotSplitEnabled()) {
    const uint64_t access_count = client_->recordHotspotAccess(bucket_id);
    config_->stats().hotspot_access_recorded_.inc();
    if (access_count < config_->hotspotThreshold()) {
      should_create_bucket = false;
    }
  }

  // Cold path: sync check to quota service (no local CachedBucket yet).
  if (!should_create_bucket && sync_quota_checker_) {
    ENVOY_LOG(debug,
              "Routing request for bucket_id={} to cold path (sync check) due to low frequency.",
              bucket_id);
    pending_deny_settings_ = deny_response_settings;

    // Create a temporary QuotaUsage to track tokens for this cold request
    std::chrono::nanoseconds now = nowMonotonicNsTyped(callbacks_->dispatcher().timeSource());
    pending_token_quota_usage_ = std::make_shared<QuotaUsage>(0, 0, now);
    resetTokenUsageState();
    cold_path_bucket_id_ = bucket_id_proto;

    const std::chrono::milliseconds timeout = coldPathTimeoutValue(top_config);

    cold_path_sync_check_pending_ = true;
    config_->stats().cold_path_sync_started_.inc();
    waiting_for_quota_check_ = true;
    sync_check_start_time_ = callbacks_->dispatcher().timeSource().monotonicTime();
    sync_check_timing_active_ = true;
    if (sync_quota_checker_->checkQuotaAsync(bucket_id_proto, kSyncCheckTokenEstimate, timeout,
                                             *this)) {
      return Envoy::Http::FilterHeadersStatus::StopIteration;
    }
    waiting_for_quota_check_ = false;
    clearPendingSyncCheckFlags();
    config_->stats().cold_path_sync_error_.inc();
    ENVOY_LOG(warn, "Failed to initiate async cold quota check for bucket_id={}", bucket_id);

    const bool fallback_allow = coldPathErrorFallbackAllow(top_config);
    if (fallback_allow) {
      return Envoy::Http::FilterHeadersStatus::Continue;
    }
    config_->stats().rate_limited_.inc();
    buildDenyDetailsLazy(bucket_id_proto);
    return sendDenyResponse(callbacks_, deny_response_settings, StreamInfo::ResponseFlag::RateLimited, deny_details_);
  }

  // Cold path would apply but no SyncQuotaChecker: policy from config (default: promote to hot).
  if (!should_create_bucket && !sync_quota_checker_) {
    using ColdCfg = envoy::extensions::filters::http::rate_limit_quota_apig::v3::ColdHotSplitConfig;
    ColdCfg::NoSyncCheckerPolicy policy = ColdCfg::PROMOTE_TO_HOT;
    if (top_config.has_cold_hot_config()) {
      policy = top_config.cold_hot_config().no_sync_checker_policy();
    }
    if (policy == ColdCfg::PROMOTE_TO_HOT) {
      config_->stats().no_sync_checker_upgrade_.inc();
    } else if (policy == ColdCfg::FAIL_OPEN) {
      return Envoy::Http::FilterHeadersStatus::Continue;
    } else {
      config_->stats().rate_limited_.inc();
      buildDenyDetailsLazy(bucket_id_proto);
      return sendDenyResponse(callbacks_, deny_response_settings,
                              StreamInfo::ResponseFlag::RateLimited, deny_details_);
    }
  }

  // Process the request using the bucket settings (creating it if needed)
  return processCachedBucket(deny_response_settings, bucket_id_proto, match_action.bucketSettings());
}

Http::FilterDataStatus RateLimitQuotaFilter::decodeData(Buffer::Instance&, bool) {
  // When decodeHeaders started a synchronous quota check it set
  // waiting_for_quota_check_ and returned StopIteration to pause the request
  // until the RLQS SyncCheck (cold path, degraded-mode SyncCheck, or token-dim
  // sync) resolves. StopIteration only pauses HEADER iteration; the request
  // body still arrives here, and the inherited PassThroughFilter::decodeData
  // returns Continue — which resumes the whole filter chain and ships the
  // request to the upstream BEFORE the check's allow/deny is known. The late
  // deny is then dropped ("Received response but no pending checks in queue")
  // and over-quota requests are never blocked. Buffer the body until the async
  // callback (onQuotaCheckComplete / timeout) calls continueDecoding().
  if (waiting_for_quota_check_) {
    return Http::FilterDataStatus::StopIterationAndBuffer;
  }
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus RateLimitQuotaFilter::decodeTrailers(Http::RequestTrailerMap&) {
  // Same rationale as decodeData: never let trailers continue the request
  // while a synchronous quota check is still pending.
  if (waiting_for_quota_check_) {
    return Http::FilterTrailersStatus::StopIteration;
  }
  return Http::FilterTrailersStatus::Continue;
}

void RateLimitQuotaFilter::createMatcher(const xds::type::matcher::v3::Matcher& matcher) {
  RateLimitOnMatchActionContext context;
  Matcher::MatchTreeFactory<Http::HttpMatchingData, RateLimitOnMatchActionContext> factory(
      context, factory_context_.getServerFactoryContext(), visitor_);
  matcher_ = factory.create(matcher)();
}

// TODO(tyxia) Currently request matching is only performed on the request
// header.
absl::StatusOr<Matcher::ActionPtr>
RateLimitQuotaFilter::requestMatching(const Http::RequestHeaderMap& headers) {
  // Initialize the data pointer on first use and reuse it for subsequent
  // requests. This avoids creating the data object for every request, which
  // is expensive.
  if (data_ptr_ == nullptr) {
    if (callbacks_ != nullptr) {
      data_ptr_ = std::make_unique<Http::Matching::HttpMatchingDataImpl>(callbacks_->streamInfo());
    } else {
      return absl::InternalError("Filter callback has not been initialized successfully yet.");
    }
  }

  const auto* per_route_config =
      Http::Utility::resolveMostSpecificPerFilterConfig<FilterConfigRoute>(callbacks_);
  if (per_route_config != nullptr) {
    matcher_ = per_route_config->matcher();
  }

  if (matcher_ == nullptr) {
    return absl::InternalError("Matcher tree has not been initialized yet.");
  } else {
    // Populate the request header.
    if (!headers.empty()) {
      data_ptr_->onRequestHeaders(headers);
    }

    // Perform the matching.
    auto match_result = Matcher::evaluateMatch<Http::HttpMatchingData>(*matcher_, *data_ptr_);

    if (match_result.match_state_ == Matcher::MatchState::MatchComplete) {
      if (match_result.result_) {
        // Return the matched result for `on_match` case.
        return match_result.result_();
      } else {
        return absl::NotFoundError("Matching completed but no match result was found.");
      }
    } else {
      // The returned state from `evaluateMatch` function is
      // `MatchState::UnableToMatch` here.
      return absl::InternalError("Unable to match due to the required data not being available.");
    }
  }
}

void RateLimitQuotaFilter::onDestroy() {
  // Invalidate the cross-thread fetchQuotaConfig callback guard so the posted
  // closure becomes a no-op if it arrives after this filter is destroyed.
  if (config_fetch_alive_guard_) {
    config_fetch_alive_guard_->store(false, std::memory_order_release);
  }
  if (config_fetch_timer_) {
    config_fetch_timer_->disableTimer();
    config_fetch_timer_.reset();
  }

  // Cancel any pending async quota check
  if (sync_quota_checker_ && waiting_for_quota_check_) {
    sync_quota_checker_->cancelCheck(*this);
    waiting_for_quota_check_ = false;
    clearPendingSyncCheckFlags();
    token_dim_bucket_id_.clear_bucket();
  }

  // Decrement concurrency counter if we incremented it
  if (concurrency_incremented_ && active_quota_usage_) {
    uint64_t current = active_quota_usage_->active_requests.load(std::memory_order_relaxed);
    while (current > 0 &&
           !active_quota_usage_->active_requests.compare_exchange_weak(current, current - 1, std::memory_order_relaxed)) {
    }
    ENVOY_LOG(debug, "Concurrency decremented: current_active={}",
              active_quota_usage_->active_requests.load(std::memory_order_relaxed));
    concurrency_incremented_ = false;
    active_quota_usage_.reset();
  }

  // Multi-dim variant decrement: spec § D-7 fans a route into N independent
  // BucketIds; any subset of them may carry concurrency_limit. shouldAllowRequest
  // CAS-incremented each successful one inside tryDynamicMultiDimensionCheck.
  // The single-dim scalars above can hold only one of those, so the rest live
  // in this vector and are decremented here. Order doesn't matter because every
  // entry is an independent atomic counter.
  for (auto& qu : multi_dim_active_quota_usages_) {
    if (!qu) {
      continue;
    }
    uint64_t current = qu->active_requests.load(std::memory_order_relaxed);
    while (current > 0 &&
           !qu->active_requests.compare_exchange_weak(current, current - 1, std::memory_order_relaxed)) {
    }
  }
  multi_dim_active_quota_usages_.clear();

  // Rollback any in-flight multi-dim Phase 2 pending deductions so concurrency
  // counters and request-allowed counts don't leak if the filter is destroyed
  // mid-dispatch (e.g. client disconnect during async SyncCheck).
  if (multi_dim_state_) {
    rollbackMultiDimPending(multi_dim_state_->pending);
    multi_dim_state_.reset();
  }

  // Release token tracking state eagerly (best-effort credit if stream ends abruptly).
  if (pending_token_quota_usage_) {
    const auto& dynamic_meta = callbacks_->streamInfo().dynamicMetadata().filter_metadata();
    auto it = dynamic_meta.find("envoy.filters.http.rate_limit_quota");
    if (it != dynamic_meta.end()) {
      const auto& fields = it->second.fields();
      uint64_t total = 0, input = 0, output = 0, cached = 0;
      bool has_metadata_tokens = false;

      auto parse_token = [&](const std::string& key, uint64_t& out) {
        auto field_it = fields.find(key);
        if (field_it != fields.end()) {
          if (field_it->second.kind_case() == ProtobufWkt::Value::kNumberValue) {
            out = static_cast<uint64_t>(field_it->second.number_value());
            has_metadata_tokens = true;
          } else if (field_it->second.kind_case() == ProtobufWkt::Value::kStringValue) {
            if (absl::SimpleAtoi(field_it->second.string_value(), &out)) {
              has_metadata_tokens = true;
            }
          }
        }
      };

      parse_token("rlqs_total_tokens", total);
      parse_token("rlqs_input_tokens", input);
      parse_token("rlqs_output_tokens", output);
      parse_token("rlqs_cached_tokens", cached);

      if (has_metadata_tokens) {
        ENVOY_LOG(debug, "Extracted tokens from dynamic metadata: total={}, input={}, output={}, cached={}", total, input, output, cached);
        if (total > last_token_credit_total_) {
          const uint64_t delta = total - last_token_credit_total_;
          pending_token_quota_usage_->tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
          last_token_credit_total_ = total;
          config_->stats().tokens_consumed_total_.add(delta);
        }
        if (input > last_input_token_credit_) {
          const uint64_t delta = input - last_input_token_credit_;
          pending_token_quota_usage_->input_tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
          last_input_token_credit_ = input;
          config_->stats().tokens_consumed_input_.add(delta);
        }
        if (output > last_output_token_credit_) {
          const uint64_t delta = output - last_output_token_credit_;
          pending_token_quota_usage_->output_tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
          last_output_token_credit_ = output;
          config_->stats().tokens_consumed_output_.add(delta);
        }
        if (cached > last_cached_token_credit_) {
          const uint64_t delta = cached - last_cached_token_credit_;
          pending_token_quota_usage_->cached_tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
          last_cached_token_credit_ = cached;
          config_->stats().tokens_consumed_cached_.add(delta);
        }
      }
    }

    if (auto merged = openai_response_stream_merger_.flush()) {
      const std::string payload = extractSseJsonPayload(*merged);
      if (auto obj = parseJsonObjectFromString(payload)) {
        token_usage_accumulator_.ingestJsonObject(*obj);
        creditPendingTokenUsageDelta();
      }
    }
    if (!sse_token_stream_buffer_.empty()) {
      processSseEventForTokens(sse_token_stream_buffer_);
      sse_token_stream_buffer_.clear();
    }
    if (!json_token_response_buffer_.empty()) {
      // Fast-path bypass for JSON parsing
      if (absl::StrContains(json_token_response_buffer_, "usage") || 
          absl::StrContains(json_token_response_buffer_, "token") || 
          absl::StrContains(json_token_response_buffer_, "Token")) {
        // Try sub-object extraction first (handles large responses where full
        // parse fails because the buffer only holds a tail window).
        const std::string usage_obj = extractUsageObject(json_token_response_buffer_);
        if (!usage_obj.empty()) {
          if (auto obj = parseJsonObjectFromString(usage_obj)) {
            token_usage_accumulator_.ingestJsonObject(*obj);
            creditPendingTokenUsageDelta();
          }
        } else if (auto obj = parseJsonObjectFromString(json_token_response_buffer_)) {
          token_usage_accumulator_.ingestJsonObject(*obj);
          creditPendingTokenUsageDelta();
        }
      }
    }
    
    if (cold_path_bucket_id_.bucket().size() > 0) {
      const uint64_t actual_total = pending_token_quota_usage_->tokens_consumed.load();
      ENVOY_LOG(debug, "Cold response ended (onDestroy). Extracted tokens to report: total={}, input={}, output={}, cached={}",
                actual_total,
                pending_token_quota_usage_->input_tokens_consumed.load(),
                pending_token_quota_usage_->output_tokens_consumed.load(),
                pending_token_quota_usage_->cached_tokens_consumed.load());

      // Warn when degraded SyncCheck token estimate significantly deviates from actual.
      // Server uses avg_tokens_per_request for the deduction; if actual is much larger,
      // the quota window may be over-admitted. Threshold: actual > 5x estimate.
      if (was_degraded_sync_ && actual_total > kSyncCheckTokenEstimate * 5) {
        ENVOY_LOG(warn,
                  "Degraded SyncCheck token deviation: server_estimate(per_request)={} "
                  "actual_tokens={} ratio={:.1f}x — consider increasing avg_tokens_per_request "
                  "in ratelimit-quota-server config",
                  kSyncCheckTokenEstimate, actual_total,
                  static_cast<double>(actual_total) / kSyncCheckTokenEstimate);
      }

      client_->reportQuotaUsage(cold_path_bucket_id_, *pending_token_quota_usage_);
      cold_path_bucket_id_.clear_bucket();
    }
    
    pending_token_quota_usage_.reset();
    token_usage_accumulator_.reset();
    openai_response_stream_merger_.reset();
    sse_token_stream_buffer_.clear();
    json_token_response_buffer_.clear();
    last_token_credit_total_ = 0;
    last_input_token_credit_ = 0;
    last_output_token_credit_ = 0;
    last_cached_token_credit_ = 0;
    response_is_json_ = false;
    response_is_sse_ = false;
    response_is_aws_eventstream_ = false;
  }
}

inline void incrementAtomic(std::atomic<uint64_t>& counter) {
  counter.fetch_add(1, std::memory_order_relaxed);
}

void RateLimitQuotaFilter::clearPendingSyncCheckFlags() {
  cold_path_sync_check_pending_ = false;
  token_dim_sync_pending_ = false;
  sync_check_timing_active_ = false;
}

void RateLimitQuotaFilter::primeStrictDenyCache(int64_t ttl_ns) {
  if (!pending_strict_request_mode_) {
    return;
  }
  // Prefer the currently-published bucket (handles TLS shard swap during
  // the round trip); fall back to the captured shared_ptr if the bucket
  // has been evicted entirely. Either way, write deny_until_ns so the
  // next request short-circuits without another SyncCheck RPC.
  std::shared_ptr<CachedBucket> target;
  if (client_ && pending_strict_bucket_id_hash_ != 0) {
    target = client_->getBucket(pending_strict_bucket_id_hash_);
  }
  if (!target) {
    target = pending_strict_bucket_;
  }
  if (target) {
    target->deny_until_ns.store(nowMonotonicNs(time_source_) + ttl_ns,
                                std::memory_order_relaxed);
  }
  pending_strict_request_mode_ = false;
  pending_strict_bucket_.reset();
  pending_strict_bucket_id_hash_ = 0;
}

bool RateLimitQuotaFilter::initiateAsyncQuotaCheck(const CachedBucket& cached_bucket) {
  if (!sync_quota_checker_) {
    return false;
  }
  // Degradation path is distinct from cold path for metrics and fallback interpretation.
  cold_path_sync_check_pending_ = false;

  const std::chrono::milliseconds timeout = degradationSyncTimeoutValue(config_->config());

  waiting_for_quota_check_ = true;
  sync_check_start_time_ = callbacks_->dispatcher().timeSource().monotonicTime();
  sync_check_timing_active_ = true;
  was_degraded_sync_ = true;

  // Capture the bucket's strict-request flag, a shared_ptr to it AND its
  // hash key at initiation so the async completion path can:
  //   1. override fallback_allow_on_timeout with fail-closed (INV-10)
  //   2. write deny_until_ns into the CURRENT live bucket — re-fetched at
  //      callback time via the cached hash, so a TLS shard swap that
  //      rebuilt the bucket between initiate and callback doesn't end up
  //      with the deny cache landing on a detached old shared_ptr.
  // The shared_ptr is retained as a fallback for the abandon_action case
  // where the bucket has been evicted entirely. Non-strict (token /
  // concurrency) callers leave all three fields cleared, preserving
  // existing behavior.
  pending_strict_request_mode_ =
      cached_bucket.degradation_state &&
      cached_bucket.degradation_state->strict_request_mode.load(std::memory_order_relaxed);
  if (pending_strict_request_mode_ && client_) {
    pending_strict_bucket_id_hash_ = hashBucketId(cached_bucket.bucket_id);
    pending_strict_bucket_ = client_->getBucket(pending_strict_bucket_id_hash_);
  } else {
    pending_strict_bucket_id_hash_ = 0;
    pending_strict_bucket_.reset();
  }

  if (!sync_quota_checker_->checkQuotaAsync(cached_bucket.bucket_id, kSyncCheckTokenEstimate,
                                            timeout, *this)) {
    ENVOY_LOG(error, "Failed to initiate async quota check");
    waiting_for_quota_check_ = false;
    sync_check_timing_active_ = false;
    was_degraded_sync_ = false;
    return false;
  }

  ENVOY_LOG(debug, "Initiated async quota check, waiting for response");
  return true;
}

void RateLimitQuotaFilter::onQuotaConfigFetchComplete(bool success) {
  ENVOY_LOG(debug, "RLQS MultiDim: onQuotaConfigFetchComplete success={} waiting={}",
            success, waiting_for_quota_config_);
  if (!waiting_for_quota_config_) {
    ENVOY_LOG(debug, "RLQS MultiDim: onQuotaConfigFetchComplete spurious callback, ignoring");
    return;
  }
  if (success && dynamic_registry_) {
    // Look up the result so we can report the variant count at info level.
    const auto& base = pending_bucket_id_proto_;
    std::string tenant, scope;
    for (const auto& kv : base.bucket()) {
      if (kv.first == "_tenant") tenant = kv.second;
      else if (kv.first == "_scope") scope = kv.second;
    }
    const auto variants = dynamic_registry_->lookup(tenant, scope);
    ENVOY_LOG(info, "RLQS MultiDim: config fetch complete tenant={} scope={} variants={}",
              tenant, scope, variants.size());
  } else if (!success) {
    std::string tenant, scope;
    for (const auto& kv : pending_bucket_id_proto_.bucket()) {
      if (kv.first == "_tenant") tenant = kv.second;
      else if (kv.first == "_scope") scope = kv.second;
    }
    ENVOY_LOG(warn, "RLQS MultiDim: config fetch FAILED tenant={} scope={}, falling back",
              tenant, scope);
  }

  if (config_fetch_timer_) {
    config_fetch_timer_->disableTimer();
    config_fetch_timer_.reset();
  }

  waiting_for_quota_config_ = false;

  const auto& deny = pending_match_action_->bucketSettings().deny_response_settings();

  // Helper: in dynamic mode a ghost base bucket must never be created even
  // in fallback paths. Evict any stale ghost and fail-open instead.
  const bool suppress_ghost = config_->isDynamicMode() &&
                              isMultiDimGhostBaseBucket(pending_bucket_id_proto_);

  if (!success) {
    if (suppress_ghost) {
      ENVOY_LOG(warn, "Dynamic multi-dim config fetch failed for ghost base bucket {}; failing open",
                pending_bucket_id_proto_.ShortDebugString());
      evictGhostBaseBucketIfPresent(pending_bucket_id_proto_);
      callbacks_->continueDecoding();
      return;
    }
    // Fetch failed, fall back to single-dim.
    auto status = processCachedBucket(deny, pending_bucket_id_proto_, pending_match_action_->bucketSettings());
    if (status == Http::FilterHeadersStatus::Continue) {
      callbacks_->continueDecoding();
    }
    return;
  }

  // Re-evaluate the multi-dim check now that config might be cached.
  auto multi_status = tryDynamicMultiDimensionCheck(pending_bucket_id_proto_, *pending_match_action_);
  if (multi_status.has_value()) {
    if (multi_status.value() == Http::FilterHeadersStatus::Continue) {
      callbacks_->continueDecoding();
    } else if (multi_status.value() == Http::FilterHeadersStatus::StopIteration) {
      if (waiting_for_quota_config_) {
        // Re-evaluation triggered another config fetch (e.g. server returned
        // empty settings so the cache is still empty). Break the loop: cancel
        // the new fetch, disarm its timer, and fall back to single-dim.
        waiting_for_quota_config_ = false;
        if (config_fetch_timer_) {
          config_fetch_timer_->disableTimer();
          config_fetch_timer_.reset();
        }
        if (suppress_ghost) {
          ENVOY_LOG(warn, "Dynamic multi-dim re-fetch loop detected for ghost base bucket {}; failing open",
                    pending_bucket_id_proto_.ShortDebugString());
          evictGhostBaseBucketIfPresent(pending_bucket_id_proto_);
          callbacks_->continueDecoding();
          return;
        }
        auto status = processCachedBucket(deny, pending_bucket_id_proto_,
                                          pending_match_action_->bucketSettings());
        if (status == Http::FilterHeadersStatus::Continue) {
          callbacks_->continueDecoding();
        }
      }
      // Otherwise it suspended for a sync check (Phase 2). Do nothing —
      // resumeMultiDimAfterSyncCheck will handle continuation.
    }
  } else {
    // Dynamic check fell back to single-dim.
    if (suppress_ghost) {
      ENVOY_LOG(debug, "Dynamic multi-dim: no variants for ghost base bucket {}; failing open",
                pending_bucket_id_proto_.ShortDebugString());
      evictGhostBaseBucketIfPresent(pending_bucket_id_proto_);
      callbacks_->continueDecoding();
      return;
    }
    auto status = processCachedBucket(deny, pending_bucket_id_proto_, pending_match_action_->bucketSettings());
    if (status == Http::FilterHeadersStatus::Continue) {
      callbacks_->continueDecoding();
    }
  }
}

void RateLimitQuotaFilter::onQuotaCheckComplete(bool allowed, uint32_t deny_retry_after_ms) {
  waiting_for_quota_check_ = false;
  pending_deny_retry_after_ms_ = deny_retry_after_ms;

  // Token-dim always-sync dispatch. Owns the cleanest path: no concurrency
  // bookkeeping, no strict-mode deny cache, no cold/degraded fan-out. The
  // num_requests_allowed/denied bump is the only local accounting needed
  // since the SyncCheck call already committed the request server-side.
  if (token_dim_sync_pending_) {
    clearPendingSyncCheckFlags();
    if (allowed) {
      config_->stats().token_dim_sync_allowed_.inc();
      if (pending_quota_usage_) {
        incrementAtomic(pending_quota_usage_->num_requests_allowed);
      }
      pending_quota_usage_.reset();
      token_dim_bucket_id_.clear_bucket();
      callbacks_->continueDecoding();
    } else {
      config_->stats().token_dim_sync_denied_.inc();
      if (pending_quota_usage_) {
        incrementAtomic(pending_quota_usage_->num_requests_denied);
      }
      pending_quota_usage_.reset();
      config_->stats().rate_limited_.inc();
      buildDenyDetailsLazy(token_dim_bucket_id_);
      token_dim_bucket_id_.clear_bucket();
      callbacks_->sendLocalReply(getDenyResponseCode(pending_deny_settings_),
                                 pending_deny_settings_.http_body().value(),
                                 addDenyResponseHeadersCb(pending_deny_settings_), absl::nullopt,
                                 deny_details_);
      callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::RateLimited);
    }
    return;
  }

  // Multi-dim 100%-accurate dispatch: when multi_dim_state_ is non-null,
  // the SyncCheck callback belongs to a deferred Phase-2 variant, not to
  // a single-dim cold/degraded request. Route into the resume state
  // machine instead of the legacy single-dim handler.
  if (multi_dim_state_) {
    // Counter selection: token-dim parallel-degrade buckets bump the
    // token_dim_* family so dashboards can attribute traffic to the
    // always-sync path (separate from the strict_request_mode degraded
    // path which uses degraded_sync_*). Concurrency-variant breakdown
    // mirrors the degraded_sync_concurrency_* split: when the variant
    // whose RPC just completed had concurrency_limit, bump the
    // concurrency-specific counter too so dashboards can split "token
    // budget exhausted" from "concurrency cap hit" inside one rule.
    const bool variant_is_concurrency =
        multi_dim_state_->deferred_cursor < multi_dim_state_->deferred.size() &&
        multi_dim_state_->deferred[multi_dim_state_->deferred_cursor].is_concurrency;
    if (multi_dim_state_->token_dim_failopen) {
      if (allowed) {
        config_->stats().token_dim_sync_allowed_.inc();
        if (variant_is_concurrency) {
          config_->stats().token_dim_sync_concurrency_allowed_.inc();
        }
      } else {
        config_->stats().token_dim_sync_denied_.inc();
        if (variant_is_concurrency) {
          config_->stats().token_dim_sync_concurrency_denied_.inc();
        }
      }
    } else {
      if (allowed) {
        config_->stats().degraded_sync_allowed_.inc();
      } else {
        config_->stats().degraded_sync_denied_.inc();
      }
    }
    clearPendingSyncCheckFlags();
    resumeMultiDimAfterSyncCheck(allowed);
    return;
  }

  const bool is_cold = cold_path_sync_check_pending_;
  cold_path_sync_check_pending_ = false;

  // Compute SyncCheck round-trip latency.
  int64_t sync_latency_ms = 0;
  if (sync_check_timing_active_) {
    sync_latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          callbacks_->dispatcher().timeSource().monotonicTime() -
                          sync_check_start_time_)
                          .count();
    sync_check_timing_active_ = false;
    if (sync_latency_ms > 50) {
      ENVOY_LOG(warn, "SyncCheck high latency: mode={} latency_ms={}",
                is_cold ? "cold" : "degraded", sync_latency_ms);
    } else {
      ENVOY_LOG(debug, "SyncCheck latency: mode={} latency_ms={}",
                is_cold ? "cold" : "degraded", sync_latency_ms);
    }
  }

  if (is_cold) {
    if (allowed) {
      config_->stats().cold_path_sync_allowed_.inc();
    } else {
      config_->stats().cold_path_sync_denied_.inc();
    }
  } else {
    // Degraded-mode SyncCheck specific counters.
    if (allowed) {
      config_->stats().degraded_sync_allowed_.inc();
      if (is_concurrency_limit_pending_) {
        config_->stats().degraded_sync_concurrency_allowed_.inc();
      }
    } else {
      config_->stats().degraded_sync_denied_.inc();
      if (is_concurrency_limit_pending_) {
        config_->stats().degraded_sync_concurrency_denied_.inc();
      }
    }
  }

  ENVOY_LOG(info, "Rate limit decision: allowed={}, mode={}, latency_ms={}", allowed ? "true" : "false",
            is_cold ? "cold_path_sync" : "degraded_sync", sync_latency_ms);

  if (allowed) {
    // CRITICAL FIX: Do NOT increment num_requests_allowed for SyncCheck requests!
    // SyncCheck-allowed requests are already counted in Redis via the SyncCheck mechanism.
    // If we increment here, the periodic report would include these requests again,
    // causing double-counting and premature rate limiting.
    //
    // The periodic report's AllowRequestNum should only include:
    // 1. Normal mode: Local TokenBucket consumed requests
    // 2. Degradation mode: Fallback requests (when SyncCheck fails/times out)
    //
    // SyncCheck-allowed requests are tracked separately in the server's synccheck_key hash.

    if (is_concurrency_limit_pending_ && pending_quota_usage_) {
      uint64_t current = pending_quota_usage_->active_requests.load(std::memory_order_relaxed);
      while (!pending_quota_usage_->active_requests.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) {
      }
      concurrency_incremented_ = true;
      active_quota_usage_ = pending_quota_usage_;
      ENVOY_LOG(debug, "Concurrency incremented after SyncCheck allowed");
    }

    pending_strict_request_mode_ = false;
    pending_strict_bucket_.reset();
    pending_strict_bucket_id_hash_ = 0;
    callbacks_->continueDecoding();
  } else {
    // Strict-request DENY: use the server-provided deny_retry_after_ms to
    // control the local deny cache. 0 = no caching (every request goes
    // through SyncCheck for 100% accuracy on small quotas).
    if (pending_deny_retry_after_ms_ > 0) {
      primeStrictDenyCache(
          static_cast<int64_t>(pending_deny_retry_after_ms_) * 1'000'000LL);
    }
    if (pending_quota_usage_) {
      incrementAtomic(pending_quota_usage_->num_requests_denied);
    }
    config_->stats().rate_limited_.inc();
    buildDenyDetailsLazy(cold_path_bucket_id_);
    callbacks_->sendLocalReply(getDenyResponseCode(pending_deny_settings_),
                               pending_deny_settings_.http_body().value(),
                               addDenyResponseHeadersCb(pending_deny_settings_), absl::nullopt,
                               deny_details_);
    callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::RateLimited);
  }

  // Clear pending state
  pending_quota_usage_.reset();
}

void RateLimitQuotaFilter::onQuotaCheckError() {
  waiting_for_quota_check_ = false;

  // Token-dim always-sync dispatch: fail-OPEN on RPC error (operator-chosen
  // policy — AI requests are expensive and brief overshoot beats blocking
  // traffic when RLQS is degraded). Still credit num_requests_allowed so
  // the next periodic report reflects the allowed-during-outage volume,
  // letting operators distinguish "allowed by server" from "allowed by
  // fail-open" via the token_dim_sync_error counter.
  if (token_dim_sync_pending_) {
    clearPendingSyncCheckFlags();
    config_->stats().token_dim_sync_error_.inc();
    if (pending_quota_usage_) {
      incrementAtomic(pending_quota_usage_->num_requests_allowed);
    }
    pending_quota_usage_.reset();
    token_dim_bucket_id_.clear_bucket();
    callbacks_->continueDecoding();
    return;
  }

  // Multi-dim dispatch: fail-closed via resume state machine.
  if (multi_dim_state_) {
    clearPendingSyncCheckFlags();
    abortMultiDimAfterError();
    return;
  }

  const bool is_cold = cold_path_sync_check_pending_;
  cold_path_sync_check_pending_ = false;

  int64_t sync_latency_ms = 0;
  if (sync_check_timing_active_) {
    sync_latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          callbacks_->dispatcher().timeSource().monotonicTime() -
                          sync_check_start_time_)
                          .count();
    sync_check_timing_active_ = false;
  }

  if (is_cold) {
    config_->stats().cold_path_sync_error_.inc();
  } else {
    config_->stats().degraded_sync_error_.inc();
  }

  const auto& top = config_->config();
  bool fallback_allow =
      is_cold ? coldPathErrorFallbackAllow(top) : degradationErrorFallbackAllow(top);

  // Strict-request fail-closed (INV-10). When the bucket opted into 100%
  // accuracy via DegradationInfo.strict_request_mode, an RPC error MUST
  // become a DENY regardless of fallback_allow_on_timeout — letting the
  // request through would silently break the global-max guarantee. We
  // also prime the bucket's deny_until_ns so the next request short-
  // circuits without another RPC. Token / concurrency buckets keep the
  // operator-configured fallback_allow_on_timeout behavior.
  if (pending_strict_request_mode_) {
    fallback_allow = false;
  }
  // primeStrictDenyCache re-fetches the live bucket (handling TLS shard
  // swap during the round trip) and resets pending_strict_* fields.
  // No-op for non-strict callers.
  primeStrictDenyCache(strict_request::kFallbackDenyTtlNs);

  ENVOY_LOG(warn, "Rate limit decision: mode={}, fallback={}, latency_ms={}",
            is_cold ? "cold_path_sync_error" : "degraded_sync_error",
            fallback_allow ? "allow" : "deny", sync_latency_ms);

  if (fallback_allow) {
    if (pending_quota_usage_) {
      incrementAtomic(pending_quota_usage_->num_requests_allowed);
    }
    callbacks_->continueDecoding();
  } else {
    if (pending_quota_usage_) {
      incrementAtomic(pending_quota_usage_->num_requests_denied);
    }
    config_->stats().rate_limited_.inc();
    buildDenyDetailsLazy(cold_path_bucket_id_);
    callbacks_->sendLocalReply(getDenyResponseCode(pending_deny_settings_),
                               pending_deny_settings_.http_body().value(),
                               addDenyResponseHeadersCb(pending_deny_settings_), absl::nullopt,
                               deny_details_);
    callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::RateLimited);
  }

  // Clear pending state
  pending_quota_usage_.reset();
}

bool RateLimitQuotaFilter::shouldAllowRequest(const CachedBucket& cached_bucket) {
  const BucketAction& bucket_action =
      (cached_bucket.cached_action) ? *cached_bucket.cached_action : cached_bucket.default_action;

  // Check for concurrency limit first
  if (bucket_action.has_quota_assignment_action() &&
      bucket_action.quota_assignment_action().has_concurrency_limit()) {
    uint64_t limit = bucket_action.quota_assignment_action().concurrency_limit().limit();
    uint64_t current_active = cached_bucket.quota_usage->active_requests.load(std::memory_order_relaxed);
    
    while (current_active < limit) {
      if (cached_bucket.quota_usage->active_requests.compare_exchange_weak(current_active, current_active + 1, std::memory_order_relaxed)) {
        ENVOY_LOG(debug, "Concurrency limit allowed and incremented: new_active={} limit={}", current_active + 1, limit);
        return true;
      }
    }
    ENVOY_LOG(debug, "Concurrency limit denied: current_active={} limit={}", current_active, limit);
    return false;
  }

  RateLimitStrategy rate_limit_strategy =
      (bucket_action.has_quota_assignment_action())
          ? bucket_action.quota_assignment_action().rate_limit_strategy()
          : RateLimitStrategy();

  // Note: Degradation mode is handled separately in processCachedBucket
  // to support async quota checking

  switch (rate_limit_strategy.strategy_case()) {
  case RateLimitStrategy::kBlanketRule:
    switch (rate_limit_strategy.blanket_rule()) {
      PANIC_ON_PROTO_ENUM_SENTINEL_VALUES;
    case RateLimitStrategy::ALLOW_ALL:
      return true;
    case RateLimitStrategy::DENY_ALL:
      return false;
    }
    break;
  case RateLimitStrategy::kTokenBucket:
    if (!cached_bucket.token_bucket_limiter) {
      // Self-quarantined bucket: limiter was deliberately nulled after
      // heartbeat staleness detection. Deny until a fresh server response
      // re-creates the bucket with a valid limiter.
      return false;
    }
    return cached_bucket.token_bucket_limiter->consume(1);
  case RateLimitStrategy::kRequestsPerTimeUnit:
    // TODO(tyxia) Implement RequestsPerTimeUnit.
    ENVOY_LOG(warn, "RequestsPerTimeUnit is not yet supported by RLQS.");
    return true;
  case RateLimitStrategy::STRATEGY_NOT_SET:
    ENVOY_LOG(error, "Bug: an RLQS bucket is cached with a missing "
                     "quota_assignment_action or rate_limit_strategy causing the "
                     "filter to fail open.");
    return true;
  }
  return true; // Unreachable.
}

std::pair<std::string, std::string>
RateLimitQuotaFilter::extractTenantScopeKey(const BucketId& base_bucket_id_proto) const {
  const auto& bucket = base_bucket_id_proto.bucket();
  auto t_it = bucket.find(std::string(kBucketIdTenantKey));
  auto s_it = bucket.find(std::string(kBucketIdScopeKey));
  if (t_it == bucket.end() || s_it == bucket.end()) {
    return {"", ""};
  }
  return {t_it->second, s_it->second};
}

void RateLimitQuotaFilter::evictGhostBaseBucketIfPresent(const BucketId& base_bucket_id_proto) {
  if (client_) {
    client_->removeBucket(hashBucketId(base_bucket_id_proto));
  }
}

Http::FilterHeadersStatus RateLimitQuotaFilter::continueMultiDimWarmupWithoutBaseBucket(
    const BucketId& base_bucket_id_proto) {
  ENVOY_LOG(debug,
            "Dynamic multi-dim: suppressing ghost base bucket {}, bypassing "
            "single-dim warm-up path",
            base_bucket_id_proto.ShortDebugString());
  return Http::FilterHeadersStatus::Continue;
}

absl::optional<Http::FilterHeadersStatus>
RateLimitQuotaFilter::tryDynamicMultiDimensionCheck(
    const BucketId& base_bucket_id_proto,
    const RateLimitOnMatchAction& match_action) {
  // match_action carries the static (xDS) BucketSettings; per-dim settings
  // for the dynamic path come from the registry instead. The parameter is
  // retained so future iterations can fall back to match_action's defaults
  // when a dim's settings omit a field.
  if (!dynamic_registry_) {
    return absl::nullopt;
  }
  const auto [tenant, scope] = extractTenantScopeKey(base_bucket_id_proto);
  if (tenant.empty() || scope.empty()) {
    return absl::nullopt;
  }

  // Subscribe (idempotent). We fetch this single (tenant, scope) config
  // from the server instead of subscribing to a full stream.
  //
  // F-1.1 worker-local dedupe: bound the dedupe set so
  // a long-lived worker cannot leak memory.
  if (config_discovery_client_) {
    // ConfigDiscoveryClient handles Singleflight and TTL deduplication natively.
    if (!waiting_for_quota_config_) {
      auto settings_list = dynamic_registry_->lookup(tenant, scope);
      if (settings_list.empty()) {
        // Not cached. Suspend the request and fetch.
        ENVOY_LOG(info, "RLQS MultiDim: registry miss tenant={} scope={}, suspending request to fetch config",
                  tenant, scope);
        waiting_for_quota_config_ = true;
        pending_bucket_id_proto_ = base_bucket_id_proto;

        // We must copy match_action because the reference might become invalid
        // after decodeHeaders returns StopIteration.
        pending_match_action_ = std::make_unique<RateLimitOnMatchAction>(
            match_action.bucketSettings()
        );

        config_fetch_alive_guard_ = std::make_shared<std::atomic<bool>>(true);
        auto guard = config_fetch_alive_guard_;
        Event::Dispatcher* worker_dispatcher_ptr = &callbacks_->dispatcher();
        RateLimitQuotaFilter* filter_ptr = this;
        config_discovery_client_->fetchQuotaConfig(tenant, scope,
            [guard, worker_dispatcher_ptr, filter_ptr](bool success) {
              ENVOY_LOG_MISC(debug, "RLQS MultiDim: config fetch callback on main thread, success={}, posting to worker",
                             success);
              worker_dispatcher_ptr->post([guard, filter_ptr, success]() {
                ENVOY_LOG_MISC(debug, "RLQS MultiDim: config fetch result on worker thread, guard_alive={} success={}",
                               guard->load(std::memory_order_acquire), success);
                if (!guard->load(std::memory_order_acquire)) {
                  ENVOY_LOG_MISC(info, "RLQS MultiDim: filter destroyed before config fetch callback, dropping");
                  return;
                }
                filter_ptr->onQuotaConfigFetchComplete(success);
              });
            });
        config_fetch_timer_ = callbacks_->dispatcher().createTimer([this]() {
          ENVOY_LOG(warn, "RLQS MultiDim: config fetch timeout expired, falling back to single-dim");
          onQuotaConfigFetchComplete(false);
        });
        auto timeout_ms = configFetchTimeoutValue(config_->config());
        config_fetch_timer_->enableTimer(timeout_ms);
        ENVOY_LOG(debug, "RLQS MultiDim: config fetch timer armed timeout_ms={}, suspending request",
                  timeout_ms.count());
        return Http::FilterHeadersStatus::StopIteration;
      } else {
        ENVOY_LOG(debug, "tryDynamicMultiDimensionCheck: registry hit for tenant={} scope={}, "
                  "settings_count={}", tenant, scope, settings_list.size());
      }
    } else {
      // If we are already waiting, this means we are in the re-evaluation phase.
      // We shouldn't fetch again. Just proceed to check the cache.
      ENVOY_LOG(debug, "tryDynamicMultiDimensionCheck: re-evaluation phase, "
                "skipping fetch for tenant={} scope={}", tenant, scope);
      waiting_for_quota_config_ = false;
    }
  }


  auto settings_list = dynamic_registry_->lookup(tenant, scope);
  if (settings_list.empty()) {
    // Empty list = (tenant, scope) hasn't been pushed by the server yet, or
    // was abandoned via spec D-6 confirmed-miss. Bumped per-request so the
    // ratio against lookup_hit shows the warm-up curve over a steady-state
    // route's lifetime.
    config_->stats().dynamic_registry_lookup_empty_.inc();
    return absl::nullopt; // server hasn't pushed yet → single-dim fallback
  }
  config_->stats().dynamic_registry_lookup_hit_.inc();

  if (config_discovery_client_ &&
      config_->shouldTouchConfigAccess(tenant, scope, time_source_)) {
    config_discovery_client_->touchAccessFromWorker(tenant, scope);
  }

  // Build variant BucketIds and look up each in the cache. Variants that
  // are missing are NOT a hard failure — we register them via createBucket
  // so the next request picks them up, then fall back to the single-dim
  // path for the current request. This keeps cold-start behavior identical
  // to today while the dim variants warm up over a few requests.
  struct Variant {
    BucketId id;
    size_t hash;
    std::shared_ptr<CachedBucket> cached;
    RateLimitQuotaBucketSettingsConstSharedPtr settings;
  };
  std::vector<Variant> variants;
  variants.reserve(settings_list.size());
  bool any_missing = false;
  for (const auto& cached_settings : settings_list) {
    if (!cached_settings || !cached_settings->settings ||
        !cached_settings->settings->has_bucket_id_builder()) {
      continue;
    }
    // Variant BucketId = base + the settings' bucket_id_builder string_value
    // entries. The overlay was precomputed at server-push time and lives on
    // CachedBucketSettings — the hot path simply applies it. The original
    // proto map traversal + value_specifier_case check is gone from this
    // request path entirely.
    BucketId variant_id = base_bucket_id_proto;
    for (const auto& [k, v] : cached_settings->overlay) {
      (*variant_id.mutable_bucket())[k] = v;
    }
    const size_t variant_hash = hashBucketId(variant_id);
    auto cached = client_->getBucket(variant_hash);
    if (!cached) {
      any_missing = true;
      config_->stats().dynamic_variant_missing_.inc();
    } else {
      config_->stats().dynamic_variant_cached_.inc();
    }
    variants.push_back({std::move(variant_id), variant_hash, std::move(cached),
                        cached_settings->settings});
  }

  if (variants.empty()) {
    return absl::nullopt;
  }

  // Register missing variants via createBucket so subsequent requests find
  // them in cache. Uses the variant's own settings — no_assignment_behavior
  // (cold-path fallback), expired_assignment_behavior (TTL), and
  // deny_response_settings (per-dim deny payload). This is a side-effect
  // registration; we do not block on a sync check for these.
  if (any_missing) {
    bool any_initial_denied = false;
    DenyResponseSettings final_deny_settings;

    for (auto& v : variants) {
      if (v.cached) {
        continue;
      }
      BucketAction default_action;
      *default_action.mutable_bucket_id() = v.id;
      bool allow_initial = true;
      if (v.settings->has_no_assignment_behavior() &&
          v.settings->no_assignment_behavior().has_fallback_rate_limit()) {
        *default_action.mutable_quota_assignment_action()->mutable_rate_limit_strategy() =
            v.settings->no_assignment_behavior().fallback_rate_limit();
        allow_initial = v.settings->no_assignment_behavior()
                            .fallback_rate_limit()
                            .strategy_case() != RateLimitStrategy::kBlanketRule ||
                        v.settings->no_assignment_behavior()
                                .fallback_rate_limit()
                                .blanket_rule() != RateLimitStrategy::DENY_ALL;
      } else {
        default_action.mutable_quota_assignment_action()
            ->mutable_rate_limit_strategy()
            ->set_blanket_rule(RateLimitStrategy::ALLOW_ALL);
      }
      if (!allow_initial) {
        any_initial_denied = true;
        final_deny_settings = v.settings->deny_response_settings();
      }

      std::unique_ptr<RateLimitStrategy> expiration_fallback;
      std::chrono::milliseconds expiration_ttl{0};
      if (v.settings->has_expired_assignment_behavior() &&
          v.settings->expired_assignment_behavior().has_fallback_rate_limit()) {
        expiration_fallback = std::make_unique<RateLimitStrategy>(
            v.settings->expired_assignment_behavior().fallback_rate_limit());
      }
      if (v.settings->has_expired_assignment_behavior() &&
          v.settings->expired_assignment_behavior().has_expired_assignment_behavior_timeout()) {
        const auto& ttl_proto =
            v.settings->expired_assignment_behavior().expired_assignment_behavior_timeout();
        expiration_ttl = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(ttl_proto.seconds()) +
            std::chrono::nanoseconds(ttl_proto.nanos()));
      }
      client_->createBucket(v.id, v.hash, default_action, std::move(expiration_fallback),
                            expiration_ttl, allow_initial, v.settings->deny_response_settings());
      ENVOY_LOG(debug, "Multi-dim: registered variant BucketId for warm-up: {}",
                v.id.ShortDebugString());
    }

    if (any_initial_denied) {
      pending_deny_settings_ = final_deny_settings;
      buildDenyDetailsLazy(base_bucket_id_proto);
      config_->stats().rate_limited_.inc();
      return sendDenyResponse(callbacks_, final_deny_settings, StreamInfo::ResponseFlag::RateLimited, deny_details_);
    }

    for (const auto& v : variants) {
      if (isTokenDimensionBucket(v.id)) {
        auto cached = client_->getBucket(v.hash);
        if (cached) {
          pending_token_quota_usage_ = cached->quota_usage;
        } else {
          std::chrono::nanoseconds now = nowMonotonicNsTyped(callbacks_->dispatcher().timeSource());
          pending_token_quota_usage_ = std::make_shared<QuotaUsage>(0, 0, now);
        }
        resetTokenUsageState();
        cold_path_bucket_id_ = v.id;
        break;
      }
    }

    // Bypass single-dim path so we don't create an unused base bucket.
    // Variants will be synced on the next request.
    return Http::FilterHeadersStatus::Continue;
  }

  // All variants cached. Two-phase 100%-accurate dispatch:
  //
  // Phase 1 (synchronous): iterate every variant. Non-strict variants take
  //   the fast path (local CAS / token bucket consume). Strict variants
  //   that would have been conservatively DENY'd (request strict +
  //   degraded; concurrency strict whose local CAS would fail) get
  //   DEFERRED into multi_dim_state_.deferred — no local state mutation
  //   yet. If any sync check denies, rollback + return immediately.
  //
  // Phase 2 (asynchronous, serial): fire each deferred SyncCheck one at
  //   a time. Each suspends the filter with StopIteration; the gRPC
  //   callback re-enters via resumeMultiDimAfterSyncCheck. SyncCheck
  //   approval = unconditional local INC for that variant; DENY = global
  //   rollback + sendDeny.
  //
  // Rollback compensation (P0 fix, extracted to rollbackMultiDimPending
  // so the async resume path can reuse it across StopIteration boundaries):
  //   - request / token dim: token_bucket->consume(1) → token_bucket->refund(1)
  //   - concurrency dim: active_requests.fetch_add(1) → fetch_sub(1)
  //   - all dims: num_requests_allowed.fetch_add(1) → fetch_sub(1) (guarded)
  // On full success: concurrency entries → multi_dim_active_quota_usages_
  // for onDestroy cleanup.
  ASSERT(multi_dim_state_ == nullptr,
         "tryDynamicMultiDimensionCheck re-entered while a dispatch is in flight");
  multi_dim_state_ = std::make_unique<MultiDimDispatchState>();
  multi_dim_state_->pending.reserve(variants.size());
  multi_dim_state_->deferred.reserve(variants.size());
  multi_dim_state_->deny_details = deny_details_;

  // If any variant is `_dim:token`, the whole rule degrades to all-sync
  // (per spec: token rules cannot be approximated locally, and a rule
  // containing token must treat its other dims with the same accuracy
  // guarantee to keep the per-rule decision consistent). Detected once
  // up front so the per-variant loop can short-circuit cleanly.
  //
  // Same scan also captures the token variant's QuotaUsage as the credit
  // target for encodeData token-usage extraction. Without this, the
  // multi-dim path leaves pending_token_quota_usage_ unset and the actual
  // token consumption never reaches the periodic report — leaving the
  // server with stale budget accounting precisely on the bucket where
  // accuracy matters most.
  for (const auto& v : variants) {
    if (isTokenDimensionBucket(v.id)) {
      multi_dim_state_->token_dim_failopen = true;
      if (v.cached) {
        pending_token_quota_usage_ = v.cached->quota_usage;
        resetTokenUsageState();
      }
      break;
    }
  }

  const int64_t now_ns = nowMonotonicNs(time_source_);
  // Hoisted out of the per-variant loop: monotonic time doesn't change
  // measurably across N variants (typically 2-5) — one duration_cast per
  // dispatch is enough.
  const std::chrono::nanoseconds now_typed =
      nowMonotonicNsTyped(callbacks_->dispatcher().timeSource());

  for (auto& v : variants) {
    // Update last access time on the variant.
    v.cached->quota_usage->time_of_last_access.store(now_typed, std::memory_order_relaxed);

    // Determine variant shape (concurrency vs token-bucket).
    const BucketAction& variant_action = v.cached->cached_action ? *v.cached->cached_action
                                                                 : v.cached->default_action;
    const bool variant_is_concurrency =
        variant_action.has_quota_assignment_action() &&
        variant_action.quota_assignment_action().has_concurrency_limit();

    // Token-dim parallel-degrade: ALL variants of this rule defer to Phase 2
    // sync RPC. Skips local CAS / shouldAllowRequest / strict deny-cache
    // entirely; resumeMultiDimAfterSyncCheck handles per-variant concurrency
    // CAS on allow, and abortMultiDimAfterError handles fail-open on RPC
    // error (instead of the default strict fail-closed).
    //
    // Critically, we short-circuit BEFORE the deny_until_ns check below: a
    // stale strict-mode deny cache primed before this rule gained a token
    // dim must not deny under the new always-sync semantics. The server's
    // SyncCheck is the sole authority for this RPC.
    if (multi_dim_state_->token_dim_failopen) {
      multi_dim_state_->deferred.push_back(
          {v.id, v.cached, v.settings, variant_is_concurrency});
      continue;
    }

    // Strict-mode deny cache fast path. Mirrors processCachedBucket's
    // prologue. No-op for non-strict buckets (deny_until_ns stays 0).
    if (v.cached->deny_until_ns.load(std::memory_order_relaxed) > now_ns) {
      ENVOY_LOG(debug, "Multi-dim: deny cache hit for variant {}", v.id.ShortDebugString());
      rollbackMultiDimPending(multi_dim_state_->pending);
      multi_dim_state_->final_deny_response_settings = v.settings->deny_response_settings();
      auto status = sendDenyResponse(callbacks_, multi_dim_state_->final_deny_response_settings,
                                     StreamInfo::ResponseFlag::RateLimited,
                                     multi_dim_state_->deny_details);
      config_->stats().rate_limited_.inc();
      config_->stats().multi_dim_denied_.inc();
      multi_dim_state_.reset();
      return status;
    }

    // Strict-request + degraded: cannot evaluate locally (server cleared
    // token_bucket_limiter via INV-2 and sent Strategy{nil}). Defer to
    // Phase 2 SyncCheck instead of the legacy conservative DENY. This is
    // the headline P2 fix.
    const bool strict_request_degraded =
        !variant_is_concurrency &&
        v.cached->degradation_state &&
        v.cached->degradation_state->strict_request_mode.load(std::memory_order_relaxed) &&
        v.cached->degradation_state->degraded.load(std::memory_order_acquire);
    if (strict_request_degraded) {
      ENVOY_LOG(debug,
                "Multi-dim: variant {} strict-request + degraded → deferring to SyncCheck",
                v.id.ShortDebugString());
      multi_dim_state_->deferred.push_back(
          {v.id, v.cached, v.settings, /*is_concurrency=*/false});
      continue;
    }

    // Strict concurrency: if the local CAS would saturate (active_requests
    // ≥ limit) AND strict mode is on, defer to SyncCheck for the R reserve
    // slots. Otherwise fall through to shouldAllowRequest's normal CAS
    // (legacy fast path). Reuses strict_request_mode as the generic
    // "100% strict" flag; server-side AllocConcurrencyStrict sets it when
    // ConcurrencyStrictMode is opt-in'd for the bucket.
    if (variant_is_concurrency &&
        v.cached->degradation_state &&
        v.cached->degradation_state->strict_request_mode.load(std::memory_order_relaxed)) {
      uint64_t limit = variant_action.quota_assignment_action().concurrency_limit().limit();
      uint64_t current_active =
          v.cached->quota_usage->active_requests.load(std::memory_order_relaxed);
      if (current_active >= limit) {
        ENVOY_LOG(debug,
                  "Multi-dim: concurrency-strict variant {} at K_i={} → deferring to SyncCheck",
                  v.id.ShortDebugString(), limit);
        multi_dim_state_->deferred.push_back(
            {v.id, v.cached, v.settings, /*is_concurrency=*/true});
        continue;
      }
      // Below K_i: legacy CAS path handles it on the local fast path.
    }

    if (!shouldAllowRequest(*v.cached)) {
      // Local tokens exhausted — defer to Phase 2 SyncCheck to consume from
      // the global reserve pool, same as the strict_request_degraded path.
      if (!variant_is_concurrency &&
          v.cached->degradation_state &&
          sync_quota_checker_) {
        ENVOY_LOG(debug,
                  "Multi-dim: variant {} local tokens exhausted → deferring to SyncCheck",
                  v.id.ShortDebugString());
        multi_dim_state_->deferred.push_back(
            {v.id, v.cached, v.settings, /*is_concurrency=*/false});
        continue;
      }
      rollbackMultiDimPending(multi_dim_state_->pending);
      multi_dim_state_->final_deny_response_settings = v.settings->deny_response_settings();
      auto status = sendDenyResponse(callbacks_, multi_dim_state_->final_deny_response_settings,
                                     StreamInfo::ResponseFlag::RateLimited,
                                     multi_dim_state_->deny_details);
      config_->stats().rate_limited_.inc();
      config_->stats().multi_dim_denied_.inc();
      multi_dim_state_.reset();
      ENVOY_LOG(info, "Multi-dim: rate limited by bucket={}", v.id.ShortDebugString());
      return status;
    }
    // Account the allowance against this dim's QuotaUsage so the next
    // report carries accurate counts per dim.
    v.cached->quota_usage->num_requests_allowed.fetch_add(1, std::memory_order_relaxed);
    multi_dim_state_->pending.push_back({v.cached, variant_is_concurrency});
  }

  // Phase 1 completed without sync deny. If any variant deferred to
  // SyncCheck, hand off to Phase 2.
  if (!multi_dim_state_->deferred.empty()) {
    return sendNextDeferredMultiDimSyncCheck();
  }

  // No deferred variants — commit cleanup and continue inline.
  // All variants passed — commit concurrency entries to the cleanup list so
  // onDestroy can decrement active_requests when the request completes
  // (mirroring the single-dim concurrency cleanup path).
  for (auto& p : multi_dim_state_->pending) {
    if (p.was_concurrency) {
      multi_dim_active_quota_usages_.push_back(p.bucket->quota_usage);
    }
  }
  // Reset dispatch state — sync-only path is fully committed.
  multi_dim_state_.reset();
  return Http::FilterHeadersStatus::Continue;
}

// =================================================================
// Multi-dim async state machine — Phase 2 implementation
// =================================================================
void RateLimitQuotaFilter::rollbackMultiDimPending(
    std::vector<MultiDimPendingDeduction>& pending) {
  // Walk in reverse for nicer log ordering / cache locality on the typical
  // case where the failing variant is the last few.
  for (auto it = pending.rbegin(); it != pending.rend(); ++it) {
    if (it->was_concurrency) {
      it->bucket->quota_usage->active_requests.fetch_sub(1, std::memory_order_relaxed);
    } else if (it->bucket->token_bucket_limiter) {
      // QuotaTokenBucket overrides refund() with a CAS-loop add; legacy
      // AtomicTokenBucketImpl silently no-ops (fill_rate semantics).
      it->bucket->token_bucket_limiter->refund(1);
    }
    uint64_t cur = it->bucket->quota_usage->num_requests_allowed.load(std::memory_order_relaxed);
    while (cur > 0 &&
           !it->bucket->quota_usage->num_requests_allowed.compare_exchange_weak(
               cur, cur - 1, std::memory_order_relaxed)) {
    }
  }
  pending.clear();
}

Http::FilterHeadersStatus RateLimitQuotaFilter::sendNextDeferredMultiDimSyncCheck() {
  if (!multi_dim_state_ ||
      multi_dim_state_->deferred_cursor >= multi_dim_state_->deferred.size()) {
    // All deferred SyncChecks done. Commit concurrency cleanup and continue.
    if (multi_dim_state_) {
      for (auto& p : multi_dim_state_->pending) {
        if (p.was_concurrency) {
          multi_dim_active_quota_usages_.push_back(p.bucket->quota_usage);
        }
      }
      multi_dim_state_.reset();
    }
    return Http::FilterHeadersStatus::Continue;
  }

  // Fire the next deferred SyncCheck. The existing sync_quota_checker_
  // path will call onQuotaCheckComplete / onQuotaCheckError; those branch
  // on multi_dim_state_ to route back here.
  if (!sync_quota_checker_) {
    // No checker wired — fail-open: allow request and continue processing
    // remaining deferred variants without rate-limiting.
    auto& v = multi_dim_state_->deferred[multi_dim_state_->deferred_cursor];
    v.cached->quota_usage->num_requests_allowed.fetch_add(1, std::memory_order_relaxed);
    if (v.is_concurrency) {
      uint64_t current = v.cached->quota_usage->active_requests.load(std::memory_order_relaxed);
      while (!v.cached->quota_usage->active_requests.compare_exchange_weak(
          current, current + 1, std::memory_order_relaxed)) {
      }
      multi_dim_active_quota_usages_.push_back(v.cached->quota_usage);
    }
    multi_dim_state_->deferred_cursor++;
    config_->stats().degraded_sync_error_.inc();
    return sendNextDeferredMultiDimSyncCheck();
  }

  auto& v = multi_dim_state_->deferred[multi_dim_state_->deferred_cursor];
  const std::chrono::milliseconds timeout = degradationSyncTimeoutValue(config_->config());
  waiting_for_quota_check_ = true;
  cold_path_sync_check_pending_ = false;

  // Token-dim parallel-degrade: don't masquerade as strict/degraded.
  //   - was_degraded_sync_ stays false so the onDestroy estimate-deviation
  //     warning doesn't fire (the warning targets the strict_request_mode
  //     flow where avg_tokens_per_request tuning matters).
  //   - pending_strict_request_mode_ stays false so neither the
  //     onQuotaCheckComplete deny path nor onQuotaCheckError prime a
  //     deny_until_ns cache (which is a strict_request_mode mechanism
  //     specifically opted into by the server).
  if (multi_dim_state_->token_dim_failopen) {
    was_degraded_sync_ = false;
    pending_strict_request_mode_ = false;
    pending_strict_bucket_id_hash_ = 0;
    pending_strict_bucket_.reset();
    config_->stats().token_dim_sync_started_.inc();
  } else {
    was_degraded_sync_ = true;
    // Stash the current deferred variant's metadata so the resume callback
    // knows which one to apply the result to. pending_strict_bucket_id_hash_
    // is repurposed to carry the variant's hash so primeStrictDenyCache /
    // RPC error handling can target the right bucket (no new field needed).
    pending_strict_request_mode_ = true;
    pending_strict_bucket_id_hash_ = hashBucketId(v.id);
    pending_strict_bucket_ = v.cached;
  }

  if (!sync_quota_checker_->checkQuotaAsync(v.id, kSyncCheckTokenEstimate, timeout, *this)) {
    // Initiation failed → treat as RPC error.
    waiting_for_quota_check_ = false;
    abortMultiDimAfterError();
    // abortMultiDim already sent the response.
    return Http::FilterHeadersStatus::StopIteration;
  }
  return Http::FilterHeadersStatus::StopIteration;
}

void RateLimitQuotaFilter::resumeMultiDimAfterSyncCheck(bool allowed) {
  if (!multi_dim_state_) {
    return;
  }
  auto& s = *multi_dim_state_;
  if (s.deferred_cursor >= s.deferred.size()) {
    multi_dim_state_.reset();
    return;
  }
  auto& v = s.deferred[s.deferred_cursor];

  if (!allowed) {
    // SyncCheck DENY: rollback all sync + previously-approved deferred,
    // prime deny cache for THIS variant, send deny response. Same shape
    // as Phase 1 sync deny.
    rollbackMultiDimPending(s.pending);
    if (pending_deny_retry_after_ms_ > 0) {
      v.cached->deny_until_ns.store(
          nowMonotonicNs(time_source_) +
              static_cast<int64_t>(pending_deny_retry_after_ms_) * 1'000'000LL,
          std::memory_order_relaxed);
    }
    s.final_deny_response_settings = v.settings->deny_response_settings();
    config_->stats().rate_limited_.inc();
    config_->stats().multi_dim_denied_.inc();
    callbacks_->sendLocalReply(getDenyResponseCode(s.final_deny_response_settings),
                               s.final_deny_response_settings.http_body().value(),
                               addDenyResponseHeadersCb(s.final_deny_response_settings),
                               absl::nullopt, s.deny_details);
    callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::RateLimited);
    multi_dim_state_.reset();
    return;
  }

  // SyncCheck ALLOW for this variant. For concurrency variant the existing
  // degraded handling expects unconditional CAS+1 on active_requests.
  // For non-concurrency (strict-request): do NOT increment num_requests_allowed.
  // SyncCheck already atomically counted this request in Redis (total_tokens).
  // Incrementing here would cause the periodic report to double-count,
  // and unreported increments at window boundaries cause cross-window pollution.
  if (v.is_concurrency) {
    uint64_t current = v.cached->quota_usage->active_requests.load(std::memory_order_relaxed);
    while (!v.cached->quota_usage->active_requests.compare_exchange_weak(
        current, current + 1, std::memory_order_relaxed)) {
    }
    v.cached->quota_usage->num_requests_allowed.fetch_add(1, std::memory_order_relaxed);
  }
  s.pending.push_back({v.cached, v.is_concurrency});
  s.deferred_cursor++;

  // Continue with the next deferred SyncCheck or commit.
  auto status = sendNextDeferredMultiDimSyncCheck();
  if (status == Http::FilterHeadersStatus::Continue) {
    callbacks_->continueDecoding();
  }
  // StopIteration: another async wait — keep paused.
}

void RateLimitQuotaFilter::abortMultiDimAfterError() {
  if (!multi_dim_state_) {
    return;
  }
  auto& s = *multi_dim_state_;

  // Token-dim parallel-degrade: fail-OPEN on RPC error. Commit the
  // current variant's num_requests_allowed (so the next periodic report
  // reflects the volume served during the outage) but DO NOT roll back
  // previously-approved variants — they were already accepted by the
  // server and represent real allowed traffic. Skip the deny-cache prime
  // (no strict mode) and skip sendLocalReply; resume request processing.
  if (s.token_dim_failopen) {
    if (s.deferred_cursor < s.deferred.size()) {
      auto& v = s.deferred[s.deferred_cursor];
      v.cached->quota_usage->num_requests_allowed.fetch_add(1, std::memory_order_relaxed);
      // If this variant had a concurrency_limit, track it for onDestroy
      // decrement just like the resume-allowed path does.
      if (v.is_concurrency) {
        uint64_t current =
            v.cached->quota_usage->active_requests.load(std::memory_order_relaxed);
        while (!v.cached->quota_usage->active_requests.compare_exchange_weak(
            current, current + 1, std::memory_order_relaxed)) {
        }
        multi_dim_active_quota_usages_.push_back(v.cached->quota_usage);
      }
      s.deferred_cursor++;
    }
    config_->stats().token_dim_sync_error_.inc();
    // Continue Phase 2 with the remaining deferred variants. If none
    // remain, the helper commits cleanup and returns Continue.
    auto status = sendNextDeferredMultiDimSyncCheck();
    if (status == Http::FilterHeadersStatus::Continue) {
      callbacks_->continueDecoding();
    }
    return;
  }

  // Fail-open: commit the current deferred variant as allowed and continue
  // processing remaining deferred variants without rate-limiting.
  if (s.deferred_cursor < s.deferred.size()) {
    auto& v = s.deferred[s.deferred_cursor];
    v.cached->quota_usage->num_requests_allowed.fetch_add(1, std::memory_order_relaxed);
    if (v.is_concurrency) {
      uint64_t current = v.cached->quota_usage->active_requests.load(std::memory_order_relaxed);
      while (!v.cached->quota_usage->active_requests.compare_exchange_weak(
          current, current + 1, std::memory_order_relaxed)) {
      }
      multi_dim_active_quota_usages_.push_back(v.cached->quota_usage);
    }
    s.deferred_cursor++;
  }
  config_->stats().degraded_sync_error_.inc();
  auto status = sendNextDeferredMultiDimSyncCheck();
  if (status == Http::FilterHeadersStatus::Continue) {
    callbacks_->continueDecoding();
  }
}

Http::FilterHeadersStatus RateLimitQuotaFilter::processCachedBucket(
    const DenyResponseSettings& deny_response_settings, const BucketId& bucket_id_proto,
    const RateLimitQuotaBucketSettings& bucket_settings) {
  const size_t bucket_id = hashBucketId(bucket_id_proto);
  std::shared_ptr<CachedBucket> cached_bucket = client_->getBucket(bucket_id);
  if (cached_bucket == nullptr) {
    bool initial_request_allowed = true;
    if (bucket_settings.has_no_assignment_behavior()) {
      initial_request_allowed =
          noAssignmentBehaviorShouldAllow(bucket_settings.no_assignment_behavior());
    }
    
    std::chrono::milliseconds fallback_ttl = std::chrono::milliseconds::zero();
    if (bucket_settings.expired_assignment_behavior().has_expired_assignment_behavior_timeout()) {
      fallback_ttl = std::chrono::milliseconds(
          DurationUtil::durationToMilliseconds(bucket_settings.expired_assignment_behavior().expired_assignment_behavior_timeout()));
    }
    
    BucketAction default_action;
    *default_action.mutable_bucket_id() = bucket_id_proto;
    if (bucket_settings.has_no_assignment_behavior()) {
      *default_action.mutable_quota_assignment_action()->mutable_rate_limit_strategy() =
          bucket_settings.no_assignment_behavior().fallback_rate_limit();
    } else {
      default_action.mutable_quota_assignment_action()->mutable_rate_limit_strategy()->set_blanket_rule(RateLimitStrategy::ALLOW_ALL);
    }
    
    std::unique_ptr<RateLimitStrategy> fallback_strategy =
        (bucket_settings.has_expired_assignment_behavior() &&
         bucket_settings.expired_assignment_behavior().has_fallback_rate_limit())
            ? std::make_unique<RateLimitStrategy>(
                  bucket_settings.expired_assignment_behavior().fallback_rate_limit())
            : nullptr;
    
    client_->createBucket(bucket_id_proto, bucket_id, default_action,
                          std::move(fallback_strategy),
                          fallback_ttl, initial_request_allowed,
                          bucket_settings.deny_response_settings());

    // Capture token usage for this request before the bucket is fully cached
    std::chrono::nanoseconds now =
        nowMonotonicNsTyped(callbacks_->dispatcher().timeSource());
    pending_token_quota_usage_ = std::make_shared<QuotaUsage>(0, 0, now);
    resetTokenUsageState();
    cold_path_bucket_id_ = bucket_id_proto;

    config_->stats().new_bucket_id_.inc();

    if (initial_request_allowed) {
      return Http::FilterHeadersStatus::Continue;
    } else {
      pending_deny_settings_ = deny_response_settings;
      buildDenyDetailsLazy(bucket_id_proto);
      config_->stats().rate_limited_.inc();
      return sendDenyResponse(callbacks_, deny_response_settings, StreamInfo::ResponseFlag::RateLimited, deny_details_);
    }
  }

  return processCachedBucket(deny_response_settings, *cached_bucket);
}

Http::FilterHeadersStatus
RateLimitQuotaFilter::processCachedBucket(const DenyResponseSettings& deny_response_settings,
                                          CachedBucket& cached_bucket) {
  // The QuotaUsage of a cached bucket should never be null. If it is due to a
  // bug, this will crash.
  std::shared_ptr<QuotaUsage> quota_usage = cached_bucket.quota_usage;

  // Check if degradation mode is disabled in config
  // Degradation mode is ENABLED by default (disabled=false)
  bool degradation_mode_disabled = config_->config().has_degradation_mode_config() &&
                                   config_->config().degradation_mode_config().disabled();

  const BucketAction& bucket_action =
      (cached_bucket.cached_action) ? *cached_bucket.cached_action : cached_bucket.default_action;

  bool is_concurrency_limit = bucket_action.has_quota_assignment_action() &&
                              bucket_action.quota_assignment_action().has_concurrency_limit();

  // Strict-request 100% accuracy: deny-cache fast path. When the server
  // (or a prior RPC error) primed deny_until_ns into the future, every
  // request to this bucket is rejected locally without contacting the
  // server — short-circuits the SyncCheck thundering herd. Token /
  // concurrency buckets never set deny_until_ns so this is a no-op for
  // them. Use monotonic time so wall-clock jumps don't break the bound.
  {
    if (cached_bucket.deny_until_ns.load(std::memory_order_relaxed) >
        nowMonotonicNs(time_source_)) {
      incrementAtomic(quota_usage->num_requests_denied);
      config_->stats().rate_limited_.inc();
      return sendDenyResponse(callbacks_, deny_response_settings,
                              StreamInfo::ResponseFlag::RateLimited, deny_details_);
    }
  }

  // Check if in degraded mode and handle accordingly
  // Note: Concurrency limits are now supported in degraded mode via SyncCheck.
  if (!degradation_mode_disabled && cached_bucket.degradation_state &&
      cached_bucket.degradation_state->degraded.load(std::memory_order_acquire)) {
  ENVOY_LOG(info, "DEGRADED: bucket entering sync check mode, bucket_id={}", 
            cached_bucket.bucket_id.DebugString());
    
    // Store pending state for async callback
    pending_quota_usage_ = quota_usage;
    pending_deny_settings_ = deny_response_settings;
    is_concurrency_limit_pending_ = is_concurrency_limit;

    // Try async quota check
    if (sync_quota_checker_ && initiateAsyncQuotaCheck(cached_bucket)) {
      // Async check initiated, pause request processing
      return Envoy::Http::FilterHeadersStatus::StopIteration;
    }

    // Failed to initiate async check, use fallback behavior.
    const bool fallback_allow = degradationErrorFallbackAllow(config_->config());
    ENVOY_LOG(warn, "Failed to initiate async quota check in degraded mode, "
                    "falling back to {} behavior",
              fallback_allow ? "allow" : "deny");

    pending_quota_usage_.reset();

    if (fallback_allow) {
      incrementAtomic(quota_usage->num_requests_allowed);
      if (is_concurrency_limit_pending_) {
        uint64_t current = quota_usage->active_requests.load(std::memory_order_relaxed);
        while (!quota_usage->active_requests.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) {
        }
        concurrency_incremented_ = true;
        active_quota_usage_ = quota_usage;
        ENVOY_LOG(debug, "Concurrency incremented on fallback_allow");
      }
      return Envoy::Http::FilterHeadersStatus::Continue;
    } else {
      incrementAtomic(quota_usage->num_requests_denied);
      config_->stats().rate_limited_.inc();
      return sendDenyResponse(callbacks_, deny_response_settings,
                              StreamInfo::ResponseFlag::RateLimited, deny_details_);
    }
  }

  // Normal mode: use local token bucket or concurrency limit
  if (shouldAllowRequest(cached_bucket)) {
    incrementAtomic(quota_usage->num_requests_allowed);

    if (is_concurrency_limit) {
      concurrency_incremented_ = true;
      active_quota_usage_ = quota_usage;
      ENVOY_LOG(debug, "Concurrency incremented tracking set for bucket_id={}",
                cached_bucket.bucket_id.ShortDebugString());
    }

    ENVOY_LOG(debug, "Rate limit decision: allowed=true, mode=normal, "
                     "tokens_remaining={}",
              cached_bucket.token_bucket_limiter ?
              cached_bucket.token_bucket_limiter->remainingTokens() : 0);
    return Envoy::Http::FilterHeadersStatus::Continue;
  }

  // Local token bucket exhausted — try SyncCheck to consume from the global
  // reserve pool before denying. This eliminates the Phase 1 gap where the
  // instance has no local tokens but the server hasn't signalled degraded yet.
  // Skipped for:
  //   - concurrency mode (uses active_requests gauge, not tokens)
  //   - strict_request_mode (秒级/小额度 buckets where SyncCheck is sole
  //     authority via forceDegradation; adding a fallback here would cause
  //     double-counting during brief window-transition non-degraded gaps)
  const bool is_strict_request =
      cached_bucket.degradation_state &&
      cached_bucket.degradation_state->strict_request_mode.load(std::memory_order_relaxed);
  if (!degradation_mode_disabled &&
      !is_concurrency_limit &&
      !is_strict_request &&
      cached_bucket.degradation_state &&
      sync_quota_checker_) {
    ENVOY_LOG(debug, "Local tokens exhausted, falling back to SyncCheck for reserve pool");
    pending_quota_usage_ = quota_usage;
    pending_deny_settings_ = deny_response_settings;
    is_concurrency_limit_pending_ = false;
    if (initiateAsyncQuotaCheck(cached_bucket)) {
      return Envoy::Http::FilterHeadersStatus::StopIteration;
    }
    pending_quota_usage_.reset();
  }

  incrementAtomic(quota_usage->num_requests_denied);
  config_->stats().rate_limited_.inc();
  ENVOY_LOG(info, "Rate limit decision: allowed=false, mode=normal, "
                  "tokens_remaining={}",
            cached_bucket.token_bucket_limiter ?
            cached_bucket.token_bucket_limiter->remainingTokens() : 0);
  return sendDenyResponse(callbacks_, deny_response_settings,
                          StreamInfo::ResponseFlag::RateLimited, deny_details_);
}

Http::FilterHeadersStatus RateLimitQuotaFilter::dispatchTokenDimensionSync(
    const BucketId& bucket_id_proto, const RateLimitQuotaBucketSettings& bucket_settings) {
  // decodeHeaders already bumped rate_total_ before calling here. Derive
  // deny_response_settings from bucket_settings here (instead of taking it
  // as a parameter) so the function has one source of truth — same value
  // the caller would have computed via match_action.bucketSettings().
  const DenyResponseSettings& deny_response_settings = bucket_settings.deny_response_settings();

  // Fail-open when no SyncQuotaChecker is wired (e.g. tests, listeners
  // without rlqs_server). Matches the operator-facing promise that AI
  // requests are never blocked by a missing dependency.
  if (!sync_quota_checker_) {
    ENVOY_LOG(warn, "Token-dim bucket but no SyncQuotaChecker configured; failing open. "
                    "bucket_id={}",
              bucket_id_proto.ShortDebugString());
    config_->stats().token_dim_sync_error_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  const size_t bucket_id = hashBucketId(bucket_id_proto);
  std::shared_ptr<CachedBucket> cached_bucket = client_->getBucket(bucket_id);
  if (cached_bucket == nullptr) {
    // First request for this bucket — register it so the periodic reporter
    // owns the tokens_consumed roll-up. The default_action / allow flag
    // hardcodes are load-bearing: for token-dim the local shouldAllowRequest
    // path is never executed (sync RPC is sole authority), so honouring
    // bucket_settings.no_assignment_behavior here would be misleading dead
    // state. ALLOW_ALL + initial_request_allowed=true keeps the cached
    // bucket in a quiescent shape until the server's first SyncCheck reply.
    BucketAction default_action;
    *default_action.mutable_bucket_id() = bucket_id_proto;
    default_action.mutable_quota_assignment_action()
        ->mutable_rate_limit_strategy()
        ->set_blanket_rule(RateLimitStrategy::ALLOW_ALL);

    std::unique_ptr<RateLimitStrategy> fallback_strategy;
    std::chrono::milliseconds fallback_ttl = std::chrono::milliseconds::zero();
    if (bucket_settings.has_expired_assignment_behavior()) {
      const auto& exp = bucket_settings.expired_assignment_behavior();
      if (exp.has_fallback_rate_limit()) {
        fallback_strategy = std::make_unique<RateLimitStrategy>(exp.fallback_rate_limit());
      }
      if (exp.has_expired_assignment_behavior_timeout()) {
        fallback_ttl = std::chrono::milliseconds(
            DurationUtil::durationToMilliseconds(exp.expired_assignment_behavior_timeout()));
      }
    }

    client_->createBucket(bucket_id_proto, bucket_id, default_action,
                          std::move(fallback_strategy), fallback_ttl,
                          /*initial_request_allowed=*/true,
                          bucket_settings.deny_response_settings());
    config_->stats().new_bucket_id_.inc();
    cached_bucket = client_->getBucket(bucket_id);
  }

  // TLS publish lag: createBucket may not be visible on this worker yet.
  // Fail-open and let the next request find the cached entry.
  if (cached_bucket == nullptr) {
    ENVOY_LOG(warn, "Token-dim bucket {} not yet visible after createBucket; failing open.",
              bucket_id);
    config_->stats().token_dim_sync_error_.inc();
    return Http::FilterHeadersStatus::Continue;
  }

  // Refresh last-access so reaper / eviction sees the bucket as live.
  const std::chrono::nanoseconds now_ns =
      nowMonotonicNsTyped(callbacks_->dispatcher().timeSource());
  cached_bucket->quota_usage->time_of_last_access.store(now_ns, std::memory_order_relaxed);

  // Pipe response-body token extraction into the bucket's shared QuotaUsage,
  // so the periodic report carries the actual tokens_consumed for the server
  // to deduct from the budget. cold_path_bucket_id_ is intentionally left
  // empty — we don't want onDestroy to emit a one-off report for this path
  // (the bucket is in the periodic reporter's working set).
  pending_token_quota_usage_ = cached_bucket->quota_usage;
  resetTokenUsageState();

  pending_deny_settings_ = deny_response_settings;
  pending_quota_usage_ = cached_bucket->quota_usage;
  token_dim_bucket_id_ = bucket_id_proto;

  const std::chrono::milliseconds timeout = degradationSyncTimeoutValue(config_->config());

  token_dim_sync_pending_ = true;
  waiting_for_quota_check_ = true;
  config_->stats().token_dim_sync_started_.inc();
  sync_check_start_time_ = callbacks_->dispatcher().timeSource().monotonicTime();
  sync_check_timing_active_ = true;

  if (sync_quota_checker_->checkQuotaAsync(bucket_id_proto, kSyncCheckTokenEstimate, timeout,
                                           *this)) {
    return Http::FilterHeadersStatus::StopIteration;
  }

  // checkQuotaAsync refused to enqueue (e.g. backpressure). Fail-open and
  // credit the request locally so the next periodic report still reflects
  // it. Reset all state we just set so a subsequent request on this filter
  // instance starts clean.
  clearPendingSyncCheckFlags();
  waiting_for_quota_check_ = false;
  pending_quota_usage_.reset();
  token_dim_bucket_id_.clear_bucket();
  config_->stats().token_dim_sync_error_.inc();
  incrementAtomic(cached_bucket->quota_usage->num_requests_allowed);
  ENVOY_LOG(warn, "Failed to initiate token-dim sync check for bucket_id={}; failing open.",
            bucket_id);
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus RateLimitQuotaFilter::encodeHeaders(Http::ResponseHeaderMap& headers,
                                                              bool /*end_stream*/) {
  if (pending_token_quota_usage_) {
    const auto ct = headers.getContentTypeValue();
    if (absl::StrContains(ct, "application/json")) {
      response_is_json_ = true;
    } else if (absl::StrContains(ct, "text/event-stream")) {
      response_is_sse_ = true;
    } else if (absl::StrContains(ct, "application/vnd.amazon.eventstream")) {
      // Bedrock streaming (ConverseStream / InvokeModelWithResponseStream)
      // wraps each event in binary framing but the JSON payload of the
      // metadata / final event still contains a `"usage":{...}` object as
      // ASCII. Route through the JSON tail-extraction path; extractUsageObject
      // brace-matches around the usage block and ignores the framing bytes.
      response_is_json_ = true;
      response_is_aws_eventstream_ = true;
    }
    ENVOY_LOG(debug,
              "encodeHeaders: checking for token response. content-type={}, is_json={}, is_sse={}, is_aws_eventstream={}",
              ct, response_is_json_, response_is_sse_, response_is_aws_eventstream_);
  }
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus RateLimitQuotaFilter::encodeData(Buffer::Instance& data, bool end_stream) {
  if (!pending_token_quota_usage_ || (!response_is_json_ && !response_is_sse_)) {
    return Http::FilterDataStatus::Continue;
  }

  const std::string chunk = data.toString();
  if (response_is_sse_) {
    appendSseBodyForTokens(chunk, end_stream);
  } else if (response_is_json_) {
    appendJsonBodyForTokens(chunk, end_stream);
  }

  return Http::FilterDataStatus::Continue;
}

void RateLimitQuotaFilter::resetTokenUsageState() {
  token_usage_accumulator_.reset();
  openai_response_stream_merger_.reset();
  sse_token_stream_buffer_.clear();
  json_token_response_buffer_.clear();
  last_token_credit_total_ = 0;
  last_input_token_credit_ = 0;
  last_output_token_credit_ = 0;
  last_cached_token_credit_ = 0;
}

void RateLimitQuotaFilter::creditPendingTokenUsageDelta() {
  if (!pending_token_quota_usage_) {
    return;
  }
  const int64_t eff = token_usage_accumulator_.effectiveTotal();
  const int64_t inp = token_usage_accumulator_.inputTokens();
  const int64_t out = token_usage_accumulator_.outputTokens();
  const int64_t cac = token_usage_accumulator_.cachedTokens();

  ENVOY_LOG(trace,
            "Extracted token usage: input_tokens={}, output_tokens={}, cache_tokens={}, total_tokens={}",
            inp, out, cac, eff);

  if (eff <= 0 && inp <= 0 && out <= 0 && cac <= 0) {
    return;
  }

  const uint64_t cur_eff = static_cast<uint64_t>(eff > 0 ? eff : 0);
  const uint64_t cur_inp = static_cast<uint64_t>(inp > 0 ? inp : 0);
  const uint64_t cur_out = static_cast<uint64_t>(out > 0 ? out : 0);
  const uint64_t cur_cac = static_cast<uint64_t>(cac > 0 ? cac : 0);

  // Each filter instance runs on a single worker thread so last_*_credit_ vars
  // have no concurrency; QuotaUsage atomics are shared across workers hence fetch_add.
  if (cur_eff > last_token_credit_total_) {
    const uint64_t delta = cur_eff - last_token_credit_total_;
    pending_token_quota_usage_->tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
    last_token_credit_total_ = cur_eff;
    config_->stats().tokens_consumed_total_.add(delta);
    ENVOY_LOG(debug, "Token usage credited delta={} cumulative_effective={}", delta, cur_eff);
    // Keep the bucket alive in the eviction sweep while tokens are actively
    // being credited (guards against mid-stream eviction on long responses).
    pending_token_quota_usage_->time_of_last_access.store(
        nowMonotonicNsTyped(time_source_), std::memory_order_relaxed);
  }

  if (cur_inp > last_input_token_credit_) {
    const uint64_t delta = cur_inp - last_input_token_credit_;
    pending_token_quota_usage_->input_tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
    last_input_token_credit_ = cur_inp;
    config_->stats().tokens_consumed_input_.add(delta);
  }

  if (cur_out > last_output_token_credit_) {
    const uint64_t delta = cur_out - last_output_token_credit_;
    pending_token_quota_usage_->output_tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
    last_output_token_credit_ = cur_out;
    config_->stats().tokens_consumed_output_.add(delta);
  }

  if (cur_cac > last_cached_token_credit_) {
    const uint64_t delta = cur_cac - last_cached_token_credit_;
    pending_token_quota_usage_->cached_tokens_consumed.fetch_add(delta, std::memory_order_relaxed);
    last_cached_token_credit_ = cur_cac;
    config_->stats().tokens_consumed_cached_.add(delta);
  }
}

void RateLimitQuotaFilter::processSseEventForTokens(absl::string_view raw_event) {
  auto maybe_merged = openai_response_stream_merger_.transformEvent(raw_event);
  if (!maybe_merged.has_value()) {
    return;
  }
  const std::string json_payload = extractSseJsonPayload(*maybe_merged);
  if (json_payload.empty()) {
    return;
  }
  Json::ObjectSharedPtr obj = parseJsonObjectFromString(json_payload);
  if (obj == nullptr) {
    return;
  }
  token_usage_accumulator_.ingestJsonObject(*obj);
  creditPendingTokenUsageDelta();
}

void RateLimitQuotaFilter::appendSseBodyForTokens(absl::string_view chunk, bool end_stream) {
  if (sse_token_stream_buffer_.size() + chunk.size() > kMaxTokenStreamBufferBytes) {
    const size_t overflow =
        sse_token_stream_buffer_.size() + chunk.size() - kMaxTokenStreamBufferBytes;
    ENVOY_LOG(warn, "SSE token buffer exceeded {} bytes; dropping {} prefix bytes",
              kMaxTokenStreamBufferBytes, overflow);
    if (overflow < sse_token_stream_buffer_.size()) {
      sse_token_stream_buffer_.erase(0, overflow);
    } else {
      sse_token_stream_buffer_.clear();
    }
  }
  sse_token_stream_buffer_.append(chunk.data(), chunk.size());

  while (true) {
    const size_t sep = sse_token_stream_buffer_.find("\n\n");
    if (sep == std::string::npos) {
      break;
    }
    ENVOY_LOG(debug, "SSE event boundary found, processing event block for tokens (size={})", sep);
    processSseEventForTokens(absl::string_view(sse_token_stream_buffer_.data(), sep));
    sse_token_stream_buffer_.erase(0, sep + 2);
  }

  if (end_stream) {
    if (!sse_token_stream_buffer_.empty()) {
      processSseEventForTokens(absl::string_view(sse_token_stream_buffer_));
      sse_token_stream_buffer_.clear();
    }
    if (auto tail = openai_response_stream_merger_.flush()) {
      const std::string payload = extractSseJsonPayload(*tail);
      if (Json::ObjectSharedPtr obj = parseJsonObjectFromString(payload)) {
        token_usage_accumulator_.ingestJsonObject(*obj);
        creditPendingTokenUsageDelta();
      }
    }
  }
}

// Scans the buffer for a top-level "usage" JSON object and returns it as a
// self-contained JSON string suitable for parsing, e.g. {"prompt_tokens":10,...}.
// Returns empty string if not found or the object is truncated.
static std::string extractUsageObject(absl::string_view buf) {
  // Look for the last occurrence of "usage" or "usageMetadata" to handle SSE-like concatenated bodies.
  size_t key_pos = buf.rfind("\"usage\"");
  size_t gkey_pos = buf.rfind("\"usageMetadata\"");
  
  size_t actual_key_pos = absl::string_view::npos;
  size_t key_len = 0;
  
  if (key_pos != absl::string_view::npos && gkey_pos != absl::string_view::npos) {
    if (key_pos > gkey_pos) {
      actual_key_pos = key_pos;
      key_len = 7;
    } else {
      actual_key_pos = gkey_pos;
      key_len = 15;
    }
  } else if (key_pos != absl::string_view::npos) {
    actual_key_pos = key_pos;
    key_len = 7;
  } else if (gkey_pos != absl::string_view::npos) {
    actual_key_pos = gkey_pos;
    key_len = 15;
  } else {
    return {};
  }

  // Skip past the key, colon, and optional whitespace to find the opening '{'.
  size_t pos = actual_key_pos + key_len;
  while (pos < buf.size() && (buf[pos] == ' ' || buf[pos] == ':' || buf[pos] == '\t')) {
    ++pos;
  }
  if (pos >= buf.size() || buf[pos] != '{') {
    return {};
  }
  
  // Walk forward counting braces to find the matching '}'.
  int depth = 0;
  bool in_string = false;
  bool escape = false;
  const size_t start = pos;
  for (; pos < buf.size(); ++pos) {
    char c = buf[pos];
    if (in_string) {
      if (escape) {
        escape = false;
      } else if (c == '\\') {
        escape = true;
      } else if (c == '"') {
        in_string = false;
      }
    } else {
      if (c == '"') {
        in_string = true;
      } else if (c == '{') {
        ++depth;
      } else if (c == '}') {
        if (--depth == 0) {
          // Wrap in an outer object so TokenUsageAccumulator path prefixes work.
          std::string prefix = (key_len == 7) ? "{\"usage\":" : "{\"usageMetadata\":";
          return absl::StrCat(prefix, buf.substr(start, pos - start + 1), "}");
        }
      }
    }
  }
  return {}; // Truncated — object not yet complete.
}

void RateLimitQuotaFilter::appendJsonBodyForTokens(absl::string_view chunk, bool /*end_stream*/) {
  // Buffer up to the cap; when exceeded, keep the tail because LLM providers
  // place the "usage" object at the end of the response body.
  json_token_response_buffer_.append(chunk.data(), chunk.size());
  if (json_token_response_buffer_.size() > kMaxTokenStreamBufferBytes) {
    json_token_response_buffer_.erase(
        0, json_token_response_buffer_.size() - kMaxTokenStreamBufferBytes);
  }

  // Fast-path bypass: skip expensive parse when no usage keywords present.
  if (!absl::StrContains(json_token_response_buffer_, "usage") &&
      !absl::StrContains(json_token_response_buffer_, "token") &&
      !absl::StrContains(json_token_response_buffer_, "Token")) {
    return;
  }

  // First try extracting just the "usage" sub-object — works even when the
  // full response body is too large to parse as a whole.
  const std::string usage_obj = extractUsageObject(json_token_response_buffer_);
  if (!usage_obj.empty()) {
    if (auto obj = parseJsonObjectFromString(usage_obj)) {
      ENVOY_LOG(debug, "Extracted usage sub-object from JSON buffer (length={})",
                json_token_response_buffer_.size());
      token_usage_accumulator_.ingestJsonObject(*obj);
      creditPendingTokenUsageDelta();
      return;
    }
  }

  // Fallback: attempt full JSON parse (succeeds for small complete responses).
  auto parsed = Json::Factory::loadFromStringNoThrow(json_token_response_buffer_);
  if (parsed.ok() && *parsed != nullptr && (*parsed)->isObject()) {
    ENVOY_LOG(debug, "JSON token buffer parsed successfully (length={}). Extracting tokens...",
              json_token_response_buffer_.size());
    token_usage_accumulator_.ingestJsonObject(**parsed);
    creditPendingTokenUsageDelta();
  } else {
    ENVOY_LOG(trace, "JSON token buffer not yet fully parseable or not an object (length={}).",
              json_token_response_buffer_.size());
  }
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
