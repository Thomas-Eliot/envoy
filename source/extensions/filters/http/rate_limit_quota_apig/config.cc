#include "source/extensions/filters/http/rate_limit_quota_apig/config.h"

#include <chrono>
#include <memory>
#include <utility>

#include "envoy/event/dispatcher.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/http/filter.h"
#include "envoy/http/filter_factory.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/type/v3/ratelimit_strategy.pb.h"

#include "source/extensions/filters/http/rate_limit_quota_apig/client_impl.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/config_discovery_client.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/dynamic_settings_registry.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/filter.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/global_client_impl.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/sync_quota_checker.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

namespace {
// Default cap on distinct bucket id hashes in GlobalHotspotTracker when cold/hot is enabled and
// `max_tracked_buckets` is 0 or unset (proto and API default).
constexpr uint64_t kDefaultMaxTrackedBucketHashes = 10000;
} // namespace

// Object to hold TLS slots after the factory itself has been cleaned up.
struct TlsStore {
  TlsStore(Server::Configuration::FactoryContext& context)
      : global_client_tls(context.getServerFactoryContext().threadLocal()),
        buckets_tls(context.getServerFactoryContext().threadLocal()),
        sync_quota_checker_tls(context.getServerFactoryContext().threadLocal()),
        dynamic_settings_tls(context.getServerFactoryContext().threadLocal()) {}

  ThreadLocal::TypedSlot<ThreadLocalGlobalRateLimitClientImpl> global_client_tls;
  ThreadLocal::TypedSlot<ThreadLocalBucketsCache> buckets_tls;
  ThreadLocal::TypedSlot<ThreadLocalSyncQuotaChecker> sync_quota_checker_tls;
  // Snapshot of per-(tenant, scope) BucketSettings pushed by the server via
  // StreamRlQsConfigs (spec § D-8). Workers read; only the
  // ConfigDiscoveryClient (main thread) writes via DynamicSettingsRegistry.
  ThreadLocal::TypedSlot<DynamicSettingsRegistry::Snapshot> dynamic_settings_tls;
  // Registry + client are owned by the TlsStore so they outlive the factory
  // closure. The registry pins the TLS slot reference; the client pins the
  // gRPC stream + reconnect timer.
  DynamicSettingsRegistrySharedPtr dynamic_registry;
  ConfigDiscoveryClientSharedPtr config_discovery_client;
};

Http::FilterFactoryCb RateLimitQuotaFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaFilterConfig&
        filter_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  // Filter config const object is created on the main thread and shared between
  // worker threads. The listener metadata snapshot (spec § D-1 / § 7) is
  // captured here so the request path can extract tenant IDs from the
  // listener's static metadata without touching dynamicMetadata.
  FilterConfigConstSharedPtr config = std::make_shared<FilterConfig>(
      filter_config, stats_prefix + ".quota", context.scope(), context.getServerFactoryContext(),
      context.listenerMetadata());

  Grpc::GrpcServiceConfigWithHashKey config_with_hash_key =
      Grpc::GrpcServiceConfigWithHashKey(config->config().rlqs_server());

  // Quota bucket & global client TLS objects are created with the config and
  // kept alive via shared_ptr to a storage struct. The local rate limit client
  // in each filter instance assumes that the slot will outlive them.
  std::shared_ptr<TlsStore> tls_store = std::make_shared<TlsStore>(context);
  // All threads share one ThreadLocalBucketsCache instance. The main thread
  // publishes a new sharded snapshot via writeBucketsToTLS() whenever
  // the bucket map changes; workers always access the latest shared snapshot.
  // The initial empty snapshot here is overwritten by the GlobalRateLimitClientImpl
  // constructor's first set, so the shard count below is just a placeholder for
  // the very brief window before the global client is built.
  auto tl_buckets_cache = std::make_shared<ThreadLocalBucketsCache>(
      ShardedBucketsCache::empty(rateLimitQuotaBucketCacheShards()));
  tls_store->buckets_tls.set(
      [tl_buckets_cache]([[maybe_unused]] Envoy::Event::Dispatcher& dispatcher) {
        return tl_buckets_cache;
      });

  // TODO(bsurber): Implement report timing & usage aggregation based on each
  // bucket's reporting_interval field. Currently this is not supported and all
  // usage is reported on a hardcoded interval.
  std::chrono::milliseconds reporting_interval = config->reportingInterval();

  const bool cold_hot_disabled = filter_config.has_cold_hot_config() &&
                                 filter_config.cold_hot_config().disabled();
  // Dynamic-loading mode (rlqs_config_server configured): server pushes
  // BucketSettings via StreamRlQsConfigs, so cold-path sync check overlaps
  // with the discovery path and only adds main-thread load. Force the
  // hotspot tracker off; FilterConfig::coldHotSplitEnabled() applies the
  // same guard so decodeHeaders skips the cold/hot branch as well.
  // `config->isDynamicMode()` is the single source of truth for both
  // gates — see filter.h.
  const bool enable_global_hotspot = !cold_hot_disabled && !config->isDynamicMode();
  uint64_t max_tracked_bucket_hashes = kDefaultMaxTrackedBucketHashes;
  std::chrono::milliseconds hotspot_window(1000);
  if (filter_config.has_cold_hot_config()) {
    const auto& ch = filter_config.cold_hot_config();
    if (ch.max_tracked_buckets() > 0) {
      max_tracked_bucket_hashes = ch.max_tracked_buckets();
    }
    if (ch.has_frequency_window()) {
      // Use duration_cast to avoid int64 overflow from large seconds * 1000.
      const auto& fw = ch.frequency_window();
      auto fw_duration =
          std::chrono::seconds(fw.seconds()) + std::chrono::nanoseconds(fw.nanos());
      hotspot_window = std::chrono::duration_cast<std::chrono::milliseconds>(fw_duration);
      if (hotspot_window.count() <= 0) {
        hotspot_window = std::chrono::milliseconds(1000);
      }
    }
  }

  const size_t max_bucket_cache_entries =
      effectiveRateLimitQuotaMaxBucketCacheEntries(filter_config.max_bucket_cache_entries());

  // Create the global client resource to be shared via TLS to all worker
  // threads (accessed through a filter-specific LocalRateLimitClient).
  auto tl_global_client = std::make_shared<ThreadLocalGlobalRateLimitClientImpl>(
      createGlobalRateLimitClientImpl(context, filter_config.domain(), reporting_interval,
                                      tls_store->buckets_tls, config_with_hash_key,
                                      enable_global_hotspot, max_tracked_bucket_hashes,
                                      hotspot_window, max_bucket_cache_entries));
  // Wire spec § D-6 abandon-action counter into the global client so the data
  // path can record server abandons as they arrive in RLQS responses.
  if (tl_global_client->global_client) {
    tl_global_client->global_client->setAbandonActionCounter(
        &config->stats().abandon_action_received_);
    // T-EC-08 Top 5 Phase 1 — bucket cache publish observability. Phase 2
    // adds the histogram + size gauges alongside the structural sharded
    // refactor; this counter establishes the baseline.
    tl_global_client->global_client->setBucketCachePublishCounter(
        &config->stats().bucket_cache_publish_total_);
    // B-5 publish-µs histogram, eagerly registered on FilterConfig
    // construction so dashboards always see the metric whether or not
    // a publish has fired yet. Pointer wiring (vs. reference) keeps the
    // GlobalRateLimitClientImpl free of Stats coupling.
    tl_global_client->global_client->setBucketCachePublishHistogram(
        &config->bucketCachePublishUsHistogram());
    // P2 #9 #10 — debounce hit counter + dirty-shards histogram. The
    // counter pairs with bucket_cache_publish_total (coalesced /
    // (coalesced + total) = batch ratio). The histogram pairs with the
    // µs histogram (small dirty-shards p50 = sharding works).
    tl_global_client->global_client->setBucketCachePublishCoalescedCounter(
        &config->stats().bucket_cache_publish_coalesced_);
    tl_global_client->global_client->setBucketCacheDirtyShardsHistogram(
        &config->bucketCacheDirtyShardsHistogram());
    // Round 3 #1 — full reporting-tick duration histogram. Closes the
    // operator gap where bucket_cache_publish_us only covered the publish
    // (snapshot copy + TLS set), not the upstream bucket walk.
    tl_global_client->global_client->setBuildReportsUsHistogram(
        &config->buildReportsUsHistogram());
  }
  tls_store->global_client_tls.set(
      [tl_global_client]([[maybe_unused]] Envoy::Event::Dispatcher& dispatcher) {
        return tl_global_client;
      });

  // Create GrpcStreamSyncQuotaChecker for degradation mode (default enabled).
  // The checker uses the same gRPC streaming interface as rlqs_server to send
  // sync check requests to the quota-server.
  // Using TLS to ensure each worker thread has its own checker instance and gRPC stream.
  if (filter_config.has_rlqs_server()) {
    // Pre-create the async client factory on main thread.
    // Use shared_ptr wrapper to allow capture by lambda (unique_ptr cannot be copied).
    auto async_client_factory = std::shared_ptr<Grpc::AsyncClientFactory>(
        context.clusterManager()
            .grpcAsyncClientManager()
            .factoryForGrpcService(config->config().rlqs_server(), context.scope(), true)
            .release());

    // Capture the factory by value (shared_ptr), not the context by reference.
    // This ensures the factory outlives the TLS lambda execution.
    const std::string domain = config->domain();

    tls_store->sync_quota_checker_tls.set(
        [async_client_factory, domain](Envoy::Event::Dispatcher& dispatcher) {
          auto async_client = async_client_factory->createUncachedRawAsyncClient();

          auto checker = std::make_shared<GrpcStreamSyncQuotaChecker>(
              std::move(async_client), domain, dispatcher,
              false // fallback_allow_on_error (fail-close) for strict rate limiting
          );
          return std::make_shared<ThreadLocalSyncQuotaChecker>(checker);
        });
    ENVOY_LOG(info, "GrpcStreamSyncQuotaChecker configured for degradation mode (TLS), domain: {}",
              filter_config.domain());
  } else {
    ENVOY_LOG(debug, "rlqs_server not configured, "
                     "degradation mode will use fallback behavior");
  }

  // Spec § D-8: stand up the RLQS Config Discovery client whenever
  // `rlqs_config_server` is configured. The client runs on the main
  // dispatcher, owns one long-lived bidi stream, and pushes server-side
  // BucketSettings (with per-dim deny_response and bucket_id_builder
  // tags) into the shared DynamicSettingsRegistry that workers read at
  // request time. When the field is unset the filter falls back to its
  // static xDS bucket_matchers — no behavior change vs. pre-Phase-1.
  if (filter_config.has_rlqs_config_server()) {
    tls_store->dynamic_registry = std::make_shared<DynamicSettingsRegistry>(
        tls_store->dynamic_settings_tls,
        &context.getServerFactoryContext().mainThreadDispatcher());
    // T-EC-08 Top 5 Phase 1 — registry publish observability. Counts every
    // snapshot republish so we can measure server-push churn and the COW
    // copy frequency before the Phase 2 sharded refactor lands here. The
    // FilterConfig outlives the TlsStore (shared_ptr captured below), so
    // taking the counter address is safe for the registry's lifetime.
    tls_store->dynamic_registry->setPublishCounter(
        &config->stats().dynamic_registry_publish_total_);
    // Round 2 #B — registry publish-µs histogram, symmetric with the
    // BucketsCache publish-µs histogram. Catches degraded hash
    // distributions where one shard absorbs the long-tail at large
    // (tenant × scope) cardinality.
    tls_store->dynamic_registry->setPublishUsHistogram(
        &config->dynamicRegistryPublishUsHistogram());

    auto config_ds_async_client =
        context.clusterManager()
            .grpcAsyncClientManager()
            .factoryForGrpcService(filter_config.rlqs_config_server(), context.scope(), true)
            ->createUncachedRawAsyncClient();

    auto& main_dispatcher = context.getServerFactoryContext().mainThreadDispatcher();
    tls_store->config_discovery_client = std::make_shared<ConfigDiscoveryClient>(
        std::move(config_ds_async_client), main_dispatcher, tls_store->dynamic_registry);
    // Wire the FilterConfig stats into the discovery client. Without this the
    // 6 config_discovery_* counters declared in filter.h stay at zero —
    // operators have no signal of stream churn or malformed pushes. The
    // FilterConfig outlives the TlsStore (shared_ptr captured below), so
    // taking the address of its counters is safe for the discovery client's
    // lifetime.
    {
      ConfigDiscoveryClientStats ds_stats;
      auto& s = config->stats();
      ds_stats.stream_connect = &s.config_discovery_stream_connect_;
      ds_stats.stream_reconnect = &s.config_discovery_stream_reconnect_;
      ds_stats.response_received = &s.config_discovery_response_received_;
      ds_stats.response_parse_error = &s.config_discovery_response_parse_error_;
      ds_stats.settings_parse_error = &s.config_discovery_settings_parse_error_;
      ds_stats.settings_missing_binding_tag =
          &s.config_discovery_settings_missing_binding_tag_;
      ds_stats.subscription_evicted = &s.config_discovery_subscription_evicted_;
      ds_stats.config_ds_abandon_applied = &s.config_discovery_abandon_applied_;
      tls_store->config_discovery_client->setStats(ds_stats);
    }
    // Defer start() onto the main dispatcher so the stream open runs after
    // the factory closure has returned; this matches how other long-lived
    // clients in this filter (GrpcStreamSyncQuotaChecker) are started on
    // first use.
    auto client_for_post = tls_store->config_discovery_client;
    main_dispatcher.post([client_for_post] { client_for_post->start(); });
    ENVOY_LOG(info, "RateLimitQuotaConfigDiscoveryService client configured (spec § D-8)");
  } else {
    ENVOY_LOG(debug, "rlqs_config_server not configured; using static xDS BucketSettings only");
  }

  return [&context, config = std::move(config), config_with_hash_key,
          tls_store](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    std::unique_ptr<RateLimitClient> local_client =
        createLocalRateLimitClient(tls_store->global_client_tls, tls_store->buckets_tls);

    std::shared_ptr<SyncQuotaChecker> sync_quota_checker = nullptr;
    auto tls_checker_opt = tls_store->sync_quota_checker_tls.get();
    if (tls_checker_opt.has_value()) {
      sync_quota_checker = tls_checker_opt->checker();
    }

    callbacks.addStreamFilter(std::make_shared<RateLimitQuotaFilter>(
        config, context, std::move(local_client), config_with_hash_key, sync_quota_checker,
        tls_store->dynamic_registry, tls_store->config_discovery_client));
  };
}

Router::RouteSpecificFilterConfigConstSharedPtr
RateLimitQuotaFilterFactory::createRouteSpecificFilterConfigTyped(
    const envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaOverride&
        proto_config,
    Server::Configuration::ServerFactoryContext& server_content,
    ProtobufMessage::ValidationVisitor&) {
  return std::make_shared<FilterConfigRoute>(proto_config, server_content);
};

/**
 * Static registration for the filter. @see RegisterFactory.
 */
REGISTER_FACTORY(RateLimitQuotaFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
