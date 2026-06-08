#pragma once
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/time.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/grpc/status.h"
#include "envoy/http/header_map.h"
#include "envoy/server/factory_context.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.h"
#include "envoy/stats/stats.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/thread_local/thread_local_object.h"

#include "source/common/common/logger.h"
#include "source/common/grpc/typed_async_client.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/global_hotspot_tracker.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"

#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

// Multi-tenant deployments wire one GlobalRateLimitClientImpl per listener.
// Without a phase offset, every listener's reporting timer ticks on the same
// boundary the dispatcher started at — at 50 tenants this stacks 50 buildReports
// + 50 sendMessage calls onto the main thread within microseconds of each
// other, producing a periodic CPU spike that scales with tenant count rather
// than total QPS.
//
// firstTickJitter returns a random offset in [0, reporting_interval) used as
// the *first* tick delay; subsequent ticks (scheduled from inside the timer
// callback) run at exactly reporting_interval, so the offset persists for the
// life of the timer without altering long-run cadence. Salting the RNG with
// the timer's address guarantees two listeners constructed on the same
// dispatcher tick land on different phases.
//
// Exposed in the header so unit tests can pin its contract (range, salt
// independence) without spinning up the full client.
std::chrono::milliseconds firstTickJitter(std::chrono::milliseconds reporting_interval, void* salt);

// Main-thread bucket cache soft cap: 0 in proto means default; values are clamped for safety.
constexpr size_t kRateLimitQuotaDefaultMaxBucketCacheEntries = 50000;
constexpr size_t kRateLimitQuotaMaxBucketCacheEntriesCeiling = 10'000'000;

// env: RATELIMIT_QUOTA_MIN_BUCKET_CACHE_ENTRIES
//
// Opt-in floor for the bucket cache cap. When set to a positive integer, the
// filter clamps the effective max upward to at least this many entries,
// regardless of what Pilot pushed via the proto. Designed for large-scale
// deployments (e.g. 250k working set) where the LDS-pushed cap is too small
// to fit the working set, without requiring a Pilot/CRD schema change.
//
// Leaving the variable unset preserves the previous behavior exactly.
// Read once at process start (static local); env mutations after start are
// ignored.
inline size_t rateLimitQuotaBucketCacheMinFloorFromEnv() {
  const char* env = std::getenv("RATELIMIT_QUOTA_MIN_BUCKET_CACHE_ENTRIES");
  if (env == nullptr) {
    return 0;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(env, &end, 10);
  if (end == env || parsed == 0 || (parsed == ULONG_MAX && errno == ERANGE)) {
    return 0;
  }
  return std::min(static_cast<size_t>(parsed), kRateLimitQuotaMaxBucketCacheEntriesCeiling);
}

inline size_t effectiveRateLimitQuotaMaxBucketCacheEntries(uint32_t configured) {
  const size_t effective =
      (configured == 0)
          ? kRateLimitQuotaDefaultMaxBucketCacheEntries
          : std::min(static_cast<size_t>(configured), kRateLimitQuotaMaxBucketCacheEntriesCeiling);
  // Cached on first call so we don't getenv() on every listener load.
  static const size_t min_floor = rateLimitQuotaBucketCacheMinFloorFromEnv();
  return std::max(effective, min_floor);
}

using ::envoy::service::rate_limit_quota_apig::v3::BucketId;
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse;
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports;
using BucketQuotaUsage =
    ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports::BucketQuotaUsage;
using GrpcAsyncClient =
    Grpc::AsyncClient<envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports,
                      envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse>;
using RateLimitQuotaResponsePtr =
    std::unique_ptr<envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse>;
using DenyResponseSettings = ::envoy::extensions::filters::http::rate_limit_quota_apig::v3::
    RateLimitQuotaBucketSettings::DenyResponseSettings;

// Callbacks to trigger when the main thread finishes executing a queued
// operation. Primarily used for testing.
class GlobalRateLimitClientCallbacks {
public:
  virtual ~GlobalRateLimitClientCallbacks() = default;
  virtual void onBucketCreated(const BucketId& bucket_id, size_t id) = 0;
  // Called on success or failure to send the actual message.
  virtual void onUsageReportsSent() = 0;
  virtual void onQuotaResponseProcessed() = 0;
  virtual void onActionExpiration() = 0;
  virtual void onFallbackExpiration() = 0;
  // Called when degradation mode changes for a bucket.
  virtual void onDegradationModeChanged(size_t id, bool degraded) { (void)id; (void)degraded; }
};

// Callback type for synchronous quota check result.
using SyncQuotaCheckResultCallback = std::function<void(bool allowed)>;

// Grpc bidirectional streaming client which handles the communication with
// RLQS server. A pointer to it should go into TLS as it should be referenced by
// worker threads' local RateLimitClients.
//
// Inheritance chain:
//   - Grpc::AsyncStreamCallbacks<...>: gRPC bidi stream callback hooks.
//     Verified at this commit that this base does NOT itself derive from
//     std::enable_shared_from_this — adding our own
//     enable_shared_from_this is unambiguous. If a future Envoy upgrade
//     introduces enable_shared_from_this anywhere on the AsyncStreamCallbacks
//     chain, the resulting "ambiguous base of enable_shared_from_this"
//     compile error must be fixed by switching to a compositional weak-ref
//     wrapper (e.g. a std::weak_ptr<GlobalRateLimitClientImpl> stored on the
//     TlsStore) rather than removing our enable_shared_from_this.
//   - std::enable_shared_from_this: required for scheduleWriteBucketsToTLS's
//     weak_from_this() guard; see the function's comment for the lifetime
//     contract.
//   - Logger::Loggable: standard Envoy logger mixin.
class GlobalRateLimitClientImpl
    : public Grpc::AsyncStreamCallbacks<
          envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse>,
      public std::enable_shared_from_this<GlobalRateLimitClientImpl>,
      public Logger::Loggable<Logger::Id::rate_limit_quota> {
public:
  GlobalRateLimitClientImpl(const Grpc::GrpcServiceConfigWithHashKey& config_with_hash_key,
                            Server::Configuration::FactoryContext& context,
                            absl::string_view domain_name,
                            std::chrono::milliseconds send_reports_interval,
                            ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_tls,
                            Envoy::Event::Dispatcher& main_dispatcher, bool enable_global_hotspot,
                            size_t max_tracked_bucket_hashes,
                            std::chrono::milliseconds hotspot_frequency_window,
                            size_t max_bucket_cache_entries);
  ~GlobalRateLimitClientImpl() override;

  void onReceiveMessage(RateLimitQuotaResponsePtr&& response) override;

  // RawAsyncStreamCallbacks methods;
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}
  void onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&&) override {}
  void onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&&) override {}
  void onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& message) override;

  // Functions needed by LocalRateLimitClientImpl to make unsafe modifications
  // to global resources. All are non-blocking & safely callable by worker
  // threads and make unsafe changes by ensuring that all such changes are done
  // by the main thread. Pointer swaps to TLS make the resources readable to
  // worker threads' LocalRateLimitClientImpl instances.
  void createBucket(const BucketId& bucket_id, size_t id, const BucketAction& default_bucket_action,
                    std::unique_ptr<envoy::type::v3::RateLimitStrategy> fallback_action,
                    std::chrono::milliseconds fallback_ttl, bool initial_request_allowed,
                    const DenyResponseSettings& deny_response_settings);

  // Cold/hot frequency; thread-safe. No-op (returns max) when global hotspot is disabled.
  uint64_t recordHotspotAccess(size_t bucket_id_hash);

  // Report quota usage for a bucket immediately (used for cold path)
  void reportQuotaUsage(const BucketId& bucket_id, const QuotaUsage& usage);

  // Approximate distinct bucket hashes tracked in the global hotspot table (0 if disabled).
  size_t approxGlobalHotspotDistinctTracked() const;

  // Set optional callbacks. Primarily used for testing asynchronous operations.
  // Not thread-safe to call when the client is in-use.
  void setCallbacks(std::unique_ptr<GlobalRateLimitClientCallbacks> callbacks) {
    callbacks_ = std::move(callbacks);
  }

  // setAbandonActionCounter wires the FilterConfig's `abandon_action_received`
  // counter into this global client. The data path increments it from the RLQS
  // response handler (spec § D-6 confirmed-miss → AbandonAction). nullptr is
  // safe — the increment site nil-checks. Set once at factory time.
  void setAbandonActionCounter(Stats::Counter* counter) { abandon_action_counter_ = counter; }

private:
  // Build usage reports (i.e., the request sent to RLQS server) from the
  // buckets in quota bucket cache. If specified, the usage reports will only
  // include the given bucket.
  RateLimitQuotaUsageReports buildReports();
  RateLimitQuotaUsageReports buildReports(std::shared_ptr<CachedBucket> cached_bucket);

  // Helpers to write to TLS.
  //
  // T-EC-08 Top 5 Phase 1 → Phase 2 sharded refactor: instead of deep-copying
  // the entire `BucketsCache` on every publish (O(N) under 5K entries / listener
  // × 50 listener cold-starts), the source-of-truth is split across K shards
  // (`buckets_cache_shards_`). Mutations call `markShardDirty(shard)`; the
  // publisher (`writeBucketsToTLS`) deep-copies only dirty shards and reuses
  // the unchanged shards' shared_ptrs from the prior snapshot. The
  // `bucket_cache_publish_total_` counter still counts whole publishes (one
  // per call to writeBucketsToTLS) — operators see the same frequency signal
  // they had pre-shard, and a follow-on histogram for "shards copied per
  // publish" is what differentiates the cost reduction.
  //
  // Returns the shard index for `bucket_id_hash`. Wrapper around
  // `bucketShardIndex(...)` plus the actual shard count to keep call sites
  // free of `shard_count_` access.
  inline size_t shardOf(size_t bucket_id_hash) const {
    return bucketShardIndex(bucket_id_hash, shard_count_);
  }
  // Mutator-side accessor: returns a non-const reference to the shard map
  // owning the given bucket_id_hash. Only the main thread calls this; the
  // returned reference is invalidated by `writeBucketsToTLS` only in the
  // sense that subsequent reads via the TLS path see the new snapshot — the
  // map itself is the source of truth and persists.
  inline BucketsCache& mutableShardForBucket(size_t bucket_id_hash) {
    return buckets_cache_shards_[shardOf(bucket_id_hash)];
  }
  // Total live bucket count across all shards. O(K), not O(N).
  inline size_t totalBucketsCacheSize() const {
    size_t sum = 0;
    for (const auto& s : buckets_cache_shards_) {
      sum += s.size();
    }
    return sum;
  }
  // Mark a shard as needing republish. Idempotent.
  inline void markShardDirty(size_t shard_idx) { dirty_shards_.insert(shard_idx); }
  // Convenience: mark by bucket_id_hash.
  inline void markShardDirtyForBucket(size_t bucket_id_hash) {
    markShardDirty(shardOf(bucket_id_hash));
  }
  // Mark every shard dirty. Used as a defensive default when the caller
  // doesn't know exactly which shards changed (rare; prefer scoped marks).
  inline void markAllShardsDirty() {
    for (size_t i = 0; i < shard_count_; ++i) {
      dirty_shards_.insert(i);
    }
  }
  // Publish dirty shards to TLS as a single new immutable snapshot. Reuses
  // unchanged shards' shared_ptrs from the prior snapshot — the only deep
  // copy is for shards in `dirty_shards_`. Clears `dirty_shards_` on success.
  // Idempotent / no-op when `dirty_shards_` is empty.
  void writeBucketsToTLS();

  // Debounced publish: coalesces a publish-storm (e.g. cold-start fan-out
  // when 5K routes hit createBucket within the same dispatcher tick) into a
  // single writeBucketsToTLS call at the end of the dispatcher iteration.
  //
  // Mechanism: first call sets `publish_scheduled_` and posts a one-shot
  // closure to the main dispatcher; subsequent calls in the same iteration
  // see the flag and no-op. The posted closure clears the flag and runs
  // writeBucketsToTLS, which iterates dirty_shards_ and snapshots the source
  // of truth as it stands at execution time — picking up every mutation the
  // intervening callbacks queued.
  //
  // Must be called from the main thread (matches writeBucketsToTLS).
  // Production callers should prefer this over the synchronous variant; the
  // sync variant is left in place for code paths that already coalesce
  // multiple mutations within a single callback (e.g. onQuotaResponseImpl
  // walking a many-bucket response, buildReports flushing eviction).
  void scheduleWriteBucketsToTLS();

public:
  // setBucketCachePublishCounter wires the per-publish counter from
  // FilterConfig::stats(). Companion observability hooks (publish-µs
  // histogram, debounce-coalesced counter, dirty-shards-per-publish
  // histogram) are wired by the matching set*() methods below; the
  // bucket-cache-size gauge and max-shard-size gauge remain TODO.
  // nullptr safe.
  void setBucketCachePublishCounter(Stats::Counter* counter) {
    bucket_cache_publish_total_ = counter;
  }

  // setBucketCachePublishHistogram wires the per-publish duration
  // histogram (microseconds). Recorded inside writeBucketsToTLS at the
  // publish boundary so operators can watch the publish-µs distribution
  // post-sharding — the sharded path's promise is sub-ms publish even at
  // 5K bucket / listener; a fat tail here surfaces a regression in the
  // partial-shard reuse path before users notice latency. nullptr safe.
  void setBucketCachePublishHistogram(Stats::Histogram* histogram) {
    bucket_cache_publish_us_ = histogram;
  }

  // setBucketCachePublishCoalescedCounter / setBucketCacheDirtyShardsHistogram
  // wire the publish-debounce hit-rate counter and dirty-shards-per-publish
  // distribution. Together with bucket_cache_publish_total they let
  // operators see (a) whether the debounce is collapsing fan-outs as
  // expected and (b) whether sharding is isolating mutations to a small
  // shard subset. nullptr safe on both sides.
  void setBucketCachePublishCoalescedCounter(Stats::Counter* counter) {
    bucket_cache_publish_coalesced_ = counter;
  }
  void setBucketCacheDirtyShardsHistogram(Stats::Histogram* histogram) {
    bucket_cache_dirty_shards_histogram_ = histogram;
  }

  // Round 3 #1 — buildReports total duration histogram (microseconds).
  // Closes the operability gap where bucket_cache_publish_us only covered
  // writeBucketsToTLS itself (snapshot copy + TLS set, < 100µs typical),
  // missing the ~5K-bucket walk that runs every reporting tick (100ms
  // default). At spec scale the buildReports walk is the largest single
  // main-thread CPU item; without timing data on it operators cannot tell
  // whether a CPU spike is publish (sharding regression) or buildReports
  // (bucket-walk volume). nullptr safe.
  void setBuildReportsUsHistogram(Stats::Histogram* histogram) {
    build_reports_us_ = histogram;
  }

  // Disables the first-tick jitter on the reporting timer. Production paths
  // never call this; it exists for unit tests that drive the timer via
  // MockTimer::invokeCallback and expect the first enableTimer call to use
  // exactly `send_reports_interval`. Long-run cadence is unaffected either
  // way (subsequent fires are always send_reports_interval). Must be called
  // before the first createBucket / startSendReportsTimerImpl invocation;
  // not safe to flip under live traffic.
  void disableFirstTickJitterForTesting() { disable_first_tick_jitter_ = true; }

private:

  // Helpers to execute in the main thread, triggered by public interfaces or by
  // internal flows.
  void createBucketImpl(const BucketId& bucket_id, size_t id,
                        const BucketAction& default_bucket_action,
                        std::unique_ptr<envoy::type::v3::RateLimitStrategy> fallback_action,
                        std::chrono::milliseconds fallback_ttl, bool initial_request_allowed,
                        const DenyResponseSettings& deny_response_settings);
  void sendUsageReportImpl(const RateLimitQuotaUsageReports& reports);
  void onQuotaResponseImpl(const RateLimitQuotaResponse* response);
  bool startStreamImpl();
  // When the send-reports timer triggers, a report should be compiled and sent
  // on the stream. If the stream isn't active (e.g. if aborted by the server),
  // it should be restarted.
  void startSendReportsTimerImpl();
  void onSendReportsTimer();

  // Optional callbacks to run after queued operations finish on the main
  // thread.
  std::unique_ptr<GlobalRateLimitClientCallbacks> callbacks_ = nullptr;

  // Note: the following timer functions do not own cached_bucket and only use
  // the pointer to verify that the targeted bucket is still the one in the
  // source-of-truth before making any changes.

  // Expiration timer starts on the main queue when an action assignment is set
  // for a Bucket, based on the assignment's TTL.
  void startActionExpirationTimer(CachedBucket* cached_bucket, size_t id);
  // Replaces the cached bucket in the source-of-truth with a new bucket. If
  // provided, the new bucket's cached_action is the fallback action of the
  // previous bucket, and the fallback ttl timer starts.
  void onActionExpirationTimer(CachedBucket* cached_bucket, size_t id);
  // Fallback timer starts on the main queue when a cached bucket has its
  // assignment expire & the fallback action has to take over for the duration
  // of its own TTL.
  void startFallbackExpirationTimer(CachedBucket* cached_bucket, size_t id);
  // Replaces the cached bucket in the source-of-truth with a new bucket with
  // its cached_action removed.
  void onFallbackExpirationTimer(CachedBucket* cached_bucket, size_t id);

  // Bucket creation should only attempt stream creation once, and after that
  // all attempts to create / recreate the stream should be handled internally
  // to avoid spam.
  bool stream_tried_by_bucket_creation_ = false;
  // Domain from filter configuration. The same domain name throughout the
  // whole lifetime of client.
  std::string domain_name_;
  // Client is stored as the bare object since there is no ownership transfer
  // involved.
  GrpcAsyncClient async_client_;
  Grpc::AsyncStream<RateLimitQuotaUsageReports> stream_{};

  // Reference to TLS slot for the global quota bucket cache. It outlives
  // the filter.
  ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_tls_;

  // Sharded source-of-truth. shard_count_ is fixed for the lifetime of the
  // client, sourced from rateLimitQuotaBucketCacheShards() at construction
  // time. Mutations and publishes are main-thread only; the mutex around
  // `buckets_cache_` is unnecessary because Envoy's filter design has every
  // mutation posted to the main dispatcher. See the spec § 14.1 / § 16.3.7
  // memory budget revision for the per-listener × per-shard sizing model.
  const size_t shard_count_;
  std::vector<BucketsCache> buckets_cache_shards_;
  // Set of shard indices that have been mutated since the last
  // writeBucketsToTLS. Cleared on publish. The flat_hash_set keeps O(1)
  // dirty-marking on the hot mutator path.
  absl::flat_hash_set<size_t> dirty_shards_;
  // Last published snapshot. Held so that a partial-publish (only dirty
  // shards) can reuse the unchanged shards' shared_ptrs without re-copying.
  // nullptr until the first publish; after that, never null.
  ShardedBucketsCacheConstSharedPtr current_sharded_snapshot_;
  // Debounce flag for scheduleWriteBucketsToTLS. true while a publish
  // closure is queued on the main dispatcher; reset by the closure itself
  // before it runs writeBucketsToTLS. Main-thread-only, no atomic needed.
  bool publish_scheduled_{false};

  std::chrono::milliseconds send_reports_interval_;
  TimeSource& time_source_;
  Envoy::Event::Dispatcher& main_dispatcher_;

  // shared_ptr (not unique): tracker uses enable_shared_from_this to capture
  // a weak_ptr in its main_dispatcher_.post closures, guarding against
  // listener drain between schedule and execution.
  std::shared_ptr<GlobalHotspotTracker> hotspot_tracker_;

  // Upper bound on main-thread bucket map size before aggressive idle eviction (1 min vs 5 min).
  const size_t max_bucket_cache_entries_;

  // Starts when the filter is hit for the first time. From then on, this
  // timer's trigger ensures the health of the RLQS stream & sends aggregated
  // usage reports.
  Event::TimerPtr send_reports_timer_ = nullptr;

  // Timestamp of the last idle-eviction sweep. The eviction check (which iterates
  // all buckets to find idle ones) runs at most once every 10 seconds rather than
  // every reporting tick, reducing O(N) scans to O(dirty) in the common case.
  std::chrono::nanoseconds last_idle_eviction_check_ns_{std::chrono::nanoseconds(0)};

  // Optional FilterConfig::stats().abandon_action_received counter wire-up.
  // nullptr unless config.cc has called setAbandonActionCounter; the response
  // handler nil-checks before incrementing.
  Stats::Counter* abandon_action_counter_{nullptr};

  // T-EC-08 Top 5 Phase 1 — bucket cache publish counter. Wired by
  // setBucketCachePublishCounter from FilterConfig::stats(). The publish-µs
  // histogram and dirty-shards-per-publish histogram below cover the
  // sharded refactor's observability story; the size gauge / max-shard-size
  // gauge remain TODO.
  Stats::Counter* bucket_cache_publish_total_{nullptr};
  // T-EC-08 Phase 2 / B-5 — per-publish duration histogram in microseconds.
  // Wired by setBucketCachePublishHistogram from the FilterConfig scope.
  // nullptr-safe: writeBucketsToTLS skips recording when not wired.
  Stats::Histogram* bucket_cache_publish_us_{nullptr};
  // P2 #9 — debounce hit counter; bumped in scheduleWriteBucketsToTLS
  // when a publish is already pending. nullptr-safe.
  Stats::Counter* bucket_cache_publish_coalesced_{nullptr};
  // P2 #10 — dirty-shards-per-publish distribution; recorded in
  // writeBucketsToTLS before dirty_shards_ is cleared. nullptr-safe.
  Stats::Histogram* bucket_cache_dirty_shards_histogram_{nullptr};
  // Round 3 #1 — buildReports duration histogram (µs). Covers the full
  // bucket walk + per-bucket atomic loads + serialization, which is the
  // dominant main-thread CPU item at 5K-bucket scale.
  Stats::Histogram* build_reports_us_{nullptr};

  // Test-only knob to skip the first-tick reporting-timer jitter. Default
  // false (production); flipped via disableFirstTickJitterForTesting() in
  // unit tests that drive the timer manually with MockTimer::invokeCallback.
  bool disable_first_tick_jitter_{false};
};

/**
 * Create a shared rate limit client. It should be shared to each worker
 * thread via TLS.
 */
inline std::shared_ptr<GlobalRateLimitClientImpl>
createGlobalRateLimitClientImpl(Server::Configuration::FactoryContext& context,
                                absl::string_view domain_name,
                                std::chrono::milliseconds send_reports_interval,
                                ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_tls,
                                Grpc::GrpcServiceConfigWithHashKey& config_with_hash_key,
                                bool enable_global_hotspot, size_t max_tracked_bucket_hashes,
                                std::chrono::milliseconds hotspot_frequency_window,
                                size_t max_bucket_cache_entries) {
  Envoy::Event::Dispatcher& main_dispatcher =
      context.getServerFactoryContext().mainThreadDispatcher();
  return std::make_shared<GlobalRateLimitClientImpl>(
      config_with_hash_key, context, domain_name, send_reports_interval, buckets_tls,
      main_dispatcher, enable_global_hotspot, max_tracked_bucket_hashes,
      hotspot_frequency_window, max_bucket_cache_entries);
}

struct ThreadLocalGlobalRateLimitClientImpl : public Envoy::ThreadLocal::ThreadLocalObject {
public:
  ThreadLocalGlobalRateLimitClientImpl(std::shared_ptr<GlobalRateLimitClientImpl> global_client)
      : global_client(global_client) {}

  // Thread-unsafe operations like index creation should only be done by the
  // global ThreadLocalClient.
  std::shared_ptr<GlobalRateLimitClientImpl> global_client;
};

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
