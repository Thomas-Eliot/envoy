#pragma once
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <utility>
#include <vector>

//#include "envoy/common/token_bucket.h"
#include "envoy/event/dispatcher.h"
#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.h"
#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.validate.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.validate.h"
#include "envoy/thread_local/thread_local_object.h"

//#include "source/common/common/token_bucket_impl.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/token_bucket.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/common/factory_base.h"
#include "absl/container/inlined_vector.h"
#include "absl/hash/hash.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

// Strict-request 100% accuracy mode constants.
namespace strict_request {

// Default deny-cache TTL applied when the SyncCheck path needs to short-
// circuit but the server did not supply (or could not supply, e.g. RPC
// error) a deny_retry_after_ms hint. Capped well below typical quota
// windows so the cache never rots past a flip; long enough to absorb a
// thundering herd inside one round trip.
inline constexpr int64_t kFallbackDenyTtlNs = 100LL * 1'000'000LL; // 100 ms

// Floor on the heartbeat-staleness threshold the global client uses to
// decide a strict bucket has not heard from the server in too long and
// must self-quarantine. Matches the server-side concurrencyHeartbeatTTL
// = max(5s, 3 × T_report) so the data plane is NEVER more aggressive
// than the control plane (which would cause needless over-rejection
// while server still treats the prealloc as live). The runtime threshold
// is max(kHeartbeatStalenessFloorNs, 3 × send_reports_interval_ns).
inline constexpr int64_t kHeartbeatStalenessFloorNs = 5LL * 1'000'000'000LL; // 5 s

}  // namespace strict_request

inline size_t hashBucketId(const ::envoy::service::rate_limit_quota_apig::v3::BucketId& bucket_id) {
  // BucketId.bucket entries are typically 3–6 keys (_tenant, _scope, _dim,
  // plus user dims). Keep the working set on the stack for the common case
  // and reference protobuf storage via string_view to skip the per-request
  // pair-of-string heap allocations the prior std::vector form incurred.
  // bucket_id is a const ref bound at call sites for the duration of the
  // hash, so the views remain valid through sort + HashOf.
  absl::InlinedVector<std::pair<absl::string_view, absl::string_view>, 8> pairs;
  pairs.reserve(bucket_id.bucket().size());
  for (const auto& kv : bucket_id.bucket()) {
    pairs.emplace_back(kv.first, kv.second);
  }
  std::sort(pairs.begin(), pairs.end());
  return absl::HashOf(pairs);
}

using ::envoy::service::rate_limit_quota_apig::v3::BucketId;

// True when the BucketId carries multi-tenant routing keys (_tenant, _scope)
// but no per-dimension `_dim` overlay. In dynamic multi-dim mode these base
// buckets must never be created or heartbeated — only variant buckets
// (with `_dim`) participate in quota enforcement.
inline bool isMultiDimGhostBaseBucket(const BucketId& bucket_id) {
  const auto& m = bucket_id.bucket();
  if (m.find("_dim") != m.end()) {
    return false;
  }
  const auto tenant_it = m.find("_tenant");
  const auto scope_it = m.find("_scope");
  return tenant_it != m.end() && !tenant_it->second.empty() && scope_it != m.end() &&
         !scope_it->second.empty();
}
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports;

using BucketAction = ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse::BucketAction;
using BucketQuotaUsage =
    ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports::BucketQuotaUsage;

using DenyResponseSettings = ::envoy::extensions::filters::http::rate_limit_quota_apig::v3::
    RateLimitQuotaBucketSettings::DenyResponseSettings;

struct QuotaUsage {
  QuotaUsage(uint64_t num_requests_allowed, uint64_t num_requests_denied,
             std::chrono::nanoseconds last_report)
      : num_requests_allowed(num_requests_allowed), num_requests_denied(num_requests_denied),
        last_report(last_report), time_of_last_access(last_report), tokens_consumed(0),
        input_tokens_consumed(0), output_tokens_consumed(0), cached_tokens_consumed(0),
        active_requests(0) {}

  // Requests allowed.
  std::atomic<uint64_t> num_requests_allowed;
  // Requests throttled.
  std::atomic<uint64_t> num_requests_denied;
  // Last report time. Should be visible to worker threads so they can check if
  // reporting timing is going correctly. Should only be updated by main thread.
  std::atomic<std::chrono::nanoseconds> last_report;
  // Last access time of this bucket. Updated on every request.
  std::atomic<std::chrono::nanoseconds> time_of_last_access;
  // Total tokens consumed by requests matching this bucket.
  // Updated from LLM usage responses by the worker threads.
  std::atomic<uint64_t> tokens_consumed;
  // Input tokens consumed.
  std::atomic<uint64_t> input_tokens_consumed;
  // Output tokens consumed.
  std::atomic<uint64_t> output_tokens_consumed;
  // Cached tokens consumed.
  std::atomic<uint64_t> cached_tokens_consumed;
  // Number of currently active requests matching this bucket.
  // Incremented on request start, decremented on request end.
  std::atomic<uint64_t> active_requests;
};

// Degradation information for a bucket. Held via shared_ptr inside CachedBucket
// and shared across all worker TLS snapshots — every field MUST be atomic
// because main mutates the same instance in-place when processing server
// responses (see global_client_impl.cc:onQuotaResponseImpl). A non-atomic
// field would be a latent UB landmine: no race today only because workers
// happen to read just `degraded`/`global_remaining_tokens`, but adding a
// hot-path read of `degradation_threshold` would silently introduce UB.
// Same lens that surfaced the Round 8 token_bucket_limiter race.
struct DegradationState {
  DegradationState() : degraded(false), global_remaining_tokens(0), degradation_threshold(0),
                       strict_request_mode(false) {}
  DegradationState(bool degraded, uint64_t global_remaining, uint64_t threshold)
      : degraded(degraded), global_remaining_tokens(global_remaining),
        degradation_threshold(threshold), strict_request_mode(false) {}

  // Whether the bucket is currently in degraded mode
  std::atomic<bool> degraded;
  // Global remaining tokens (informational)
  std::atomic<uint64_t> global_remaining_tokens;
  // Threshold below which degradation is triggered. Atomic for parity with
  // the other two fields and to keep the worker-readable contract uniform.
  std::atomic<uint64_t> degradation_threshold;
  // Strict request-mode flag. Lives here (not on CachedBucket) because
  // DegradationState is shared across old/new bucket objects via shared_ptr,
  // while CachedBucket is replaced on every Phase 1 response — worker threads
  // holding a stale CachedBucket pointer would miss updates to a per-bucket field.
  std::atomic<bool> strict_request_mode;
};

// This object stores the data for single bucket entry. The usage cache & action
// cache are in separate pointers to enable separate pointer-swapping.
struct CachedBucket {
  CachedBucket(const BucketId& bucket_id, std::shared_ptr<QuotaUsage> quota_usage,
               std::unique_ptr<BucketAction> cached_action,
               std::shared_ptr<envoy::type::v3::RateLimitStrategy> fallback_action,
               std::chrono::milliseconds fallback_ttl, const BucketAction& default_action,
               std::shared_ptr<TokenBucket> token_bucket_limiter,
               const DenyResponseSettings& response_settings,
               std::shared_ptr<DegradationState> degradation_state = nullptr)
      : bucket_id(bucket_id), quota_usage(quota_usage), cached_action(std::move(cached_action)),
        fallback_action(fallback_action), fallback_ttl(fallback_ttl),
        default_action(default_action), token_bucket_limiter(token_bucket_limiter),
        response_settings(response_settings),
        degradation_state(degradation_state ? degradation_state
                                            : std::make_shared<DegradationState>()) {}

  // BucketId object that is associated with this bucket. It is part of the
  // report that is sent to RLQS server.
  BucketId bucket_id;

  // Aggregated usage of the ID'd bucket for the next report cycle.
  std::shared_ptr<QuotaUsage> quota_usage;

  // Cached action from the RLQS server's last response that gave an updated
  // assignment for this ID'd bucket. Can be null if no assignment has been
  // received yet or if the previous assignment has passed its time-to-live.
  std::unique_ptr<BucketAction> cached_action;

  // Set in the bucket config's expired_assignment_behavior, this fallback
  // action has its own TTL and determines behavior after a cached assignment
  // expires. After this action's TTL passes the bucket reverts back to its
  // default_action.
  std::shared_ptr<envoy::type::v3::RateLimitStrategy> fallback_action;
  std::chrono::milliseconds fallback_ttl;
  // Default action defined by the bucket's no_assignment_behavior setting. Used
  // when the bucket is waiting for an assigned action from the RLQS server
  // (e.g. during initial bucket hits & after stale assignments expire).
  BucketAction default_action;

  // Action expiration timer when assignments haven't been sent for this bucket
  // for too long & the current assignment passes its TTL. This triggers a
  // bucket write-operation so the timer triggers and calls back to operations
  // on the main thread (through the global client).
  Envoy::Event::TimerPtr action_expiration_timer = nullptr;
  // Fallback expiration timer for when the cached_action has expired and the
  // fallback_action has its own TTL.
  Envoy::Event::TimerPtr fallback_expiration_timer = nullptr;

  // Rate limiter based on token bucket algorithm. Shared to make a single
  // TokenBucket reusable when copying & pointer-swapping the overall cache.
  std::shared_ptr<TokenBucket> token_bucket_limiter;

  DenyResponseSettings response_settings;

  // Degradation state for this bucket. Shared across TLS copies.
  // When degraded, the filter should use synchronous quota checks.
  std::shared_ptr<DegradationState> degradation_state;

  // deny_until_ns is the wall-clock (monotonic) instant until which any
  // request hitting this bucket is rejected locally without consulting the
  // server. Populated either by a SyncCheck DENY response (via the
  // server-supplied retry_after_ms hint) or by a SyncCheck RPC error in
  // strict mode. Cleared when the server pushes a non-degraded action.
  // 0 == no deny cached.
  //
  // last_ack_ns is the most recent monotonic time at which the global
  // client received any successful response from the server for this
  // bucket. The send-reports timer compares it against now to detect a
  // dead control plane (no acks for ≥ 3 × reporting interval) and self-
  // quarantines the bucket — drops local token_bucket and writes a short
  // deny cache so the data path fails closed instead of silently
  // double-spending an outdated allocation.
  //
  // Both are atomic so the worker hot path can read them lock-free
  // (memory_order_relaxed is sufficient: any over-rejection caused by a
  // stale read is the safe direction).
  //
  // NOTE: strict_request_mode lives on DegradationState (shared_ptr),
  // not here, because CachedBucket is replaced on every Phase 1 response
  // and worker threads holding a stale pointer would miss updates.
  std::atomic<int64_t> deny_until_ns{0};
  std::atomic<int64_t> last_ack_ns{0};
};

/**
 * An interface for a client used in the RateLimitQuotaService (RLQS) filter
 * worker threads to safely access & modify global resources.
 */
class RateLimitClient {
public:
  virtual ~RateLimitClient() = default;

  // Safe creation & getting of global buckets.
  virtual void createBucket(const BucketId& bucket_id, size_t id,
                            const BucketAction& default_bucket_action,
                            std::unique_ptr<envoy::type::v3::RateLimitStrategy> fallback_action,
                            std::chrono::milliseconds fallback_ttl, bool initial_request_allowed,
                            const DenyResponseSettings& deny_response_settings) PURE;
  virtual std::shared_ptr<CachedBucket> getBucket(size_t id) PURE;

  // Remove a cached bucket by hash. Used to evict ghost multi-dim base buckets
  // that were created before the dynamic warm-up path completed.
  virtual void removeBucket(size_t id) PURE;

  // Report quota usage for a bucket immediately (used for cold path)
  virtual void reportQuotaUsage(const BucketId& bucket_id, const QuotaUsage& usage) PURE;

  // Cold/hot split: process-wide request frequency in the configured window. When the global
  // client has no tracker (cold/hot disabled), implementations should return a value large
  // enough to treat the bucket as hot.
  virtual uint64_t recordHotspotAccess(size_t bucket_id_hash) PURE;
};

// shared_ptr<CachedBucket> must be passed around to guarantee the
// CachedBucket's existence for the duration of its use in a local thread after
// getting it via getBucket.
//
// Note on type identity: `BucketsCache` is the *per-shard* map type. The whole
// thread-visible cache is the sharded view (`ShardedBucketsCache`) below.
// Keeping `BucketsCache` as the per-shard alias lets call sites that already
// took an `absl::flat_hash_map<size_t, ...>` reference continue to work after
// the sharding refactor without further churn.
using BucketsCache = absl::flat_hash_map<size_t, std::shared_ptr<CachedBucket>>;

// Sharding constants. The compile-time default is 16 — large enough to drop
// the worst case publish copy from O(N) to O(N/16) under the spec's 50-listener
// target without making per-publish overhead (one shared_ptr swap per shard)
// dominate. Operators can override via the env hook below; the value is read
// once at process start and cached, so post-start mutations are ignored.
//
// The clamp is tight on purpose: K < 4 leaves single-listener cold-starts
// near the original O(N²) curve, K > 64 makes the per-shard ptr array iteration
// in writeBucketsToTLS / buildReports the dominant cost.
constexpr size_t kRateLimitQuotaDefaultBucketCacheShards = 16;
constexpr size_t kRateLimitQuotaMinBucketCacheShards = 4;
constexpr size_t kRateLimitQuotaMaxBucketCacheShards = 64;

inline size_t rateLimitQuotaBucketCacheShardsFromEnv() {
  const char* env = std::getenv("RATELIMIT_QUOTA_BUCKETS_CACHE_SHARDS");
  if (env == nullptr) {
    return kRateLimitQuotaDefaultBucketCacheShards;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(env, &end, 10);
  if (end == env || parsed == 0 || (parsed == ULONG_MAX && errno == ERANGE)) {
    return kRateLimitQuotaDefaultBucketCacheShards;
  }
  return std::min(std::max(static_cast<size_t>(parsed), kRateLimitQuotaMinBucketCacheShards),
                  kRateLimitQuotaMaxBucketCacheShards);
}

inline size_t rateLimitQuotaBucketCacheShards() {
  static const size_t shards = rateLimitQuotaBucketCacheShardsFromEnv();
  return shards;
}

// Maps a bucket id hash to its shard index. Identical hash → identical shard,
// always; this is a contract relied upon by writers (mark dirty on the right
// shard) and readers (look up in the right shard).
inline size_t bucketShardIndex(size_t bucket_id_hash, size_t shard_count) {
  return bucket_id_hash % shard_count;
}

// ShardedBucketsCache is the immutable, worker-visible representation of the
// bucket cache. It's an array of K immutable per-shard map shared_ptrs; a
// publish replaces only the affected shard pointers, leaving unaffected shards
// pinned by the previous snapshot. Workers reading a shard during publish
// continue to see the prior pointer until the TLS slot is updated.
//
// Construction patterns:
//   - empty(K): K shards, each an empty BucketsCache. Used at startup.
//   - vector<shared_ptr> ctor: explicit replacement of all K shards (used when
//     publishing multiple dirty shards in one batch).
//
// Lifetime: published as `std::shared_ptr<const ShardedBucketsCache>` via the
// TLS slot. Workers hold a snapshot pointer for the duration of a request;
// even if main publishes a new snapshot mid-request, the worker's prior
// pointer keeps the shards it observed alive.
class ShardedBucketsCache {
public:
  static std::shared_ptr<const ShardedBucketsCache> empty(size_t shard_count) {
    std::vector<std::shared_ptr<const BucketsCache>> shards;
    shards.reserve(shard_count);
    for (size_t i = 0; i < shard_count; ++i) {
      shards.push_back(std::make_shared<const BucketsCache>());
    }
    return std::make_shared<const ShardedBucketsCache>(std::move(shards));
  }

  explicit ShardedBucketsCache(std::vector<std::shared_ptr<const BucketsCache>> shards)
      : shards_(std::move(shards)) {}

  size_t shardCount() const { return shards_.size(); }

  // Look up the per-shard map for the bucket id hash. Returns the immutable
  // shard map; callers do `shard->find(id)` to get the CachedBucket.
  std::shared_ptr<const BucketsCache> shardForBucket(size_t bucket_id_hash) const {
    return shards_[bucketShardIndex(bucket_id_hash, shards_.size())];
  }

  // Direct shard access by index. Used by the publisher when reusing
  // unchanged shards from a prior snapshot.
  const std::shared_ptr<const BucketsCache>& shardAt(size_t i) const { return shards_[i]; }

  // Total bucket count across all shards. O(K) in shard count, not in entries.
  size_t totalSize() const {
    size_t sum = 0;
    for (const auto& s : shards_) {
      sum += s->size();
    }
    return sum;
  }

private:
  std::vector<std::shared_ptr<const BucketsCache>> shards_;
};

using ShardedBucketsCacheConstSharedPtr = std::shared_ptr<const ShardedBucketsCache>;

class ThreadLocalBucketsCache : public Envoy::ThreadLocal::ThreadLocalObject,
                                Logger::Loggable<Logger::Id::rate_limit_quota> {
public:
  explicit ThreadLocalBucketsCache(ShardedBucketsCacheConstSharedPtr sharded)
      : sharded_(std::move(sharded)) {}

  // Worker read accessor. Returns the immutable sharded snapshot pointer;
  // workers read shards directly via `sharded()->shardForBucket(id)`.
  ShardedBucketsCacheConstSharedPtr sharded() const { return sharded_; }

private:
  ShardedBucketsCacheConstSharedPtr sharded_;
};

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
