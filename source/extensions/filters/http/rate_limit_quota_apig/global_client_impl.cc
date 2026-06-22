#include "source/extensions/filters/http/rate_limit_quota_apig/global_client_impl.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <utility>

#include "envoy/common/exception.h"
#include "envoy/common/time.h"
// #include "envoy/common/token_bucket.h"
#include "envoy/event/dispatcher.h"
#include "envoy/grpc/async_client.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/grpc/status.h"
#include "envoy/http/async_client.h"
#include "envoy/server/factory_context.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/type/v3/ratelimit_strategy.pb.h"
#include "envoy/type/v3/token_bucket.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
// #include "source/common/common/token_bucket_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/time_utils.h"

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

using BucketAction = RateLimitQuotaResponse::BucketAction;
using envoy::type::v3::RateLimitStrategy;

std::shared_ptr<TokenBucket> createTokenBucketFromAction(const RateLimitStrategy& strategy) {
  const auto& token_bucket = strategy.token_bucket();
  // This is a PRE-ALLOCATION model: the quota server atomically assigns the
  // entire share to this Envoy instance for the current window. All allocated
  // tokens are immediately available — there is no gradual fill. Quota accuracy
  // is maintained centrally by the server via atomic Lua scripts; the local
  // bucket is just a fast-path gate to avoid per-request gRPC round-trips.
  return std::make_shared<QuotaTokenBucketImpl>(token_bucket.max_tokens());
}

std::shared_ptr<TokenBucket> createDefaultTokenBucketFromAction(const RateLimitStrategy& strategy,
                                                                TimeSource& time_source) {
  const auto& token_bucket = strategy.token_bucket();

  const auto& interval_proto = token_bucket.fill_interval();
  // Convert absl::duration to int64_t seconds.
  // Clamp to at least 1 second to avoid division by zero for zero or sub-second intervals.
  int64_t fill_interval_sec = absl::ToInt64Seconds(absl::Seconds(interval_proto.seconds()) +
                                                   absl::Nanoseconds(interval_proto.nanos()));
  if (fill_interval_sec <= 0) {
    fill_interval_sec = 1;
    ENVOY_LOG_MISC(warn, "RLQS: fill_interval rounds to 0s; clamped to 1s for token bucket fill rate.");
  }
  double fill_rate_per_sec =
      static_cast<double>(token_bucket.tokens_per_fill().value()) / fill_interval_sec;

  return std::make_shared<AtomicTokenBucketImpl>(token_bucket.max_tokens(), time_source,
                                                 fill_rate_per_sec, token_bucket.max_tokens());
}

GlobalRateLimitClientImpl::GlobalRateLimitClientImpl(
    const Grpc::GrpcServiceConfigWithHashKey& config_with_hash_key,
    Server::Configuration::FactoryContext& context, absl::string_view domain_name,
    std::chrono::milliseconds send_reports_interval,
    Envoy::ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_tls,
    Envoy::Event::Dispatcher& main_dispatcher, bool enable_global_hotspot,
    size_t max_tracked_bucket_hashes, std::chrono::milliseconds hotspot_frequency_window,
    size_t max_bucket_cache_entries, bool suppress_multi_dim_ghost_base_buckets)
    : domain_name_(domain_name), async_client_(context.getServerFactoryContext()
                                                  .clusterManager()
                                                  .grpcAsyncClientManager()
                                                  .getOrCreateRawAsyncClientWithHashKey(
                                                      config_with_hash_key, context.scope(), true)),
      buckets_tls_(buckets_tls), shard_count_(rateLimitQuotaBucketCacheShards()),
      buckets_cache_shards_(shard_count_),
      send_reports_interval_(send_reports_interval),
      time_source_(context.getServerFactoryContext().mainThreadDispatcher().timeSource()),
      main_dispatcher_(main_dispatcher),
      max_bucket_cache_entries_(max_bucket_cache_entries),
      suppress_multi_dim_ghost_base_buckets_(suppress_multi_dim_ghost_base_buckets) {
  if (enable_global_hotspot) {
    hotspot_tracker_ = std::make_shared<GlobalHotspotTracker>(
        main_dispatcher_, context.getServerFactoryContext().threadLocal(),
        time_source_, max_tracked_bucket_hashes, hotspot_frequency_window);
  }
  // Publish the initial empty sharded snapshot so workers reading before the
  // first mutation see a well-formed (empty) cache rather than nullptr.
  current_sharded_snapshot_ = ShardedBucketsCache::empty(shard_count_);
  auto initial_tlc = std::make_shared<ThreadLocalBucketsCache>(current_sharded_snapshot_);
  buckets_tls_.set([initial_tlc](Envoy::Event::Dispatcher&) { return initial_tlc; });
}

GlobalRateLimitClientImpl::~GlobalRateLimitClientImpl() {
  if (stream_ != nullptr) {
    stream_.resetStream();
    stream_ = nullptr;
  }
}

void GlobalRateLimitClientImpl::writeBucketsToTLS() {
  // Cross-component shard-count invariant: writers index via shardOf →
  // bucketShardIndex(hash, shard_count_), readers via
  // ShardedBucketsCache::shardForBucket → bucketShardIndex(hash, shards_.size()).
  // The two MUST agree; if they ever diverge (e.g. a future rolling K change
  // half-applied), inserts and lookups would silently target different
  // shards. Assert at the publish boundary so a regression fails the listener
  // load loudly instead of silently corrupting cache routing.
  if (current_sharded_snapshot_) {
    RELEASE_ASSERT(current_sharded_snapshot_->shardCount() == shard_count_,
                   "RLQS sharded snapshot shard count drifted from configured shard_count_");
  }
  if (dirty_shards_.empty() && current_sharded_snapshot_) {
    return;
  }
  // Capture the publish start time only when the histogram is wired —
  // skips a monotonicTime() call (~30ns) on the hot path when operators
  // haven't asked for the metric. The end-of-publish recordValue is also
  // gated on the same nullptr check below.
  const auto publish_start =
      (bucket_cache_publish_us_ != nullptr) ? time_source_.monotonicTime()
                                            : MonotonicTime{};
  // Build the next sharded snapshot. For each shard:
  //  - if dirty, deep-copy the current source-of-truth shard map
  //  - else, reuse the immutable shared_ptr from the prior snapshot
  // The deep copy is bounded to dirty_shards_.size() shards, which under
  // single-bucket mutations is exactly 1.
  std::vector<std::shared_ptr<const BucketsCache>> next_shards;
  next_shards.reserve(shard_count_);
  for (size_t i = 0; i < shard_count_; ++i) {
    if (dirty_shards_.contains(i) || !current_sharded_snapshot_) {
      next_shards.push_back(std::make_shared<const BucketsCache>(buckets_cache_shards_[i]));
    } else {
      next_shards.push_back(current_sharded_snapshot_->shardAt(i));
    }
  }
  // Record the dirty-shards distribution BEFORE clearing — this is the
  // direct signal of sharding effectiveness. p50 ≈ 1 means single-bucket
  // mutations are isolating to one shard (good); p50 ≈ K means every
  // mutation touches every shard (sharding gives nothing).
  if (bucket_cache_dirty_shards_histogram_ != nullptr) {
    bucket_cache_dirty_shards_histogram_->recordValue(
        static_cast<uint64_t>(dirty_shards_.size()));
  }
  current_sharded_snapshot_ = std::make_shared<const ShardedBucketsCache>(std::move(next_shards));
  dirty_shards_.clear();

  auto tlc = std::make_shared<ThreadLocalBucketsCache>(current_sharded_snapshot_);
  buckets_tls_.set(
      [tlc]([[maybe_unused]] Envoy::Event::Dispatcher& dispatcher) { return tlc; });
  if (bucket_cache_publish_total_ != nullptr) {
    bucket_cache_publish_total_->inc();
  }
  if (bucket_cache_publish_us_ != nullptr) {
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                time_source_.monotonicTime() - publish_start)
                                .count();
    // Histogram values are uint64; chrono::microseconds::count() is signed
    // but the delta is non-negative for monotonic time. Clamp to 0 for
    // defensive coding (e.g. spuriously non-monotonic system clocks under
    // virtualization).
    bucket_cache_publish_us_->recordValue(static_cast<uint64_t>(std::max<int64_t>(0, elapsed_us)));
  }
  ENVOY_LOG(debug, "RLQS buckets cache written to TLS (sharded).");
}

void GlobalRateLimitClientImpl::scheduleWriteBucketsToTLS() {
  // Main-thread contract: `publish_scheduled_` is a non-atomic bool, safe
  // only because all callers are main-thread (createBucketImpl runs via
  // main_dispatcher_.post; the closure below also runs on main). A future
  // worker-thread caller would race the flag, dropping a publish if the
  // closure resets the flag between two near-simultaneous schedules. The
  // assertion catches the regression at the call site instead of as
  // dropped-publish corruption later.
  ENVOY_BUG(main_dispatcher_.isThreadSafe(),
            "scheduleWriteBucketsToTLS must run on the main dispatcher; "
            "publish_scheduled_ is non-atomic by contract");
  if (publish_scheduled_) {
    if (bucket_cache_publish_coalesced_ != nullptr) {
      bucket_cache_publish_coalesced_->inc();
    }
    return;
  }
  publish_scheduled_ = true;
  // weak_from_this guards against a listener-drain race. Every
  // main_dispatcher_.post site in this file uses the same pattern (see
  // reportQuotaUsage, createBucket, onReceiveMessage, onRemoteClose); the
  // caller's pin (worker TLS shared_ptr, gRPC-stream-callback frame) is
  // released the moment the call returns, so any queued-but-unrun closure
  // can outlive `*this` if config update drops the TlsStore. lock() returns
  // null → closure no-ops, vs. `[this]` capture which would dereference
  // freed memory.
  //
  // Re-entry: closure clears `publish_scheduled_` BEFORE invoking
  // writeBucketsToTLS. A re-entrant scheduleWriteBucketsToTLS from inside
  // writeBucketsToTLS (e.g. an eviction-triggered mutation that posts a
  // follow-up publish) will see `publish_scheduled_ == false`, queue a
  // fresh closure, and that closure will correctly capture every shard
  // mutation made during the re-entry — including any from the in-flight
  // writeBucketsToTLS call itself.
  std::weak_ptr<GlobalRateLimitClientImpl> weak = weak_from_this();
  main_dispatcher_.post([weak]() {
    auto self = weak.lock();
    if (!self) {
      return;
    }
    self->publish_scheduled_ = false;
    self->writeBucketsToTLS();
  });
}

uint64_t GlobalRateLimitClientImpl::recordHotspotAccess(size_t bucket_id_hash) {
  if (!hotspot_tracker_) {
    return std::numeric_limits<uint64_t>::max();
  }
  return hotspot_tracker_->recordAccess(bucket_id_hash);
}

size_t GlobalRateLimitClientImpl::approxGlobalHotspotDistinctTracked() const {
  return hotspot_tracker_ ? hotspot_tracker_->approxDistinctTracked() : 0;
}

void getUsageFromBucket(const CachedBucket& cached_bucket, TimeSource& time_source,
                        BucketQuotaUsage& usage) {
  std::shared_ptr<QuotaUsage> cached_usage = cached_bucket.quota_usage;
  *usage.mutable_bucket_id() = cached_bucket.bucket_id;

  std::atomic<uint64_t>& num_requests_allowed = cached_usage->num_requests_allowed;
  std::atomic<uint64_t>& num_requests_denied = cached_usage->num_requests_denied;
  std::atomic<uint64_t>& tokens_consumed = cached_usage->tokens_consumed;
  std::atomic<uint64_t>& input_tokens_consumed = cached_usage->input_tokens_consumed;
  std::atomic<uint64_t>& output_tokens_consumed = cached_usage->output_tokens_consumed;
  std::atomic<uint64_t>& cached_tokens_consumed = cached_usage->cached_tokens_consumed;
  std::atomic<uint64_t>& active_requests = cached_usage->active_requests;

  // Reset usage atomics to 0 and save prior values as request totals (single exchange per field).
  const uint64_t allowed = num_requests_allowed.exchange(0, std::memory_order_relaxed);
  const uint64_t denied = num_requests_denied.exchange(0, std::memory_order_relaxed);
  const uint64_t tokens = tokens_consumed.exchange(0, std::memory_order_relaxed);
  const uint64_t input_tokens = input_tokens_consumed.exchange(0, std::memory_order_relaxed);
  const uint64_t output_tokens = output_tokens_consumed.exchange(0, std::memory_order_relaxed);
  const uint64_t cached_tokens = cached_tokens_consumed.exchange(0, std::memory_order_relaxed);
  
  // For active_requests, we DO NOT reset it to 0 because it's a gauge representing 
  // current in-flight requests. We just read the current value.
  uint64_t active = active_requests.load(std::memory_order_relaxed);

  usage.set_num_requests_allowed(allowed);
  usage.set_num_requests_denied(denied);
  usage.set_tokens_consumed(tokens);
  usage.set_input_tokens_consumed(input_tokens);
  usage.set_output_tokens_consumed(output_tokens);
  usage.set_cached_tokens_consumed(cached_tokens);
  usage.set_active_requests(active);

  // Get the time elapsed since this bucket last went into a usage report.
  std::atomic<std::chrono::nanoseconds>& cached_last_report = cached_usage->last_report;
  const std::chrono::nanoseconds now = nowMonotonicNsTyped(time_source);
  const std::chrono::nanoseconds prev_last_report =
      cached_last_report.exchange(now, std::memory_order_relaxed);

  const int64_t elapsed_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(now - prev_last_report).count();
  if (elapsed_seconds > 0) {
    usage.mutable_time_elapsed()->set_seconds(elapsed_seconds);
  }
}

// Read a specific bucket's aggregated usage & build it into a UsageReports
// message.
RateLimitQuotaUsageReports
GlobalRateLimitClientImpl::buildReports(std::shared_ptr<CachedBucket> cached_bucket) {
  RateLimitQuotaUsageReports report;
  getUsageFromBucket(*cached_bucket, time_source_, *report.add_bucket_quota_usages());

  // Set the domain name.
  report.set_domain(domain_name_);
  ENVOY_LOG(debug, "The bucket-specific usage report that will be sent to RLQS server:\n{}",
            report.DebugString());
  return report;
}

// Read all active buckets' aggregated usage & build them into a UsageReports
// message.
//
// B-7 optimisation: idle-eviction (O(N) full scan) runs at most once every
// 10 seconds.  Per-tick reporting skips buckets that have had no new traffic
// and no active requests since their last report, reducing the common-case
// cost from O(N) to O(dirty_buckets).
RateLimitQuotaUsageReports GlobalRateLimitClientImpl::buildReports() {
  // Round 3 #1 — measure the full reporting-tick cost (bucket walk + atomic
  // loads + proto serialization). At spec scale (5K buckets / 100ms tick)
  // this is the dominant main-thread CPU item; without timing here ops
  // can't disambiguate "buildReports is slow" from "publish is slow".
  // Skip the monotonicTime() call when the histogram isn't wired —
  // matches the bucket_cache_publish_us pattern.
  const auto build_start =
      (build_reports_us_ != nullptr) ? time_source_.monotonicTime() : MonotonicTime{};

  RateLimitQuotaUsageReports report;
  std::chrono::nanoseconds now = nowMonotonicNsTyped(time_source_);

  const size_t max_buckets_limit = max_bucket_cache_entries_;
  const size_t total_size = totalBucketsCacheSize();

  // Idle-eviction sweep runs at most once every 10 s.
  const bool do_idle_check =
      std::chrono::duration_cast<std::chrono::seconds>(now - last_idle_eviction_check_ns_).count() >=
      10;
  if (do_idle_check) {
    last_idle_eviction_check_ns_ = now;
    if (total_size > max_buckets_limit) {
      ENVOY_LOG(warn, "Bucket cache size {} exceeds limit {}, forcing aggressive eviction",
                total_size, max_buckets_limit);
    }
  }

  // If cache is too large, use aggressive 1-minute eviction, else 5-minutes.
  const int eviction_threshold = (total_size > max_buckets_limit) ? 1 : 5;

  // Walk every shard. Eviction is shard-local — only shards with at least one
  // erased entry are marked dirty for republish, so an idle sweep that touches
  // 0 shards costs only one TLS write skip.
  for (size_t shard_idx = 0; shard_idx < shard_count_; ++shard_idx) {
    BucketsCache& shard = buckets_cache_shards_[shard_idx];
    std::vector<uint64_t> keys_to_evict;

    for (auto& [key, cached] : shard) {
      if (suppress_multi_dim_ghost_base_buckets_ &&
          isMultiDimGhostBaseBucket(cached->bucket_id)) {
        continue;
      }

      std::shared_ptr<QuotaUsage> cached_usage = cached->quota_usage;

      // Strict-request heartbeat self-quarantine (INV-9). When the global
      // client has not received an ack for this strict bucket in
      // 3 × reporting_interval — matching the server-side heartbeat eviction
      // window in concurrencyHeartbeatTTL — the local view is unsafe to
      // continue trusting. Drop the local token bucket so the worker hot
      // path falls into the strict deny path; a short deny cache prevents
      // RPC stampede until the next successful response refreshes
      // last_ack_ns. Token / concurrency buckets skip this check (they
      // never set strict_request_mode).
      if (cached->degradation_state &&
          cached->degradation_state->strict_request_mode.load(std::memory_order_relaxed)) {
        const int64_t now_ns = now.count();
        const int64_t last_ack_ns = cached->last_ack_ns.load(std::memory_order_relaxed);
        if (last_ack_ns > 0) {
          const int64_t age_ns = now_ns - last_ack_ns;
          // Fix B: align with server-side concurrencyHeartbeatTTL =
          // max(5s, 3 × T_report). The data plane MUST NOT be more
          // sensitive than the control plane: if filter self-quarantines
          // before server expires the prealloc, the filter rejects locally
          // while server still considers the share live → over-rejection
          // (safe direction, but throws away utilization). Floor at 5s.
          const int64_t three_intervals_ns =
              static_cast<int64_t>(send_reports_interval_.count()) * 3LL * 1'000'000LL;
          const int64_t heartbeat_threshold_ns =
              std::max(three_intervals_ns, strict_request::kHeartbeatStalenessFloorNs);
          if (age_ns > heartbeat_threshold_ns && cached->token_bucket_limiter) {
            ENVOY_LOG(warn,
                      "Strict-request bucket {} self-quarantining after stale "
                      "ack ({} ms > {} ms threshold); dropping local token bucket",
                      cached->bucket_id.ShortDebugString(), age_ns / 1'000'000,
                      heartbeat_threshold_ns / 1'000'000);
            // COW replacement, NOT in-place mutation. Workers hold the same
            // CachedBucket via TLS snapshot shared_ptrs; an in-place
            // `cached->token_bucket_limiter = nullptr` is a non-atomic
            // shared_ptr write racing the worker's hot-path read in
            // shouldAllowRequest — UB regardless of memory order on the
            // adjacent atomic deny_until_ns store. The COW + markShardDirty
            // pattern matches every other CachedBucket replacement in this
            // file (server-push response, expiration timer, etc.).
            //
            // Existing timers on `cached` stay alive (still owned by the
            // soon-to-be-detached old CachedBucket); when they fire, the
            // shard.get() != bucket check at onActionExpirationTimer turns
            // them into a no-op. The next successful server response
            // re-creates the bucket + timers from scratch, so no
            // expiration is "leaked" — losing the timer is exactly the
            // intended self-quarantine semantic.
            auto new_bucket = std::make_shared<CachedBucket>(
                /*bucket_id=*/cached->bucket_id,
                /*quota_usage=*/cached->quota_usage,
                /*cached_action=*/cached->cached_action
                    ? std::make_unique<BucketAction>(*cached->cached_action)
                    : nullptr,
                /*fallback_action=*/cached->fallback_action,
                /*fallback_ttl=*/cached->fallback_ttl,
                /*default_action=*/cached->default_action,
                /*token_bucket_limiter=*/nullptr,
                /*response_settings=*/cached->response_settings,
                /*degradation_state=*/cached->degradation_state);
            new_bucket->last_ack_ns.store(
                cached->last_ack_ns.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
            new_bucket->deny_until_ns.store(now_ns + strict_request::kFallbackDenyTtlNs,
                                            std::memory_order_relaxed);
            shard[key] = std::move(new_bucket);
            markShardDirty(shard_idx);
          }
        }
      }

      std::chrono::nanoseconds last_access =
          cached_usage->time_of_last_access.load(std::memory_order_relaxed);
      std::chrono::nanoseconds last_reported =
          cached_usage->last_report.load(std::memory_order_relaxed);
      uint64_t active = cached_usage->active_requests.load(std::memory_order_relaxed);
      bool needs_heartbeat =
          std::chrono::duration_cast<std::chrono::seconds>(now - last_reported).count() > 10;

      // Idle-eviction check (slow path, every 10 s).
      if (do_idle_check) {
        int idle_minutes =
            std::chrono::duration_cast<std::chrono::minutes>(now - last_access).count();
        if (idle_minutes >= eviction_threshold && active == 0) {
          ENVOY_LOG(info, "Evicting idle bucket due to inactivity ({} mins): {}",
                    idle_minutes, cached->bucket_id.ShortDebugString());

          // Flush any pending usage before evicting.
          if (cached_usage->tokens_consumed.load(std::memory_order_relaxed) > 0 ||
              cached_usage->input_tokens_consumed.load(std::memory_order_relaxed) > 0 ||
              cached_usage->output_tokens_consumed.load(std::memory_order_relaxed) > 0 ||
              cached_usage->cached_tokens_consumed.load(std::memory_order_relaxed) > 0 ||
              cached_usage->num_requests_allowed.load(std::memory_order_relaxed) > 0 ||
              cached_usage->num_requests_denied.load(std::memory_order_relaxed) > 0) {
            auto* usage = report.add_bucket_quota_usages();
            getUsageFromBucket(*cached, time_source_, *usage);
          }

          keys_to_evict.push_back(key);
          continue;
        }
      }

      // Fast-path skip: no new traffic and no active requests since last report.
      // The heartbeat guard ensures we still send an occasional keep-alive.
      if (!needs_heartbeat && last_access <= last_reported && active == 0) {
        continue;
      }

      // Delta/Dirty reporting: only send when there is something to report.
      uint64_t allowed = cached_usage->num_requests_allowed.load(std::memory_order_relaxed);
      uint64_t denied = cached_usage->num_requests_denied.load(std::memory_order_relaxed);
      uint64_t consumed = cached_usage->tokens_consumed.load(std::memory_order_relaxed);
      uint64_t input_consumed = cached_usage->input_tokens_consumed.load(std::memory_order_relaxed);
      uint64_t output_consumed =
          cached_usage->output_tokens_consumed.load(std::memory_order_relaxed);
      uint64_t cached_consumed =
          cached_usage->cached_tokens_consumed.load(std::memory_order_relaxed);

      if (allowed > 0 || denied > 0 || consumed > 0 || input_consumed > 0 ||
          output_consumed > 0 || cached_consumed > 0 || active > 0 || needs_heartbeat) {
        auto* usage = report.add_bucket_quota_usages();
        getUsageFromBucket(*cached, time_source_, *usage);
      }
    }

    // Erase evicted buckets in this shard and mark it dirty for republish.
    if (!keys_to_evict.empty()) {
      for (uint64_t key : keys_to_evict) {
        shard.erase(key);
      }
      markShardDirty(shard_idx);
    }
  }

  // Single publish covering whatever shards changed; no-op when nothing was
  // evicted (the common steady-state path).
  writeBucketsToTLS();

  // Set the domain name.
  report.set_domain(domain_name_);
  // Record after writeBucketsToTLS so the histogram captures the publish
  // cost too — operators see the full reporting-tick CPU. The publish
  // itself is also captured by bucket_cache_publish_us (subset metric)
  // for shard-level diagnosis.
  if (build_reports_us_ != nullptr) {
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                time_source_.monotonicTime() - build_start)
                                .count();
    build_reports_us_->recordValue(static_cast<uint64_t>(std::max<int64_t>(0, elapsed_us)));
  }
  return report;
}

void GlobalRateLimitClientImpl::reportQuotaUsage(const BucketId& bucket_id, const QuotaUsage& usage) {
  uint64_t allowed = usage.num_requests_allowed.load(std::memory_order_relaxed);
  uint64_t denied = usage.num_requests_denied.load(std::memory_order_relaxed);
  uint64_t tokens = usage.tokens_consumed.load(std::memory_order_relaxed);
  uint64_t input = usage.input_tokens_consumed.load(std::memory_order_relaxed);
  uint64_t output = usage.output_tokens_consumed.load(std::memory_order_relaxed);
  uint64_t cached = usage.cached_tokens_consumed.load(std::memory_order_relaxed);
  
  if (allowed == 0 && denied == 0 && tokens == 0 && input == 0 && output == 0 && cached == 0) {
    return;
  }

  // weak_from_this guards the post against listener drain: caller's
  // shared_ptr (via TLS slot) is dropped the moment this method returns,
  // so a queued-but-unrun closure can outlive `*this` if config update
  // races the post. lock() returns null → closure no-ops.
  std::weak_ptr<GlobalRateLimitClientImpl> weak = weak_from_this();
  main_dispatcher_.post([weak, bucket_id, allowed, denied, tokens, input, output, cached]() {
    auto self = weak.lock();
    if (!self) {
      return;
    }

    const size_t id = hashBucketId(bucket_id);
    BucketsCache& shard = self->mutableShardForBucket(id);
    if (shard.find(id) == shard.end()) {
      ENVOY_LOG(debug, "Skipping async report for evicted bucket: {}",
                bucket_id.ShortDebugString());
      return;
    }

    RateLimitQuotaUsageReports report;
    report.set_domain(self->domain_name_);
    auto* bucket_usage = report.add_bucket_quota_usages();
    *bucket_usage->mutable_bucket_id() = bucket_id;

    bucket_usage->set_num_requests_allowed(allowed);
    bucket_usage->set_num_requests_denied(denied);
    bucket_usage->set_tokens_consumed(tokens);
    bucket_usage->set_input_tokens_consumed(input);
    bucket_usage->set_output_tokens_consumed(output);
    bucket_usage->set_cached_tokens_consumed(cached);

    bucket_usage->mutable_time_elapsed()->set_seconds(0);
    // Use 2ms to differentiate from SyncCheck (which uses 1ns/1ms).
    // The Go server uses <= 1000000 (1ms) to identify SyncCheck.
    // By using 2000000 (2ms), it will be treated as an ASYNC_REPORT.
    bucket_usage->mutable_time_elapsed()->set_nanos(2000000);

    self->sendUsageReportImpl(report);
  });
}

void GlobalRateLimitClientImpl::removeBucket(size_t id) {
  std::weak_ptr<GlobalRateLimitClientImpl> weak = weak_from_this();
  main_dispatcher_.post([weak, id]() {
    if (auto self = weak.lock()) {
      self->removeBucketImpl(id);
    }
  });
}

void GlobalRateLimitClientImpl::removeBucketImpl(size_t id) {
  BucketsCache& shard = mutableShardForBucket(id);
  auto it = shard.find(id);
  if (it == shard.end()) {
    return;
  }
  if (!isMultiDimGhostBaseBucket(it->second->bucket_id)) {
    ENVOY_LOG(debug, "removeBucketImpl skipped non-ghost bucket {}",
              it->second->bucket_id.ShortDebugString());
    return;
  }
  ENVOY_LOG(info, "Evicting ghost multi-dim base bucket {}",
            it->second->bucket_id.ShortDebugString());
  const size_t shard_idx = shardOf(id);
  shard.erase(it);
  markShardDirty(shard_idx);
  scheduleWriteBucketsToTLS();
}

void GlobalRateLimitClientImpl::createBucket(const BucketId& bucket_id, size_t id,
                                             const BucketAction& default_bucket_action,
                                             std::unique_ptr<RateLimitStrategy> fallback_action,
                                             std::chrono::milliseconds fallback_ttl,
                                             bool initial_request_allowed,
                                             const DenyResponseSettings& deny_response_settings) {
  // Mutable to move fallback_action ownership into the main thread then into
  // the created bucket. weak_from_this guards against listener drain: the
  // caller's TLS shared_ptr drops on return, so the queued closure may
  // outlive `*this`. lock() returns null → closure no-ops.
  std::weak_ptr<GlobalRateLimitClientImpl> weak = weak_from_this();
  main_dispatcher_.post([weak, bucket_id, id, default_bucket_action,
                         fallback_action_ptr = std::move(fallback_action), fallback_ttl,
                         initial_request_allowed, deny_response_settings]() mutable {
    if (auto self = weak.lock()) {
      self->createBucketImpl(bucket_id, id, default_bucket_action,
                             std::move(fallback_action_ptr), fallback_ttl,
                             initial_request_allowed, deny_response_settings);
    }
  });
}

void GlobalRateLimitClientImpl::createBucketImpl(
    const BucketId& bucket_id, size_t id, const BucketAction& default_bucket_action,
    std::unique_ptr<RateLimitStrategy> fallback_action, std::chrono::milliseconds fallback_ttl,
    bool initial_request_allowed, const DenyResponseSettings& deny_response_settings) {
  if (suppress_multi_dim_ghost_base_buckets_ && isMultiDimGhostBaseBucket(bucket_id)) {
    ENVOY_LOG(warn, "Refusing to create ghost multi-dim base bucket {}",
              bucket_id.ShortDebugString());
    return;
  }

  // On the first createBucket call (so the first time a bucket is hit in the
  // RLQS filter), start the stream & reporting timer.
  if (!stream_tried_by_bucket_creation_) {
    stream_tried_by_bucket_creation_ = true;
    startSendReportsTimerImpl();
    if (startStreamImpl()) {
      ENVOY_LOG(info, "RLQS stream started successfully.");
    } else {
      ENVOY_LOG(error, "RLQS stream failed to start. Usage collection will continue "
                       "regardless while reattempting to open the stream.");
    }
  }

  // If multiple createBucket calls were posted before the bucket was pushed to
  // TLS, just increment the appropriate usage counter.
  BucketsCache& shard = mutableShardForBucket(id);
  if (auto bucket_it = shard.find(id); bucket_it != shard.end()) {
    // The bucket and underlying QuotaUsage in the source-of-truth should never
    // be null. If there's a bug that creates null entries, then this will
    // crash.
    std::shared_ptr<CachedBucket> bucket = bucket_it->second;
    std::shared_ptr<QuotaUsage> quota_usage = bucket->quota_usage;

    // Increment num_requests_(allowed|denied) based on the allow/deny choice
    // already made by the calling filter.
    std::atomic<uint64_t>& num_requests =
        (initial_request_allowed ? quota_usage->num_requests_allowed
                                 : quota_usage->num_requests_denied);
    num_requests.fetch_add(1, std::memory_order_relaxed);
    return;
  }

  // Create new bucket and add it into the source-of-truth then pointer-swap
  // with the BucketsCache already in TLS. Start the QuotaUsage at 1
  // request to count the request that was allowed/denied before calling to
  // CreateBucket. Default the bucket's action assignment to the configured
  // no_assignment_behavior.
  std::chrono::nanoseconds now = nowMonotonicNsTyped(time_source_);

  RateLimitStrategy default_fallback_action =
      fallback_action ? *fallback_action : RateLimitStrategy();

  if (default_bucket_action.has_quota_assignment_action() &&
      default_bucket_action.quota_assignment_action().has_rate_limit_strategy()) {
    default_fallback_action = default_bucket_action.quota_assignment_action().rate_limit_strategy();
  }

  std::shared_ptr<TokenBucket> new_token_bucket =
      createDefaultTokenBucketFromAction(default_fallback_action, time_source_);

  ENVOY_LOG(debug, "Creating new bucket: bucket={} hash={}", bucket_id.ShortDebugString(), id);

  // Create degradation state for the new bucket
  auto degradation_state = std::make_shared<DegradationState>();

  std::shared_ptr<CachedBucket> new_bucket = std::make_shared<CachedBucket>(
      bucket_id,
      std::make_shared<QuotaUsage>(initial_request_allowed, !initial_request_allowed, now), nullptr,
      std::move(fallback_action), fallback_ttl, default_bucket_action, new_token_bucket,
      deny_response_settings, degradation_state);
  shard[id] = new_bucket;
  markShardDirtyForBucket(id);

  // Send initial usage report only if the stream is already open. If the stream
  // is down the initial request count (seeded to 1 above) stays in the atomic
  // and will be included in the next periodic report cycle instead.
  if (stream_ != nullptr) {
    RateLimitQuotaUsageReports initial_report = buildReports(new_bucket);
    sendUsageReportImpl(initial_report);
  }

  // Debounce the publish: a 5K-route cold start posts createBucketImpl 5K
  // times to the main dispatcher; coalescing them onto a single publish at
  // the end of the iteration drops the per-publish copy cost from O(N²/K) to
  // O(N) (one publish, deep-copies only dirty shards). The synchronous
  // writeBucketsToTLS contract is preserved for callers that already
  // coalesce internally (response handler, eviction sweep, expiration
  // timers).
  scheduleWriteBucketsToTLS();
  if (callbacks_)
    callbacks_->onBucketCreated(new_bucket->bucket_id, id);
}

// This helper function reads from the current usage caches & sends the
// resulting reports message over the stream.
void GlobalRateLimitClientImpl::sendUsageReportImpl(const RateLimitQuotaUsageReports& reports) {
  if (stream_ == nullptr) {
    ENVOY_LOG(debug, "The RLQS stream is not currently open. Attempting to start / restart it now.");
    if (!startStreamImpl()) {
      ENVOY_LOG(error, "Failed to start the RLQS stream. Dropping the collected usage reports.");
      return;
    }
  }
  stream_->sendMessage(reports, /*end_stream=*/false);
}

bool actionHasTokenBucket(BucketAction* bucket_action) {
  return (bucket_action && bucket_action->has_quota_assignment_action() &&
          bucket_action->quota_assignment_action().has_rate_limit_strategy() &&
          bucket_action->quota_assignment_action().rate_limit_strategy().has_token_bucket());
}

// Check if TokenBuckets are deeply equal.
bool protoTokenBucketsEq(const ::envoy::type::v3::TokenBucket& new_tb,
                         const ::envoy::type::v3::TokenBucket& old_tb) {
  return (new_tb.max_tokens() == old_tb.max_tokens() &&
          new_tb.tokens_per_fill().value() == old_tb.tokens_per_fill().value() &&
          new_tb.fill_interval().seconds() == old_tb.fill_interval().seconds() &&
          new_tb.fill_interval().nanos() == old_tb.fill_interval().nanos());
}

void GlobalRateLimitClientImpl::onReceiveMessage(RateLimitQuotaResponsePtr&& response) {
  if (!response)
    return;
  // weak_from_this guards the post against listener drain. While the gRPC
  // stream callback that brought us here implies `*this` is alive AT
  // CALLBACK TIME, the actual processing is deferred onto main_dispatcher_
  // — and a config-update could destruct `*this` before that closure runs.
  // Replaces the previous `[&, ...]` ref-capture which both implied unsafe
  // sharing and was easy to misread (it does capture `this` by value, but
  // syntactically looks like a ref-only capture).
  std::weak_ptr<GlobalRateLimitClientImpl> weak = weak_from_this();
  main_dispatcher_.post([weak, response = std::move(response)]() {
    if (auto self = weak.lock()) {
      self->onQuotaResponseImpl(response.get());
    }
  });
}

// Updating a cached_bucket shouldn't reset the cached token bucket if the
// existing token bucket rate_limit_strategy matches the new one.
bool shouldReplaceTokenBucket(const CachedBucket* cached_bucket,
                              const RateLimitStrategy& token_bucket_strategy) {
  return (!actionHasTokenBucket(cached_bucket->cached_action.get()) ||
          !protoTokenBucketsEq(token_bucket_strategy.token_bucket(),
                               cached_bucket->cached_action->quota_assignment_action()
                                   .rate_limit_strategy()
                                   .token_bucket()));
}

void GlobalRateLimitClientImpl::onQuotaResponseImpl(const RateLimitQuotaResponse* response) {
  ENVOY_LOG(debug, "The response that is received from RLQS server:\n{}", response->DebugString());

  for (const auto& action : response->bucket_action()) {
    if (!action.has_bucket_id() || action.bucket_id().bucket().empty()) {
      ENVOY_LOG(error,
                "Received an RLQS response, but a bucket is missing its id. "
                "Complete response: {}",
                response->ShortDebugString());
      continue;
    }

    // Get the hash id value from BucketId in the response.
    const size_t bucket_id = hashBucketId(action.bucket_id());
    BucketsCache& shard = mutableShardForBucket(bucket_id);
    auto bucket_it = shard.find(bucket_id);
    if (bucket_it == shard.end()) {
      // The response should be matched to the report we sent.
      ENVOY_LOG(error,
                "Received a response, but it includes an unexpected bucket "
                "that isn't present in the bucket cache. ID: {}. From response: {}",
                action.bucket_id().ShortDebugString(), response->ShortDebugString());
      continue;
    }
    // Indexed bucket in the source-of-truth cache. The indexed shared_ptr
    // should never be null. If it is null due to a bug, this will crash.
    std::shared_ptr<CachedBucket> cached_bucket = bucket_it->second;

    // Process degradation information if present
    std::shared_ptr<DegradationState> degradation_state = cached_bucket->degradation_state;
    if (!degradation_state) {
      degradation_state = std::make_shared<DegradationState>();
    }

    bool degradation_changed = false;
    bool strict_request_mode = false;
    uint32_t deny_retry_after_ms = 0;
    if (action.has_quota_assignment_action() &&
        action.quota_assignment_action().has_degradation_info()) {
      const auto& degradation_info = action.quota_assignment_action().degradation_info();
      bool was_degraded = degradation_state->degraded.load(std::memory_order_relaxed);
      bool is_degraded = degradation_info.degraded();

      degradation_state->degraded.store(is_degraded, std::memory_order_release);
      degradation_state->global_remaining_tokens.store(
          degradation_info.global_remaining_tokens(), std::memory_order_relaxed);
      degradation_state->degradation_threshold.store(degradation_info.degradation_threshold(),
                                                     std::memory_order_relaxed);

      // Strict-request mode flags. The server only sets strict_request_mode
      // on the request dimension; for token / concurrency it stays false and
      // the legacy code path below runs unchanged.
      strict_request_mode = degradation_info.strict_request_mode();
      deny_retry_after_ms = degradation_info.deny_retry_after_ms();

      degradation_changed = (was_degraded != is_degraded);

      if (degradation_changed) {
        ENVOY_LOG(info, "Bucket {} degradation mode changed: {} -> {}, "
                        "global_remaining: {}, threshold: {}, strict: {}, retry_after_ms: {}",
                  action.bucket_id().ShortDebugString(), was_degraded, is_degraded,
                  degradation_info.global_remaining_tokens(),
                  degradation_info.degradation_threshold(),
                  strict_request_mode, deny_retry_after_ms);
      }
    }

    // T-EC-08 D-2/D-7: per-action deny_response override. When the server
    // enforces a multi-dimension route, it sets
    // BucketAction.bucket_settings.deny_response_settings to the override
    // for the dimension that actually triggered the deny. We swap that into
    // the cached response_settings so the next sendDenyResponse call
    // returns the right HTTP status / headers / body for the triggering
    // dimension. When the field is unset (single-dim, or server didn't
    // override), the cached single-dim value is preserved.
    auto effective_response_settings = cached_bucket->response_settings;
    if (action.has_bucket_settings() &&
        action.bucket_settings().has_deny_response_settings()) {
      effective_response_settings = action.bucket_settings().deny_response_settings();
    }

    // Create a new bucket from the copy-able fields of the cached bucket.
    // Timers & old action are intentionally not carried over.
    std::shared_ptr<CachedBucket> bucket = std::make_shared<CachedBucket>(
        /*bucket_id=*/cached_bucket->bucket_id,
        /*quota_usage=*/cached_bucket->quota_usage,
        /*cached_action=*/std::make_unique<BucketAction>(action),
        /*fallback_action=*/cached_bucket->fallback_action,
        /*fallback_ttl=*/cached_bucket->fallback_ttl,
        /*default_action=*/cached_bucket->default_action,
        /*token_bucket_limiter=*/nullptr,
        /*response_settings=*/effective_response_settings,
        /*degradation_state=*/degradation_state);

    // Translate `quota_assignment_action` to a TokenBucket or a blanket
    // assignment as appropriate.
    if (action.has_quota_assignment_action()) {
      if (action.quota_assignment_action().has_concurrency_limit()) {
        ENVOY_LOG(debug, "Received concurrency limit assignment for bucket {}: {}", 
                  bucket_id, action.quota_assignment_action().concurrency_limit().limit());
        // Concurrency limit doesn't use a token bucket. The limit is checked directly in the filter.
        bucket->token_bucket_limiter = nullptr;
      } else {
        const auto& rate_limit_strategy = action.quota_assignment_action().rate_limit_strategy();
        switch (rate_limit_strategy.strategy_case()) {
        case RateLimitStrategy::kBlanketRule:
          // No additional processing needed.
          break;
        case RateLimitStrategy::kTokenBucket: {
          // Determine if we need to create a new TokenBucket:
          // 1. No existing limiter (e.g., exiting from degradation mode)
          // 2. Configuration changed (different TokenBucket settings)
          // 3. Token count mismatch (server assigned different quota)
          bool need_new_bucket = false;
          std::string reason;

          if (!cached_bucket->token_bucket_limiter) {
            // No existing limiter - must create new one
            // This happens when exiting degradation mode or first assignment
            need_new_bucket = true;
            reason = "no_existing_limiter";
          } else if (shouldReplaceTokenBucket(cached_bucket.get(), rate_limit_strategy)) {
            // TokenBucket proto configuration changed - rebuild required.
            // Note: do NOT compare remainingTokens() against max_tokens() here.
            // remainingTokens() is the dynamically-computed available token count and is
            // strictly <= max_tokens after any consumption; using it as a rebuild trigger
            // would discard the bucket's accumulated state on every server response.
            need_new_bucket = true;
            reason = "config_changed";
          }

          if (need_new_bucket) {
            bucket->token_bucket_limiter = createTokenBucketFromAction(rate_limit_strategy);
            // Log at info only when the bucket is first created (exiting degradation
            // or first assignment). Preallocation rebalances fire every reporting
            // interval and are too noisy at info level.
            if (reason == "no_existing_limiter") {
              ENVOY_LOG(info,
                        "TokenBucket created for bucket={} max_tokens={}",
                        action.bucket_id().ShortDebugString(),
                        rate_limit_strategy.token_bucket().max_tokens());
            } else {
              ENVOY_LOG(debug,
                        "TokenBucket rebalanced for bucket={} reason={} max_tokens={}",
                        action.bucket_id().ShortDebugString(), reason,
                        rate_limit_strategy.token_bucket().max_tokens());
            }
          } else {
            bucket->token_bucket_limiter = cached_bucket->token_bucket_limiter;
            ENVOY_LOG(debug,
                      "The TokenBucket for id: {} is carried over during "
                      "response processing as the assignment hasn't changed.",
                      bucket_id);
          }

          break;
        }
        case RateLimitStrategy::kRequestsPerTimeUnit:
          ENVOY_LOG(error, "RequestsPerTimeUnit rate limit strategies are not yet "
                           "supported in RLQS.");
          continue;
        case RateLimitStrategy::STRATEGY_NOT_SET:
          // When degradation mode is enabled, an empty rate_limit_strategy is valid.
          // The system will use synchronous rate limiting instead of local token bucket.
          if (action.quota_assignment_action().has_degradation_info() &&
              action.quota_assignment_action().degradation_info().degraded()) {
            // Preserve existing token bucket limiter for fallback if available
            if (cached_bucket->token_bucket_limiter) {
              bucket->token_bucket_limiter = cached_bucket->token_bucket_limiter;
              ENVOY_LOG(debug,
                        "Bucket {} in degraded mode with empty rate_limit_strategy. "
                        "Using synchronous rate limiting. Preserved existing token bucket limiter.",
                        bucket_id);
            } else {
              ENVOY_LOG(debug,
                        "Bucket {} in degraded mode with empty rate_limit_strategy. "
                        "Using synchronous rate limiting.",
                        bucket_id);
            }
            break;
          }
          // If not in degradation mode, empty strategy is an error
          ENVOY_LOG(error, "Unexpected rate limit strategy in RLQS response: {}", bucket_id);
          continue;
        }
      }
    } else if (action.has_abandon_action()) {
      shard.erase(bucket_id);
      markShardDirtyForBucket(bucket_id);
      // Spec § D-6: server signals "no policy for this BucketId" via abandon
      // (data path) or confirmed-miss-omission (Config DS). The data-path
      // counter measures how often the server is rejecting BucketIds the
      // filter sent — a high rate suggests stale binding routes / scoping
      // mismatch between filter and server.
      if (abandon_action_counter_ != nullptr) {
        abandon_action_counter_->inc();
      }
      ENVOY_LOG(debug, "Cached bucket wiped by abandon action for bucket id: {}.", bucket_id);
      continue;
    }

    // 100% accuracy mode: when the server has flipped this bucket to
    // strict_request_mode + degraded, the local token bucket MUST be dropped
    // (INV-2). Otherwise, residual tokens in the local bucket would be
    // consumed in addition to the SyncCheck-allowed traffic, leaking past
    // max_quota. For non-strict (token / concurrency) buckets, leave the
    // existing assignment logic above untouched.
    if (strict_request_mode &&
        degradation_state->degraded.load(std::memory_order_relaxed)) {
      bucket->token_bucket_limiter = nullptr;
    }

    // Mirror the strict flag onto the cached bucket so the worker hot path
    // can read it without re-parsing the cached_action proto. Atomic write
    // pairs with the relaxed load in shouldAllowRequest's prologue.
    degradation_state->strict_request_mode.store(strict_request_mode, std::memory_order_relaxed);

    // Successful response observed for this bucket: refresh the heartbeat
    // timestamp used by the send-reports timer for self-quarantine (INV-9).
    // A non-decreasing monotonic clock is fine here; relaxed ordering is
    // sufficient because over-rejection is the safe direction if the read
    // side observes a slightly stale value.
    bucket->last_ack_ns.store(nowMonotonicNs(time_source_), std::memory_order_relaxed);

    // Strict mode: when transitioning out of degraded (was=true, is=false),
    // clear any locally cached deny so the next request hits the server
    // promptly to learn the new allocation. When transitioning IN to
    // degraded with a server-supplied retry_after_ms hint, prime the cache
    // so the immediately-following requests fail closed without RPC. These
    // behaviors only apply to strict_request_mode buckets — token /
    // concurrency are unaffected.
    if (strict_request_mode) {
      const bool now_degraded = degradation_state->degraded.load(std::memory_order_relaxed);
      if (!now_degraded) {
        bucket->deny_until_ns.store(0, std::memory_order_relaxed);
      } else if (deny_retry_after_ms > 0) {
        bucket->deny_until_ns.store(
            nowMonotonicNs(time_source_) +
                static_cast<int64_t>(deny_retry_after_ms) * 1'000'000LL,
            std::memory_order_relaxed);
      }
    }

    // Set the source of truth to the new bucket.
    shard[bucket_id] = bucket;
    markShardDirtyForBucket(bucket_id);

    // Start the expiration timer for the newly set action based on the its TTL.
    startActionExpirationTimer(bucket.get(), bucket_id);

    // Log and notify callbacks if degradation mode changed
    if (degradation_changed) {
      bool is_degraded = degradation_state->degraded.load(std::memory_order_relaxed);
      if (is_degraded) {
        ENVOY_LOG(info, "ENTERING degradation mode for bucket={}, "
                        "global_remaining: {}, threshold: {}",
                  cached_bucket->bucket_id.ShortDebugString(),
                  degradation_state->global_remaining_tokens.load(std::memory_order_relaxed),
                  degradation_state->degradation_threshold.load(std::memory_order_relaxed));
      } else {
        ENVOY_LOG(info, "EXITING degradation mode for bucket={}, "
                        "global_remaining: {}, threshold: {}, "
                        "TokenBucket will be recreated with new quota from server",
                  cached_bucket->bucket_id.ShortDebugString(),
                  degradation_state->global_remaining_tokens.load(std::memory_order_relaxed),
                  degradation_state->degradation_threshold.load(std::memory_order_relaxed));
      }

      if (callbacks_) {
        callbacks_->onDegradationModeChanged(bucket_id, is_degraded);
      }
    }

    // When entering degradation mode, immediately flush local usage to ensure
    // the quota-server has accurate global state for synchronous checks.
    // This prevents the race condition where local tokens consumed but not yet
    // reported could cause over-quota in synchronous mode.
    if (degradation_changed && degradation_state->degraded.load(std::memory_order_relaxed)) {
      ENVOY_LOG(info, "Entering degradation mode for bucket={}, flushing local usage immediately",
                cached_bucket->bucket_id.ShortDebugString());
      RateLimitQuotaUsageReports immediate_report = buildReports(bucket);
      sendUsageReportImpl(immediate_report);
    }
  }

  // Publish the updated source-of-truth to all threads.
  writeBucketsToTLS();

  if (callbacks_)
    callbacks_->onQuotaResponseProcessed();
}

void GlobalRateLimitClientImpl::onRemoteClose(Grpc::Status::GrpcStatus status,
                                              const std::string& message) {
  // weak_from_this guards the post against listener drain. The
  // (gRPC-callback-time → main-post-time) gap can span a config update
  // that destructs `*this`; without the guard, lock() vs `[this]` is the
  // difference between a counter-bumped no-op and a UAF.
  std::weak_ptr<GlobalRateLimitClientImpl> weak = weak_from_this();
  main_dispatcher_.post([weak, status, message]() {
    if (auto self = weak.lock()) {
      ENVOY_LOG(debug, "gRPC stream closed remotely with status {}: {}", status, message);
      self->stream_ = nullptr;
    }
  });
}

bool GlobalRateLimitClientImpl::startStreamImpl() {
  // Starts stream if it has not been opened yet.
  if (stream_ == nullptr) {
    ENVOY_LOG(debug, "Trying to start the new gRPC stream");
    stream_ = async_client_.start(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
                                     "envoy.service.rate_limit_quota_apig.v3.RateLimitQuotaService."
                                     "StreamRateLimitQuotas"),
                                 *this, Http::AsyncClient::RequestOptions());
  }
  // Returns error status if start failed (i.e., stream_ is nullptr).
  return (stream_ != nullptr);
}

std::chrono::milliseconds
firstTickJitter(std::chrono::milliseconds reporting_interval, void* salt) {
  if (reporting_interval <= std::chrono::milliseconds::zero()) {
    return std::chrono::milliseconds::zero();
  }
  static thread_local std::mt19937 rng{std::random_device{}()};
  const int64_t range = std::max<int64_t>(1, reporting_interval.count() - 1);
  std::uniform_int_distribution<int64_t> dist(0, range);
  // Mix the salt (timer address) into the output rather than re-seeding the
  // RNG, which would destroy mt19937's statistical properties.
  const int64_t base = dist(rng);
  const int64_t salt_mix = static_cast<int64_t>(
      reinterpret_cast<uintptr_t>(salt) % static_cast<uint64_t>(range + 1));
  return std::chrono::milliseconds((base + salt_mix) % (range + 1));
}

void GlobalRateLimitClientImpl::startSendReportsTimerImpl() {
  if (send_reports_timer_)
    return;
  ENVOY_LOG(debug, "Start the usage reporting timer for the RLQS stream.");
  send_reports_timer_ = main_dispatcher_.createTimer([&]() {
    onSendReportsTimer();
    if (callbacks_)
      callbacks_->onUsageReportsSent();
    send_reports_timer_->enableTimer(send_reports_interval_);
  });
  // First tick fires at a random phase in [0, send_reports_interval) so that
  // 50 listeners' timers don't pile up on the same dispatcher tick. After
  // the first fire the cadence is exactly send_reports_interval. Jitter is
  // skipped when disable_first_tick_jitter_ is true (set by tests that
  // depend on a deterministic first-fire delay).
  const auto first_delay = disable_first_tick_jitter_
                               ? send_reports_interval_
                               : firstTickJitter(send_reports_interval_,
                                                 send_reports_timer_.get());
  ENVOY_LOG(debug,
            "RLQS reporting timer scheduled with first-tick phase offset {} ms (interval {} ms)",
            first_delay.count(), send_reports_interval_.count());
  send_reports_timer_->enableTimer(first_delay);
}

void GlobalRateLimitClientImpl::onSendReportsTimer() {
  // buildReports() must run (even when the cache is empty) so idle-bucket eviction
  // in buildReports() can run. Do not send a domain-only report when there are no
  // bucket quota entries.
  RateLimitQuotaUsageReports reports = buildReports();
  if (stream_ == nullptr) {
    ENVOY_LOG(debug, "The RLQS stream is not currently open. Attempting to start / "
                     "restart it now.");
    if (!startStreamImpl()) {
      ENVOY_LOG(error, "Failed to start the RLQS stream. Dropping the collected usage "
                       "reports.");
      return;
    }
  }
  if (reports.bucket_quota_usages().empty()) {
    ENVOY_LOG(debug, "Skipping empty usage report for domain: {}", reports.domain());
    return;
  }
  ENVOY_LOG(debug, "The usage report that will be sent to RLQS server:\n{}", reports.DebugString());
  sendUsageReportImpl(reports);
}

void GlobalRateLimitClientImpl::startActionExpirationTimer(CachedBucket* cached_bucket, size_t id) {
  // Pointer safety as all writes are against the source-of-truth.
  cached_bucket->action_expiration_timer = main_dispatcher_.createTimer([&, id, cached_bucket]() {
    onActionExpirationTimer(cached_bucket, id);
    if (callbacks_)
      callbacks_->onActionExpiration();
  });
  const auto& attl = cached_bucket->cached_action->quota_assignment_action().assignment_time_to_live();
  // Include both seconds and nanos so that sub-second TTLs are respected.
  // A zero-or-negative result is clamped to 1ms to avoid an immediate re-fire.
  auto ttl_duration = std::chrono::seconds(attl.seconds()) + std::chrono::nanoseconds(attl.nanos());
  std::chrono::milliseconds ttl = std::chrono::duration_cast<std::chrono::milliseconds>(ttl_duration);
  if (ttl.count() <= 0) {
    ttl = std::chrono::milliseconds(1);
    ENVOY_LOG(warn, "RLQS: assignment_time_to_live is zero or negative; clamped to 1ms.");
  }
  cached_bucket->action_expiration_timer->enableTimer(ttl);
}

void GlobalRateLimitClientImpl::onActionExpirationTimer(CachedBucket* bucket, size_t id) {
  // Find index of the cached bucket in the source-of-truth.
  BucketsCache& shard = mutableShardForBucket(id);
  auto bucket_it = shard.find(id);
  if (bucket_it == shard.end() || bucket_it->second.get() != bucket) {
    // The bucket has been deleted while this was queued.
    return;
  }
  std::shared_ptr<CachedBucket> cached_bucket = bucket_it->second;

  // Lease fencing for concurrency buckets: when the server assignment
  // expires, freeze the concurrency limit to the current active_requests
  // count instead of falling back to default_action (which may be
  // ALLOW_ALL). This prevents burst admission during server unavailability.
  if (cached_bucket->cached_action &&
      cached_bucket->cached_action->has_quota_assignment_action() &&
      cached_bucket->cached_action->quota_assignment_action().has_concurrency_limit()) {
    uint64_t current_active =
        cached_bucket->quota_usage->active_requests.load(std::memory_order_relaxed);

    ENVOY_LOG(info,
              "RLQS: Concurrency lease expired for bucket {}, self-fencing "
              "limit to current active_requests={}",
              id, current_active);

    // Build a new action with concurrency_limit frozen to current_active.
    // No NEW requests can be admitted but existing in-flight requests can
    // complete and decrement the counter.
    std::unique_ptr<BucketAction> fenced_action = std::make_unique<BucketAction>();
    fenced_action->mutable_quota_assignment_action()
        ->mutable_concurrency_limit()
        ->set_limit(current_active);

    shard[id] = std::make_shared<CachedBucket>(
        /*bucket_id=*/cached_bucket->bucket_id,
        /*quota_usage=*/cached_bucket->quota_usage,
        /*cached_action=*/std::move(fenced_action),
        /*fallback_action=*/cached_bucket->fallback_action,
        /*fallback_ttl=*/cached_bucket->fallback_ttl,
        /*default_action=*/cached_bucket->default_action,
        /*token_bucket_limiter=*/nullptr,
        /*response_settings=*/cached_bucket->response_settings,
        /*degradation_state=*/cached_bucket->degradation_state);
    markShardDirtyForBucket(id);
    writeBucketsToTLS();
    return;
  }

  // Without a fallback action, the cached action will be deleted and the bucket
  // will revert to its default action.
  if (!cached_bucket->fallback_action) {
    ENVOY_LOG(debug,
              "No fallback action is configured for bucket id {}, reverting to "
              "its default action.",
              id);

    RateLimitStrategy default_fallback_action;
    if (cached_bucket->default_action.has_quota_assignment_action() &&
        cached_bucket->default_action.quota_assignment_action().has_rate_limit_strategy()) {
      default_fallback_action =
          cached_bucket->default_action.quota_assignment_action().rate_limit_strategy();
    }

    std::shared_ptr<TokenBucket> new_token_bucket =
        createDefaultTokenBucketFromAction(default_fallback_action, time_source_);
    shard[id] = std::make_shared<CachedBucket>(
        /*bucket_id=*/cached_bucket->bucket_id,
        /*quota_usage=*/cached_bucket->quota_usage,
        /*cached_action=*/nullptr,
        /*fallback_action=*/cached_bucket->fallback_action,
        /*fallback_ttl=*/cached_bucket->fallback_ttl,
        /*default_action=*/cached_bucket->default_action,
        /*token_bucket_limiter=*/new_token_bucket,
        /*response_settings=*/cached_bucket->response_settings,
        /*degradation_state=*/cached_bucket->degradation_state);
    markShardDirtyForBucket(id);
    writeBucketsToTLS();
    return;
  }

  ENVOY_LOG(debug, "The cached action for a bucket has expired, reverting to the "
                   "configured fallback action.");
  const auto& fallback_action = *cached_bucket->fallback_action;

  // Fallback to the configured fallback action.
  std::unique_ptr<BucketAction> new_action = std::make_unique<BucketAction>();
  new_action->mutable_quota_assignment_action()->mutable_rate_limit_strategy()->MergeFrom(
      fallback_action);

  // Handle fallback to a TokenBucket if given.
  std::shared_ptr<TokenBucket> new_token_bucket = nullptr;
  if (fallback_action.has_token_bucket() &&
      shouldReplaceTokenBucket(cached_bucket.get(), fallback_action)) {
    ENVOY_LOG(debug,
              "The cached token bucket at bucket id {} has been replaced by "
              "the configured fallback token bucket.",
              id);
    new_token_bucket = createDefaultTokenBucketFromAction(fallback_action, time_source_);
  } else if (fallback_action.has_token_bucket()) {
    ENVOY_LOG(debug,
              "The cached token bucket at bucket id {} is carrying over during "
              "fallback.",
              id);
    new_token_bucket = cached_bucket->token_bucket_limiter;
  } // else not a TokenBucket fallback so leave the new token bucket null.

  // Build the new cached bucket from the fallback action and new token bucket.
  std::shared_ptr<CachedBucket> new_bucket = std::make_shared<CachedBucket>(
      /*bucket_id=*/cached_bucket->bucket_id,
      /*quota_usage=*/cached_bucket->quota_usage,
      /*cached_action=*/std::move(new_action),
      /*fallback_action=*/cached_bucket->fallback_action,
      /*fallback_ttl=*/cached_bucket->fallback_ttl,
      /*default_action=*/cached_bucket->default_action,
      /*token_bucket_limiter=*/new_token_bucket,
      /*response_settings=*/cached_bucket->response_settings,
      /*degradation_state=*/cached_bucket->degradation_state);
  shard[id] = new_bucket;
  markShardDirtyForBucket(id);
  // Start the fallback ttl timer for the new bucket.
  startFallbackExpirationTimer(new_bucket.get(), id);
  writeBucketsToTLS();
}

// Start a timer for the duration of the fallback action's TTL.
void GlobalRateLimitClientImpl::startFallbackExpirationTimer(CachedBucket* cached_bucket,
                                                             size_t id) {
  // Pointer safety as all writes are against the source-of-truth.
  cached_bucket->fallback_expiration_timer = main_dispatcher_.createTimer([&, id, cached_bucket]() {
    onFallbackExpirationTimer(cached_bucket, id);
    if (callbacks_)
      callbacks_->onFallbackExpiration();
  });
  cached_bucket->fallback_expiration_timer->enableTimer(cached_bucket->fallback_ttl);
}

void GlobalRateLimitClientImpl::onFallbackExpirationTimer(CachedBucket* bucket, size_t id) {
  // Find index of the cached bucket in the source-of-truth.
  BucketsCache& shard = mutableShardForBucket(id);
  auto bucket_it = shard.find(id);
  if (bucket_it == shard.end() || bucket_it->second.get() != bucket) {
    // The bucket has been deleted while this was queued.
    return;
  }
  std::shared_ptr<CachedBucket> cached_bucket = bucket_it->second;

  // Once the fallback action expires, the next step is to fallback to the
  // no_assignment_behavior, so do not set a cached action.
  ENVOY_LOG(debug, "The fallback action for a bucket has expired, reverting to "
                   "the default action.");

  const auto& fallback_action = cached_bucket->default_action;

  RateLimitStrategy rate_limit_strategy =
      (fallback_action.has_quota_assignment_action())
          ? fallback_action.quota_assignment_action().rate_limit_strategy()
          : RateLimitStrategy();

  // Handle fallback to a TokenBucket if given.
  std::shared_ptr<TokenBucket> new_token_bucket =
      createDefaultTokenBucketFromAction(rate_limit_strategy, time_source_);

  // Build the new cached bucket from the fallback action and new token bucket.
  std::shared_ptr<CachedBucket> new_bucket = std::make_shared<CachedBucket>(
      /*bucket_id=*/cached_bucket->bucket_id,
      /*quota_usage=*/cached_bucket->quota_usage,
      /*cached_action=*/nullptr,
      /*fallback_action=*/cached_bucket->fallback_action,
      /*fallback_ttl=*/cached_bucket->fallback_ttl,
      /*default_action=*/cached_bucket->default_action,
      /*token_bucket_limiter=*/new_token_bucket,
      /*response_settings=*/cached_bucket->response_settings,
      /*degradation_state=*/cached_bucket->degradation_state);
  shard[id] = new_bucket;
  markShardDirtyForBucket(id);
  writeBucketsToTLS();
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
