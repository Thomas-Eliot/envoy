#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "envoy/common/time.h"
#include "envoy/event/dispatcher.h"
#include "envoy/thread_local/thread_local.h"

#include "absl/container/flat_hash_map.h"

#include "source/common/common/assert.h"
#include "source/common/common/non_copyable.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/time_utils.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

// Process-wide sliding-window frequency counter for cold/hot bucket promotion.
// Worker hot path is lock-free: each bucket's counter and window-start live as
// per-entry std::atomic, and the entry-id → entry map is published via a TLS
// COW snapshot. New (un-cached) bucket ids are registered asynchronously on
// the main dispatcher; the first hits return 1 optimistically until the
// snapshot is republished, which is fine for hotspot detection (delayed
// warm-up by at most a couple of dispatcher ticks — the time the worker's
// own dispatcher takes to pump the TLS update).
//
// Publish coalescing: registerOnMain inserts into main_entries_ and SCHEDULES
// a single publish via a one-shot main_dispatcher_.post when no publish is
// already pending. A burst of N distinct cold-start registers therefore pays
// only ONE map copy + TLS set, instead of N — bounding main-thread CPU under
// config storms. Mirrors `GlobalRateLimitClientImpl::scheduleWriteBucketsToTLS`.
//
// LRU eviction also runs on main — when a register would exceed max_tracked,
// main scans `main_entries_` for the oldest `last_access_ns` and erases it.
// O(N) per eviction is acceptable because evictions only fire at the cap and
// main isn't on the per-request hot path.
//
// Mirrors the rest of the apig fork's "shared atomic + TLS COW + main-thread
// post" pattern — same design family as `GlobalRateLimitClientImpl::
// buckets_cache_shards_` and `DynamicSettingsRegistry`.
//
// Counts across a window roll are best-effort: a worker that loses the CAS
// claiming the new window may briefly fetch_add on the old (non-yet-reset)
// count. The losing increment is dropped when the winner's count.store(1)
// races in. This is intentional — hotspot detection only needs an order-
// of-magnitude estimate, and adding cross-counter ordering would defeat
// the lock-free design.
struct HotspotEntry {
  // Hits within the current window. Reset to 1 by the CAS-winning worker
  // when the window rolls.
  std::atomic<uint64_t> count{0};
  // Monotonic-ns timestamp marking the start of the current window. Worker
  // CAS this to claim the window roll.
  std::atomic<int64_t> window_start_ns{0};
  // Updated on each access; consulted by main for LRU eviction. Relaxed
  // because LRU is approximate (we evict the entry with the smallest
  // observed last_access at eviction time).
  std::atomic<int64_t> last_access_ns{0};
};

struct HotspotSnapshot : public ThreadLocal::ThreadLocalObject {
  // The map is shared (immutable) across all worker copies of the snapshot;
  // each `set()` call publishes a fresh shared_ptr. Entries themselves are
  // shared_ptr<HotspotEntry> so a republish doesn't invalidate live atomic
  // operations on already-known entries.
  using EntriesMap = absl::flat_hash_map<size_t, std::shared_ptr<HotspotEntry>>;
  std::shared_ptr<const EntriesMap> entries;
};

// enable_shared_from_this is load-bearing: posts to main_dispatcher_ outlive
// the tracker if the parent listener's TlsStore drops between the post and
// the dispatcher iteration that runs it. weak_from_this() captured by the
// closure resurrects a strong ref iff the tracker is still alive — otherwise
// the closure is a no-op. Mirrors GlobalRateLimitClientImpl's pattern; the
// tracker has the same lifetime hazard because it lives behind the same
// TLS-released ownership chain.
class GlobalHotspotTracker : public std::enable_shared_from_this<GlobalHotspotTracker>,
                             NonCopyable {
public:
  GlobalHotspotTracker(Event::Dispatcher& main_dispatcher,
                       ThreadLocal::SlotAllocator& tls_allocator,
                       TimeSource& time_source, size_t max_tracked,
                       std::chrono::milliseconds window_size)
      : main_dispatcher_(main_dispatcher), tls_slot_(tls_allocator),
        time_source_(time_source),
        window_size_ns_(std::chrono::duration_cast<std::chrono::nanoseconds>(window_size).count()),
        max_tracked_(std::max<size_t>(1, max_tracked)) {
    // Publish initial empty snapshot so worker reads before the first
    // register return well-defined empty (snap.has_value() == true, but
    // entries empty).
    auto empty_map = std::make_shared<HotspotSnapshot::EntriesMap>();
    auto initial = std::make_shared<HotspotSnapshot>();
    initial->entries = empty_map;
    tls_slot_.set([initial]([[maybe_unused]] Event::Dispatcher&) { return initial; });
  }

  // Worker-callable. Lock-free fast path: TLS lookup + atomic CAS/fetch_add.
  // Returns the post-increment hit count for this bucket within its current
  // window, or 1 if the bucket is being registered for the first time.
  uint64_t recordAccess(size_t bucket_id) {
    auto snap_opt = tls_slot_.get();
    if (!snap_opt.has_value() || snap_opt->entries == nullptr) {
      return 1;
    }
    const auto& entries = *snap_opt->entries;
    auto it = entries.find(bucket_id);
    if (it != entries.end()) {
      HotspotEntry& e = *it->second;
      const int64_t now_ns = nowMonotonicNs(time_source_);
      e.last_access_ns.store(now_ns, std::memory_order_relaxed);

      int64_t old_start = e.window_start_ns.load(std::memory_order_relaxed);
      // Window rolled: try CAS to claim the reset. On success the winner sets
      // count=1; losers fall through and fetch_add against the new window.
      if (now_ns - old_start > window_size_ns_) {
        if (e.window_start_ns.compare_exchange_strong(old_start, now_ns,
                                                      std::memory_order_relaxed)) {
          e.count.store(1, std::memory_order_relaxed);
          return 1;
        }
        // Lost the CAS — another worker already rolled; just count.
      }
      return e.count.fetch_add(1, std::memory_order_relaxed) + 1;
    }
    // Unknown bucket: post register to main and return 1 optimistically.
    // Subsequent requests within the same window will hit the snapshot once
    // main has run the register and the worker's dispatcher has pumped its
    // TLS update — typically within a couple of ticks under load.
    // weak_from_this guards the post against listener-drain: the tracker may
    // be destroyed between scheduling and execution if the TlsStore drops.
    std::weak_ptr<GlobalHotspotTracker> weak = weak_from_this();
    main_dispatcher_.post([weak, bucket_id]() {
      if (auto self = weak.lock()) {
        self->registerOnMain(bucket_id);
      }
    });
    return 1;
  }

  size_t approxDistinctTracked() const {
    return approx_distinct_tracked_.load(std::memory_order_relaxed);
  }

private:
  void registerOnMain(size_t bucket_id) {
    // ENVOY_BUG (not ASSERT) so a regression that calls this off-main is
    // surfaced as a counter increment + log line in release builds —
    // main_entries_ has no synchronization, so a real off-main caller would
    // be a silent data race otherwise.
    ENVOY_BUG(main_dispatcher_.isThreadSafe(),
              "GlobalHotspotTracker::registerOnMain must run on main");
    // Dedup: another worker's post may have arrived first; treat as no-op.
    if (main_entries_.contains(bucket_id)) {
      return;
    }
    if (main_entries_.size() >= max_tracked_) {
      evictOldestOnMain();
    }
    auto entry = std::make_shared<HotspotEntry>();
    const int64_t now_ns = nowMonotonicNs(time_source_);
    entry->count.store(1, std::memory_order_relaxed);
    entry->window_start_ns.store(now_ns, std::memory_order_relaxed);
    entry->last_access_ns.store(now_ns, std::memory_order_relaxed);
    main_entries_.emplace(bucket_id, std::move(entry));
    approx_distinct_tracked_.fetch_add(1, std::memory_order_relaxed);
    schedulePublish();
  }

  // Linear-scan O(N) eviction. Acceptable because eviction only fires at the
  // cap (rare); main is not on the per-request hot path. A more sophisticated
  // LRU would require a side list maintained by main on every access — but
  // workers don't notify main on access, so the side list would lag the real
  // LRU anyway. Direct scan over `last_access_ns` (which workers DO update)
  // is the simplest correct approach.
  void evictOldestOnMain() {
    if (main_entries_.empty()) {
      return;
    }
    auto oldest = main_entries_.begin();
    int64_t oldest_ts = oldest->second->last_access_ns.load(std::memory_order_relaxed);
    for (auto it = std::next(main_entries_.begin()); it != main_entries_.end(); ++it) {
      const int64_t ts = it->second->last_access_ns.load(std::memory_order_relaxed);
      if (ts < oldest_ts) {
        oldest = it;
        oldest_ts = ts;
      }
    }
    main_entries_.erase(oldest);
    approx_distinct_tracked_.fetch_sub(1, std::memory_order_relaxed);
  }

  // Schedule a single publish per dispatcher iteration. A burst of register
  // calls in one dispatcher tick coalesces into ONE publishSnapshot call —
  // bounding main-thread CPU during cold-start storms (1000 distinct new
  // buckets → 1 map copy + TLS set, not 1000). Mirrors the same pattern in
  // GlobalRateLimitClientImpl::scheduleWriteBucketsToTLS.
  void schedulePublish() {
    if (publish_scheduled_) {
      return;
    }
    publish_scheduled_ = true;
    // Same listener-drain protection as recordAccess's post above. The
    // post-and-clear ordering matches GlobalRateLimitClientImpl::
    // scheduleWriteBucketsToTLS exactly.
    std::weak_ptr<GlobalHotspotTracker> weak = weak_from_this();
    main_dispatcher_.post([weak]() {
      if (auto self = weak.lock()) {
        self->publish_scheduled_ = false;
        self->publishSnapshot();
      }
    });
  }

  void publishSnapshot() {
    auto next_map = std::make_shared<HotspotSnapshot::EntriesMap>(main_entries_);
    auto next = std::make_shared<HotspotSnapshot>();
    next->entries = next_map;
    tls_slot_.set([next]([[maybe_unused]] Event::Dispatcher&) { return next; });
  }

  Event::Dispatcher& main_dispatcher_;
  ThreadLocal::TypedSlot<HotspotSnapshot> tls_slot_;
  TimeSource& time_source_;
  const int64_t window_size_ns_;
  const size_t max_tracked_;
  // main-only source of truth — every mutation goes through registerOnMain
  // which runs on main_dispatcher_, so no synchronization is needed.
  absl::flat_hash_map<size_t, std::shared_ptr<HotspotEntry>> main_entries_;
  std::atomic<size_t> approx_distinct_tracked_{0};
  // Coalescing flag: main-only access (set/cleared inside posted closures
  // run on main_dispatcher_), no atomic needed by contract.
  bool publish_scheduled_{false};
};

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
