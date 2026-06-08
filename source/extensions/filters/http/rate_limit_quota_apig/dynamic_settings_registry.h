#pragma once

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.h"
#include "envoy/stats/stats.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/assert.h"

#include "absl/container/flat_hash_map.h"
#include "absl/hash/hash.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

using RateLimitQuotaBucketSettings =
    envoy::extensions::filters::http::rate_limit_quota_apig::v3::RateLimitQuotaBucketSettings;
using RateLimitQuotaBucketSettingsConstSharedPtr =
    std::shared_ptr<const RateLimitQuotaBucketSettings>;

// Precomputed per-variant overlay extracted from
// RateLimitQuotaBucketSettings.bucket_id_builder.
//
// The hot path (tryDynamicMultiDimensionCheck) builds variant BucketIds by
// merging the request's base BucketId with the constant string-value entries
// the server stamped into bucket_id_builder (typically `_tenant`, `_scope`,
// `_dim`). The original inline loop traversed the protobuf map and called
// `value_specifier_case()` on every entry per request — at 250K QPS × N
// variants, the proto reflection cost is non-trivial.
//
// precomputeStringOverlay extracts these (key, value) pairs into a
// flat std::vector once per `RateLimitQuotaBucketSettings`. The result is
// cached on the CachedBucketSettings wrapper at server-push time (see
// wrapSettings below) so the per-request hot path does zero proto reflection.
//
// Non-string-value entries (kCustomValue / kEmptyValue) are intentionally
// dropped: the multi-dim variant identity is purely the (constant) string
// stamping the server applies; per-request CEL/header extraction is not
// part of the variant's deterministic identity.
inline std::vector<std::pair<std::string, std::string>>
precomputeStringOverlay(const RateLimitQuotaBucketSettings& settings) {
  std::vector<std::pair<std::string, std::string>> out;
  if (!settings.has_bucket_id_builder()) {
    return out;
  }
  const auto& m = settings.bucket_id_builder().bucket_id_builder();
  out.reserve(m.size());
  for (const auto& [k, vb] : m) {
    if (vb.value_specifier_case() ==
        envoy::extensions::filters::http::rate_limit_quota_apig::v3::
            RateLimitQuotaBucketSettings_BucketIdBuilder_ValueBuilder::kStringValue) {
      out.emplace_back(k, vb.string_value());
    }
  }
  return out;
}

// CachedBucketSettings bundles a server-pushed BucketSettings with the
// precomputed string-value overlay extracted from its bucket_id_builder.
//
// Lifecycle: the discovery client wraps every newly-arriving settings with
// wrapSettings() before publishing through DynamicSettingsRegistry::update.
// The wrapper is immutable for its lifetime — the overlay is a deterministic
// function of the contained settings, computed once on construction.
//
// Hot-path benefit: tryDynamicMultiDimensionCheck reads `overlay` directly
// without re-traversing the protobuf bucket_id_builder map per request, and
// applies it to a copy of the request's base BucketId. At 250K QPS × N
// variants this saves N proto map iterations + value_specifier_case checks
// per request.
struct CachedBucketSettings {
  RateLimitQuotaBucketSettingsConstSharedPtr settings;
  std::vector<std::pair<std::string, std::string>> overlay;
};
using CachedBucketSettingsConstSharedPtr = std::shared_ptr<const CachedBucketSettings>;

// wrapSettings constructs a CachedBucketSettings around a server-pushed
// settings shared_ptr, precomputing the overlay once. Returning a const
// shared_ptr lets the registry publish the wrapper through the TLS snapshot
// without further copies.
inline CachedBucketSettingsConstSharedPtr
wrapSettings(RateLimitQuotaBucketSettingsConstSharedPtr settings) {
  auto wrapped = std::make_shared<CachedBucketSettings>();
  wrapped->overlay = settings ? precomputeStringOverlay(*settings)
                              : std::vector<std::pair<std::string, std::string>>{};
  wrapped->settings = std::move(settings);
  return wrapped;
}

// Sharding constants for the DynamicSettingsRegistry snapshot. Mirrors the
// BucketsCache sharding model: each update / erase only COWs a single shard
// instead of the entire map, capping per-publish copy cost at O(N/K).
//
// At spec-target scale (50 tenants × 5000 BucketSettings = 250 K entries),
// the unsharded flat_hash_map COW dominated config-server push latency. K=16
// drops the per-publish copy cost ~16× while keeping the per-publish overhead
// (one shared_ptr swap per shard) negligible. Operators override with
// RATELIMIT_QUOTA_SETTINGS_REGISTRY_SHARDS in [4, 64].
constexpr size_t kRateLimitQuotaDefaultSettingsRegistryShards = 16;
constexpr size_t kRateLimitQuotaMinSettingsRegistryShards = 4;
constexpr size_t kRateLimitQuotaMaxSettingsRegistryShards = 64;

inline size_t rateLimitQuotaSettingsRegistryShardsFromEnv() {
  const char* env = std::getenv("RATELIMIT_QUOTA_SETTINGS_REGISTRY_SHARDS");
  if (env == nullptr) {
    return kRateLimitQuotaDefaultSettingsRegistryShards;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(env, &end, 10);
  if (end == env || parsed == 0 || (parsed == ULONG_MAX && errno == ERANGE)) {
    return kRateLimitQuotaDefaultSettingsRegistryShards;
  }
  return std::min(std::max(static_cast<size_t>(parsed), kRateLimitQuotaMinSettingsRegistryShards),
                  kRateLimitQuotaMaxSettingsRegistryShards);
}

inline size_t rateLimitQuotaSettingsRegistryShards() {
  static const size_t shards = rateLimitQuotaSettingsRegistryShardsFromEnv();
  return shards;
}

/**
 * DynamicSettingsRegistry holds the per-(tenant, scope) BucketSettings pushed
 * by the server via the RateLimitQuotaConfigDiscoveryService.
 *
 * Lifecycle and threading model (spec § D-2 / D-7 / D-8):
 *  - The main thread owns the source-of-truth map (Snapshot under main_mu_).
 *    Only the config discovery client (running on the main dispatcher) calls
 *    update() / erase().
 *  - Workers read via a ThreadLocal<Snapshot> published by main on every
 *    change. Reads are lock-free; the worker sees an immutable snapshot
 *    captured at publish time.
 *  - Snapshots are copy-on-write: each update() copies the previous map,
 *    applies the change, and publishes the new shared_ptr. Worker threads
 *    holding an old snapshot continue using it until they pick up the new
 *    one via the TLS slot — no torn reads.
 *
 * Keying: scope is encoded as "{scope_type}:{scope_value}" (matches the wire
 * format used by the server's resource_name; e.g. "route:chat-api"). Tenant
 * is the raw _tenant value injected by the filter from listener metadata or
 * filter-chain name.
 *
 * Multi-dimension routes (spec § 4.2 array form): the value is a vector of
 * BucketSettings, one per configured dimension. Each entry's
 * bucket_id_builder carries `_dim` so the filter can fan the matched route
 * out into N independent BucketIds for independent quota checks.
 */
class DynamicSettingsRegistry {
public:
  // SettingsList holds the server-pushed BucketSettings for a (tenant, scope)
  // key. Each element is a CachedBucketSettings wrapper that bundles the raw
  // settings shared_ptr with a precomputed bucket_id_builder string overlay,
  // letting the filter hot path skip per-request proto reflection. Discovery
  // client builders MUST construct elements via wrapSettings() so the overlay
  // is non-empty before publish.
  using SettingsList = std::vector<CachedBucketSettingsConstSharedPtr>;

  // SettingsMap is the per-shard map type. Each shard is an independent
  // immutable shared_ptr; update / erase swap a single shard's pointer
  // without touching the rest. The full keyspace is recovered by walking
  // all K shards.
  using SettingsMap = absl::flat_hash_map<std::string, SettingsList>;
  using SettingsMapConstSharedPtr = std::shared_ptr<const SettingsMap>;

  // Snapshot is the immutable, sharded view workers read through the TLS slot.
  // shards.size() is fixed for the lifetime of the registry (sourced from
  // rateLimitQuotaSettingsRegistryShards() at construction). Lookup hashes
  // the key and indexes into shards directly — no mutex on the read path.
  //
  // Publish strategy: deep-copy ONLY the shard owning the changed key, then
  // build a new Snapshot reusing the unchanged shards' shared_ptrs. Workers
  // holding the prior snapshot pin the old shard pointers; the new snapshot
  // keeps the unchanged ones alive too, so neither side observes a torn read.
  struct Snapshot : public ThreadLocal::ThreadLocalObject {
    explicit Snapshot(size_t shard_count) : shards(shard_count) {
      for (size_t i = 0; i < shard_count; ++i) {
        shards[i] = std::make_shared<const SettingsMap>();
      }
    }
    explicit Snapshot(std::vector<SettingsMapConstSharedPtr> in) : shards(std::move(in)) {}

    std::vector<SettingsMapConstSharedPtr> shards;

    size_t shardCount() const { return shards.size(); }

    // Pick the shard that owns `key`. The hash is computed on the
    // already-built std::string key so insert and lookup land on the same
    // shard; using absl::HashOf keeps it independent of the inner
    // flat_hash_map's hasher.
    size_t shardIndexFor(absl::string_view key) const {
      return absl::HashOf(key) % shards.size();
    }

    // Total entry count across all shards. O(K), not O(N entries).
    size_t totalSize() const {
      size_t sum = 0;
      for (const auto& s : shards) {
        sum += s->size();
      }
      return sum;
    }
  };

  // Construct the registry, publishing an initial empty sharded snapshot to
  // every worker thread so lookups before the first server push are
  // well-defined. The shard count is fixed at construction by the env hook
  // and lives on the published Snapshot — no class member needed because
  // every mutation path reads `main_snapshot_->shards.size()` anyway.
  // The optional `main_dispatcher` is used for thread-safety assertions on
  // the mutator paths (`update` / `erase`). Pass nullptr in tests that don't
  // care about the assertion (or have no real dispatcher); production must
  // pass the main thread dispatcher so a worker-thread call gets caught at
  // ASSERT time instead of as a silent data race.
  explicit DynamicSettingsRegistry(ThreadLocal::TypedSlot<Snapshot>& tls_slot,
                                   Event::Dispatcher* main_dispatcher = nullptr)
      : tls_slot_(tls_slot), main_dispatcher_(main_dispatcher) {
    auto empty = std::make_shared<Snapshot>(rateLimitQuotaSettingsRegistryShards());
    main_snapshot_ = empty;
    tls_slot_.set([empty]([[maybe_unused]] Event::Dispatcher&) { return empty; });
  }

  // setPublishCounter wires an optional FilterConfig stats counter that is
  // bumped once per snapshot republish. Designed for nullptr-safe wiring so
  // unit tests that don't care about metrics don't have to construct the
  // counter scaffold. Set once at factory time; not safe to flip live.
  void setPublishCounter(Stats::Counter* counter) { publish_counter_ = counter; }

  // setPublishUsHistogram wires the per-publish duration histogram (µs).
  // Symmetric with `bucket_cache_publish_us` on GlobalRateLimitClientImpl;
  // captures the full publishLocked path (TLS set + counter increment +
  // shard vector copy already done by buildNextSnapshot).
  //
  // At spec scale (50 tenant × 5K BucketSettings = 250K wrappers) a single
  // server push can exercise an unfortunate hash distribution where one
  // shard holds N/K + tail; this histogram surfaces that regression
  // before users see the corresponding StreamRlQsConfigs latency.
  // nullptr safe.
  void setPublishUsHistogram(Stats::Histogram* histogram) {
    publish_us_histogram_ = histogram;
  }

  // update() runs on the main thread. Replaces the SettingsList for
  // (tenant, scope) and republishes the snapshot to TLS. An empty list
  // is equivalent to erase() — including the no-op contract for unknown
  // keys (no shard COW, no publish counter bump). Without this guard a
  // server bug that pushes empty lists to never-subscribed keys would
  // ghost-publish a shard COW per call, dragging the publish counter and
  // per-publish histogram off their real-mutation baselines.
  void update(absl::string_view tenant, absl::string_view scope, SettingsList settings) {
    // Mutators run only on main: ConfigDiscoveryClient (the sole writer in
    // production) is constructed with main_dispatcher and its gRPC stream
    // callbacks fire on that same dispatcher. ENVOY_BUG (not ASSERT) so the
    // invariant survives release builds: main_snapshot_ is unsynchronized,
    // so a regression that calls this off-main would be a silent data race
    // without a release-build counter / log line.
    ENVOY_BUG(main_dispatcher_ == nullptr || main_dispatcher_->isThreadSafe(),
              "DynamicSettingsRegistry::update must run on the main dispatcher");
    const std::string key = makeKey(tenant, scope);
    const size_t shard_idx = main_snapshot_->shardIndexFor(key);
    const auto& current_shard = *main_snapshot_->shards[shard_idx];

    if (settings.empty()) {
      if (current_shard.find(key) == current_shard.end()) {
        // erase-of-unknown contract; mirrors erase() below.
        return;
      }
      auto next_shard = std::make_shared<SettingsMap>(current_shard);
      next_shard->erase(key);
      publish(buildNextSnapshot(shard_idx, std::move(next_shard)));
      return;
    }

    // Deep-copy ONLY the affected shard; reuse the rest from the prior snapshot.
    auto next_shard = std::make_shared<SettingsMap>(current_shard);
    next_shard->insert_or_assign(key, std::move(settings));
    publish(buildNextSnapshot(shard_idx, std::move(next_shard)));
  }

  // erase() removes a (tenant, scope) entry (spec D-6 AbandonAction).
  // Lookups after erase return an empty list, which the filter treats as
  // "no dynamic override → fall back to static xDS BucketSettings".
  void erase(absl::string_view tenant, absl::string_view scope) {
    ENVOY_BUG(main_dispatcher_ == nullptr || main_dispatcher_->isThreadSafe(),
              "DynamicSettingsRegistry::erase must run on the main dispatcher");
    const std::string key = makeKey(tenant, scope);
    const size_t shard_idx = main_snapshot_->shardIndexFor(key);
    const auto& current_shard = *main_snapshot_->shards[shard_idx];
    if (current_shard.find(key) == current_shard.end()) {
      // Spec contract: erase of unknown key is a silent no-op (no publish,
      // no counter bump). The filter calls erase optimistically on
      // AbandonAction.
      return;
    }
    auto next_shard = std::make_shared<SettingsMap>(current_shard);
    next_shard->erase(key);
    publish(buildNextSnapshot(shard_idx, std::move(next_shard)));
  }

  // lookup() is the worker-side read. Returns the SettingsList for the
  // (tenant, scope) key in the currently-visible snapshot, or an empty
  // list when not yet pushed (or erased). Lock-free: reads the worker's
  // TLS-cached Snapshot shared_ptr, hashes once into the shard, then does
  // a single flat_hash_map lookup.
  //
  // Returns by value (shared_ptr copy) so the caller pins the list for the
  // duration of the request even if the snapshot rolls forward mid-request.
  SettingsList lookup(absl::string_view tenant, absl::string_view scope) const {
    const auto snap_opt = tls_slot_.get();
    if (!snap_opt.has_value()) {
      return {};
    }
    const std::string key = makeKey(tenant, scope);
    const auto& shard = *snap_opt->shards[snap_opt->shardIndexFor(key)];
    auto it = shard.find(key);
    if (it == shard.end()) {
      return {};
    }
    return it->second;
  }

  // Subscriber API: report all currently-known (tenant, scope) pairs the
  // filter has observed at request time. The config discovery client uses
  // this to populate the resource_names of its DiscoveryRequest.
  //
  // Walks every shard (O(K) shard pointers + O(N) total entries). Returned
  // order is undefined — matches the prior unsharded behavior, which the
  // discovery client's resource_names builder doesn't depend on.
  std::vector<std::string> knownResourceKeys() const {
    const auto snap_opt = tls_slot_.get();
    std::vector<std::string> out;
    if (!snap_opt.has_value()) {
      return out;
    }
    out.reserve(snap_opt->totalSize());
    for (const auto& shard : snap_opt->shards) {
      for (const auto& [k, _] : *shard) {
        out.push_back(k);
      }
    }
    return out;
  }

  static std::string makeKey(absl::string_view tenant, absl::string_view scope) {
    std::string out;
    out.reserve(tenant.size() + 1 + scope.size());
    out.append(tenant.data(), tenant.size());
    out.push_back('|');
    out.append(scope.data(), scope.size());
    return out;
  }

private:
  // Build a new snapshot with one shard replaced; reuse all other shard
  // shared_ptrs from the prior snapshot. Caller must run on main thread
  // (the public mutators ASSERT this on entry).
  std::shared_ptr<Snapshot>
  buildNextSnapshot(size_t shard_idx, SettingsMapConstSharedPtr next_shard) {
    std::vector<SettingsMapConstSharedPtr> next_shards = main_snapshot_->shards;
    next_shards[shard_idx] = std::move(next_shard);
    return std::make_shared<Snapshot>(std::move(next_shards));
  }

  void publish(std::shared_ptr<Snapshot> next) {
    // steady_clock (not TimeSource) keeps the registry ctor signature
    // stable — workers do not construct registries, so injecting a
    // TimeSource just for one histogram would ripple through every test
    // call site without buying determinism (the histogram is operator-
    // facing, not asserted on in unit tests).
    const auto start =
        (publish_us_histogram_ != nullptr) ? std::chrono::steady_clock::now()
                                           : std::chrono::steady_clock::time_point{};
    main_snapshot_ = next;
    tls_slot_.set([next]([[maybe_unused]] Event::Dispatcher&) { return next; });
    if (publish_counter_ != nullptr) {
      publish_counter_->inc();
    }
    if (publish_us_histogram_ != nullptr) {
      const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                  std::chrono::steady_clock::now() - start)
                                  .count();
      publish_us_histogram_->recordValue(
          static_cast<uint64_t>(std::max<int64_t>(0, elapsed_us)));
    }
  }

  ThreadLocal::TypedSlot<Snapshot>& tls_slot_;
  // main_dispatcher_ is referenced only by ASSERTs on the mutator paths.
  // Held as raw pointer because the dispatcher outlives the registry
  // (registry is owned by the TlsStore which is destroyed before the
  // server's main dispatcher). nullptr disables the assertion (test mode).
  Event::Dispatcher* main_dispatcher_{nullptr};
  // main thread is the sole writer (ConfigDiscoveryClient gRPC callbacks
  // run on main_dispatcher_), so no mutex is needed — the ASSERT in each
  // mutator catches a future regression at the call site.
  std::shared_ptr<Snapshot> main_snapshot_;
  // Optional stats counter; nullptr unless setPublishCounter wired it.
  // The publish path nil-checks before incrementing.
  Stats::Counter* publish_counter_{nullptr};
  // Optional publish-µs histogram; nullptr unless setPublishUsHistogram
  // wired it. Records the duration of publishLocked. Symmetric with
  // GlobalRateLimitClientImpl::bucket_cache_publish_us_.
  Stats::Histogram* publish_us_histogram_{nullptr};
};

using DynamicSettingsRegistrySharedPtr = std::shared_ptr<DynamicSettingsRegistry>;

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
