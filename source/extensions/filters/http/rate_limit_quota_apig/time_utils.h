#pragma once

#include <chrono>
#include <cstdint>

#include "envoy/common/time.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

// Monotonic-clock "now" in nanoseconds. Centralized so the duration_cast +
// time_since_epoch incantation appears in one place across filter.cc and the
// global_hotspot_tracker / dynamic_settings_registry / global_client_impl
// call sites that read or compare deny_until_ns / window_start_ns / etc.
inline int64_t nowMonotonicNs(TimeSource& ts) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             ts.monotonicTime().time_since_epoch())
      .count();
}

// Same source value as `nowMonotonicNs` but typed for atomic stores into
// `time_of_last_access` (std::atomic<std::chrono::nanoseconds>). Provided
// alongside the int64 variant to avoid a round-trip cast at each call site.
inline std::chrono::nanoseconds nowMonotonicNsTyped(TimeSource& ts) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
      ts.monotonicTime().time_since_epoch());
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
