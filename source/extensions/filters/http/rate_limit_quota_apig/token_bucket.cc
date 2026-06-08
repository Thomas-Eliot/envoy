#include "source/extensions/filters/http/rate_limit_quota_apig/token_bucket.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

double AtomicTokenBucketImpl::timeNowInSeconds() const {
  return std::chrono::duration<double>(time_source_.monotonicTime().time_since_epoch()).count();
}

bool AtomicTokenBucketImpl::consume(uint64_t tokens) {
  if (tokens == 0) {
    return true;
  }
  const double requested = static_cast<double>(tokens);
  const double consumed = consume([requested](double total_tokens) -> double {
    return total_tokens >= requested ? requested : 0.0;
  });
  return consumed >= requested - 1e-9;
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy