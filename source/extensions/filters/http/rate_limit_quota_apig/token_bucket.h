#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>

#include "envoy/common/pure.h"
#include "envoy/common/time.h"
#include "source/common/common/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

namespace {
// The minimal fill rate will be one second every year.
constexpr double kMinFillRate = 1.0 / (365 * 24 * 60 * 60);

} // namespace

class TokenBucket {
public:
  virtual ~TokenBucket() = default;

  virtual bool consume(uint64_t tokens) PURE;
  virtual uint64_t remainingTokens() const PURE;

  // Refund previously-consumed tokens. Used by the multi-dimension dispatch
  // path when a later dim denies and earlier dims must roll back their
  // deductions. Default: no-op (sliding-window buckets like
  // AtomicTokenBucketImpl reconstruct state from time, so a "refund" is
  // implicit in the next consume window — overriding here would violate
  // their fill-rate semantics). QuotaTokenBucketImpl overrides because its
  // monotonic counter has no other way to recover from a rollback.
  virtual void refund(uint64_t /*tokens*/) {}
};

using TokenBucketPtr = std::shared_ptr<TokenBucket>;

/*
 * Quota QuotaTokenBucketImpl
 * 产生固定值的配额，该值只会减少不会增加
 */
class QuotaTokenBucketImpl : public TokenBucket {
public:
  /**
   * @param max_tokens supplies the maximum number of tokens in the bucket.
   */
  explicit QuotaTokenBucketImpl(uint64_t max_tokens) : tokens_(max_tokens) {}

  /**
   * Consumes multiple tokens from the bucket.
   * @param tokens the number of tokens to consume.
   * @return true if tokens were successfully consumed, false if insufficient tokens.
   *
   * IMPORTANT: Uses retry loop for compare_exchange_weak to handle spurious failures.
   * Without the loop, concurrent requests could be incorrectly denied when CAS fails
   * due to contention rather than insufficient tokens.
   */
  bool consume(uint64_t tokens) override {
    auto remain_token = tokens_.load(std::memory_order_relaxed);
    do {
      if (tokens > remain_token) {
        // Insufficient tokens - this is a real denial
        return false;
      }
      // Try to atomically decrement. If CAS fails due to contention,
      // remain_token is updated with current value and we retry.
    } while (!tokens_.compare_exchange_weak(remain_token, remain_token - tokens,
                                            std::memory_order_release, std::memory_order_relaxed));
    return true;
  }

  /**
   * Refund previously-consumed tokens back to the bucket. Bounded by the
   * original max_tokens hint isn't tracked here (the bucket is a one-shot
   * pre-allocation), so over-refund is theoretically possible if the caller
   * mis-pairs consume / refund. Callers MUST refund only what they
   * successfully consumed (multi-dim dispatch tracks this via a
   * pending-deduction list — see filter.cc::tryDynamicMultiDimensionCheck).
   *
   * No-op when tokens == 0.
   */
  void refund(uint64_t tokens) override {
    if (tokens == 0) {
      return;
    }
    // Saturating add via CAS loop — protects against overflow at uint64_t
    // boundary (which would only happen on absurd refund counts but we'd
    // rather clamp than wrap).
    auto current = tokens_.load(std::memory_order_relaxed);
    while (true) {
      uint64_t next = current + tokens;
      if (next < current) { // wrap detected
        next = std::numeric_limits<uint64_t>::max();
      }
      if (tokens_.compare_exchange_weak(current, next, std::memory_order_release,
                                        std::memory_order_relaxed)) {
        return;
      }
    }
  }

  /**
   * Get the remaining number of tokens in the bucket. This is a snapshot and may change after the
   * call.
   * @return the remaining number of tokens in the bucket.
   */
  uint64_t remainingTokens() const override {
    auto token = tokens_.load(std::memory_order_relaxed);
    return token;
  }

private:
  std::atomic<uint64_t> tokens_;
};

class AtomicTokenBucketImpl : public TokenBucket {
public:
  explicit AtomicTokenBucketImpl(uint64_t max_tokens, TimeSource& time_source, double fill_rate,
                                 uint64_t initial_tokens)
      : max_tokens_(max_tokens), fill_rate_(std::max(std::abs(fill_rate), kMinFillRate)),
        time_source_(time_source) {
    auto time_in_seconds = timeNowInSeconds();
    if (initial_tokens) {
      time_in_seconds -= initial_tokens / fill_rate_;
    }
    time_in_seconds_.store(time_in_seconds, std::memory_order_relaxed);
  }

  bool consume(uint64_t tokens) override;
  template <class GetConsumedTokens> double consume(const GetConsumedTokens& cb) {
    const double time_now = timeNowInSeconds();

    double time_old = time_in_seconds_.load(std::memory_order_relaxed);
    double time_new{};
    double consumed{};
    do {
      const double total_tokens = std::min(max_tokens_, (time_now - time_old) * fill_rate_);
      if (consumed = cb(total_tokens); consumed == 0) {
        return 0;
      }

      // There are two special cases that should rarely happen in practice but we will not
      // prevent them in this common template method:
      // The consumed is negative. It means the token is added back to the bucket.
      // The consumed is larger than total_tokens. It means the bucket is overflowed and future
      // tokens are consumed.

      // Move the time_in_seconds_ forward by the number of tokens consumed.
      const double total_tokens_new = total_tokens - consumed;
      time_new = time_now - (total_tokens_new / fill_rate_);
    } while (
        !time_in_seconds_.compare_exchange_weak(time_old, time_new, std::memory_order_relaxed));

    return consumed;
  }

  bool consume() {
    constexpr auto consumed_cb = [](double total_tokens) -> double {
      return total_tokens >= 1 ? 1 : 0;
    };
    return consume(consumed_cb) == 1;
  }
  uint64_t remainingTokens() const override {
    const double time_now = timeNowInSeconds();
    const double time_old = time_in_seconds_.load(std::memory_order_relaxed);
    const double tokens = std::min(max_tokens_, (time_now - time_old) * fill_rate_);
    return static_cast<uint64_t>(std::max(0.0, tokens));
  }

private:
  double timeNowInSeconds() const;
  const double max_tokens_;
  const double fill_rate_;

  std::atomic<double> time_in_seconds_{};
  TimeSource& time_source_;
};

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy