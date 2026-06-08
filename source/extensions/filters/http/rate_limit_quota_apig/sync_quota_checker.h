#pragma once

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/grpc/async_client.h"
#include "envoy/grpc/async_client_manager.h"
#include "envoy/service/rate_limit_quota_apig/v3/rlqs.pb.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/grpc/typed_async_client.h"

#include "google/protobuf/util/time_util.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

using ::envoy::service::rate_limit_quota_apig::v3::BucketId;
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse;
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports;
using ::envoy::type::v3::RateLimitStrategy;

/**
 * Callback interface for async quota check results.
 */
class AsyncQuotaCheckCallbacks {
public:
  virtual ~AsyncQuotaCheckCallbacks() = default;

  /**
   * Called when the quota check completes.
   * @param allowed Whether the request should be allowed.
   */
  virtual void onQuotaCheckComplete(bool allowed) PURE;

  /**
   * Called when the quota check fails (timeout, network error, etc).
   * The filter should use fallback behavior.
   */
  virtual void onQuotaCheckError() PURE;
};

/**
 * Interface for synchronous quota checking during cold-path / degradation mode.
 * Note: Despite the name, this now uses async callbacks to be compatible
 * with Envoy's event-driven architecture.
 *
 * SYNC-CHECK TOKEN PROTOCOL CONTRACT
 * ----------------------------------
 * The current sync-check wire protocol marks the request with `time_elapsed = 1ns`
 * and is treated by the RLQS server as a single-request probe; the server deducts
 * 1 logical "request" (or `avg_tokens_per_request` tokens, configured server-side)
 * regardless of the actual token cost. Real per-request token deltas (e.g. LLM
 * input/output token counts that are only known after the response is generated)
 * MUST be reported asynchronously via `RateLimitClient::reportQuotaUsage()`
 * after the response stream completes — the cold/degraded path does this in
 * `RateLimitQuotaFilter::encodeData` / `onDestroy`.
 *
 * Implications for callers of `checkQuotaAsync`:
 *   - The `tokens_estimate` parameter is currently always treated as 1.
 *   - Passing a value other than 1 is logged as a warning (it indicates the
 *     caller assumes a multi-token sync-check semantic that the protocol does
 *     not yet support).
 *   - To rate-limit on real token consumption, accumulate the actual count
 *     during response processing and call `reportQuotaUsage` at end-of-stream.
 */
class SyncQuotaChecker {
public:
  virtual ~SyncQuotaChecker() = default;

  /**
   * Initiate an async quota check for a bucket.
   * @param bucket_id The bucket identifier.
   * @param tokens_estimate Caller's estimate of the request's token cost. See the
   *        "SYNC-CHECK TOKEN PROTOCOL CONTRACT" comment above: the current
   *        protocol always deducts 1 token per check regardless of this value.
   *        Real token deltas must be reported via `reportQuotaUsage` post-response.
   * @param timeout Maximum time to wait for response.
   * @param callbacks Callbacks to invoke with the result.
   * @return True if the check was initiated successfully, false otherwise.
   */
  virtual bool checkQuotaAsync(const BucketId& bucket_id, uint64_t tokens_estimate,
                               std::chrono::milliseconds timeout,
                               AsyncQuotaCheckCallbacks& callbacks) PURE;

  /**
   * Cancel a specific pending quota check by callback reference.
   * @param callbacks The callback to cancel.
   */
  virtual void cancelCheck(AsyncQuotaCheckCallbacks& callbacks) PURE;
};

using SyncQuotaCheckerPtr = std::unique_ptr<SyncQuotaChecker>;
using SyncQuotaCheckerSharedPtr = std::shared_ptr<SyncQuotaChecker>;

/**
 * Thread Local wrapper for SyncQuotaChecker.
 */
class ThreadLocalSyncQuotaChecker : public ThreadLocal::ThreadLocalObject {
public:
  ThreadLocalSyncQuotaChecker(SyncQuotaCheckerSharedPtr checker) : checker_(std::move(checker)) {}

  SyncQuotaCheckerSharedPtr checker() { return checker_; }

private:
  SyncQuotaCheckerSharedPtr checker_;
};

/**
 * Represents a pending quota check request in the queue.
 */
struct PendingQuotaCheck {
  AsyncQuotaCheckCallbacks* callbacks;
  Event::TimerPtr timeout_timer;
  bool completed{false};
  // Wall-clock time when this check was sent, for latency tracking.
  std::chrono::steady_clock::time_point send_time;

  PendingQuotaCheck(AsyncQuotaCheckCallbacks* cb)
      : callbacks(cb), send_time(std::chrono::steady_clock::now()) {}
};

/**
 * gRPC stream-based async quota checker implementation with request queue.
 *
 * This implementation uses the existing RLQS gRPC streaming service to perform
 * quota checks in degradation mode. It sends RateLimitQuotaUsageReports requests
 * and asynchronously receives RateLimitQuotaResponse messages.
 *
 * Key features:
 * - Request Queue: Supports multiple concurrent requests using a FIFO queue
 * - FIFO Response Matching: gRPC stream preserves message order, so responses
 *   are matched to requests in order
 * - Per-request Timeout: Each request has its own timeout timer
 * - Circuit Breaker: Limits max concurrent checks to prevent overload
 *
 * The quota-server recognizes sync check requests (time_elapsed <= 1ms)
 * and immediately returns a response with ALLOW_ALL or DENY_ALL.
 *
 * Flow: Envoy -> (gRPC Stream) -> Quota Server -> Redis -> Response (async callback)
 */
class GrpcStreamSyncQuotaChecker
    : public SyncQuotaChecker,
      public Grpc::RawAsyncStreamCallbacks,
      public Logger::Loggable<Logger::Id::rate_limit_quota> {
public:
  /**
   * Constructor for GrpcStreamSyncQuotaChecker.
   * @param async_client The gRPC async client for RLQS service.
   * @param domain The domain for quota checks.
   * @param dispatcher The dispatcher for timer operations.
   * @param fallback_allow_on_error If true, allow requests when quota check fails (fail-open).
   * @param max_concurrent_checks Max concurrent active quota checks (circuit breaker).
   */
  GrpcStreamSyncQuotaChecker(Grpc::RawAsyncClientSharedPtr async_client, const std::string& domain,
                             Event::Dispatcher& dispatcher, bool fallback_allow_on_error = false,
                             uint32_t max_concurrent_checks = 100)
      : async_client_(async_client), domain_(domain), dispatcher_(dispatcher),
        fallback_allow_on_error_(fallback_allow_on_error),
        max_concurrent_checks_(max_concurrent_checks),
        service_method_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
            "envoy.service.rate_limit_quota_apig.v3.RateLimitQuotaService.StreamRateLimitQuotas")) {}

  ~GrpcStreamSyncQuotaChecker() override { cancelAll(); }

  bool checkQuotaAsync(const BucketId& bucket_id, uint64_t tokens_estimate,
                       std::chrono::milliseconds timeout,
                       AsyncQuotaCheckCallbacks& callbacks) override {
    // The current sync-check protocol always deducts 1 logical request server-side
    // (see SYNC-CHECK TOKEN PROTOCOL CONTRACT in sync_quota_checker.h). A non-1
    // estimate signals that the caller assumes a multi-token sync semantic that
    // does not exist; surface it via warn so the misuse is visible. Real per-request
    // token deltas must be reported via reportQuotaUsage after end-of-stream.
    if (tokens_estimate != 1) {
      ENVOY_LOG(warn,
                "checkQuotaAsync called with tokens_estimate={}, but the sync-check "
                "protocol always deducts 1 token; report actual deltas via "
                "reportQuotaUsage. See sync_quota_checker.h docs.",
                tokens_estimate);
    }

    // Circuit Breaker: check concurrent requests
    if (pending_checks_.size() >= max_concurrent_checks_) {
      ENVOY_LOG(warn, "Async quota check circuit breaker open. Active checks: {}, Max: {}",
                pending_checks_.size(), max_concurrent_checks_);
      return false;
    }

    // Ensure stream is open before adding to queue
    if (!ensureStreamOpen()) {
      ENVOY_LOG(error, "Failed to open gRPC stream for async quota check");
      return false;
    }

    // Create pending check entry
    auto pending = std::make_unique<PendingQuotaCheck>(&callbacks);

    // Create timeout timer for this specific request
    pending->timeout_timer = dispatcher_.createTimer([this, cb = &callbacks]() {
      onCheckTimeout(cb);
    });
    pending->timeout_timer->enableTimer(timeout);

    // Build the sync check request
    RateLimitQuotaUsageReports request;
    request.set_domain(domain_);

    auto* bucket_usage = request.add_bucket_quota_usages();
    *bucket_usage->mutable_bucket_id() = bucket_id;
    // Use time_elapsed = 1ns as a marker for sync check request
    bucket_usage->mutable_time_elapsed()->set_seconds(0);
    bucket_usage->mutable_time_elapsed()->set_nanos(1);
    bucket_usage->set_num_requests_allowed(0);
    bucket_usage->set_num_requests_denied(0);

    // Send request through the stream
    Buffer::InstancePtr buffer = std::make_unique<Buffer::OwnedImpl>();
    std::string serialized_request;
    if (!request.SerializeToString(&serialized_request)) {
      ENVOY_LOG(error, "Failed to serialize sync quota check request");
      pending->timeout_timer->disableTimer();
      return false;
    }

    buffer->add(serialized_request);
    stream_->sendMessageRaw(std::move(buffer), false);

    // Add to queue AFTER successful send
    pending_checks_.push_back(std::move(pending));

    ENVOY_LOG(debug, "Sent async quota check request, queue size: {}", pending_checks_.size());
    return true;
  }

  void cancelCheck(AsyncQuotaCheckCallbacks& callbacks) override {
    // Find and remove the pending check for this callback
    for (auto it = pending_checks_.begin(); it != pending_checks_.end(); ++it) {
      if ((*it)->callbacks == &callbacks) {
        if ((*it)->timeout_timer) {
          (*it)->timeout_timer->disableTimer();
          (*it)->timeout_timer.reset();
        }
        (*it)->completed = true;
        (*it)->callbacks = nullptr;
        ENVOY_LOG(debug, "Cancelled pending quota check, queue size: {}", pending_checks_.size());
        break;
      }
    }
    // Don't erase here to maintain FIFO order for response matching
    // Cancelled entries will be skipped when processing responses
  }

  // Grpc::RawAsyncStreamCallbacks
  void onCreateInitialMetadata(Http::RequestHeaderMap&) override {}

  void onReceiveInitialMetadata(Http::ResponseHeaderMapPtr&&) override {}

  bool onReceiveMessageRaw(Buffer::InstancePtr&& response_buffer) override {
    // Parse response
    RateLimitQuotaResponse response;
    std::string data = response_buffer->toString();
    if (!response.ParseFromString(data)) {
      ENVOY_LOG(error, "Failed to parse sync quota check response");
      // Complete the first pending check with error
      completeFrontCheck(false, true);
      return false;
    }

    // Determine if request should be allowed
    bool allowed = fallback_allow_on_error_;

    if (response.bucket_action_size() > 0) {
      const auto& action = response.bucket_action(0);
      if (action.has_quota_assignment_action()) {
        const auto& assignment = action.quota_assignment_action();
        if (assignment.has_rate_limit_strategy()) {
          const auto& strategy = assignment.rate_limit_strategy();
          if (strategy.strategy_case() == RateLimitStrategy::kBlanketRule) {
            allowed = (strategy.blanket_rule() == RateLimitStrategy::ALLOW_ALL);
            ENVOY_LOG(debug, "Async quota check response: blanket_rule={}, allowed={}",
                      static_cast<int>(strategy.blanket_rule()), allowed ? "true" : "false");
          } else {
            ENVOY_LOG(debug, "Async quota check response: non-blanket strategy, fallback={}",
                      allowed ? "allow" : "deny");
          }
        } else {
          allowed = true;
          ENVOY_LOG(debug, "Async quota check response: no strategy, allowing");
        }
      }
    }

    // Complete the first pending check
    completeFrontCheck(allowed, false);

    return true;
  }

  void onReceiveTrailingMetadata(Http::ResponseTrailerMapPtr&&) override {}

  void onRemoteClose(Grpc::Status::GrpcStatus status, const std::string& message) override {
    ENVOY_LOG(debug, "gRPC stream closed with status {}: {}", static_cast<int>(status), message);
    stream_ = nullptr;

    // Fail all pending checks
    while (!pending_checks_.empty()) {
      completeFrontCheck(false, true);
    }
  }

private:
  /**
   * Complete the front-most pending check in the queue.
   * @param allowed Whether the request should be allowed (ignored if is_error is true).
   * @param is_error Whether this completion is due to an error.
   */
  void completeFrontCheck(bool allowed, bool is_error) {
    // Skip already completed/cancelled entries
    while (!pending_checks_.empty() && pending_checks_.front()->completed) {
      pending_checks_.pop_front();
    }

    if (pending_checks_.empty()) {
      ENVOY_LOG(warn, "Received response but no pending checks in queue");
      return;
    }

    auto& pending = pending_checks_.front();

    // Disable timeout timer
    if (pending->timeout_timer) {
      pending->timeout_timer->disableTimer();
      pending->timeout_timer.reset();
    }

    // Invoke callback if not cancelled
    if (pending->callbacks && !pending->completed) {
      pending->completed = true;

      // Measure SyncCheck RTT at the checker level (covers network + server processing).
      const auto rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - pending->send_time)
                              .count();
      if (is_error) {
        ENVOY_LOG(warn, "SyncQuotaChecker: check error, rtt_ms={} queue_remaining={}", rtt_ms,
                  pending_checks_.size() - 1);
        pending->callbacks->onQuotaCheckError();
      } else {
        ENVOY_LOG(debug, "SyncQuotaChecker: check complete allowed={} rtt_ms={} queue_remaining={}",
                  allowed ? "true" : "false", rtt_ms, pending_checks_.size() - 1);
        pending->callbacks->onQuotaCheckComplete(allowed);
      }
    }

    // Remove from queue
    pending_checks_.pop_front();

    ENVOY_LOG(debug, "Completed quota check, remaining queue size: {}", pending_checks_.size());
  }

  /**
   * Handle timeout for a specific check.
   *
   * IMPORTANT: When a request times out, the server may still send a response later.
   * This would cause response/request mismatch in our FIFO queue. To maintain
   * correctness, we reset the entire stream when any request times out.
   * This ensures all subsequent requests get fresh responses.
   */
  void onCheckTimeout(AsyncQuotaCheckCallbacks* callbacks) {
    ENVOY_LOG(warn, "Async quota check timed out, resetting stream to prevent response mismatch");

    // Find the timed-out check and invoke error callback
    bool found = false;
    for (auto& pending : pending_checks_) {
      if (pending->callbacks == callbacks && !pending->completed) {
        pending->completed = true;
        pending->timeout_timer.reset();
        if (pending->callbacks) {
          pending->callbacks->onQuotaCheckError();
          pending->callbacks = nullptr;
        }
        found = true;
        break;
      }
    }

    if (!found) {
      // Already completed or cancelled
      return;
    }

    // Reset the stream to prevent response/request mismatch.
    // All pending requests will receive error callbacks.
    resetStreamAndFailPending();
  }

  /**
   * Reset the gRPC stream and fail all remaining pending checks.
   * This is called when a timeout occurs to prevent response/request mismatch.
   */
  void resetStreamAndFailPending() {
    // Close the stream first
    if (stream_ != nullptr) {
      stream_->resetStream();
      stream_ = nullptr;
    }

    // Fail all remaining pending checks
    for (auto& pending : pending_checks_) {
      if (pending->timeout_timer) {
        pending->timeout_timer->disableTimer();
        pending->timeout_timer.reset();
      }
      if (pending->callbacks && !pending->completed) {
        pending->completed = true;
        pending->callbacks->onQuotaCheckError();
        pending->callbacks = nullptr;
      }
    }
    pending_checks_.clear();

    ENVOY_LOG(debug, "Stream reset and all pending checks failed due to timeout");
  }

  /**
   * Cancel all pending checks.
   */
  void cancelAll() {
    for (auto& pending : pending_checks_) {
      if (pending->timeout_timer) {
        pending->timeout_timer->disableTimer();
        pending->timeout_timer.reset();
      }
      if (pending->callbacks && !pending->completed) {
        pending->callbacks->onQuotaCheckError();
      }
    }
    pending_checks_.clear();

    if (stream_ != nullptr) {
      stream_->closeStream();
      stream_->resetStream();
      stream_ = nullptr;
    }
  }

  bool ensureStreamOpen() {
    if (stream_ != nullptr) {
      return true;
    }

    ENVOY_LOG(debug, "Attempting to start/restart sync quota checker gRPC stream.");
    stream_ = async_client_->startRaw(
        service_method_.service()->full_name(), service_method_.name(), *this,
        Http::AsyncClient::StreamOptions().setBufferBodyForRetry(false));

    return stream_ != nullptr;
  }

  Grpc::RawAsyncClientSharedPtr async_client_;
  const std::string domain_;
  Event::Dispatcher& dispatcher_;
  const bool fallback_allow_on_error_;
  const uint32_t max_concurrent_checks_;
  const Protobuf::MethodDescriptor& service_method_;

  Grpc::RawAsyncStream* stream_{nullptr};

  // FIFO queue of pending checks - responses match requests in order
  std::deque<std::unique_ptr<PendingQuotaCheck>> pending_checks_;
};

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
