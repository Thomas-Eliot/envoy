#pragma once
#include <memory>
#include <string>

#include "envoy/config/core/v3/grpc_service.pb.h"
#include "envoy/grpc/async_client_manager.h"

#include "source/common/grpc/typed_async_client.h"
#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/global_client_impl.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"
#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.h"
#include "envoy/extensions/filters/http/rate_limit_quota_apig/v3/rate_limit_quota.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

using ::envoy::service::rate_limit_quota_apig::v3::BucketId;
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse;
using ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports;
using BucketQuotaUsage =
    ::envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports::BucketQuotaUsage;
using GrpcAsyncClient =
    Grpc::AsyncClient<envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaUsageReports,
                      envoy::service::rate_limit_quota_apig::v3::RateLimitQuotaResponse>;

using DenyResponseSettings = ::envoy::extensions::filters::http::rate_limit_quota_apig::v3::
    RateLimitQuotaBucketSettings::DenyResponseSettings;

// A RateLimitClient that should be created locally in each worker thread. It
// knows to write by posting GlobalRateLimitClientImpl calls to the main thread
// and it knows how to read current values from TLS.
class LocalRateLimitClientImpl : public RateLimitClient,
                                 public Logger::Loggable<Logger::Id::rate_limit_quota> {
public:
  explicit LocalRateLimitClientImpl(
      Envoy::ThreadLocal::TypedSlot<ThreadLocalGlobalRateLimitClientImpl>& global_client_tls,
      Envoy::ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_cache_tls)
      : global_client_tls_(global_client_tls), buckets_cache_tls_(buckets_cache_tls) {}

  void createBucket(const BucketId& bucket_id, size_t id, const BucketAction& default_bucket_action,
                    std::unique_ptr<envoy::type::v3::RateLimitStrategy> fallback_action,
                    std::chrono::milliseconds fallback_ttl, bool initial_request_allowed,
                    const DenyResponseSettings& deny_response_settings) override;
  // Note: returns null if the global resources (client or bucket) are
  // unavailable. Resource creation is left to createBucket(). The CachedBucket*
  // is safe to reference so long as the local client exists.
  std::shared_ptr<CachedBucket> getBucket(size_t id) override;

  void removeBucket(size_t id) override;

  void reportQuotaUsage(const BucketId& bucket_id, const QuotaUsage& usage) override;

  uint64_t recordHotspotAccess(size_t bucket_id_hash) override;

private:
  inline std::shared_ptr<GlobalRateLimitClientImpl> getGlobalClient() {
    return (global_client_tls_.get().has_value()) ? global_client_tls_.get()->global_client
                                                  : nullptr;
  }
  inline ShardedBucketsCacheConstSharedPtr getShardedBucketsCache() {
    return (buckets_cache_tls_.get().has_value()) ? buckets_cache_tls_.get()->sharded()
                                                  : nullptr;
  }

  // Lockless access to global resources via TLS.
  ThreadLocal::TypedSlot<ThreadLocalGlobalRateLimitClientImpl>& global_client_tls_;
  ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_cache_tls_;
};

inline std::unique_ptr<RateLimitClient> createLocalRateLimitClient(
    ThreadLocal::TypedSlot<ThreadLocalGlobalRateLimitClientImpl>& global_client_tls,
    ThreadLocal::TypedSlot<ThreadLocalBucketsCache>& buckets_cache_tls_) {
  return std::make_unique<LocalRateLimitClientImpl>(global_client_tls, buckets_cache_tls_);
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
