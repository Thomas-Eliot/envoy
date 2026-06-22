#include "source/extensions/filters/http/rate_limit_quota_apig/client_impl.h"

#include <cstddef>
#include <limits>
#include <memory>

#include "envoy/type/v3/ratelimit_strategy.pb.h"
#include "envoy/type/v3/token_bucket.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/global_client_impl.h"
#include "source/extensions/filters/http/rate_limit_quota_apig/quota_bucket_cache.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

using BucketAction = RateLimitQuotaResponse::BucketAction;

void LocalRateLimitClientImpl::createBucket(
    const BucketId& bucket_id, size_t id, const BucketAction& default_bucket_action,
    std::unique_ptr<envoy::type::v3::RateLimitStrategy> fallback_action,
    std::chrono::milliseconds fallback_ttl, bool initial_request_allowed,
    const DenyResponseSettings& deny_response_settings) {
  std::shared_ptr<GlobalRateLimitClientImpl> global_client = getGlobalClient();
  RELEASE_ASSERT(global_client != nullptr,
                 "RLQS global client is null when creating bucket; TLS slot may not be initialized");
  global_client->createBucket(bucket_id, id, default_bucket_action, std::move(fallback_action),
                              fallback_ttl, initial_request_allowed, deny_response_settings);
}

std::shared_ptr<CachedBucket> LocalRateLimitClientImpl::getBucket(size_t id) {
  ShardedBucketsCacheConstSharedPtr sharded = getShardedBucketsCache();
  RELEASE_ASSERT(sharded != nullptr,
                 "RLQS buckets cache is null when getting bucket; TLS slot may not be initialized");
  // Pin the shard pointer so a concurrent main-thread publish swapping the
  // sharded snapshot cannot release the per-shard map mid-lookup.
  std::shared_ptr<const BucketsCache> shard = sharded->shardForBucket(id);
  auto bucket_it = shard->find(id);
  return (bucket_it != shard->end()) ? bucket_it->second : nullptr;
}

void LocalRateLimitClientImpl::removeBucket(size_t id) {
  std::shared_ptr<GlobalRateLimitClientImpl> global_client = getGlobalClient();
  if (global_client != nullptr) {
    global_client->removeBucket(id);
  }
}

void LocalRateLimitClientImpl::reportQuotaUsage(const BucketId& bucket_id, const QuotaUsage& usage) {
  std::shared_ptr<GlobalRateLimitClientImpl> global_client = getGlobalClient();
  if (global_client != nullptr) {
    global_client->reportQuotaUsage(bucket_id, usage);
  } else {
    ENVOY_LOG(debug, "RLQS global client is null when reporting quota usage; usage report dropped");
  }
}

uint64_t LocalRateLimitClientImpl::recordHotspotAccess(size_t bucket_id_hash) {
  std::shared_ptr<GlobalRateLimitClientImpl> global_client = getGlobalClient();
  if (global_client == nullptr) {
    return std::numeric_limits<uint64_t>::max();
  }
  return global_client->recordHotspotAccess(bucket_id_hash);
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
