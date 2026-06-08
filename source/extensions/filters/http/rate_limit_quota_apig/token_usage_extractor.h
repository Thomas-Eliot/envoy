#pragma once

#include <climits>
#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

#include "envoy/json/json_object.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

// Accumulates per-stream token fields to mirror wasm-go pkg/tokenusage GetTokenUsage +
// ExtractTotalTokens (same path order and explicit-total vs sum fallback).
//
// When `extract_agent_token_usage` is false (default), only canonical LLM
// provider paths are tried (OpenAI, Anthropic, Gemini, Bedrock, DashScope
// legacy). When true, the extractor additionally probes agent-shaped formats:
// DashScope `usage.models[*]`, Dify `metadata.usage.*`, Coze `data.usage.*`.
class TokenUsageAccumulator {
public:
  TokenUsageAccumulator() = default;
  explicit TokenUsageAccumulator(bool extract_agent_token_usage)
      : extract_agent_token_usage_(extract_agent_token_usage) {}
  void setExtractAgentTokenUsage(bool v) { extract_agent_token_usage_ = v; }

  void ingestJsonObject(const Json::Object& o);
  void reset();

  // Latest effective total after the last ingest (explicit total field or sum of components).
  int64_t effectiveTotal() const { return current_effective_total_; }
  int64_t inputTokens() const { return input_token_; }
  int64_t outputTokens() const { return output_token_; }
  int64_t cachedTokens() const {
    int64_t sum = anthropic_cache_creation_;
    if (anthropic_cache_read_ > 0 && sum > INT64_MAX - anthropic_cache_read_) {
      return INT64_MAX;
    }
    sum += anthropic_cache_read_;
    if (generic_cached_token_ > 0 && sum > INT64_MAX - generic_cached_token_) {
      return INT64_MAX;
    }
    return sum + generic_cached_token_;
  }

private:
  int64_t input_token_{0};
  int64_t output_token_{0};
  int64_t anthropic_cache_creation_{0};
  int64_t anthropic_cache_read_{0};
  // Cache tokens reported by formats that don't use the Anthropic split
  // (e.g. DashScope agent/application response where each `usage.models[*]`
  // element may carry a `cached_tokens` field).
  int64_t generic_cached_token_{0};
  int64_t current_effective_total_{0};
  bool extract_agent_token_usage_{false};
};

// OpenAI /v1/responses streaming: usage may span multiple SSE events; mirror
// mergeLargeResponseAPIChunks in wasm-go/pkg/tokenusage/tokenusage.go.
class OpenAiResponseStreamMerger {
public:
  static constexpr size_t kMaxMergeBufferBytes = 1 << 20; // 1 MiB
  // Returns a payload to parse when this event should be JSON-processed, or
  // nullopt when the event was absorbed into an in-progress merge.
  absl::optional<std::string> transformEvent(absl::string_view raw_event);

  // If a merge was in progress, return buffered bytes as a final payload.
  absl::optional<std::string> flush();

  void reset();

private:
  bool pending_{false};
  std::string buffer_;
};

// Strip `data:` SSE lines (join multiple data lines with '\n'); if no data lines,
// try the whole block. Skips "[DONE]" lines.
std::string extractSseJsonPayload(absl::string_view sse_event_block);

// Parse JSON object from a payload string; returns nullptr on failure.
Json::ObjectSharedPtr parseJsonObjectFromString(absl::string_view json_text);

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
