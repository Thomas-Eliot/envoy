#include "source/extensions/filters/http/rate_limit_quota_apig/token_usage_extractor.h"

#include <climits>
#include <vector>

#include "source/common/json/json_loader.h"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace RateLimitQuotaApig {

namespace {

absl::optional<int64_t> tryNumericLeaf(const Json::Object& o, absl::string_view leaf) {
  const std::string key{leaf};
  auto result = o.getValue(key);
  if (!result.ok()) {
    return absl::nullopt;
  }
  if (auto* iv = absl::get_if<int64_t>(&*result)) {
    return *iv;
  }
  if (auto* dv = absl::get_if<double>(&*result)) {
    return static_cast<int64_t>(*dv);
  }
  return absl::nullopt;
}

absl::optional<int64_t> tryNumericAtPath(const Json::Object& root, absl::string_view dot_path) {
  std::vector<absl::string_view> parts = absl::StrSplit(dot_path, '.');
  if (parts.empty()) {
    return absl::nullopt;
  }
  std::vector<std::string> keys;
  keys.reserve(parts.size());
  for (auto p : parts) {
    keys.emplace_back(p);
  }

  const Json::Object* cur = &root;
  for (size_t i = 0; i + 1 < keys.size(); ++i) {
    auto sub = cur->getObjectNoThrow(keys[i], false);
    if (!sub.ok() || sub.value() == nullptr) {
      return absl::nullopt;
    }
    cur = sub.value().get();
  }
  return tryNumericLeaf(*cur, keys.back());
}

absl::optional<int64_t> firstExistingNumericFromPaths(
    const Json::Object& o, const std::vector<absl::string_view>& paths) {
  for (absl::string_view p : paths) {
    auto v = tryNumericAtPath(o, p);
    if (v.has_value()) {
      return v;
    }
  }
  return absl::nullopt;
}

// Sum a numeric leaf across every element of the JSON array reachable via
// `array_path` (dotted). Returns nullopt when the array is missing/empty or
// no element exposes the leaf as a number. Used for response shapes that
// aggregate per-model usage in an array, e.g. DashScope `usage.models[]`.
absl::optional<int64_t> sumNumericInArray(const Json::Object& root,
                                          absl::string_view array_path,
                                          absl::string_view leaf) {
  std::vector<absl::string_view> parts = absl::StrSplit(array_path, '.');
  if (parts.empty()) {
    return absl::nullopt;
  }
  const Json::Object* cur = &root;
  for (size_t i = 0; i + 1 < parts.size(); ++i) {
    auto sub = cur->getObjectNoThrow(std::string{parts[i]}, false);
    if (!sub.ok() || sub.value() == nullptr) {
      return absl::nullopt;
    }
    cur = sub.value().get();
  }
  std::vector<Json::ObjectSharedPtr> arr;
  try {
    arr = cur->getObjectArray(std::string{parts.back()}, true);
  } catch (const Json::Exception&) {
    return absl::nullopt;
  }
  if (arr.empty()) {
    return absl::nullopt;
  }
  int64_t sum = 0;
  bool any = false;
  for (const auto& el : arr) {
    if (el == nullptr) {
      continue;
    }
    if (auto v = tryNumericLeaf(*el, leaf)) {
      // Saturating add to prevent overflow with large/malicious data.
      if (*v > 0 && sum > INT64_MAX - *v) {
        sum = INT64_MAX;
      } else if (*v < 0 && sum < INT64_MIN - *v) {
        sum = INT64_MIN;
      } else {
        sum += *v;
      }
      any = true;
    }
  }
  return any ? absl::optional<int64_t>(sum) : absl::nullopt;
}

struct ArrayLeafPath {
  absl::string_view array_path;
  absl::string_view leaf;
};

absl::optional<int64_t>
firstExistingNumericFromArrayPaths(const Json::Object& o,
                                   const std::vector<ArrayLeafPath>& paths) {
  for (const auto& p : paths) {
    if (auto v = sumNumericInArray(o, p.array_path, p.leaf)) {
      return v;
    }
  }
  return absl::nullopt;
}

// Canonical LLM-provider input paths (always probed). Mirrors wasm-go
// UsageInputTokensPath* order.
const std::vector<absl::string_view>& inputTokenCorePaths() {
  static const std::vector<absl::string_view> kPaths = {
      "usage.prompt_tokens",
      "usage.input_tokens",
      "response.usage.input_tokens",
      "usageMetadata.promptTokenCount",
      "message.usage.input_tokens",
      "usage.inputTokens",
      "amazon-bedrock-invocationMetrics.inputTokenCount",
  };
  return kPaths;
}

// Agent-shaped scalar input paths (Dify `metadata.usage.*` and Coze
// `data.usage.*_count`, plus a bare `usage.input_count` for when
// filter.cc:extractUsageObject has already unwrapped the `usage` key in
// tail-only mode). Only probed when extract_agent_token_usage is enabled.
const std::vector<absl::string_view>& inputTokenAgentPaths() {
  static const std::vector<absl::string_view> kPaths = {
      "metadata.usage.prompt_tokens",
      "data.usage.input_count",
      "usage.input_count",
  };
  return kPaths;
}

const std::vector<absl::string_view>& outputTokenCorePaths() {
  static const std::vector<absl::string_view> kPaths = {
      "usage.completion_tokens",
      "usage.output_tokens",
      "response.usage.output_tokens",
      "usageMetadata.candidatesTokenCount",
      "message.usage.output_tokens",
      "usage.outputTokens",
      "amazon-bedrock-invocationMetrics.outputTokenCount",
  };
  return kPaths;
}

const std::vector<absl::string_view>& outputTokenAgentPaths() {
  static const std::vector<absl::string_view> kPaths = {
      "metadata.usage.completion_tokens",
      "data.usage.output_count",
      "usage.output_count",
  };
  return kPaths;
}

const std::vector<absl::string_view>& totalTokenCorePaths() {
  static const std::vector<absl::string_view> kPaths = {
      "usage.total_tokens",
      "response.usage.total_tokens",
      "usageMetadata.totalTokenCount",
      "usage.totalTokens",
  };
  return kPaths;
}

const std::vector<absl::string_view>& totalTokenAgentPaths() {
  static const std::vector<absl::string_view> kPaths = {
      "metadata.usage.total_tokens",
      "data.usage.token_count",
      "usage.token_count",
  };
  return kPaths;
}

// Per-model usage entries in an array (DashScope agent/application form):
//   {"usage":{"models":[{"input_tokens":N,"output_tokens":M,"cached_tokens":K,
//                        "model_id":"..."}, ...]}}
// Each category sums across the array so a multi-model agent call credits
// the combined cost.
const std::vector<ArrayLeafPath>& inputTokenArrayPaths() {
  static const std::vector<ArrayLeafPath> kPaths = {
      {"usage.models", "input_tokens"},
  };
  return kPaths;
}
const std::vector<ArrayLeafPath>& outputTokenArrayPaths() {
  static const std::vector<ArrayLeafPath> kPaths = {
      {"usage.models", "output_tokens"},
  };
  return kPaths;
}
const std::vector<ArrayLeafPath>& cachedTokenArrayPaths() {
  static const std::vector<ArrayLeafPath> kPaths = {
      {"usage.models", "cached_tokens"},
  };
  return kPaths;
}

} // namespace

void TokenUsageAccumulator::reset() {
  input_token_ = 0;
  output_token_ = 0;
  anthropic_cache_creation_ = 0;
  anthropic_cache_read_ = 0;
  generic_cached_token_ = 0;
  current_effective_total_ = 0;
}

void TokenUsageAccumulator::ingestJsonObject(const Json::Object& o) {
  if (auto v = firstExistingNumericFromPaths(o, inputTokenCorePaths())) {
    input_token_ = *v;
  } else if (extract_agent_token_usage_) {
    if (auto v = firstExistingNumericFromPaths(o, inputTokenAgentPaths())) {
      input_token_ = *v;
    } else if (auto v = firstExistingNumericFromArrayPaths(o, inputTokenArrayPaths())) {
      input_token_ = *v;
    }
  }
  if (auto v = firstExistingNumericFromPaths(o, outputTokenCorePaths())) {
    output_token_ = *v;
  } else if (extract_agent_token_usage_) {
    if (auto v = firstExistingNumericFromPaths(o, outputTokenAgentPaths())) {
      output_token_ = *v;
    } else if (auto v = firstExistingNumericFromArrayPaths(o, outputTokenArrayPaths())) {
      output_token_ = *v;
    }
  }

  // Anthropic non-streaming and message_delta carry cache fields under top-level
  // `usage`; streaming `message_start` nests them under `message.usage` instead.
  if (auto v = tryNumericAtPath(o, "usage.cache_creation_input_tokens")) {
    anthropic_cache_creation_ = *v;
  } else if (auto v = tryNumericAtPath(o, "message.usage.cache_creation_input_tokens")) {
    anthropic_cache_creation_ = *v;
  }
  if (auto v = tryNumericAtPath(o, "usage.cache_read_input_tokens")) {
    anthropic_cache_read_ = *v;
  } else if (auto v = tryNumericAtPath(o, "message.usage.cache_read_input_tokens")) {
    anthropic_cache_read_ = *v;
  }

  // Array-shaped cached tokens (DashScope-style per-model entries) — gated.
  if (extract_agent_token_usage_) {
    if (auto v = firstExistingNumericFromArrayPaths(o, cachedTokenArrayPaths())) {
      generic_cached_token_ = *v;
    }
  }

  absl::optional<int64_t> explicit_total =
      firstExistingNumericFromPaths(o, totalTokenCorePaths());
  if (!explicit_total.has_value() && extract_agent_token_usage_) {
    explicit_total = firstExistingNumericFromPaths(o, totalTokenAgentPaths());
  }
  if (explicit_total.has_value()) {
    current_effective_total_ = *explicit_total;
  } else {
    int64_t sum = 0;
    for (int64_t v : {input_token_, output_token_, anthropic_cache_creation_,
                      anthropic_cache_read_, generic_cached_token_}) {
      if (v > 0 && sum > INT64_MAX - v) {
        sum = INT64_MAX;
      } else if (v < 0 && sum < INT64_MIN - v) {
        sum = INT64_MIN;
      } else {
        sum += v;
      }
    }
    current_effective_total_ = sum;
  }
}

absl::optional<std::string> OpenAiResponseStreamMerger::transformEvent(absl::string_view raw_event) {
  std::string ev{absl::StripAsciiWhitespace(raw_event)};
  if (pending_) {
    if (ev.empty()) {
      pending_ = false;
      std::string merged = std::move(buffer_);
      buffer_.clear();
      return merged;
    }
    if (buffer_.size() + ev.size() > kMaxMergeBufferBytes) {
      pending_ = false;
      std::string merged = std::move(buffer_);
      buffer_.clear();
      return merged;
    }
    absl::StrAppend(&buffer_, ev);
    return absl::nullopt;
  }

  const bool has_completed = absl::StrContains(ev, "\"response.completed\"");
  const bool has_usage = absl::StrContains(ev, "\"usage\"");
  if (has_completed && !has_usage) {
    pending_ = true;
    buffer_ = std::move(ev);
    return absl::nullopt;
  }
  return ev;
}

absl::optional<std::string> OpenAiResponseStreamMerger::flush() {
  if (!pending_) {
    return absl::nullopt;
  }
  pending_ = false;
  std::string merged = std::move(buffer_);
  buffer_.clear();
  return merged;
}

void OpenAiResponseStreamMerger::reset() {
  pending_ = false;
  buffer_.clear();
}

std::string extractSseJsonPayload(absl::string_view sse_event_block) {
  std::string block{absl::StripAsciiWhitespace(sse_event_block)};
  if (block.empty()) {
    return {};
  }

  std::vector<std::string> data_bodies;
  for (absl::string_view line : absl::StrSplit(block, '\n', absl::SkipEmpty())) {
    absl::string_view l = absl::StripAsciiWhitespace(line);
    if (l.empty()) {
      continue;
    }
    if (absl::StartsWithIgnoreCase(l, "data:")) {
      l = absl::StripAsciiWhitespace(l.substr(5));
      if (l == "[DONE]") {
        continue;
      }
      data_bodies.emplace_back(std::string{l});
    }
  }

  if (!data_bodies.empty()) {
    return absl::StrJoin(data_bodies, "");
  }

  return block;
}

Json::ObjectSharedPtr parseJsonObjectFromString(absl::string_view json_text) {
  auto parsed = Json::Factory::loadFromStringNoThrow(std::string{json_text});
  if (!parsed.ok() || *parsed == nullptr || !(*parsed)->isObject()) {
    return nullptr;
  }
  return *parsed;
}

} // namespace RateLimitQuotaApig
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
