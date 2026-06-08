# Rate Limit Quota APIG Filter — Changelog

## v2.0: Token-Level Rate Limiting & Multi-Tenancy

**Branch**: `dev-support-token-limit`
**Baseline**: `develop`
**Diff**: 34 files, +14,822 / -490 lines

---

### Overview

在 `rate_limit_quota_apig` filter 原有 QPS 限流基础上，实现 AI Gateway 场景下的
**Token 级限流**、**并发控制**、**多租户隔离**、**多维度配额**全链路能力。

核心设计原则：
- 冷热分离 — 低频 bucket 走同步 RPC，高频 bucket 走本地 Token Bucket + 异步上报
- Lock-free 热路径 — Worker 线程零锁竞争，主线程负责 TLS 快照发布
- 多维度 fan-out — 同一 bucket 可拆分为 QPS / 并发 / Token 独立维度分别计量

---

### 1. Proto API Changes

#### 1.1 rate_limit_quota.proto (+153 lines)

**新增配置字段** (RateLimitQuotaFilterConfig):

| Field | Type | Description |
|-------|------|-------------|
| `cold_hot_config` (104) | `ColdHotSplitConfig` | 冷热分离配置。低频 bucket 走同步检查，超频率阈值后提升为 CachedBucket |
| `max_bucket_cache_entries` (105) | `uint32` | 桶缓存软上限，默认 50000，最大 10M |
| `tenant_key_source` (106) | `TenantKeySource` | 多租户键提取配置（Listener Metadata / FilterChain Name / Route Name / Header） |
| `rlqs_config_server` (107) | `GrpcService` | 配置发现服务地址，启用动态多维度配额 |
| `extract_agent_token_usage` (108) | `bool` | 是否提取 Agent 格式的 token 用量（DashScope Agent / Dify / Coze） |

**新增 Message**:

- **`ColdHotSplitConfig`** — 冷热分离策略
  - `disabled`: 禁用冷热分离
  - `hotspot_threshold`: 热点提升阈值（默认 10 次/窗口）
  - `frequency_window`: 统计窗口（默认 1s）
  - `max_tracked_buckets`: 追踪上限（默认 10000）
  - `cold_sync_timeout`: 冷路径超时（默认 20ms）
  - `cold_fallback_allow_on_error`: 冷路径失败放行策略
  - `no_sync_checker_policy`: 无检查器时策略（PROMOTE_TO_HOT / FAIL_OPEN / FAIL_CLOSE）

- **`TenantKeySource`** — 租户 / Scope 键提取
  - `TenantConfig`: 租户提取（LISTENER_METADATA / FILTER_CHAIN_NAME），支持 RE2 正则
  - `ScopeConfig`: Scope 提取（ROUTE_NAME / VIRTUAL_HOST_NAME / CLUSTER_NAME / GLOBAL / REQUEST_HEADER），支持 MD5 hash
  - `additional_scopes`: 额外维度提取

#### 1.2 rlqs.proto (+110 lines)

**新增 Service**:

```protobuf
service RateLimitQuotaConfigDiscoveryService {
  rpc StreamRlQsConfigs(stream DiscoveryRequest) returns (stream DiscoveryResponse);
  rpc FetchRlQsConfigs(DiscoveryRequest) returns (DiscoveryResponse);
  rpc GetQuotaConfig(GetQuotaConfigRequest) returns (GetQuotaConfigResponse);
}
```

**BucketUsage 扩展字段**:

| Field | Type | Description |
|-------|------|-------------|
| `tokens_consumed` (5) | `uint64` | 区间内消耗的 token 总量 |
| `active_requests` (6) | `uint64` | 当前活跃请求数（并发） |
| `input_tokens_consumed` (7) | `uint64` | 输入 token |
| `output_tokens_consumed` (8) | `uint64` | 输出 token |
| `cached_tokens_consumed` (9) | `uint64` | 缓存命中 token |

**BucketAction 扩展**:

| Field | Type | Description |
|-------|------|-------------|
| `concurrency_limit` (5) | `ConcurrencyLimit` | 并发上限（替代 token_bucket 策略） |
| `degradation_info.strict_request_mode` (4) | `bool` | 严格模式：每请求同步检查 |
| `degradation_info.deny_retry_after_ms` (5) | `uint32` | 拒绝缓存 TTL |
| `bucket_settings_override` | `BucketSettings` | 多维度场景下 per-action 的 settings 覆盖 |

---

### 2. New Modules

#### 2.1 Token Usage Extractor

**Files**: `token_usage_extractor.h` / `token_usage_extractor.cc` (+476 lines)

从 LLM 响应 body 中提取 token 用量，支持两种传输模式：

- **JSON body** — 非流式响应，`encodeData` 阶段 buffer 拼接后一次解析
- **SSE streaming** — 流式响应，逐 event 解析，支持 OpenAI `/v1/responses` 跨 event 合并

**支持的 LLM 格式**:

| Provider | JSON Path | 字段映射 |
|----------|-----------|---------|
| OpenAI | `usage.{prompt,completion,total}_tokens` | input / output / total |
| Anthropic | `usage.{input,output}_tokens` + `cache_creation_input_tokens` / `cache_read_input_tokens` | input / output / cached |
| Gemini | `usageMetadata.{promptTokenCount,candidatesTokenCount,totalTokenCount}` | input / output / total |
| Bedrock | `usage.{inputTokens,outputTokens,totalTokens}` | input / output / total |
| DashScope | `usage.{input_tokens,output_tokens,total_tokens}` | input / output / total |
| DashScope Agent | `usage.models[*].{input_tokens,output_tokens}` | 累加 (需开启 `extract_agent_token_usage`) |
| Dify | `metadata.usage.{total_tokens,...}` | (需开启 `extract_agent_token_usage`) |
| Coze | `data.usage.{token_count,output_count}` | (需开启 `extract_agent_token_usage`) |

**关键类**:
- `TokenUsageAccumulator` — 累加器，处理 explicit total vs sum fallback
- `OpenAiResponseStreamMerger` — SSE event 合并（`kMaxMergeBufferBytes` = 1 MiB）
- `extractSseJsonPayload()` — SSE `data:` 行提取
- `parseJsonObjectFromString()` — 安全 JSON 解析

#### 2.2 Global Hotspot Tracker

**File**: `global_hotspot_tracker.h` (+245 lines)

进程级滑动窗口频率计数器，用于冷热分离决策。

**设计**:
- **Lock-free**: 每 bucket 的 count / window_start 为 `std::atomic`，Worker 通过 CAS 滚动窗口
- **TLS COW**: 主线程维护 `main_entries_`，通过 `shared_ptr<const EntriesMap>` 发布到 Worker TLS
- **Publish coalescing**: N 次 register 批量合并为 1 次 TLS 发布
- **LRU eviction**: 超 `max_tracked_buckets` 时主线程扫描 `last_access_ns` 淘汰最旧条目

**接口**:
```
recordAccess(bucket_hash) → uint64_t  // Worker 热路径，返回当前窗口计数
isHot(count) → bool                    // count >= threshold
registerOnMain(bucket_hash)            // 异步注册新 bucket
```

#### 2.3 Config Discovery Client

**Files**: `config_discovery_client.h` / `config_discovery_client.cc` (+828 lines)

xDS 风格的双向 gRPC 流客户端，实现 `RateLimitQuotaConfigDiscoveryService` 消费端。

**职责**:
- 订阅 per-(tenant, scope) 的 `BucketSettings` 资源
- 接收 server push 的多维度配置（`_dim` tag 区分 QPS / 并发 / Token）
- 写入 `DynamicSettingsRegistry` 供 Worker 线程读取

**特性**:
- 重连退避：1s → 30s，±20% jitter
- SOTW 订阅：每次发送全量 resource_names
- AbandonAction：server 省略已订阅资源时，从 registry 中清除
- 订阅集 LRU：超上限时淘汰最久未访问的 (tenant, scope)

**resource_name 格式**: `"{tenant}|{scope_type}:{scope_value}"`
例如: `"t1|route:chat-api"`

#### 2.4 Dynamic Settings Registry

**File**: `dynamic_settings_registry.h` (+423 lines)

主线程写、Worker TLS 读的配置注册表，存储 per-(tenant, scope) 的多维度 BucketSettings。

**核心数据结构**:
```
Registry[tenant][scope] → vector<CachedBucketSettings>
  └─ CachedBucketSettings
       ├─ settings: RateLimitQuotaBucketSettings (proto)
       └─ string_overlay: vector<pair<key, value>>  // 预计算的 BucketId overlay
```

**性能优化**:
- `precomputeStringOverlay()` — 构建时提取 bucket_id_builder 中的 string_value 对，避免热路径 proto 反射
- 主线程 `update()` → 生成新 `shared_ptr<const Snapshot>` → TLS `set()` 发布
- Worker 读取零锁、零拷贝（shared_ptr 引用计数）

---

### 3. Enhanced Modules

#### 3.1 Filter (filter.h / filter.cc)

**filter.h** (+569 lines):

- 40+ 新 stats 计数器，覆盖全链路可观测：
  - 冷路径: `cold_path_sync_{started,allowed,denied,error}`
  - 热点: `hotspot_access_recorded`
  - Token 维度: `token_dim_sync_{started,allowed,denied,error}`, `tokens_consumed_{total,input,output,cached}`
  - 租户提取: `tenant_extract_{success,unknown}`, `tenant_chain_regex_unmatched`
  - 配置发现: `config_discovery_{stream_connect,response_received,...}`
  - 动态注册: `dynamic_registry_lookup_{hit,empty}`, `dynamic_variant_{cached,missing}`
  - Cache 发布: `bucket_cache_publish_{total,coalesced}`
- 保留 BucketId key 常量：`_tenant`, `_scope`, `_dim`
- Per-worker `RouteMd5Cache` (ThreadLocal)

**filter.cc** (+2190 lines):

请求处理主流程:
```
decodeHeaders
  ├─ extractTenantAndScope()          // 提取 _tenant / _scope
  ├─ matchBucket()                    // CEL matcher 匹配 BucketSettings
  ├─ composeBucketId()                // 构造 BucketId (含 tenant/scope/dim)
  ├─ coldHotDecision()                // 查 hotspot tracker 判定冷/热
  │   ├─ [cold] syncQuotaCheck()      // 同步 RPC 检查 → onQuotaCheckComplete
  │   └─ [hot]  shouldAllowRequest()  // 本地 token bucket 检查
  ├─ tryDynamicMultiDimensionCheck()  // 多维度 fan-out (QPS + 并发 + Token)
  │   ├─ lookupDynamicSettings()      // 查 DynamicSettingsRegistry
  │   └─ per-variant sync check       // 每维度独立同步检查
  └─ return Continue / StopIteration

encodeHeaders + encodeData
  ├─ extractTokenUsage()              // 解析 LLM 响应中的 token 用量
  ├─ creditPendingTokenUsageDelta()   // 记入 QuotaUsage
  └─ processSseEventForTokens()       // SSE 流式 token 提取
```

#### 3.2 Global Client (global_client_impl.h / global_client_impl.cc)

**global_client_impl.h** (+326 lines):
- `firstTickJitter()` — 报告定时器相位偏移，避免多 listener 同时 spike
- `effectiveRateLimitQuotaMaxBucketCacheEntries()` — bucket cache 上限计算，支持 env floor (`RATELIMIT_QUOTA_MIN_BUCKET_CACHE_ENTRIES`)
- Hotspot tracker 集成

**global_client_impl.cc** (+885 lines):
- `buildReports()` 上报 token 用量字段 (`tokens_consumed`, `input/output/cached_tokens_consumed`, `active_requests`)
- `onReceiveMessage()` 处理 `ConcurrencyLimit` 和 `strict_request_mode`
- Bucket cache idle eviction 双阈值（cap 内 5 min，超 cap 1 min）
- Publish coalescing（`scheduleWriteBucketsToTLS` 去抖）

#### 3.3 Quota Bucket Cache (quota_bucket_cache.h, +231 lines)

- `QuotaUsage` 新增原子字段: `tokens_consumed`, `input/output/cached_tokens_consumed`, `active_requests`
- `CachedBucket` 新增: `strict_request_mode`, `deny_until_ns`, `last_ack_ns`
- `BucketIdHash` 优化: `absl::InlinedVector<..., 8>` 避免小 bucket 的堆分配

#### 3.4 Token Bucket (token_bucket.h / token_bucket.cc, +143/-11 lines)

- 支持 token 消耗维度的令牌扣减
- 扩展接口适配并发限流场景

#### 3.5 Sync Quota Checker (sync_quota_checker.h, +58 lines)

- 同步配额 RPC 接口 (`AsyncQuotaCheckCallbacks`)
- 支持冷路径 / degradation mode / strict_request_mode 三种触发场景
- Wire protocol: `time_elapsed = 1ns` 标记同步检查请求

#### 3.6 Config (config.cc, +171 lines)

- 解析 `TenantKeySource` 配置，编译 `chain_name_pattern` 为 RE2
- 解析 `ColdHotSplitConfig`，初始化 `GlobalHotspotTracker`
- 解析 `rlqs_config_server`，初始化 `ConfigDiscoveryClient` + `DynamicSettingsRegistry`

---

### 4. Architecture

```
                    ┌─────────────────────────────────────────────────┐
                    │              Control Plane (RLQS Server)        │
                    │  ┌──────────────┐    ┌───────────────────────┐  │
                    │  │ RateLimitQuo │    │ RateLimitQuotaConfig  │  │
                    │  │ taService    │    │ DiscoveryService      │  │
                    │  │ (bidi gRPC)  │    │ (bidi gRPC / xDS)    │  │
                    │  └──────┬───────┘    └──────────┬────────────┘  │
                    └─────────┼───────────────────────┼──────────────-┘
                              │                       │
              ┌───────────────┼───────────────────────┼──────────────────┐
              │  Main Thread  │                       │                  │
              │               ▼                       ▼                  │
              │  ┌─────────────────────┐  ┌────────────────────────┐    │
              │  │ GlobalRateLimitCli  │  │ ConfigDiscoveryClient  │    │
              │  │ entImpl             │  │                        │    │
              │  │ - buildReports()    │  │ - subscribe(t, s)      │    │
              │  │ - onReceiveMessage()│  │ - onReceiveMessage()   │    │
              │  │ - bucket cache mgmt │  └───────────┬────────────┘    │
              │  └──────────┬──────────┘              │                 │
              │             │ TLS publish              │ update()        │
              │             ▼                          ▼                 │
              │  ┌───────────────────┐    ┌────────────────────────┐    │
              │  │ BucketsCache      │    │ DynamicSettingsRegistry│    │
              │  │ (TLS snapshot)    │    │ (TLS snapshot)         │    │
              │  └───────────────────┘    └────────────────────────┘    │
              │                                                         │
              │  ┌────────────────────────┐                            │
              │  │ GlobalHotspotTracker   │                            │
              │  │ (TLS COW + atomics)    │                            │
              │  └────────────────────────┘                            │
              └─────────────────────────────────────────────────────────┘
                              │ TLS read (lock-free)
              ┌───────────────┼─────────────────────────────────────────┐
              │  Worker Thread│                                         │
              │               ▼                                         │
              │  ┌──────────────────────────────────────────────────┐   │
              │  │              RateLimitQuotaFilter                │   │
              │  │                                                  │   │
              │  │  Request Flow:                                   │   │
              │  │  ┌──────────┐    ┌──────────┐    ┌───────────┐  │   │
              │  │  │ Extract  │───▶│ Cold/Hot │───▶│ Allow /   │  │   │
              │  │  │ Tenant & │    │ Decision │    │ Deny      │  │   │
              │  │  │ Scope    │    └────┬─────┘    └───────────┘  │   │
              │  │  └──────────┘         │                         │   │
              │  │                  ┌────┴─────┐                   │   │
              │  │              [cold]      [hot]                  │   │
              │  │            sync RPC    local TB                 │   │
              │  │                                                 │   │
              │  │  Response Flow:                                 │   │
              │  │  ┌──────────────────┐    ┌──────────────────┐  │   │
              │  │  │ TokenUsageExtrac │───▶│ Report to RLQS   │  │   │
              │  │  │ tor (JSON / SSE) │    │ (async)          │  │   │
              │  │  └──────────────────┘    └──────────────────┘  │   │
              │  └──────────────────────────────────────────────────┘   │
              └─────────────────────────────────────────────────────────┘
```

---

### 5. Configuration Example

```yaml
http_filters:
- name: envoy.filters.http.rate_limit_quota_apig
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.rate_limit_quota_apig.v3.RateLimitQuotaFilterConfig
    domain: "ai-gateway"
    rlqs_server:
      envoy_grpc:
        cluster_name: rlqs_server
    reporting_interval: 5s
    max_bucket_cache_entries: 100000

    # Token usage extraction
    extract_agent_token_usage: true

    # Cold/Hot split
    cold_hot_config:
      hotspot_threshold: 10
      frequency_window: 1s
      max_tracked_buckets: 50000
      cold_sync_timeout: 0.02s
      cold_fallback_allow_on_error: true

    # Multi-tenancy
    tenant_key_source:
      tenant:
        order: [LISTENER_METADATA, FILTER_CHAIN_NAME]
        metadata_namespace: "apig_tenant"
        metadata_field: "tenant_id"
        chain_name_pattern: "^tenant-(.+)-fc$"
        capture_group: 1
      scope:
        type: ROUTE_NAME
        prefix: "route:"
      additional_scopes:
        - type: REQUEST_HEADER
          header_name: "x-api-key"
          bucket_key: "_api_key"
          prefix: "key:"

    # Config discovery for multi-dimension
    rlqs_config_server:
      envoy_grpc:
        cluster_name: rlqs_config_server

    # Degradation mode
    degradation_mode_config:
      sync_check_timeout: 0.05s
      fallback_allow_on_timeout: true
```

---

### 6. Test Coverage

| Test File | Lines | Coverage |
|-----------|-------|---------|
| `filter_test.cc` | +3140 | 冷热分离、多租户、多维度、token 限流、并发限流、deny cache、降级模式 |
| `token_usage_extractor_test.cc` | +1464 | 全格式 token 提取（OpenAI / Anthropic / Gemini / Bedrock / DashScope / Agent）、SSE streaming、边界 case |
| `client_test.cc` | +1068 | gRPC 生命周期、token/concurrency 上报、BucketAction 处理 |
| `config_discovery_client_test.cc` | +733 | 订阅/推送/AbandonAction/重连退避 |
| `dynamic_settings_registry_test.cc` | +581 | update/lookup/eviction/TLS publish |
| `real_server_e2e_integration_test.cc` | +954 | 与真实 quota server 的端到端测试 |
| `hotspot_tracker_test.cc` | +183 | 频率计数、窗口滚动、LRU 淘汰 |
| `config_test.cc` | +47 | 配置解析 |

---

### 7. Review Checklist

- [ ] **Proto 兼容性**: field 编号 104-108 / BucketUsage 5-9 / BucketAction 5 是否与 quota server 对齐
- [ ] **冷热 CAS**: `global_hotspot_tracker.h` 窗口滚动的 compare_exchange_strong 正确性
- [ ] **多维度 fan-out**: `tryDynamicMultiDimensionCheck` 中 variant BucketId 构造 + rollback 逻辑
- [ ] **Token 提取**: SSE stream merge 边界（跨 chunk split、`kMaxMergeBufferBytes` 溢出）
- [ ] **内存上限**: bucket cache / hotspot tracker / config discovery 三处 LRU 淘汰逻辑
- [ ] **并发计数**: `active_requests` 的 increment/decrement 配对（destroy 时 rollback）
- [ ] **deny cache TTL**: `primeStrictDenyCache` 的 monotonic_ns 计算
- [ ] **TLS 发布频率**: publish coalescing 在高并发下的行为
