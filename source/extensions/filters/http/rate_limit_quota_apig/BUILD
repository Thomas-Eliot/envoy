load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "rate_limit_quota_apig",
    srcs = [
        "filter.cc",
        "token_usage_extractor.cc",
    ],
    hdrs = [
        "filter.h",
        "sync_quota_checker.h",
        "token_usage_extractor.h",
    ],
    external_deps = ["ssl"],
    deps = [
        ":client_lib",
        ":config_discovery_client_lib",
        ":dynamic_settings_registry",
        ":matcher_lib",
        ":quota_bucket_cache",
        "//envoy/grpc:async_client_manager_interface",
        "//envoy/registry",
        "//source/common/common:hex_lib",
        "//source/common/http:headers_lib",
        "//source/common/http:message_lib",
        "//source/common/http:utility_lib",
        "//source/common/http/matching:data_impl_lib",
        "//source/common/json:json_loader_lib",
        "//source/common/matcher:matcher_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "//source/extensions/matching/input_matchers/cel_matcher:config",
        "@com_googlesource_code_re2//:re2",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":config_discovery_client_lib",
        ":dynamic_settings_registry",
        ":global_client_lib",
        ":rate_limit_quota_apig",
        "//envoy/grpc:async_client_manager_interface",
        "//envoy/registry",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "client_lib",
    srcs = ["client_impl.cc"],
    hdrs = ["client_impl.h"],
    deps = [
        ":global_client_lib",
        ":quota_bucket_cache",
        "//envoy/grpc:async_client_interface",
        "//envoy/grpc:status",
        "//source/common/common:statusor_lib",
        "//source/common/grpc:typed_async_client_lib",
        "//source/common/tracing:http_tracer_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "global_client_lib",
    srcs = ["global_client_impl.cc"],
    hdrs = [
        "global_client_impl.h",
        "global_hotspot_tracker.h",
        "time_utils.h",
    ],
    external_deps = ["abseil_synchronization"],
    deps = [
        ":quota_bucket_cache",
        "//envoy/grpc:async_client_interface",
        "//envoy/grpc:status",
        "//source/common/common:statusor_lib",
        "//source/common/grpc:typed_async_client_lib",
        "//source/common/tracing:http_tracer_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/service/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "matcher_lib",
    srcs = ["matcher.cc"],
    hdrs = ["matcher.h"],
    deps = [
        "//envoy/registry",
        "//source/common/http:headers_lib",
        "//source/common/http:message_lib",
        "//source/common/http:utility_lib",
        "//source/common/http/matching:data_impl_lib",
        "//source/common/matcher:matcher_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota_apig/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "quota_bucket_cache",
    hdrs = ["quota_bucket_cache.h"],
    deps = [
        ":token_bucket",
        "//source/common/http:headers_lib",
        "//source/common/http:utility_lib",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota_apig/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "token_bucket",
    hdrs = ["token_bucket.h"],
    srcs = ["token_bucket.cc"],
    external_deps = ["abseil_synchronization"],
    deps = [
        "//envoy/common:time_interface",
        "//source/common/common:logger_lib",
        "//source/common/common:utility_lib",
    ],
)

envoy_cc_library(
    name = "dynamic_settings_registry",
    hdrs = ["dynamic_settings_registry.h"],
    external_deps = ["abseil_synchronization"],
    deps = [
        "//envoy/stats:stats_interface",
        "//envoy/thread_local:thread_local_interface",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota_apig/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "config_discovery_client_lib",
    srcs = ["config_discovery_client.cc"],
    hdrs = ["config_discovery_client.h"],
    deps = [
        ":dynamic_settings_registry",
        "//envoy/event:dispatcher_interface",
        "//envoy/event:timer_interface",
        "//envoy/grpc:async_client_interface",
        "//envoy/grpc:status",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/grpc:common_lib",
        "//source/common/grpc:typed_async_client_lib",
        "//source/common/protobuf",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota_apig/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/discovery/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota_apig/v3:pkg_cc_proto",
    ],
)
