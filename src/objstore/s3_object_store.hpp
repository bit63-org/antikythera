// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// An ObjectStore that speaks S3 (.kiro/specs/oar-blk-data-plane/
// Requirements 8.2 and 8.9, design "Components"): HTTP/1.1 GETs, HEADs and
// PUTs over TCP or TLS to any S3-compatible endpoint (AWS S3, MinIO,
// SeaweedFS, Ceph RGW). HEAD and PUT are hold's, for snapshot uploads
// (.kiro/specs/block-volume-service/ task 20).
//
//   - Path-style URLs (http://host/bucket/key) by default, which every
//     S3-compatible store accepts; virtual-host style as an option.
//   - AWS Signature V4 with the configured credentials (a read-only key
//     scoped to the image bucket), or anonymous for a public bucket.
//   - TLS verifies the server against the configured CA file, or the
//     system's trust store when none is given, and checks its name; TLS
//     1.2 or later. Plain HTTP is for a store on a trusted local network
//     only (harbor, tests): images are checked against their digests
//     either way, but credentials would cross in the clear.
//
// Responses are held to exactly what was asked for (Requirement 8.9): a
// range GET must answer 206 with a Content-Range equal to the request and
// a matching Content-Length, or 200 with exactly the bytes asked for when
// the range is the whole object; no chunked encoding, nothing past the
// declared body. 404 and 416 are not_found, 401 and 403 denied, 429 and
// 5xx io; anything else is bad_response. A connection that answered with
// an error, or said "Connection: close", is not reused.
//
// A HEAD must answer 200 with a Content-Length (the object's size) and no
// body. A PUT is signed over the SHA-256 of its body (x-amz-content-sha256
// carries it, so the store refuses a body changed in transit) and sends a
// Content-Length; it must answer 200, with a short body at most (S3 sends
// none; anything up to 64 KiB is read and dropped so the connection can be
// reused). A PUT replaces the object, so retrying one is safe.
//
// Connections are kept alive in a small pool shared by all callers, so the
// fetcher's workers each reuse one. A pooled connection the server closed
// while idle is retried once on a new connection. Every socket operation
// polls against the caller's deadline.
//
// Thread-safe.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "objstore/object_store.hpp"
#include "objstore/sigv4.hpp"

namespace ak::objstore {

struct S3Config {
    bool tls{true};
    std::string host;       // DNS name or IP address of the endpoint
    std::uint16_t port{0};  // 0: 443 with TLS, 80 without
    std::string bucket;
    std::string region{"us-east-1"};
    bool path_style{true};
    std::optional<SigV4Credentials> credentials;  // none: anonymous
    std::string ca_file;                          // empty: system trust store
    std::size_t max_idle_connections{8};
    // Empty: system_clock::now (for x-amz-date).
    std::function<std::chrono::system_clock::time_point()> clock;
};

enum class S3ConfigError : std::uint8_t {
    no_host,
    no_bucket,    // or one that is not a valid DNS label set for virtual-host style
    bad_ca_file,  // the CA file could not be loaded
    tls_failure,  // OpenSSL could not set up a context
};

[[nodiscard]] auto to_string(S3ConfigError e) noexcept -> const char*;

struct S3Counters {
    std::uint64_t requests{0};
    std::uint64_t connections{0};  // opened
    std::uint64_t reused{0};       // requests sent on a pooled connection
    std::uint64_t stale{0};        // pooled connections found closed and replaced
};

class S3ObjectStore final : public ObjectStore {
public:
    [[nodiscard]] static auto create(S3Config config)
        -> std::expected<std::unique_ptr<S3ObjectStore>, S3ConfigError>;

    S3ObjectStore(const S3ObjectStore&) = delete;
    auto operator=(const S3ObjectStore&) -> S3ObjectStore& = delete;
    S3ObjectStore(S3ObjectStore&&) = delete;
    auto operator=(S3ObjectStore&&) -> S3ObjectStore& = delete;
    ~S3ObjectStore() override;

    [[nodiscard]] auto get_range(std::string_view key, std::uint64_t offset,
                                 std::span<std::byte> out, Clock::time_point deadline)
        -> std::expected<void, FetchError> override;
    [[nodiscard]] auto get(std::string_view key, std::size_t max_bytes, Clock::time_point deadline)
        -> std::expected<std::vector<std::byte>, FetchError> override;
    [[nodiscard]] auto head(std::string_view key, Clock::time_point deadline)
        -> std::expected<std::uint64_t, FetchError> override;
    [[nodiscard]] auto put(std::string_view key, std::span<const std::byte> bytes,
                           Clock::time_point deadline) -> std::expected<void, FetchError> override;

    [[nodiscard]] auto counters() const -> S3Counters;

    class Connection;

private:
    struct TlsContext;
    struct Range {
        std::uint64_t offset;
        std::uint64_t length;
    };
    // Where a response body goes: a fixed buffer, or a vector up to a cap.
    struct Sink {
        std::span<std::byte> fixed;
        std::vector<std::byte>* grow{nullptr};
        std::size_t max{0};
    };
    enum class Method : std::uint8_t {
        get,
        head,
        put,
    };
    // One request: GET (a range into `sink.fixed`, or the whole object
    // into `sink.grow`), HEAD (the size into `size`) or PUT of `body`.
    struct Call {
        Method method{Method::get};
        std::optional<Range> range;
        Sink sink;
        std::span<const std::byte> body;
        std::uint64_t* size{nullptr};
    };

    S3ObjectStore(S3Config config, std::unique_ptr<TlsContext> tls);

    [[nodiscard]] auto request(std::string_view key, const Call& call, Clock::time_point deadline)
        -> std::expected<void, FetchError>;
    [[nodiscard]] auto exchange(Connection& c, const std::string& text, const Call& call,
                                Clock::time_point deadline, bool& reusable, bool& got_any)
        -> std::expected<void, FetchError>;
    [[nodiscard]] auto build_request(std::string_view key, const Call& call) const
        -> std::expected<std::string, FetchError>;
    [[nodiscard]] auto take_connection(Clock::time_point deadline, bool& pooled)
        -> std::expected<std::unique_ptr<Connection>, FetchError>;
    auto give_back(std::unique_ptr<Connection> c) -> void;

    S3Config _config;
    std::unique_ptr<TlsContext> _tls;
    std::string _host_header;
    mutable std::mutex _mutex;
    std::vector<std::unique_ptr<Connection>> _idle;
    S3Counters _counters;
};

}  // namespace ak::objstore
