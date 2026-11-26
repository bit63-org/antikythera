// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The HTTP half of a network role's metadata service
// (.kiro/specs/oar-net-data-plane/ Requirements 13.4 to 13.8, design
// "Metadata service"; task 21.4). Pure functions and values, no sockets:
// MetadataServer (metadata_server.hpp) runs them over connections.
//
// parse_request reads one request head from bytes a guest sent, so it is
// strict and fuzzed (fuzz/fuzz_metadata_http.cpp):
//
//   - the request line is "METHOD SP origin-form SP HTTP/1.0|1.1" and at
//     most max_request_line bytes; bare LF line endings and obsolete line
//     folding are refused;
//   - the header fields after it are at most max_request_headers bytes and
//     max_request_fields fields;
//   - a body is refused: Content-Length must be 0 when present, and any
//     Transfer-Encoding is refused (the token PUT has an empty body);
//   - a field the service reads (the token, the TTL, Content-Length) may
//     appear once only, so a proxy and this parser cannot disagree on it.
//
// Tokens (Requirements 13.6 to 13.8) are
//
//   base64url(version u8 | nic_id be64 | expiry be64 | nonce [16] | mac [32])
//
// with no padding (87 characters), the MAC an HMAC-SHA256 over the 33
// bytes before it and the record's instance ID, under a 32-byte key the
// role draws from the OpenSSL RNG when it starts. The key never leaves the
// TokenKey, so every token dies with the role. Expiry is in seconds on the
// role's steady clock, which does not jump with the wall clock.
//
// answer() is the path table and the IMDSv2 rules for one parsed request
// and one NIC's view: its signed record and what the role's mapping and
// VPC config say about its addresses.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "oar/net/neighbor.hpp"
#include "oar/net/vtep_policy.hpp"
#include "proto/instance_metadata.hpp"

namespace ak::oar::net {

// ---- requests -------------------------------------------------------------------

inline constexpr std::size_t max_request_line = 2048;     // without its CRLF
inline constexpr std::size_t max_request_headers = 8192;  // fields and the blank line
inline constexpr std::size_t max_request_fields = 32;
inline constexpr std::size_t max_request_head = max_request_line + 2 + max_request_headers;

enum class HttpMethod : std::uint8_t {
    get,
    head,
    put,
    other
};

struct HttpRequest {
    HttpMethod method{HttpMethod::other};
    std::string path;                      // the target up to any '?' or '#'
    std::uint8_t minor{1};                 // HTTP/1.minor
    bool keep_alive{true};                 // 1.1 unless "close"; 1.0 only with "keep-alive"
    std::optional<std::string> token;      // X-aws-ec2-metadata-token
    std::optional<std::string> token_ttl;  // X-aws-ec2-metadata-token-ttl-seconds
    bool forwarded_for{false};             // X-Forwarded-For present
    std::size_t head_bytes{0};             // up to and including the blank line
};

enum class RequestError : std::uint8_t {
    incomplete,         // no blank line yet: read more
    line_too_long,      // request line over max_request_line
    headers_too_large,  // fields over max_request_headers
    too_many_fields,    // more than max_request_fields
    bad_request_line,   // malformed line, bare LF, or a target not in origin form
    bad_version,        // not HTTP/1.0 or HTTP/1.1
    bad_header,         // malformed field, folding, or a control character
    duplicate_field,    // a field the service reads, twice
    has_body,           // Content-Length other than 0, or Transfer-Encoding
};

[[nodiscard]] auto to_string(RequestError e) noexcept -> const char*;

// The status a request error is answered with before the connection is
// closed: 414, 431 or 400. incomplete has none (0).
[[nodiscard]] auto status_for(RequestError e) noexcept -> unsigned;

// Parses the request head at the start of `bytes` (more requests may follow).
[[nodiscard]] auto parse_request(std::span<const std::byte> bytes)
    -> std::expected<HttpRequest, RequestError>;

// ---- tokens ---------------------------------------------------------------------

inline constexpr std::uint8_t token_version = 1;
inline constexpr std::size_t token_key_size = 32;
inline constexpr std::size_t token_nonce_size = 16;
inline constexpr std::size_t token_mac_size = 32;
inline constexpr std::size_t token_bytes = 1 + 8 + 8 + token_nonce_size + token_mac_size;  // 65
inline constexpr std::size_t token_chars = (token_bytes * 8 + 5) / 6;                      // 87
inline constexpr std::uint32_t min_token_ttl = 1;
inline constexpr std::uint32_t max_token_ttl = 21600;  // six hours, as EC2

enum class TokenError : std::uint8_t {
    bad_length,    // not token_chars characters
    bad_encoding,  // not base64url, or stray bits in the last character
    bad_version,
    wrong_nic,  // issued to another NIC
    expired,
    bad_mac,     // forged, or issued for another instance
    rng_failed,  // the OpenSSL RNG failed (issue and generate only)
};

[[nodiscard]] auto to_string(TokenError e) noexcept -> const char*;

struct TokenFields {
    std::uint8_t version{0};
    std::uint64_t nic_id{0};
    std::uint64_t expiry{0};
    std::array<std::byte, token_nonce_size> nonce{};
    std::array<std::byte, token_mac_size> mac{};
};

// Decodes the token's layout without checking its MAC.
[[nodiscard]] auto decode_token(std::string_view token) -> std::expected<TokenFields, TokenError>;

class TokenKey {
public:
    // A fresh key from the OpenSSL RNG.
    [[nodiscard]] static auto generate() -> std::expected<TokenKey, TokenError>;
    // A given key (tests and fuzzing).
    explicit TokenKey(std::span<const std::byte, token_key_size> key) noexcept;

    TokenKey(const TokenKey&) = delete;
    auto operator=(const TokenKey&) -> TokenKey& = delete;
    TokenKey(TokenKey&& other) noexcept;
    auto operator=(TokenKey&& other) noexcept -> TokenKey&;
    ~TokenKey();

    // A token for `nic_id` and `instance_id` valid until now + ttl.
    [[nodiscard]] auto issue(std::uint64_t nic_id, std::string_view instance_id, std::uint32_t ttl,
                             std::uint64_t now) const -> std::expected<std::string, TokenError>;

    // The token's expiry when it was issued by this key to `nic_id` for
    // `instance_id` and has not expired at `now`.
    [[nodiscard]] auto check(std::string_view token, std::uint64_t nic_id,
                             std::string_view instance_id, std::uint64_t now) const
        -> std::expected<std::uint64_t, TokenError>;

private:
    TokenKey() noexcept = default;
    [[nodiscard]] auto mac(std::span<const std::byte> fields, std::string_view instance_id,
                           std::span<std::byte, token_mac_size> out) const -> bool;

    std::array<std::byte, token_key_size> _key{};
};

// ---- answers --------------------------------------------------------------------

// What the role knows about a NIC's addresses, from its mapping entry,
// guest address tables and VPC config.
struct NicNetwork {
    MacAddress mac{};
    std::vector<neighbor::Ipv4Address> ipv4;  // the first is local-ipv4
    std::vector<Ipv6Address> ipv6;
    // From the VPC's config, when the VNI has one and the NIC is in one of
    // its subnets (vpc-subnets-routing design "Metadata").
    std::optional<std::uint64_t> subnet_id;        // rendered as subnet-...
    std::optional<neighbor::Ipv4Address> subnet4;  // the NIC's subnet's IPv4 prefix
    std::uint8_t subnet4_length{0};
    std::optional<Ipv6Address> subnet6;  // the subnet's /64
    struct Ipv4Block {
        neighbor::Ipv4Address address{};
        std::uint8_t length{0};
    };
    std::vector<Ipv4Block> vpc4;      // the VPC's IPv4 blocks, the primary first
    std::optional<Ipv6Address> vpc6;  // the VPC's /56
};

struct MetadataView {
    const proto::InstanceMetadata* record{nullptr};  // null: the NIC has none
    NicNetwork network;
};

struct HttpResponse {
    unsigned status{200};
    std::string content_type{"text/plain"};
    std::string body;
    std::optional<std::uint32_t> token_ttl;  // the TTL header on a token answer
    std::optional<std::uint8_t> hop_limit;   // set on the socket before writing
    bool close{false};                       // close after writing
    bool reset{false};  // write nothing and reset the connection (endpoint disabled)
};

// Answers `request` from `view` at `now` (steady-clock seconds).
[[nodiscard]] auto answer(const HttpRequest& request, const MetadataView& view, const TokenKey& key,
                          std::uint64_t now) -> HttpResponse;

// The response for a request that failed to parse; it always closes.
[[nodiscard]] auto error_response(RequestError e) -> HttpResponse;

// The bytes on the wire; a HEAD answer has the GET head without its body.
[[nodiscard]] auto render(const HttpResponse& response, bool head_only) -> std::string;

}  // namespace ak::oar::net
