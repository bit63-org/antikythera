// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AWS Signature Version 4 for S3 requests (.kiro/specs/oar-blk-data-plane/
// Requirement 8.9, design "Components"): the Authorization header for a
// request whose headers are all signed. Image fetches are GETs with no
// body, so the payload hash is the SHA-256 of the empty string and goes in
// x-amz-content-sha256 as S3 requires.
//
// Only what S3 GETs need: no query string (the canonical query is empty),
// header values without internal runs of spaces, header names already
// lowercase. The secret key never leaves this module except as derived
// HMAC keys on the stack, which are cleansed.

#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ak::oar::blk {

struct SigV4Credentials {
    std::string access_key;
    std::string secret_key;
    std::string session_token;  // empty unless temporary credentials
};

struct SigV4Request {
    std::string_view method;         // "GET"
    std::string_view canonical_uri;  // already URI-encoded: s3_uri_encode_path
    // Every header to sign, names lowercase; must include host,
    // x-amz-content-sha256 and x-amz-date. Sorted by the signer.
    std::vector<std::pair<std::string, std::string>> headers;
    std::string_view payload_hash;  // hex SHA-256 of the body
    std::string_view amz_date;      // YYYYMMDDTHHMMSSZ
    std::string_view region;        // "us-east-1"
    std::string_view service{"s3"};
};

enum class SigV4Error : std::uint8_t {
    bad_request,     // a required header is missing or a field is malformed
    crypto_failure,  // OpenSSL failed
};

[[nodiscard]] auto to_string(SigV4Error e) noexcept -> const char*;

// The hex SHA-256 of an empty payload.
inline constexpr std::string_view empty_payload_sha256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

[[nodiscard]] auto sigv4_authorization(const SigV4Request& request,
                                       const SigV4Credentials& credentials)
    -> std::expected<std::string, SigV4Error>;

// Lowercase hex SHA-256 of `bytes`.
[[nodiscard]] auto sha256_hex(std::string_view bytes) -> std::expected<std::string, SigV4Error>;

// "YYYYMMDDTHHMMSSZ" in UTC.
[[nodiscard]] auto amz_date(std::chrono::system_clock::time_point t) -> std::string;

// S3's encoding of an object path: every byte except unreserved characters
// (A-Z a-z 0-9 - . _ ~) and '/' as %XX, uppercase hex.
[[nodiscard]] auto s3_uri_encode_path(std::string_view path) -> std::string;

}  // namespace ak::oar::blk
