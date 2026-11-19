// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/sigv4.hpp"

#include <algorithm>
#include <array>
#include <ctime>
#include <span>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace ak::oar::blk {

namespace {

constexpr std::size_t sha256_size = 32;
using Mac = std::array<unsigned char, sha256_size>;

auto hex(std::span<const unsigned char> bytes) -> std::string {
    static constexpr std::string_view digits = "0123456789abcdef";
    constexpr unsigned nibble_bits = 4;
    constexpr unsigned nibble_mask = 0xF;
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const unsigned char b : bytes) {
        out.push_back(digits[b >> nibble_bits]);
        out.push_back(digits[b & nibble_mask]);
    }
    return out;
}

auto hmac(std::span<const unsigned char> key, std::string_view data, Mac& out) -> bool {
    unsigned int len = 0;
    return HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                reinterpret_cast<const unsigned char*>(data.data()), data.size(), out.data(),
                &len) != nullptr &&
           len == out.size();
}

auto as_bytes(std::string_view s) -> std::span<const unsigned char> {
    return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

auto find_header(const std::vector<std::pair<std::string, std::string>>& headers,
                 std::string_view name) -> bool {
    return std::ranges::any_of(headers, [&](const auto& h) { return h.first == name; });
}

}  // namespace

auto to_string(SigV4Error e) noexcept -> const char* {
    switch (e) {
        case SigV4Error::bad_request:
            return "bad_request";
        case SigV4Error::crypto_failure:
            return "crypto_failure";
    }
    return "unknown";
}

auto sha256_hex(std::string_view bytes) -> std::expected<std::string, SigV4Error> {
    Mac d{};
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), d.data(), &len, EVP_sha256(), nullptr) != 1 ||
        len != d.size()) {
        return std::unexpected(SigV4Error::crypto_failure);
    }
    return hex(d);
}

auto amz_date(std::chrono::system_clock::time_point t) -> std::string {
    const std::time_t secs = std::chrono::system_clock::to_time_t(t);
    std::tm utc{};
    ::gmtime_r(&secs, &utc);
    std::array<char, 17> buf{};
    const std::size_t n = std::strftime(buf.data(), buf.size(), "%Y%m%dT%H%M%SZ", &utc);
    return {buf.data(), n};
}

auto s3_uri_encode_path(std::string_view path) -> std::string {
    static constexpr std::string_view digits = "0123456789ABCDEF";
    constexpr unsigned nibble_bits = 4;
    constexpr unsigned nibble_mask = 0xF;
    std::string out;
    out.reserve(path.size());
    for (const char ch : path) {
        const auto c = static_cast<unsigned char>(ch);
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                                c == '~' || c == '/';
        if (unreserved) {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(digits[c >> nibble_bits]);
            out.push_back(digits[c & nibble_mask]);
        }
    }
    return out;
}

auto sigv4_authorization(const SigV4Request& request, const SigV4Credentials& credentials)
    -> std::expected<std::string, SigV4Error> {
    constexpr std::size_t date_len = 8;
    constexpr std::size_t amz_date_len = 16;
    if (request.amz_date.size() != amz_date_len || request.region.empty() ||
        request.method.empty() || request.canonical_uri.empty() || credentials.access_key.empty() ||
        credentials.secret_key.empty() || !find_header(request.headers, "host") ||
        !find_header(request.headers, "x-amz-content-sha256") ||
        !find_header(request.headers, "x-amz-date")) {
        return std::unexpected(SigV4Error::bad_request);
    }
    auto headers = request.headers;
    std::ranges::sort(headers);
    std::string canonical_headers;
    std::string signed_headers;
    for (const auto& [name, value] : headers) {
        if (name.empty() ||
            std::ranges::any_of(name, [](char c) { return c >= 'A' && c <= 'Z'; })) {
            return std::unexpected(SigV4Error::bad_request);
        }
        canonical_headers += name + ':' + value + '\n';
        if (!signed_headers.empty()) {
            signed_headers += ';';
        }
        signed_headers += name;
    }
    std::string canonical;
    canonical.append(request.method).append("\n");
    canonical.append(request.canonical_uri).append("\n");
    canonical.append("\n");  // no query string
    canonical.append(canonical_headers).append("\n");
    canonical.append(signed_headers).append("\n");
    canonical.append(request.payload_hash);

    const std::string_view date = request.amz_date.substr(0, date_len);
    std::string scope;
    scope.append(date).append("/").append(request.region).append("/");
    scope.append(request.service).append("/aws4_request");
    const auto canonical_hash = sha256_hex(canonical);
    if (!canonical_hash) {
        return std::unexpected(canonical_hash.error());
    }
    std::string to_sign = "AWS4-HMAC-SHA256\n";
    to_sign.append(request.amz_date).append("\n").append(scope).append("\n");
    to_sign.append(*canonical_hash);

    std::string secret = "AWS4" + credentials.secret_key;
    Mac k_date{};
    Mac k_region{};
    Mac k_service{};
    Mac k_signing{};
    Mac signature{};
    const bool ok =
        hmac(as_bytes(secret), date, k_date) && hmac(k_date, request.region, k_region) &&
        hmac(k_region, request.service, k_service) && hmac(k_service, "aws4_request", k_signing) &&
        hmac(k_signing, to_sign, signature);
    OPENSSL_cleanse(secret.data(), secret.size());
    for (auto* k : {&k_date, &k_region, &k_service, &k_signing}) {
        OPENSSL_cleanse(k->data(), k->size());
    }
    if (!ok) {
        return std::unexpected(SigV4Error::crypto_failure);
    }
    std::string out = "AWS4-HMAC-SHA256 Credential=";
    out.append(credentials.access_key).append("/").append(scope);
    out.append(", SignedHeaders=").append(signed_headers);
    out.append(", Signature=").append(hex(signature));
    return out;
}

}  // namespace ak::oar::blk
