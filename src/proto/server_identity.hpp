// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A storage role's identity on the storage network, shared by hold and
// oar-blk's initiator
// (.kiro/specs/block-volume-service/ design "hold wire protocol",
// Requirement 13.2): the certificate the controller's CA issues at
// enrollment carries the server's ID as a URI subjectAltName,
//
//   urn:antikythera:server:<server_id in decimal>
//
// and that ID, not an address, is what a hold role checks against the
// ReplicaConfig. The CA has vouched for the name, but the parse is strict
// anyway: decimal digits only, no sign or leading zero, non-zero, within
// 64 bits.

#include <charconv>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace ak::proto {

inline constexpr std::string_view server_uri_prefix = "urn:antikythera:server:";

enum class IdentityError : std::uint8_t {
    none,       // no URI names a server
    malformed,  // a server URI that does not parse
    ambiguous,  // more than one server URI
};

[[nodiscard]] inline auto to_string(IdentityError e) noexcept -> const char* {
    switch (e) {
        case IdentityError::none:
            return "none";
        case IdentityError::malformed:
            return "malformed";
        case IdentityError::ambiguous:
            return "ambiguous";
    }
    return "unknown";
}

[[nodiscard]] inline auto server_uri(std::uint64_t server_id) -> std::string {
    return std::string{server_uri_prefix} + std::to_string(server_id);
}

[[nodiscard]] inline auto parse_server_uri(std::string_view uri)
    -> std::expected<std::uint64_t, IdentityError> {
    if (!uri.starts_with(server_uri_prefix)) {
        return std::unexpected(IdentityError::none);
    }
    const auto digits = uri.substr(server_uri_prefix.size());
    if (digits.empty() || digits.front() == '0') {
        return std::unexpected(IdentityError::malformed);
    }
    std::uint64_t id = 0;
    const char* first = &digits.front();
    const char* end = first + digits.size();
    const auto [ptr, ec] = std::from_chars(first, end, id);
    if (ec != std::errc{} || ptr != end) {
        return std::unexpected(IdentityError::malformed);
    }
    return id;
}

// The one server ID among a certificate's URIs (other URIs are ignored).
[[nodiscard]] inline auto server_id_of(std::span<const std::string> uris)
    -> std::expected<std::uint64_t, IdentityError> {
    std::uint64_t found = 0;
    for (const auto& u : uris) {
        const auto id = parse_server_uri(u);
        if (!id) {
            if (id.error() == IdentityError::none) {
                continue;
            }
            return std::unexpected(id.error());
        }
        if (found != 0) {
            return std::unexpected(IdentityError::ambiguous);
        }
        found = *id;
    }
    if (found == 0) {
        return std::unexpected(IdentityError::none);
    }
    return found;
}

}  // namespace ak::proto
