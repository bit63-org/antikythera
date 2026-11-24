// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A storage role's own TLS identity on the storage segment
// (.kiro/specs/block-volume-service/ design "hold wire protocol", task 12
// enrollment): the role creates its key pair, asks the controller's CA
// for a certificate through helm, and checks what comes back before it
// uses or keeps it.
//
// The key is an ECDSA P-256 key the role generates on first start and
// keeps in key_path (PEM, created 0600 and refused if group or other can
// read it); it never leaves the role. The certificate request names the
// server (urn:antikythera:server:<id>, server_identity.hpp) and, for a
// hold role, the IP addresses its storage endpoint listens on, which the
// initiators check when they connect. It is made once per process, so it
// is the same bytes every time it is asked for.
//
// A certificate chain (DER, leaf first, as role_certificate carries it) is
// installed only if
//   - every certificate parses and nothing follows the last,
//   - the leaf holds this role's key,
//   - the leaf names exactly one server, this one,
//   - the leaf carries every configured address as an IP SAN, and
//   - the chain verifies against the storage CA now (expiry included).
// It is then written to cert_path (PEM, atomically) and used for every
// new connection. On start an existing cert_path that no longer passes
// (expired, another key, another server) is ignored, not trusted.
//
// Renewal: request() returns the request again once the certificate has
// less than a third of its lifetime left, and an installed renewal
// replaces the old certificate; the key stays the same.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "tls/tls.hpp"

namespace ak::tls {

enum class IdentityError : std::uint8_t {
    io,               // the key or certificate file could not be read or written
    bad_key,          // the key file does not parse or is readable by others
    bad_config,       // no server ID, a CA that does not parse, or a bad address
    bad_certificate,  // the chain is empty or does not parse as DER certificates
    wrong_key,        // the leaf does not hold this role's key
    wrong_server,     // the leaf names no server, another server, or several
    missing_address,  // the leaf lacks a configured IP address
    untrusted,        // the chain does not verify against the storage CA
};

[[nodiscard]] auto to_string(IdentityError e) noexcept -> const char*;

struct IdentityConfig {
    std::filesystem::path key_path;
    std::filesystem::path cert_path;
    std::string ca_pem;  // the storage CA: the only trust anchor
    std::uint64_t server_id{0};
    std::string common_name;             // the request's subject CN, e.g. "hold"
    std::vector<std::string> addresses;  // IP SANs the certificate must carry
};

struct IdentityImpl;

class RoleIdentity {
public:
    using SystemClock = std::chrono::system_clock;

    // Loads the key (creating it if key_path does not exist) and any
    // certificate in cert_path that still passes every check.
    [[nodiscard]] static auto open(IdentityConfig config)
        -> std::expected<RoleIdentity, IdentityError>;

    RoleIdentity(RoleIdentity&&) noexcept;
    auto operator=(RoleIdentity&&) noexcept -> RoleIdentity&;
    RoleIdentity(const RoleIdentity&) = delete;
    auto operator=(const RoleIdentity&) -> RoleIdentity& = delete;
    ~RoleIdentity();

    // Holds a certificate that passed every check.
    [[nodiscard]] auto ready() const noexcept -> bool;

    // A TLS configuration with the current certificate, when ready.
    [[nodiscard]] auto config(Role role) const -> std::optional<Config>;

    // The DER certificate request to send now, or empty while the current
    // certificate has more than a third of its lifetime left.
    [[nodiscard]] auto request(SystemClock::time_point now = SystemClock::now()) const
        -> std::span<const std::byte>;

    // Checks a DER chain (leaf first) and, if it passes, keeps it, writes
    // it to cert_path and uses it from now on.
    auto install(std::span<const std::byte> chain) -> std::expected<void, IdentityError>;

    // The current certificate's validity, when ready.
    [[nodiscard]] auto not_after() const -> std::optional<SystemClock::time_point>;

private:
    explicit RoleIdentity(std::unique_ptr<IdentityImpl> impl) noexcept;
    std::unique_ptr<IdentityImpl> _impl;
};

}  // namespace ak::tls
