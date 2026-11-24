// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A storage role's half of enrollment on helm's sideband
// (.kiro/specs/block-volume-service/ task 12), shared by the hold role and
// oar-blk: cert_request answers with the role's certificate request (none
// while its certificate is good), and role_certificate installs the chain
// helm passes down from the controller, if tls::RoleIdentity accepts it,
// then hands the new TLS configuration to the role (a hold node's
// listener, oar-blk's initiators). helm is not trusted with any of it:
// the identity checks the chain against the storage CA, this server and
// the role's own key.

#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <utility>

#include "helm/oar_protocol.hpp"
#include "tls/role_identity.hpp"
#include "tls/tls.hpp"

namespace ak::helm {

struct EnrollmentStats {
    std::uint64_t installed{0};
    std::uint64_t refused{0};
};

class RoleEnrollment {
public:
    // Takes the new configuration; false if the role could not use it.
    using Apply = std::function<bool(const tls::Config&)>;

    // `identity` must outlive this. `tls_role` is how the role uses its
    // certificate (server for hold, client for oar-blk's initiators).
    RoleEnrollment(tls::RoleIdentity& identity, oar::Role role, tls::Role tls_role, Apply apply)
        : _identity{&identity}, _role{role}, _tls_role{tls_role}, _apply{std::move(apply)} {}

    [[nodiscard]] auto answer() const -> std::expected<oar::CertAnswer, oar::Status> {
        return oar::CertAnswer{.role = _role, .csr = _identity->request()};
    }

    auto install(std::span<const std::byte> chain) -> oar::Status {
        if (!_identity->install(chain)) {
            ++_stats.refused;
            return oar::Status::failed;
        }
        const auto config = _identity->config(_tls_role);
        if (!config || (_apply && !_apply(*config))) {
            ++_stats.refused;
            return oar::Status::failed;
        }
        ++_stats.installed;
        return oar::Status::ok;
    }

    [[nodiscard]] auto identity() const noexcept -> const tls::RoleIdentity& { return *_identity; }
    [[nodiscard]] auto stats() const noexcept -> const EnrollmentStats& { return _stats; }

private:
    tls::RoleIdentity* _identity;
    oar::Role _role;
    tls::Role _tls_role;
    Apply _apply;
    EnrollmentStats _stats;
};

}  // namespace ak::helm
