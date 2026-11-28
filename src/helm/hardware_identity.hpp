// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The server's hardware identity as helm reports it
// (.kiro/specs/server-provisioning/ Requirement 6, task 6): the
// hardware_identity report (kind 25) at registration and on any change,
// and a hardware_changed host fault when it differs from the identity
// recorded at enrollment.
//
// The pieces come from three places:
//
//   helm itself   the secure element's key hash and the board's serial and
//                 firmware (HelmIdentity, from ak-helm's configuration)
//   each slot     its board's serial, firmware and drives, which helm asks
//                 the role for over the sideband (oar role_identity) when
//                 the sideband opens
//   hull          Secure Boot and IOMMU state, memory and CPUs (set_host);
//                 until hull reports them they are absent and the report
//                 says so (identity_host_reported clear)
//
// A slot's identity is kept once read: a role whose sideband drops and
// comes back is not a hardware change, and a slot that has not answered
// is simply absent from the report until it does.
//
// The baseline is the first identity reported, kept in the sealed store
// (`helm.identity-baseline`, a whole encoded report) until enrollment or
// decommission replaces or clears it (clear_baseline). A store that
// opened rolled back or degraded loses it, so the identity is
// baselined again rather than compared against a copy that may be old.
//
// Not thread-safe: helm's loop thread owns it.

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string_view>

#include "helm/oar_protocol.hpp"
#include "helm/power_sequencer.hpp"
#include "helm/sealed_store.hpp"
#include "proto/report.hpp"

namespace ak::helm {

inline constexpr std::string_view identity_baseline_object = "helm.identity-baseline";

struct HelmIdentity {
    proto::ImageDigest ek_hash{};  // SHA-256 of the secure element's key; never all zero
    proto::IdentityText board_serial{};
    proto::IdentityText firmware{};
};

struct HostIdentity {
    bool secure_boot{false};
    bool iommu{false};
    std::uint64_t memory_bytes{0};
    std::uint32_t cpu_count{0};
    friend auto operator==(const HostIdentity&, const HostIdentity&) -> bool = default;
};

class HardwareIdentityTracker {
public:
    struct Update {
        proto::HardwareIdentity report;
        // It differs from the enrollment baseline (Requirement 6.2).
        bool changed{false};
    };

    // `store` may be null (no baseline kept across restarts). Not owned.
    HardwareIdentityTracker(std::uint64_t server_id, HelmIdentity helm, SealedStore* store);

    // Reads the stored baseline. Call once at start.
    auto load() -> void;
    // A slot's role answered role_identity.
    auto set_slot(SlotNumber slot, oar::Role role, const oar::RoleIdentity& identity) -> void;
    auto set_host(const HostIdentity& host) -> void;
    // Forgets the baseline (decommission), so the next report sets it.
    auto clear_baseline() -> void;

    // The identity now.
    [[nodiscard]] auto current() const -> proto::HardwareIdentity;
    // The report to send when the identity changed since the last one
    // sent (always, the first time), with whether it differs from the
    // baseline. With no baseline, the first report polled `settled`
    // (every slot has answered or refused role_identity) becomes it: one
    // taken while a slot is still starting would make that slot's first
    // answer look like new hardware. Host facts arriving after the
    // baseline complete it rather than change it.
    [[nodiscard]] auto poll(bool settled = true) -> std::optional<Update>;

    [[nodiscard]] auto baseline() const noexcept -> const std::optional<proto::HardwareIdentity>& {
        return _baseline;
    }

private:
    struct Slot {
        oar::Role role{oar::Role::net};
        oar::RoleIdentity identity;
    };

    std::uint64_t _server_id;
    HelmIdentity _helm;
    SealedStore* _store;
    std::map<SlotNumber, Slot> _slots;
    std::optional<HostIdentity> _host;
    std::optional<proto::HardwareIdentity> _baseline;
    std::optional<proto::HardwareIdentity> _sent;

    auto keep_baseline() -> void;
};

// SHA-256 of a public key, as the report's ek_hash carries it.
[[nodiscard]] auto key_hash(std::span<const std::byte> key) -> std::optional<proto::ImageDigest>;

}  // namespace ak::helm
