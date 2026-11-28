// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/hardware_identity.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <utility>

namespace ak::helm {

namespace {

auto slot_kind(oar::Role role) noexcept -> proto::SlotKind {
    switch (role) {
        case oar::Role::net:
            return proto::SlotKind::network;
        case oar::Role::gpu:
            return proto::SlotKind::gpu;
        case oar::Role::blk:
            return proto::SlotKind::blk;
        case oar::Role::hold:
        case oar::Role::khold:
            return proto::SlotKind::storage;
    }
    return proto::SlotKind::storage;
}

}  // namespace

HardwareIdentityTracker::HardwareIdentityTracker(std::uint64_t server_id, HelmIdentity helm,
                                                 SealedStore* store)
    : _server_id{server_id}, _helm{helm}, _store{store} {}

auto HardwareIdentityTracker::load() -> void {
    _baseline.reset();
    if (_store == nullptr) {
        return;
    }
    if (_store->rolled_back() || _store->degraded()) {
        // An old copy's baseline could hide a change: baseline again.
        if (_store->contains(identity_baseline_object)) {
            (void)_store->remove(identity_baseline_object);
        }
        return;
    }
    const auto bytes = _store->get(identity_baseline_object);
    if (!bytes || !*bytes) {
        return;
    }
    const auto report = proto::decode_report(**bytes);
    if (!report || report->server_id != _server_id) {
        return;
    }
    if (const auto* id = std::get_if<proto::HardwareIdentity>(&report->body)) {
        _baseline = *id;
    }
}

auto HardwareIdentityTracker::set_slot(SlotNumber slot, oar::Role role,
                                       const oar::RoleIdentity& identity) -> void {
    _slots[slot] = Slot{.role = role, .identity = identity};
}

auto HardwareIdentityTracker::set_host(const HostIdentity& host) -> void {
    _host = host;
}

auto HardwareIdentityTracker::clear_baseline() -> void {
    _baseline.reset();
    _sent.reset();
    if (_store != nullptr && _store->contains(identity_baseline_object)) {
        (void)_store->remove(identity_baseline_object);
    }
}

auto HardwareIdentityTracker::current() const -> proto::HardwareIdentity {
    proto::HardwareIdentity id;
    id.ek_hash = _helm.ek_hash;
    id.board_serial = _helm.board_serial;
    id.firmware = _helm.firmware;
    if (_host) {
        id.memory_bytes = _host->memory_bytes;
        id.cpu_count = _host->cpu_count;
        id.flags = proto::identity_host_reported;
        if (_host->secure_boot) {
            id.flags |= proto::identity_secure_boot;
        }
        if (_host->iommu) {
            id.flags |= proto::identity_iommu;
        }
    }
    // The map keeps slots in order, and each role's drives are in serial
    // order, so slots and drives come out as the report requires.
    for (const auto& [number, slot] : _slots) {
        if (id.slots.size() == proto::max_identity_slots) {
            break;
        }
        const auto kind = slot_kind(slot.role);
        id.slots.push_back({.slot = number,
                            .kind = kind,
                            .serial = slot.identity.serial,
                            .firmware = slot.identity.firmware});
        if (kind != proto::SlotKind::storage) {
            continue;  // only storage slots list drives
        }
        for (const auto& d : slot.identity.drives) {
            if (id.drives.size() == proto::max_identity_drives) {
                break;
            }
            id.drives.push_back({.slot = number, .size_bytes = d.size_bytes, .serial = d.serial});
        }
    }
    return id;
}

auto HardwareIdentityTracker::keep_baseline() -> void {
    if (_store == nullptr || !_baseline) {
        return;
    }
    auto bytes =
        proto::encode_report({.server_id = _server_id, .report_seq = 1, .body = *_baseline});
    if (bytes) {
        (void)_store->put(identity_baseline_object, *bytes);
    }
}

auto HardwareIdentityTracker::poll(bool settled) -> std::optional<Update> {
    auto id = current();
    if (_sent && *_sent == id) {
        return std::nullopt;
    }
    _sent = id;
    if (!_baseline) {
        if (settled) {
            _baseline = id;
            keep_baseline();
        }
        return Update{.report = std::move(id), .changed = false};
    }
    if ((_baseline->flags & proto::identity_host_reported) == 0 &&
        (id.flags & proto::identity_host_reported) != 0) {
        // hull reports the host's part after the baseline was taken: it
        // completes the baseline rather than changing it.
        _baseline->flags = id.flags;
        _baseline->memory_bytes = id.memory_bytes;
        _baseline->cpu_count = id.cpu_count;
        keep_baseline();
    }
    // Until hull reports the host's part (after every helm restart), only
    // the rest is compared.
    auto compared = id;
    if ((compared.flags & proto::identity_host_reported) == 0) {
        compared.flags = _baseline->flags;
        compared.memory_bytes = _baseline->memory_bytes;
        compared.cpu_count = _baseline->cpu_count;
    }
    const bool changed = *_baseline != compared;
    return Update{.report = std::move(id), .changed = changed};
}

auto key_hash(std::span<const std::byte> key) -> std::optional<proto::ImageDigest> {
    proto::ImageDigest out{};
    unsigned int size = 0;
    if (::EVP_Digest(key.data(), key.size(), reinterpret_cast<unsigned char*>(out.data()), &size,
                     ::EVP_sha256(), nullptr) != 1 ||
        size != out.size()) {
        return std::nullopt;
    }
    return out;
}

}  // namespace ak::helm
