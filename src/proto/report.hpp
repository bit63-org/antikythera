// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Report: what a server's helm tells the controller about itself
// (.kiro/specs/controller-interface/ Requirement 3, design "Inventory and
// status reports").
//
// Reports travel helm -> controller over the mTLS ControllerLink. They are
// not signed: mTLS authenticates helm, and the controller treats a server
// as authoritative only for state that server reported (Requirement 3.3).
//
// Header (little-endian, 0x20 bytes):
//   0x00  magic       u32  'AKRP'
//   0x04  version     u16  report format version (1)
//   0x06  kind        u16  ReportKind
//   0x08  server_id   u64  reporting server; non-zero
//   0x10  report_seq  u64  non-zero, strictly increasing within one helm boot
//   0x18  body_len    u32  exact length of the body that follows
//   0x1C  reserved    u32  zero
//   0x20  body
//
// Bodies (every reserved byte zero, every enum a known value):
//
//   inventory  -- a full snapshot, sent first on every connection
//     0x00 boot_id u64 (non-zero, fresh per helm boot)
//     0x08 last_command_seq u64 (highest sequence hull accepted; 0 = none)
//     0x10 cores_total u16 | cores_free u16 | health u8 | vtep_count u8 | rsvd u16
//     0x18 pages_1g_total u32 | pages_1g_free u32
//     0x20 function_count u16 | vm_count u16 | volume_count u16 | network_count u16
//     0x28 vteps      vtep_count x 16 (IPv6 underlay addresses)
//          functions  function_count x 16:
//                       slot u8 | type u8 | function u16 | state u8 | rsvd [3] | owner_vm u64
//          vms        vm_count x 16: vm_id u64 | vcpus u16 | rsvd u16 | memory_mib u32
//          volumes    volume_count x 24:
//                       volume_id u64 | owner_vm u64 | size_gib u32 | rsvd u32
//          networks   network_count x 16: vni u32 | rsvd u32 | map_version u64
//   command_outcome  -- hull's response to one command
//     in_reply_to u64 | command u16 | status u16 | payload_len u8 | rsvd [3] | payload
//   pool_state  -- a device-pool transition
//     slot u8 | type u8 | function u16 | from u8 | to u8 | rsvd u16 | owner_vm u64
//   vm_exited  -- a VM exit hull did not cause
//     vm_id u64 | exit_status u32 | reason u8 | rsvd [3]
//   map_applied  -- oar-net swapped in a mapping version
//     vni u32 | rsvd u32 | map_version u64
//   host_fault
//     code u16 | slot u8 | rsvd [5] | detail u64
//
// Every inventory list is in strictly increasing key order (functions by
// (slot, function), the others by ID), so the encoding is canonical and
// carries no duplicates. A function has an owner VM exactly when it is
// assigned or releasing. map_version 0 in `networks` means the network
// exists but no mapping has been applied yet.
//
// Enum values are shared with helm (FunctionType, FunctionState) and the
// mailbox (Status, ExitReason, FaultCode); tests/proto_report_test.cpp
// pins them together, since this header must not depend on helm.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/map_update.hpp"

namespace ak::proto {

inline constexpr std::uint32_t report_magic = 0x5052'4B41;  // "AKRP" as little-endian bytes
inline constexpr std::uint16_t report_version = 1;
inline constexpr std::size_t report_header_size = 0x20;

// Inventory bounds. They keep the largest report under 128 KiB; a server
// that outgrows one needs a new format version.
inline constexpr std::size_t max_vteps = 8;
inline constexpr std::size_t max_functions = 1024;
inline constexpr std::size_t max_vms = 512;
inline constexpr std::size_t max_volumes = 1024;
inline constexpr std::size_t max_networks = 4096;

inline constexpr std::size_t inventory_fixed_size = 0x28;
inline constexpr std::size_t inventory_function_size = 16;
inline constexpr std::size_t inventory_vm_size = 16;
inline constexpr std::size_t inventory_volume_size = 24;
inline constexpr std::size_t inventory_network_size = 16;
inline constexpr std::size_t command_outcome_fixed_size = 16;
// The mailbox response payload limit (helm/mailbox.hpp max_response_payload).
inline constexpr std::size_t max_outcome_payload = 156;
inline constexpr std::size_t fixed_event_size = 16;

inline constexpr std::size_t max_inventory_size =
    inventory_fixed_size + (max_vteps * vtep_address_size) +
    (max_functions * inventory_function_size) + (max_vms * inventory_vm_size) +
    (max_volumes * inventory_volume_size) + (max_networks * inventory_network_size);
inline constexpr std::size_t max_report_size = report_header_size + max_inventory_size;

// Values are part of the wire protocol: never renumber.
enum class ReportKind : std::uint16_t {
    inventory = 1,
    command_outcome = 2,
    pool_state = 3,
    vm_exited = 4,
    map_applied = 5,
    host_fault = 6,
};

enum class Health : std::uint8_t {
    ok = 0,
    degraded = 1,  // running, but a role or function is faulted
    faulted = 2,   // the host cannot take new work
};

// helm::FunctionType.
enum class FunctionType : std::uint8_t {
    nic_vf = 1,
    blk_fn = 2,
    gpu_whole = 3,
    gpu_vf = 4,
};

// helm::FunctionState.
enum class FunctionState : std::uint8_t {
    free = 0,
    assigned = 1,
    releasing = 2,
    cleaning = 3,
    faulted = 4,
};

// helm::mailbox::Status.
enum class CommandStatus : std::uint16_t {
    ok = 0,
    accepted = 1,
    bad_signature = 2,
    stale_sequence = 3,
    malformed = 4,
    unknown_vm = 5,
    unknown_device = 6,
    unknown_volume = 7,
    insufficient_resources = 8,
    conflict = 9,
    timed_out = 10,
    internal_error = 11,
    unsupported = 12,
};

// helm::mailbox::ExitReason.
enum class ExitReason : std::uint8_t {
    guest_shutdown = 1,
    guest_fault = 2,
    vmm_failure = 3,
};

// helm::mailbox::FaultCode.
enum class FaultCode : std::uint16_t {
    iommu_fault = 1,
    machine_check = 2,
    agent_restarted = 3,
    device_lost = 4,
    resources_exhausted = 5,
};

struct InventoryFunction {
    std::uint8_t slot{0};
    FunctionType type{FunctionType::nic_vf};
    std::uint16_t function{0};
    FunctionState state{FunctionState::free};
    std::uint64_t owner_vm{0};  // non-zero exactly when assigned or releasing
    friend auto operator==(const InventoryFunction&, const InventoryFunction&) -> bool = default;
};

struct InventoryVm {
    std::uint64_t vm_id{0};
    std::uint16_t vcpus{0};
    std::uint32_t memory_mib{0};
    friend auto operator==(const InventoryVm&, const InventoryVm&) -> bool = default;
};

struct InventoryVolume {
    std::uint64_t volume_id{0};
    std::uint64_t owner_vm{0};
    std::uint32_t size_gib{0};
    friend auto operator==(const InventoryVolume&, const InventoryVolume&) -> bool = default;
};

struct InventoryNetwork {
    std::uint32_t vni{0};
    std::uint64_t map_version{0};  // 0: created, no mapping applied yet
    friend auto operator==(const InventoryNetwork&, const InventoryNetwork&) -> bool = default;
};

struct Inventory {
    std::uint64_t boot_id{0};
    std::uint64_t last_command_seq{0};
    std::uint16_t cores_total{0};
    std::uint16_t cores_free{0};
    Health health{Health::ok};
    std::uint32_t pages_1g_total{0};
    std::uint32_t pages_1g_free{0};
    std::vector<VtepAddress> vteps;
    std::vector<InventoryFunction> functions;
    std::vector<InventoryVm> vms;
    std::vector<InventoryVolume> volumes;
    std::vector<InventoryNetwork> networks;
    friend auto operator==(const Inventory&, const Inventory&) -> bool = default;
};

struct CommandOutcome {
    std::uint64_t in_reply_to{0};  // the command's sequence number
    std::uint16_t command{0};      // the command's mailbox type
    CommandStatus status{CommandStatus::ok};
    std::vector<std::byte> payload;  // at most max_outcome_payload bytes
    friend auto operator==(const CommandOutcome&, const CommandOutcome&) -> bool = default;
};

struct PoolStateChange {
    std::uint8_t slot{0};
    FunctionType type{FunctionType::nic_vf};
    std::uint16_t function{0};
    FunctionState from{FunctionState::free};
    FunctionState to{FunctionState::free};
    std::uint64_t owner_vm{0};  // the VM involved, if any
    friend auto operator==(const PoolStateChange&, const PoolStateChange&) -> bool = default;
};

struct VmExitedReport {
    std::uint64_t vm_id{0};
    std::uint32_t exit_status{0};
    ExitReason reason{ExitReason::guest_shutdown};
    friend auto operator==(const VmExitedReport&, const VmExitedReport&) -> bool = default;
};

struct MapApplied {
    std::uint32_t vni{0};
    std::uint64_t map_version{0};
    friend auto operator==(const MapApplied&, const MapApplied&) -> bool = default;
};

struct HostFaultReport {
    FaultCode code{FaultCode::iommu_fault};
    std::uint8_t slot{0xFF};  // 0xFF: no slot involved
    std::uint64_t detail{0};
    friend auto operator==(const HostFaultReport&, const HostFaultReport&) -> bool = default;
};

using ReportBody = std::variant<Inventory, CommandOutcome, PoolStateChange, VmExitedReport,
                                MapApplied, HostFaultReport>;

struct Report {
    std::uint64_t server_id{0};
    std::uint64_t report_seq{0};
    ReportBody body;
    friend auto operator==(const Report&, const Report&) -> bool = default;
};

[[nodiscard]] inline auto report_kind(const ReportBody& body) noexcept -> ReportKind {
    return std::visit(
        []<typename T>(const T&) {
            if constexpr (std::is_same_v<T, Inventory>) {
                return ReportKind::inventory;
            } else if constexpr (std::is_same_v<T, CommandOutcome>) {
                return ReportKind::command_outcome;
            } else if constexpr (std::is_same_v<T, PoolStateChange>) {
                return ReportKind::pool_state;
            } else if constexpr (std::is_same_v<T, VmExitedReport>) {
                return ReportKind::vm_exited;
            } else if constexpr (std::is_same_v<T, MapApplied>) {
                return ReportKind::map_applied;
            } else {
                return ReportKind::host_fault;
            }
        },
        body);
}

namespace detail {

[[nodiscard]] constexpr auto known(Health h) noexcept -> bool {
    return h == Health::ok || h == Health::degraded || h == Health::faulted;
}
[[nodiscard]] constexpr auto known(FunctionType t) noexcept -> bool {
    return t >= FunctionType::nic_vf && t <= FunctionType::gpu_vf;
}
[[nodiscard]] constexpr auto known(FunctionState s) noexcept -> bool {
    return s <= FunctionState::faulted;
}
[[nodiscard]] constexpr auto known(CommandStatus s) noexcept -> bool {
    return s <= CommandStatus::unsupported;
}
[[nodiscard]] constexpr auto known(ExitReason r) noexcept -> bool {
    return r >= ExitReason::guest_shutdown && r <= ExitReason::vmm_failure;
}
[[nodiscard]] constexpr auto known(FaultCode c) noexcept -> bool {
    return c >= FaultCode::iommu_fault && c <= FaultCode::resources_exhausted;
}
[[nodiscard]] constexpr auto has_owner(FunctionState s) noexcept -> bool {
    return s == FunctionState::assigned || s == FunctionState::releasing;
}

[[nodiscard]] inline auto valid_vtep(const VtepAddress& a) noexcept -> bool {
    return !all_zero(a) && std::to_integer<std::uint8_t>(a[0]) != ipv6_multicast_prefix;
}

[[nodiscard]] inline auto check_inventory(const Inventory& inv) noexcept
    -> std::expected<void, DecodeError> {
    if (inv.boot_id == 0) {
        return std::unexpected(DecodeError::bad_boot_id);
    }
    if (!known(inv.health)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (inv.cores_free > inv.cores_total || inv.pages_1g_free > inv.pages_1g_total) {
        return std::unexpected(DecodeError::bad_capacity);
    }
    if (inv.vteps.size() > max_vteps || inv.functions.size() > max_functions ||
        inv.vms.size() > max_vms || inv.volumes.size() > max_volumes ||
        inv.networks.size() > max_networks) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    for (const auto& v : inv.vteps) {
        if (!valid_vtep(v)) {
            return std::unexpected(DecodeError::bad_vtep);
        }
    }
    if (std::ranges::adjacent_find(inv.vteps, std::ranges::greater_equal{}) != inv.vteps.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& f : inv.functions) {
        if (!known(f.type) || !known(f.state)) {
            return std::unexpected(DecodeError::unknown_value);
        }
        if ((f.owner_vm != 0) != has_owner(f.state)) {
            return std::unexpected(DecodeError::bad_owner);
        }
    }
    const auto fn_key = [](const InventoryFunction& f) { return std::tuple{f.slot, f.function}; };
    if (std::ranges::adjacent_find(inv.functions, [&](const auto& a, const auto& b) {
            return fn_key(a) >= fn_key(b);
        }) != inv.functions.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& vm : inv.vms) {
        if (vm.vm_id == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
    }
    if (std::ranges::adjacent_find(inv.vms, std::ranges::greater_equal{}, &InventoryVm::vm_id) !=
        inv.vms.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& vol : inv.volumes) {
        if (vol.volume_id == 0 || vol.owner_vm == 0 || vol.size_gib == 0) {
            return std::unexpected(DecodeError::bad_id);
        }
    }
    if (std::ranges::adjacent_find(inv.volumes, std::ranges::greater_equal{},
                                   &InventoryVolume::volume_id) != inv.volumes.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    for (const auto& n : inv.networks) {
        if (n.vni == 0 || n.vni > max_vni) {
            return std::unexpected(DecodeError::bad_vni);
        }
    }
    if (std::ranges::adjacent_find(inv.networks, std::ranges::greater_equal{},
                                   &InventoryNetwork::vni) != inv.networks.end()) {
        return std::unexpected(DecodeError::not_ascending);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const CommandOutcome& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.in_reply_to == 0 || c.command == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (!known(c.status)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (c.payload.size() > max_outcome_payload) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const PoolStateChange& p) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(p.type) || !known(p.from) || !known(p.to)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const VmExitedReport& v) noexcept
    -> std::expected<void, DecodeError> {
    if (v.vm_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (!known(v.reason)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const MapApplied& m) noexcept
    -> std::expected<void, DecodeError> {
    if (m.vni == 0 || m.vni > max_vni) {
        return std::unexpected(DecodeError::bad_vni);
    }
    if (m.map_version == 0) {
        return std::unexpected(DecodeError::bad_map_version);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const HostFaultReport& h) noexcept
    -> std::expected<void, DecodeError> {
    if (!known(h.code)) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto check_body(const Inventory& inv) noexcept
    -> std::expected<void, DecodeError> {
    return check_inventory(inv);
}

// A reader over a body whose length the header has already checked, so
// every field read below either succeeds or the frame is truncated.
struct BodyReader {
    wire::Reader r;
    bool ok{true};

    auto u8() -> std::uint8_t { return take(r.u8()); }
    auto le16() -> std::uint16_t { return take(r.le16()); }
    auto le32() -> std::uint32_t { return take(r.le32()); }
    auto le64() -> std::uint64_t { return take(r.le64()); }
    // Reads n bytes that must be zero.
    auto zeros(std::size_t n) -> bool {
        auto b = r.bytes(n);
        ok = ok && b.has_value();
        return b.has_value() && all_zero(*b);
    }
    auto bytes(std::span<std::byte> out) -> void {
        auto b = r.bytes(out.size());
        ok = ok && b.has_value();
        if (b) {
            std::ranges::copy(*b, out.begin());
        }
    }

private:
    template<typename T> auto take(std::expected<T, wire::WireError> v) -> T {
        ok = ok && v.has_value();
        return v.value_or(T{});
    }
};

[[nodiscard]] inline auto inventory_size(std::size_t vteps, std::size_t functions, std::size_t vms,
                                         std::size_t volumes, std::size_t networks) noexcept
    -> std::size_t {
    return inventory_fixed_size + (vteps * vtep_address_size) +
           (functions * inventory_function_size) + (vms * inventory_vm_size) +
           (volumes * inventory_volume_size) + (networks * inventory_network_size);
}

[[nodiscard]] inline auto decode_inventory(std::span<const std::byte> body)
    -> std::expected<Inventory, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    Inventory inv;
    inv.boot_id = in.le64();
    inv.last_command_seq = in.le64();
    inv.cores_total = in.le16();
    inv.cores_free = in.le16();
    inv.health = static_cast<Health>(in.u8());
    const std::size_t vtep_count = in.u8();
    bool zero = in.zeros(2);
    inv.pages_1g_total = in.le32();
    inv.pages_1g_free = in.le32();
    const std::size_t function_count = in.le16();
    const std::size_t vm_count = in.le16();
    const std::size_t volume_count = in.le16();
    const std::size_t network_count = in.le16();
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (vtep_count > max_vteps || function_count > max_functions || vm_count > max_vms ||
        volume_count > max_volumes || network_count > max_networks) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    // The exact length is known before anything is allocated.
    const auto want =
        inventory_size(vtep_count, function_count, vm_count, volume_count, network_count);
    if (body.size() < want) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    inv.vteps.resize(vtep_count);
    for (auto& v : inv.vteps) {
        in.bytes(v);
    }
    inv.functions.resize(function_count);
    for (auto& f : inv.functions) {
        f.slot = in.u8();
        f.type = static_cast<FunctionType>(in.u8());
        f.function = in.le16();
        f.state = static_cast<FunctionState>(in.u8());
        zero = in.zeros(3) && zero;
        f.owner_vm = in.le64();
    }
    inv.vms.resize(vm_count);
    for (auto& vm : inv.vms) {
        vm.vm_id = in.le64();
        vm.vcpus = in.le16();
        zero = in.zeros(2) && zero;
        vm.memory_mib = in.le32();
    }
    inv.volumes.resize(volume_count);
    for (auto& vol : inv.volumes) {
        vol.volume_id = in.le64();
        vol.owner_vm = in.le64();
        vol.size_gib = in.le32();
        zero = in.zeros(4) && zero;
    }
    inv.networks.resize(network_count);
    for (auto& n : inv.networks) {
        n.vni = in.le32();
        zero = in.zeros(4) && zero;
        n.map_version = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_inventory(inv); !ok) {
        return std::unexpected(ok.error());
    }
    return inv;
}

inline auto write_inventory(wire::Writer& w, const Inventory& inv) -> void {
    w.le64(inv.boot_id);
    w.le64(inv.last_command_seq);
    w.le16(inv.cores_total);
    w.le16(inv.cores_free);
    w.u8(static_cast<std::uint8_t>(inv.health));
    w.u8(static_cast<std::uint8_t>(inv.vteps.size()));
    w.le16(0);
    w.le32(inv.pages_1g_total);
    w.le32(inv.pages_1g_free);
    w.le16(static_cast<std::uint16_t>(inv.functions.size()));
    w.le16(static_cast<std::uint16_t>(inv.vms.size()));
    w.le16(static_cast<std::uint16_t>(inv.volumes.size()));
    w.le16(static_cast<std::uint16_t>(inv.networks.size()));
    for (const auto& v : inv.vteps) {
        w.bytes(v);
    }
    for (const auto& f : inv.functions) {
        w.u8(f.slot);
        w.u8(static_cast<std::uint8_t>(f.type));
        w.le16(f.function);
        w.u8(static_cast<std::uint8_t>(f.state));
        w.u8(0);
        w.le16(0);
        w.le64(f.owner_vm);
    }
    for (const auto& vm : inv.vms) {
        w.le64(vm.vm_id);
        w.le16(vm.vcpus);
        w.le16(0);
        w.le32(vm.memory_mib);
    }
    for (const auto& vol : inv.volumes) {
        w.le64(vol.volume_id);
        w.le64(vol.owner_vm);
        w.le32(vol.size_gib);
        w.le32(0);
    }
    for (const auto& n : inv.networks) {
        w.le32(n.vni);
        w.le32(0);
        w.le64(n.map_version);
    }
}

[[nodiscard]] inline auto decode_outcome(std::span<const std::byte> body)
    -> std::expected<CommandOutcome, DecodeError> {
    BodyReader in{.r = wire::Reader{body}};
    CommandOutcome c;
    c.in_reply_to = in.le64();
    c.command = in.le16();
    c.status = static_cast<CommandStatus>(in.le16());
    const std::size_t payload_len = in.u8();
    const bool zero = in.zeros(3);
    if (!in.ok) {
        return std::unexpected(DecodeError::truncated);
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (payload_len > max_outcome_payload) {
        return std::unexpected(DecodeError::too_many_entries);
    }
    if (in.r.remaining() < payload_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (in.r.remaining() > payload_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    c.payload.resize(payload_len);
    in.bytes(c.payload);
    if (auto ok = check_body(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

// Decodes one of the fixed 16-byte event bodies.
template<typename T>
[[nodiscard]] auto decode_fixed(std::span<const std::byte> body) -> std::expected<T, DecodeError> {
    if (body.size() < fixed_event_size) {
        return std::unexpected(DecodeError::truncated);
    }
    if (body.size() > fixed_event_size) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    BodyReader in{.r = wire::Reader{body}};
    T out{};
    bool zero = true;
    if constexpr (std::is_same_v<T, PoolStateChange>) {
        out.slot = in.u8();
        out.type = static_cast<FunctionType>(in.u8());
        out.function = in.le16();
        out.from = static_cast<FunctionState>(in.u8());
        out.to = static_cast<FunctionState>(in.u8());
        zero = in.zeros(2);
        out.owner_vm = in.le64();
    } else if constexpr (std::is_same_v<T, VmExitedReport>) {
        out.vm_id = in.le64();
        out.exit_status = in.le32();
        out.reason = static_cast<ExitReason>(in.u8());
        zero = in.zeros(3);
    } else if constexpr (std::is_same_v<T, MapApplied>) {
        out.vni = in.le32();
        zero = in.zeros(4);
        out.map_version = in.le64();
    } else {
        static_assert(std::is_same_v<T, HostFaultReport>);
        out.code = static_cast<FaultCode>(in.le16());
        out.slot = in.u8();
        zero = in.zeros(5);
        out.detail = in.le64();
    }
    if (!zero) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (auto ok = check_body(out); !ok) {
        return std::unexpected(ok.error());
    }
    return out;
}

inline auto write_body(wire::Writer& w, const ReportBody& body) -> void {
    std::visit(
        [&w]<typename T>(const T& b) {
            if constexpr (std::is_same_v<T, Inventory>) {
                write_inventory(w, b);
            } else if constexpr (std::is_same_v<T, CommandOutcome>) {
                w.le64(b.in_reply_to);
                w.le16(b.command);
                w.le16(static_cast<std::uint16_t>(b.status));
                w.u8(static_cast<std::uint8_t>(b.payload.size()));
                w.u8(0);
                w.le16(0);
                w.bytes(b.payload);
            } else if constexpr (std::is_same_v<T, PoolStateChange>) {
                w.u8(b.slot);
                w.u8(static_cast<std::uint8_t>(b.type));
                w.le16(b.function);
                w.u8(static_cast<std::uint8_t>(b.from));
                w.u8(static_cast<std::uint8_t>(b.to));
                w.le16(0);
                w.le64(b.owner_vm);
            } else if constexpr (std::is_same_v<T, VmExitedReport>) {
                w.le64(b.vm_id);
                w.le32(b.exit_status);
                w.u8(static_cast<std::uint8_t>(b.reason));
                w.u8(0);
                w.le16(0);
            } else if constexpr (std::is_same_v<T, MapApplied>) {
                w.le32(b.vni);
                w.le32(0);
                w.le64(b.map_version);
            } else {
                w.le16(static_cast<std::uint16_t>(b.code));
                w.u8(b.slot);
                w.u8(0);
                w.le32(0);
                w.le64(b.detail);
            }
        },
        body);
}

}  // namespace detail

// Strict decode: exactly one report, known magic, version and kind, a
// non-zero server ID and sequence number, body_len equal to the body that
// follows, and a body that passes every rule in the header comment.
[[nodiscard]] inline auto decode_report(std::span<const std::byte> bytes)
    -> std::expected<Report, DecodeError> {
    wire::Reader r{bytes};
    auto magic = r.le32();
    auto version = r.le16();
    auto kind = r.le16();
    auto server_id = r.le64();
    auto report_seq = r.le64();
    auto body_len = r.le32();
    auto reserved = r.le32();
    if (!magic || !version || !kind || !server_id || !report_seq || !body_len || !reserved) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*magic != report_magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (*version != report_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (*reserved != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (*report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    if (r.remaining() < *body_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > *body_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    const auto body = r.rest();
    auto wrap = [&](auto decoded) -> std::expected<Report, DecodeError> {
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        return Report{
            .server_id = *server_id, .report_seq = *report_seq, .body = std::move(*decoded)};
    };
    switch (static_cast<ReportKind>(*kind)) {
        case ReportKind::inventory:
            return wrap(detail::decode_inventory(body));
        case ReportKind::command_outcome:
            return wrap(detail::decode_outcome(body));
        case ReportKind::pool_state:
            return wrap(detail::decode_fixed<PoolStateChange>(body));
        case ReportKind::vm_exited:
            return wrap(detail::decode_fixed<VmExitedReport>(body));
        case ReportKind::map_applied:
            return wrap(detail::decode_fixed<MapApplied>(body));
        case ReportKind::host_fault:
            return wrap(detail::decode_fixed<HostFaultReport>(body));
    }
    return std::unexpected(DecodeError::unknown_value);
}

// Encodes a report, enforcing every rule decode_report checks.
[[nodiscard]] inline auto encode_report(const Report& report)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (report.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (report.report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    if (auto ok = std::visit([](const auto& b) { return detail::check_body(b); }, report.body);
        !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> body;
    wire::Writer bw{body};
    detail::write_body(bw, report.body);

    std::vector<std::byte> out;
    out.reserve(report_header_size + body.size());
    wire::Writer w{out};
    w.le32(report_magic);
    w.le16(report_version);
    w.le16(static_cast<std::uint16_t>(report_kind(report.body)));
    w.le64(report.server_id);
    w.le64(report.report_seq);
    w.le32(static_cast<std::uint32_t>(body.size()));
    w.le32(0);
    w.bytes(body);
    return out;
}

}  // namespace ak::proto
