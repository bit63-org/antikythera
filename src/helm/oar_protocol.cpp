// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/oar_protocol.hpp"

#include <algorithm>
#include <utility>

#include "common/wire.hpp"

namespace ak::helm::oar {

namespace {

constexpr std::uint8_t zero8 = 0;
constexpr std::uint16_t zero16 = 0;
constexpr std::uint32_t zero32 = 0;
constexpr std::byte mac_multicast_bit{0x01};
constexpr std::byte mac_local_bit{0x02};
constexpr std::uint32_t logical_block_4k = 4096;

// Fixed-size bodies: reject both short and long input before reading.
auto check_size(std::span<const std::byte> body, std::size_t want) noexcept
    -> std::expected<void, BodyError> {
    if (body.size() < want) {
        return std::unexpected(BodyError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(BodyError::trailing_bytes);
    }
    return {};
}

auto known_function_type(std::uint8_t v) noexcept -> bool {
    return std::ranges::any_of(all_function_types,
                               [v](FunctionType t) { return std::to_underlying(t) == v; });
}

auto known_cleaning_action(std::uint8_t v) noexcept -> bool {
    return v <= std::to_underlying(CleaningAction::scrub_gpu_vf);
}

auto known_status(std::uint8_t v) noexcept -> bool {
    return v <= std::to_underlying(Status::unsupported);
}

auto known_role(std::uint8_t v) noexcept -> bool {
    return v >= std::to_underlying(Role::net) && v <= std::to_underlying(Role::gpu);
}

auto known_health(std::uint8_t v) noexcept -> bool {
    return v <= std::to_underlying(HealthState::faulted);
}

auto valid_mac(const Mac& mac) noexcept -> bool {
    return (mac[0] & mac_local_bit) != std::byte{0} && (mac[0] & mac_multicast_bit) == std::byte{0};
}

auto all_zero(std::span<const std::byte> bytes) noexcept -> bool {
    return std::ranges::all_of(bytes, [](std::byte b) { return b == std::byte{0}; });
}

// The config a function type takes: which variant alternative it must hold.
auto config_matches(FunctionType type, const FunctionConfig& config) noexcept -> bool {
    switch (type) {
        case FunctionType::nic_vf:
            return std::holds_alternative<NicConfig>(config);
        case FunctionType::blk_fn:
            return std::holds_alternative<BlkConfig>(config);
        case FunctionType::gpu_whole:
        case FunctionType::gpu_vf:
            return std::holds_alternative<std::monostate>(config);
    }
    return false;
}

auto check_nic(const NicConfig& n) noexcept -> std::expected<void, BodyError> {
    if (n.nic_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    if (n.vni == 0 || n.vni > max_vni) {
        return std::unexpected(BodyError::bad_vni);
    }
    if (!valid_mac(n.mac)) {
        return std::unexpected(BodyError::bad_mac);
    }
    return {};
}

auto check_prepare(const PrepareFunction& p) noexcept -> std::expected<void, BodyError> {
    if (!known_function_type(std::to_underlying(p.type))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (p.vm_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    if (!config_matches(p.type, p.config)) {
        return std::unexpected(BodyError::type_mismatch);
    }
    if (const auto* nic = std::get_if<NicConfig>(&p.config)) {
        return check_nic(*nic);
    }
    if (const auto* blk = std::get_if<BlkConfig>(&p.config);
        blk != nullptr && blk->volume_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    return {};
}

auto config_size(FunctionType type) noexcept -> std::size_t {
    switch (type) {
        case FunctionType::nic_vf:
            return nic_config_size;
        case FunctionType::blk_fn:
            return blk_config_size;
        case FunctionType::gpu_whole:
        case FunctionType::gpu_vf:
            return 0;
    }
    return 0;
}

auto check_chunk(std::uint32_t total, std::uint32_t offset, std::size_t len) noexcept
    -> std::expected<void, BodyError> {
    if (total == 0 || total > max_map_frame || len == 0 || len > max_map_chunk || offset >= total ||
        len > total - offset) {
        return std::unexpected(BodyError::bad_chunk);
    }
    return {};
}

auto check_inventory(const Inventory& inv) noexcept -> std::expected<void, BodyError> {
    if (!known_role(std::to_underlying(inv.role))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (inv.functions.size() > max_inventory_entries) {
        return std::unexpected(BodyError::too_many_entries);
    }
    if (all_zero(inv.vtep) == (inv.role == Role::net)) {
        return std::unexpected(BodyError::bad_vtep);
    }
    for (std::size_t i = 0; i < inv.functions.size(); ++i) {
        const auto& e = inv.functions[i];
        if (!known_function_type(std::to_underlying(e.type))) {
            return std::unexpected(BodyError::unknown_enum);
        }
        if (!role_serves(inv.role, e.type)) {
            return std::unexpected(BodyError::type_mismatch);
        }
        if (i > 0 && e.fn <= inv.functions[i - 1].fn) {
            return std::unexpected(BodyError::not_increasing);
        }
    }
    return {};
}

// Body for a function and volume (deliver_key and drop_key share it).
auto write_fn_volume(wire::Writer& w, FunctionNumber fn, VolumeId volume) -> void {
    w.le16(fn);
    w.le16(zero16);
    w.le32(zero32);
    w.le64(volume);
}

struct FnVolume {
    FunctionNumber fn;
    VolumeId volume;
};

auto read_fn_volume(wire::Reader& r) noexcept -> std::expected<FnVolume, BodyError> {
    const auto fn = r.le16();
    const auto reserved16 = r.le16();
    const auto reserved32 = r.le32();
    const auto volume = r.le64();
    if (!fn || !reserved16 || !reserved32 || !volume) {
        return std::unexpected(BodyError::truncated);
    }
    if (*reserved16 != 0 || *reserved32 != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (*volume == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    return FnVolume{.fn = *fn, .volume = *volume};
}

auto check_wrapped_key(std::span<const std::byte> key) noexcept -> std::expected<void, BodyError> {
    if (key.empty() || key.size() > max_wrapped_volume_key) {
        return std::unexpected(BodyError::bad_key_length);
    }
    return {};
}

auto check_create_volume(const CreateVolume& c) noexcept -> std::expected<void, BodyError> {
    if (c.volume_id == 0 || c.owner_vm == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    if ((c.block_size != sector_size && c.block_size != logical_block_4k) ||
        c.capacity_sectors == 0 || c.capacity_sectors > max_capacity_sectors ||
        c.capacity_sectors % (c.block_size / sector_size) != 0) {
        return std::unexpected(BodyError::bad_geometry);
    }
    return check_wrapped_key(c.wrapped_key);
}

auto check_rewrap_volume(const RewrapVolume& r) noexcept -> std::expected<void, BodyError> {
    if (r.volume_id == 0 || r.owner_vm == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    return check_wrapped_key(r.wrapped_key);
}

// The wrapped key that ends a volume body: exactly `len` bytes must remain.
auto read_wrapped_key(wire::Reader& r, std::uint16_t len) noexcept
    -> std::expected<std::span<const std::byte>, BodyError> {
    if (len == 0 || len > max_wrapped_volume_key || r.remaining() != len) {
        return std::unexpected(BodyError::bad_key_length);
    }
    return r.rest();
}

}  // namespace

auto role_serves(Role role, FunctionType type) noexcept -> bool {
    switch (role) {
        case Role::net:
            return type == FunctionType::nic_vf;
        case Role::blk:
            return type == FunctionType::blk_fn;
        case Role::gpu:
            return is_gpu(type);
    }
    return false;
}

// ---- prepare_function -----------------------------------------------------

auto encode_prepare_function(const PrepareFunction& p)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_prepare(p); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(prepare_head_size + config_size(p.type));
    wire::Writer w{out};
    w.le16(p.fn);
    w.u8(std::to_underlying(p.type));
    w.u8(zero8);
    w.le32(zero32);
    w.le64(p.vm_id);
    if (const auto* nic = std::get_if<NicConfig>(&p.config)) {
        w.le64(nic->nic_id);
        w.le32(nic->vni);
        w.bytes(nic->mac);
        w.le16(zero16);
    } else if (const auto* blk = std::get_if<BlkConfig>(&p.config)) {
        w.le64(blk->volume_id);
    }
    return out;
}

auto decode_prepare_function(std::span<const std::byte> body) noexcept
    -> std::expected<PrepareFunction, BodyError> {
    if (body.size() < prepare_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    PrepareFunction p;
    p.fn = r.le16().value_or(0);
    const auto type = r.u8().value_or(0);
    const auto reserved8 = r.u8().value_or(0);
    const auto reserved32 = r.le32().value_or(0);
    p.vm_id = r.le64().value_or(0);
    if (reserved8 != 0 || reserved32 != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!known_function_type(type)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    p.type = static_cast<FunctionType>(type);
    if (auto ok = check_size(r.rest(), config_size(p.type)); !ok) {
        return std::unexpected(ok.error());
    }
    if (p.type == FunctionType::nic_vf) {
        NicConfig nic;
        nic.nic_id = r.le64().value_or(0);
        nic.vni = r.le32().value_or(0);
        std::ranges::copy(r.bytes(mac_size).value_or(std::span<const std::byte>{}),
                          nic.mac.begin());
        if (r.le16().value_or(0) != 0) {
            return std::unexpected(BodyError::reserved_not_zero);
        }
        p.config = nic;
    } else if (p.type == FunctionType::blk_fn) {
        p.config = BlkConfig{.volume_id = r.le64().value_or(0)};
    }
    if (auto ok = check_prepare(p); !ok) {
        return std::unexpected(ok.error());
    }
    return p;
}

// ---- clean_function -------------------------------------------------------

auto encode_clean_function(const CleanFunction& c)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (!known_cleaning_action(std::to_underlying(c.action))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    std::vector<std::byte> out;
    out.reserve(clean_function_size);
    wire::Writer w{out};
    w.le16(c.fn);
    w.u8(std::to_underlying(c.action));
    w.u8(zero8);
    return out;
}

auto decode_clean_function(std::span<const std::byte> body) noexcept
    -> std::expected<CleanFunction, BodyError> {
    if (auto ok = check_size(body, clean_function_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto fn = r.le16().value_or(0);
    const auto action = r.u8().value_or(0);
    if (r.u8().value_or(0) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!known_cleaning_action(action)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    return CleanFunction{.fn = fn, .action = static_cast<CleaningAction>(action)};
}

// ---- deliver_key / drop_key -----------------------------------------------

auto encode_deliver_key(const DeliverKey& d) -> std::expected<std::vector<std::byte>, BodyError> {
    if (d.volume_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    // Reserved to the exact size so the buffer never reallocates and leaves
    // a stray copy of the key behind.
    std::vector<std::byte> out;
    out.reserve(deliver_key_size);
    wire::Writer w{out};
    write_fn_volume(w, d.fn, d.volume_id);
    w.bytes(d.key);
    return out;
}

auto decode_deliver_key(std::span<const std::byte> body) noexcept
    -> std::expected<DeliverKey, BodyError> {
    if (auto ok = check_size(body, deliver_key_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    auto head = read_fn_volume(r);
    if (!head) {
        return std::unexpected(head.error());
    }
    return DeliverKey{
        .fn = head->fn, .volume_id = head->volume, .key = r.rest().first<volume_key_size>()};
}

auto encode_drop_key(const DropKey& d) -> std::expected<std::vector<std::byte>, BodyError> {
    if (d.volume_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    std::vector<std::byte> out;
    out.reserve(drop_key_size);
    wire::Writer w{out};
    write_fn_volume(w, d.fn, d.volume_id);
    return out;
}

auto decode_drop_key(std::span<const std::byte> body) noexcept
    -> std::expected<DropKey, BodyError> {
    if (auto ok = check_size(body, drop_key_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    auto head = read_fn_volume(r);
    if (!head) {
        return std::unexpected(head.error());
    }
    return DropKey{.fn = head->fn, .volume_id = head->volume};
}

// ---- create_volume / delete_volume / rewrap_volume -------------------------

auto encode_create_volume(const CreateVolume& c)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_create_volume(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(create_volume_head_size + c.wrapped_key.size());
    wire::Writer w{out};
    w.le64(c.volume_id);
    w.le64(c.owner_vm);
    w.le64(c.capacity_sectors);
    w.le32(c.block_size);
    w.le16(static_cast<std::uint16_t>(c.wrapped_key.size()));
    w.le16(zero16);
    w.bytes(c.wrapped_key);
    return out;
}

auto decode_create_volume(std::span<const std::byte> body) noexcept
    -> std::expected<CreateVolume, BodyError> {
    if (body.size() < create_volume_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    CreateVolume c;
    c.volume_id = r.le64().value_or(0);
    c.owner_vm = r.le64().value_or(0);
    c.capacity_sectors = r.le64().value_or(0);
    c.block_size = r.le32().value_or(0);
    const auto key_len = r.le16().value_or(0);
    if (r.le16().value_or(0) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    auto key = read_wrapped_key(r, key_len);
    if (!key) {
        return std::unexpected(key.error());
    }
    c.wrapped_key = *key;
    if (auto ok = check_create_volume(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

auto encode_delete_volume(const DeleteVolume& d)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (d.volume_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    std::vector<std::byte> out;
    out.reserve(delete_volume_size);
    wire::Writer w{out};
    w.le64(d.volume_id);
    return out;
}

auto decode_delete_volume(std::span<const std::byte> body) noexcept
    -> std::expected<DeleteVolume, BodyError> {
    if (auto ok = check_size(body, delete_volume_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto volume = r.le64().value_or(0);
    if (volume == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    return DeleteVolume{.volume_id = volume};
}

auto encode_rewrap_volume(const RewrapVolume& v)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_rewrap_volume(v); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(rewrap_volume_head_size + v.wrapped_key.size());
    wire::Writer w{out};
    w.le64(v.volume_id);
    w.le64(v.owner_vm);
    w.le16(static_cast<std::uint16_t>(v.wrapped_key.size()));
    w.le16(zero16);
    w.le32(zero32);
    w.bytes(v.wrapped_key);
    return out;
}

auto decode_rewrap_volume(std::span<const std::byte> body) noexcept
    -> std::expected<RewrapVolume, BodyError> {
    if (body.size() < rewrap_volume_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    RewrapVolume v;
    v.volume_id = r.le64().value_or(0);
    v.owner_vm = r.le64().value_or(0);
    const auto key_len = r.le16().value_or(0);
    const auto reserved16 = r.le16().value_or(0);
    const auto reserved32 = r.le32().value_or(0);
    if (reserved16 != 0 || reserved32 != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    auto key = read_wrapped_key(r, key_len);
    if (!key) {
        return std::unexpected(key.error());
    }
    v.wrapped_key = *key;
    if (auto ok = check_rewrap_volume(v); !ok) {
        return std::unexpected(ok.error());
    }
    return v;
}

// ---- map_update -----------------------------------------------------------

auto encode_map_chunk(const MapChunk& m) -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_chunk(m.total, m.offset, m.chunk.size()); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(map_chunk_head_size + m.chunk.size());
    wire::Writer w{out};
    w.le32(m.total);
    w.le32(m.offset);
    w.bytes(m.chunk);
    return out;
}

auto decode_map_chunk(std::span<const std::byte> body) noexcept
    -> std::expected<MapChunk, BodyError> {
    if (body.size() <= map_chunk_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    MapChunk m;
    m.total = r.le32().value_or(0);
    m.offset = r.le32().value_or(0);
    m.chunk = r.rest();
    if (auto ok = check_chunk(m.total, m.offset, m.chunk.size()); !ok) {
        return std::unexpected(ok.error());
    }
    return m;
}

auto decode_empty(std::span<const std::byte> body) noexcept -> std::expected<void, BodyError> {
    return check_size(body, 0);
}

// ---- Responses ------------------------------------------------------------

auto encode_response(Status status, std::span<const std::byte> body)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (!known_status(std::to_underlying(status))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (status != Status::ok && !body.empty()) {
        return std::unexpected(BodyError::status_with_body);
    }
    if (body.size() > max_body_size - response_head_size) {
        return std::unexpected(BodyError::trailing_bytes);
    }
    std::vector<std::byte> out;
    out.reserve(response_head_size + body.size());
    wire::Writer w{out};
    w.u8(std::to_underlying(status));
    w.u8(zero8);
    w.bytes(body);
    return out;
}

auto decode_response(std::span<const std::byte> response) noexcept
    -> std::expected<ResponseView, BodyError> {
    if (response.size() < response_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{response};
    const auto status = r.u8().value_or(0);
    if (r.u8().value_or(0) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!known_status(status)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    const auto s = static_cast<Status>(status);
    if (s != Status::ok && r.remaining() != 0) {
        return std::unexpected(BodyError::status_with_body);
    }
    return ResponseView{.status = s, .body = r.rest()};
}

auto encode_inventory(const Inventory& inv) -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_inventory(inv); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(inventory_head_size + (inv.functions.size() * inventory_entry_size));
    wire::Writer w{out};
    w.u8(std::to_underlying(inv.role));
    w.u8(zero8);
    w.le16(static_cast<std::uint16_t>(inv.functions.size()));
    w.bytes(inv.vtep);
    for (const auto& e : inv.functions) {
        w.le16(e.fn);
        w.u8(std::to_underlying(e.type));
        w.u8(zero8);
    }
    return out;
}

auto decode_inventory(std::span<const std::byte> body) -> std::expected<Inventory, BodyError> {
    if (body.size() < inventory_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    const auto role = r.u8().value_or(0);
    const auto reserved = r.u8().value_or(0);
    const auto count = r.le16().value_or(0);
    Inventory inv;
    std::ranges::copy(r.bytes(vtep_size).value_or(std::span<const std::byte>{}), inv.vtep.begin());
    if (reserved != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!known_role(role)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    inv.role = static_cast<Role>(role);
    if (count > max_inventory_entries) {
        return std::unexpected(BodyError::too_many_entries);
    }
    if (auto ok = check_size(r.rest(), std::size_t{count} * inventory_entry_size); !ok) {
        return std::unexpected(ok.error());
    }
    inv.functions.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto fn = r.le16().value_or(0);
        const auto type = r.u8().value_or(0);
        if (r.u8().value_or(0) != 0) {
            return std::unexpected(BodyError::reserved_not_zero);
        }
        if (!known_function_type(type)) {
            return std::unexpected(BodyError::unknown_enum);
        }
        inv.functions.push_back({.fn = fn, .type = static_cast<FunctionType>(type)});
    }
    if (auto ok = check_inventory(inv); !ok) {
        return std::unexpected(ok.error());
    }
    return inv;
}

auto encode_health(const Health& h) -> std::expected<std::vector<std::byte>, BodyError> {
    if (!known_health(std::to_underlying(h.state))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    std::vector<std::byte> out;
    out.reserve(health_body_size);
    wire::Writer w{out};
    w.u8(std::to_underlying(h.state));
    w.u8(zero8);
    w.le16(h.fault_code);
    w.le32(h.uptime_seconds);
    return out;
}

auto decode_health(std::span<const std::byte> body) noexcept -> std::expected<Health, BodyError> {
    if (auto ok = check_size(body, health_body_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto state = r.u8().value_or(0);
    const auto reserved = r.u8().value_or(0);
    Health h;
    h.fault_code = r.le16().value_or(0);
    h.uptime_seconds = r.le32().value_or(0);
    if (reserved != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!known_health(state)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    h.state = static_cast<HealthState>(state);
    return h;
}

// ---- Names ----------------------------------------------------------------

auto to_string(Status s) noexcept -> const char* {
    switch (s) {
        case Status::ok:
            return "ok";
        case Status::unknown_function:
            return "unknown_function";
        case Status::wrong_type:
            return "wrong_type";
        case Status::bad_request:
            return "bad_request";
        case Status::busy:
            return "busy";
        case Status::failed:
            return "failed";
        case Status::unsupported:
            return "unsupported";
    }
    return "unknown";
}

auto to_string(Role r) noexcept -> const char* {
    switch (r) {
        case Role::net:
            return "net";
        case Role::blk:
            return "blk";
        case Role::gpu:
            return "gpu";
    }
    return "unknown";
}

auto to_string(HealthState h) noexcept -> const char* {
    switch (h) {
        case HealthState::ok:
            return "ok";
        case HealthState::degraded:
            return "degraded";
        case HealthState::faulted:
            return "faulted";
    }
    return "unknown";
}

auto to_string(BodyError e) noexcept -> const char* {
    switch (e) {
        case BodyError::truncated:
            return "truncated";
        case BodyError::trailing_bytes:
            return "trailing_bytes";
        case BodyError::reserved_not_zero:
            return "reserved_not_zero";
        case BodyError::unknown_enum:
            return "unknown_enum";
        case BodyError::zero_id:
            return "zero_id";
        case BodyError::bad_vni:
            return "bad_vni";
        case BodyError::bad_mac:
            return "bad_mac";
        case BodyError::bad_vtep:
            return "bad_vtep";
        case BodyError::type_mismatch:
            return "type_mismatch";
        case BodyError::not_increasing:
            return "not_increasing";
        case BodyError::too_many_entries:
            return "too_many_entries";
        case BodyError::bad_chunk:
            return "bad_chunk";
        case BodyError::bad_geometry:
            return "bad_geometry";
        case BodyError::bad_key_length:
            return "bad_key_length";
        case BodyError::status_with_body:
            return "status_with_body";
    }
    return "unknown";
}

}  // namespace ak::helm::oar
