// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/oar_protocol.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <tuple>
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
    return v >= std::to_underlying(Role::net) && v <= std::to_underlying(Role::khold);
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
        blk != nullptr &&
        (blk->volume_id == 0 || (blk->attachment_id == 0) != (blk->generation == 0))) {
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
    const bool zero_name =
        std::ranges::all_of(c.image_name, [](std::byte b) { return b == std::byte{0}; });
    if (c.image_store == 0) {
        if (!zero_name) {
            return std::unexpected(BodyError::bad_image);
        }
        return check_wrapped_key(c.wrapped_key);
    }
    if (zero_name) {
        return std::unexpected(BodyError::bad_image);
    }
    // An image volume may have no key (a plain image).
    if (c.wrapped_key.size() > max_wrapped_volume_key) {
        return std::unexpected(BodyError::bad_key_length);
    }
    return {};
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
        case Role::hold:
        case Role::khold:
            return false;
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
        w.le64(blk->attachment_id);
        w.le32(blk->generation);
        w.le32(zero32);
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
        BlkConfig blk;
        blk.volume_id = r.le64().value_or(0);
        blk.attachment_id = r.le64().value_or(0);
        blk.generation = r.le32().value_or(0);
        if (r.le32().value_or(0) != 0) {
            return std::unexpected(BodyError::reserved_not_zero);
        }
        p.config = blk;
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
    out.reserve(d.image_key ? deliver_keys_size : deliver_key_size);
    wire::Writer w{out};
    write_fn_volume(w, d.fn, d.volume_id);
    w.bytes(d.key);
    if (d.image_key) {
        w.bytes(*d.image_key);
    }
    return out;
}

auto decode_deliver_key(std::span<const std::byte> body) noexcept
    -> std::expected<DeliverKey, BodyError> {
    // One key, or the ephemeral key and an image key.
    if (body.size() != deliver_keys_size) {
        if (auto ok = check_size(body, deliver_key_size); !ok) {
            return std::unexpected(ok.error());
        }
    }
    wire::Reader r{body};
    auto head = read_fn_volume(r);
    if (!head) {
        return std::unexpected(head.error());
    }
    const auto keys = r.rest();
    DeliverKey d{.fn = head->fn,
                 .volume_id = head->volume,
                 .key = keys.first<volume_key_size>(),
                 .image_key = std::nullopt};
    if (keys.size() == 2 * volume_key_size) {
        d.image_key = keys.subspan<volume_key_size, volume_key_size>();
    }
    return d;
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

// ---- set_tunnel_key / set_tunnel_peer / remove_tunnel_peer ----------------

auto encode_set_tunnel_key(const SetTunnelKey& k)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (all_zero(k.private_key)) {
        return std::unexpected(BodyError::zero_key);
    }
    std::vector<std::byte> out;
    out.reserve(set_tunnel_key_size);  // no reallocation, no stray copy
    wire::Writer w{out};
    w.bytes(k.private_key);
    return out;
}

auto decode_set_tunnel_key(std::span<const std::byte> body) noexcept
    -> std::expected<SetTunnelKey, BodyError> {
    if (auto ok = check_size(body, set_tunnel_key_size); !ok) {
        return std::unexpected(ok.error());
    }
    if (all_zero(body)) {
        return std::unexpected(BodyError::zero_key);
    }
    return SetTunnelKey{.private_key = body.first<tunnel_key_size>()};
}

auto encode_set_tunnel_peer(const SetTunnelPeer& p)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (all_zero(p.vtep)) {
        return std::unexpected(BodyError::bad_vtep);
    }
    if (all_zero(p.public_key)) {
        return std::unexpected(BodyError::zero_key);
    }
    std::vector<std::byte> out;
    out.reserve(set_tunnel_peer_size);
    wire::Writer w{out};
    w.bytes(p.vtep);
    w.bytes(p.public_key);
    w.bytes(p.psk);
    return out;
}

auto decode_set_tunnel_peer(std::span<const std::byte> body) noexcept
    -> std::expected<SetTunnelPeer, BodyError> {
    if (auto ok = check_size(body, set_tunnel_peer_size); !ok) {
        return std::unexpected(ok.error());
    }
    SetTunnelPeer p{.vtep = {},
                    .public_key = body.subspan(vtep_size).first<tunnel_key_size>(),
                    .psk = body.subspan(vtep_size + tunnel_key_size).first<tunnel_key_size>()};
    std::ranges::copy(body.first<vtep_size>(), p.vtep.begin());
    if (all_zero(p.vtep)) {
        return std::unexpected(BodyError::bad_vtep);
    }
    if (all_zero(p.public_key)) {
        return std::unexpected(BodyError::zero_key);
    }
    return p;
}

auto encode_remove_tunnel_peer(const RemoveTunnelPeer& r)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (all_zero(r.vtep)) {
        return std::unexpected(BodyError::bad_vtep);
    }
    return std::vector<std::byte>(r.vtep.begin(), r.vtep.end());
}

auto decode_remove_tunnel_peer(std::span<const std::byte> body) noexcept
    -> std::expected<RemoveTunnelPeer, BodyError> {
    if (auto ok = check_size(body, remove_tunnel_peer_size); !ok) {
        return std::unexpected(ok.error());
    }
    RemoveTunnelPeer r;
    std::ranges::copy(body, r.vtep.begin());
    if (all_zero(r.vtep)) {
        return std::unexpected(BodyError::bad_vtep);
    }
    return r;
}

// ---- create_volume / delete_volume / rewrap_volume -------------------------

auto encode_create_volume(const CreateVolume& c)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_create_volume(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(create_volume_head_size + image_name_size + c.wrapped_key.size());
    wire::Writer w{out};
    w.le64(c.volume_id);
    w.le64(c.owner_vm);
    w.le64(c.capacity_sectors);
    w.le32(c.block_size);
    w.le16(static_cast<std::uint16_t>(c.wrapped_key.size()));
    w.le16(c.image_store);
    if (c.image_store != 0) {
        w.bytes(c.image_name);
    }
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
    c.image_store = r.le16().value_or(0);
    if (c.image_store != 0) {
        const auto name = r.bytes(image_name_size);
        if (!name) {
            return std::unexpected(BodyError::truncated);
        }
        std::ranges::copy(*name, c.image_name.begin());
        // A plain image's volume has no key: nothing may follow the name.
        if (key_len == 0) {
            if (r.remaining() != 0) {
                return std::unexpected(BodyError::bad_key_length);
            }
            if (auto ok = check_create_volume(c); !ok) {
                return std::unexpected(ok.error());
            }
            return c;
        }
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

auto encode_replica_config_frame(std::span<const std::byte> frame)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = decode_replica_config_frame(frame); !ok) {
        return std::unexpected(ok.error());
    }
    return std::vector<std::byte>(frame.begin(), frame.end());
}

auto decode_replica_config_frame(std::span<const std::byte> body) noexcept
    -> std::expected<std::span<const std::byte>, BodyError> {
    if (body.size() < min_replica_config_frame) {
        return std::unexpected(BodyError::truncated);
    }
    if (body.size() > max_replica_config_frame) {
        return std::unexpected(BodyError::trailing_bytes);
    }
    return body;
}

auto encode_volume_op_frame(std::span<const std::byte> frame)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_size(frame, volume_op_frame_size); !ok) {
        return std::unexpected(ok.error());
    }
    return std::vector<std::byte>(frame.begin(), frame.end());
}

auto decode_volume_op_frame(std::span<const std::byte> body) noexcept
    -> std::expected<std::span<const std::byte>, BodyError> {
    if (auto ok = check_size(body, volume_op_frame_size); !ok) {
        return std::unexpected(ok.error());
    }
    return body;
}

auto encode_lease_grant(const LeaseGrant& g) -> std::expected<std::vector<std::byte>, BodyError> {
    if (g.volume_id == 0 || g.epoch == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    std::vector<std::byte> out;
    out.reserve(lease_grant_size);
    wire::Writer w{out};
    w.le64(g.volume_id);
    w.le64(g.epoch);
    return out;
}

auto decode_lease_grant(std::span<const std::byte> body) noexcept
    -> std::expected<LeaseGrant, BodyError> {
    if (auto ok = check_size(body, lease_grant_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const LeaseGrant g{.volume_id = r.le64().value_or(0), .epoch = r.le64().value_or(0)};
    if (g.volume_id == 0 || g.epoch == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    return g;
}

auto encode_report_request(const ReportRequest& req)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (req.offset >= max_role_report) {
        return std::unexpected(BodyError::bad_chunk);
    }
    std::vector<std::byte> out;
    out.reserve(report_request_size);
    wire::Writer w{out};
    w.le64(req.ack);
    w.le32(req.offset);
    w.le32(zero32);
    return out;
}

auto decode_report_request(std::span<const std::byte> body) noexcept
    -> std::expected<ReportRequest, BodyError> {
    if (auto ok = check_size(body, report_request_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const ReportRequest req{.ack = r.le64().value_or(0), .offset = r.le32().value_or(0)};
    if (r.le32().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (req.offset >= max_role_report) {
        return std::unexpected(BodyError::bad_chunk);
    }
    return req;
}

namespace {

auto check_report_chunk(const ReportChunk& c) noexcept -> std::expected<void, BodyError> {
    if (c.total == 0) {
        if (c.report_seq != 0 || c.offset != 0 || !c.chunk.empty()) {
            return std::unexpected(BodyError::bad_chunk);
        }
        return {};
    }
    if (c.report_seq == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    if (c.total > max_role_report || c.chunk.empty() || c.chunk.size() > max_report_chunk ||
        c.offset >= c.total || c.chunk.size() > c.total - c.offset) {
        return std::unexpected(BodyError::bad_chunk);
    }
    return {};
}

}  // namespace

auto encode_report_chunk(const ReportChunk& c) -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_report_chunk(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(report_chunk_head_size + c.chunk.size());
    wire::Writer w{out};
    w.le64(c.report_seq);
    w.le32(c.total);
    w.le32(c.offset);
    w.bytes(c.chunk);
    return out;
}

auto decode_report_chunk(std::span<const std::byte> body) noexcept
    -> std::expected<ReportChunk, BodyError> {
    if (body.size() < report_chunk_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    ReportChunk c;
    c.report_seq = r.le64().value_or(0);
    c.total = r.le32().value_or(0);
    c.offset = r.le32().value_or(0);
    c.chunk = r.rest();
    if (auto ok = check_report_chunk(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

namespace {

constexpr auto valid_eject_op(std::uint8_t raw) noexcept -> bool {
    return raw >= std::to_underlying(EjectOp::request) && raw <= std::to_underlying(EjectOp::query);
}

constexpr auto valid_eject_state(std::uint8_t raw) noexcept -> bool {
    return raw <= std::to_underlying(EjectState::released);
}

}  // namespace

auto encode_eject(const Eject& e) -> std::expected<std::vector<std::byte>, BodyError> {
    if (!valid_eject_op(std::to_underlying(e.op))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    std::vector<std::byte> out;
    out.reserve(eject_request_size);
    wire::Writer w{out};
    w.le16(e.fn);
    w.u8(std::to_underlying(e.op));
    w.u8(0);
    return out;
}

auto decode_eject(std::span<const std::byte> body) noexcept -> std::expected<Eject, BodyError> {
    if (auto ok = check_size(body, eject_request_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto fn = r.le16().value_or(0);
    const auto op = r.u8().value_or(0);
    if (r.u8().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!valid_eject_op(op)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    return Eject{.fn = fn, .op = static_cast<EjectOp>(op)};
}

auto encode_eject_answer(EjectState s) -> std::expected<std::vector<std::byte>, BodyError> {
    if (!valid_eject_state(std::to_underlying(s))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    std::vector<std::byte> out;
    out.reserve(eject_answer_size);
    wire::Writer w{out};
    w.u8(std::to_underlying(s));
    w.u8(0);
    return out;
}

auto decode_eject_answer(std::span<const std::byte> body) noexcept
    -> std::expected<EjectState, BodyError> {
    if (auto ok = check_size(body, eject_answer_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto state = r.u8().value_or(0xFF);
    if (r.u8().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!valid_eject_state(state)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    return static_cast<EjectState>(state);
}

// ---- copy_volume ---------------------------------------------------------------

namespace {

constexpr auto valid_copy_op(std::uint8_t raw) noexcept -> bool {
    return raw >= std::to_underlying(CopyOp::start) && raw <= std::to_underlying(CopyOp::release);
}

constexpr auto valid_copy_direction(std::uint8_t raw) noexcept -> bool {
    return raw == std::to_underlying(CopyDirection::to_network) ||
           raw == std::to_underlying(CopyDirection::to_local);
}

constexpr auto valid_copy_state(std::uint8_t raw) noexcept -> bool {
    return raw <= std::to_underlying(CopyVolumeState::failed);
}

constexpr auto valid_copy_failure(std::uint8_t raw) noexcept -> bool {
    return raw <= std::to_underlying(CopyVolumeFailure::crypto);
}

// The rules both ends hold a copy_volume request to.
auto check_copy_volume(const CopyVolume& c) noexcept -> std::expected<void, BodyError> {
    if (!valid_copy_op(std::to_underlying(c.op)) ||
        !valid_copy_direction(std::to_underlying(c.direction))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (c.local_volume_id == 0 || c.network_volume_id == 0 || c.attachment_id == 0 ||
        c.generation == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    const bool start = c.op == CopyOp::start;
    if (c.local_key.has_value() != start || c.network_key.has_value() != start) {
        return std::unexpected(BodyError::bad_key_length);
    }
    return {};
}

}  // namespace

auto encode_copy_volume(const CopyVolume& c) -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_copy_volume(c); !ok) {
        return std::unexpected(ok.error());
    }
    // Reserved to the exact size so the buffer never reallocates and leaves
    // a stray copy of a key behind.
    std::vector<std::byte> out;
    out.reserve(c.local_key ? copy_volume_start_size : copy_volume_head_size);
    wire::Writer w{out};
    w.u8(std::to_underlying(c.op));
    w.u8(std::to_underlying(c.direction));
    w.le16(zero16);
    w.le32(c.mib_per_s);
    w.le64(c.local_volume_id);
    w.le64(c.network_volume_id);
    w.le64(c.attachment_id);
    w.le32(c.generation);
    w.le32(zero32);
    if (c.local_key) {
        w.bytes(*c.local_key);
        w.bytes(*c.network_key);
    }
    return out;
}

auto decode_copy_volume(std::span<const std::byte> body) noexcept
    -> std::expected<CopyVolume, BodyError> {
    if (body.size() != copy_volume_start_size) {
        if (auto ok = check_size(body, copy_volume_head_size); !ok) {
            return std::unexpected(ok.error());
        }
    }
    wire::Reader r{body};
    const auto op = r.u8().value_or(0);
    const auto direction = r.u8().value_or(0);
    if (r.le16().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!valid_copy_op(op) || !valid_copy_direction(direction)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    CopyVolume c{.op = static_cast<CopyOp>(op),
                 .direction = static_cast<CopyDirection>(direction),
                 .mib_per_s = r.le32().value_or(0),
                 .local_volume_id = r.le64().value_or(0),
                 .network_volume_id = r.le64().value_or(0),
                 .attachment_id = r.le64().value_or(0),
                 .generation = r.le32().value_or(0),
                 .local_key = std::nullopt,
                 .network_key = std::nullopt};
    if (r.le32().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (body.size() == copy_volume_start_size) {
        const auto keys = r.rest();
        c.local_key = keys.first<volume_key_size>();
        c.network_key = keys.subspan<volume_key_size, volume_key_size>();
    }
    if (auto ok = check_copy_volume(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

auto encode_copy_answer(const CopyAnswer& a) -> std::expected<std::vector<std::byte>, BodyError> {
    if (!valid_copy_state(std::to_underlying(a.state)) ||
        !valid_copy_failure(std::to_underlying(a.failure)) ||
        ((a.failure != CopyVolumeFailure::none) != (a.state == CopyVolumeState::failed))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (a.done_bytes > a.total_bytes || a.written_bytes > a.total_bytes) {
        return std::unexpected(BodyError::bad_geometry);
    }
    std::vector<std::byte> out;
    out.reserve(copy_volume_answer_size);
    wire::Writer w{out};
    w.u8(std::to_underlying(a.state));
    w.u8(std::to_underlying(a.failure));
    w.le16(zero16);
    w.le32(zero32);
    w.le64(a.total_bytes);
    w.le64(a.done_bytes);
    w.le64(a.written_bytes);
    return out;
}

auto decode_copy_answer(std::span<const std::byte> body) noexcept
    -> std::expected<CopyAnswer, BodyError> {
    if (auto ok = check_size(body, copy_volume_answer_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto state = r.u8().value_or(0xFF);
    const auto failure = r.u8().value_or(0xFF);
    if (r.le16().value_or(1) != 0 || r.le32().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!valid_copy_state(state) || !valid_copy_failure(failure) ||
        ((failure != 0) != (state == std::to_underlying(CopyVolumeState::failed)))) {
        return std::unexpected(BodyError::unknown_enum);
    }
    CopyAnswer a{.state = static_cast<CopyVolumeState>(state),
                 .failure = static_cast<CopyVolumeFailure>(failure),
                 .total_bytes = r.le64().value_or(0),
                 .done_bytes = r.le64().value_or(0),
                 .written_bytes = r.le64().value_or(0)};
    if (a.done_bytes > a.total_bytes || a.written_bytes > a.total_bytes) {
        return std::unexpected(BodyError::bad_geometry);
    }
    return a;
}

auto encode_cert_answer(const CertAnswer& a) -> std::expected<std::vector<std::byte>, BodyError> {
    if (!is_storage_role(a.role)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (a.csr.size() > max_csr) {
        return std::unexpected(BodyError::bad_csr);
    }
    std::vector<std::byte> out;
    out.reserve(cert_answer_head_size + a.csr.size());
    wire::Writer w{out};
    w.u8(static_cast<std::uint8_t>(a.role));
    w.u8(0);
    w.le16(static_cast<std::uint16_t>(a.csr.size()));
    w.bytes(a.csr);
    return out;
}

auto decode_cert_answer(std::span<const std::byte> body) noexcept
    -> std::expected<CertAnswer, BodyError> {
    if (body.size() < cert_answer_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    const auto role = static_cast<Role>(r.u8().value_or(0));
    const auto reserved = r.u8().value_or(0);
    const auto len = r.le16().value_or(0);
    if (reserved != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (!is_storage_role(role)) {
        return std::unexpected(BodyError::unknown_enum);
    }
    if (len > max_csr) {
        return std::unexpected(BodyError::bad_csr);
    }
    if (r.remaining() < len) {
        return std::unexpected(BodyError::truncated);
    }
    if (r.remaining() > len) {
        return std::unexpected(BodyError::trailing_bytes);
    }
    return CertAnswer{.role = role, .csr = r.rest()};
}

auto ReportQueue::push(std::uint64_t seq, std::vector<std::byte> report) -> bool {
    if (seq == 0 || report.empty() || report.size() > max_role_report) {
        return false;
    }
    if (_limit == 0) {
        ++_dropped;
        return true;
    }
    while (_reports.size() >= _limit) {
        _reports.pop_front();
        ++_dropped;
    }
    _reports.push_back({.seq = seq, .bytes = std::move(report)});
    return true;
}

auto ReportQueue::serve(const ReportRequest& request) -> std::expected<ReportChunk, Status> {
    if (!_reports.empty() && request.ack != 0 && _reports.front().seq == request.ack) {
        _reports.pop_front();
    }
    if (_reports.empty()) {
        if (request.offset != 0) {
            return std::unexpected(Status::bad_request);
        }
        return ReportChunk{};
    }
    const auto& head = _reports.front();
    if (request.offset >= head.bytes.size()) {
        return std::unexpected(Status::bad_request);
    }
    const auto n = std::min(max_report_chunk, head.bytes.size() - request.offset);
    return ReportChunk{.report_seq = head.seq,
                       .total = static_cast<std::uint32_t>(head.bytes.size()),
                       .offset = request.offset,
                       .chunk = std::span{head.bytes}.subspan(request.offset, n)};
}

auto encode_usage_request(std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError> {
    std::vector<std::byte> out;
    out.reserve(usage_request_size);
    wire::Writer w{out};
    w.le16(cursor);
    w.le16(0);
    return out;
}

auto decode_usage_request(std::span<const std::byte> body) noexcept
    -> std::expected<std::uint16_t, BodyError> {
    if (auto ok = check_size(body, usage_request_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    const auto cursor = r.le16().value_or(0);
    if (r.le16().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    return cursor;
}

namespace {

auto usage_key(const UsageEntry& e) noexcept -> std::pair<NicId, std::uint64_t> {
    return {e.nic_id, e.attachment};
}

auto check_usage_entries(std::span<const UsageEntry> entries) noexcept
    -> std::expected<void, BodyError> {
    for (const auto& e : entries) {
        if (e.nic_id == 0 || e.attachment == 0) {
            return std::unexpected(BodyError::zero_id);
        }
        if (e.vni == 0 || e.vni > max_vni) {
            return std::unexpected(BodyError::bad_vni);
        }
    }
    if (std::ranges::adjacent_find(entries, [](const auto& a, const auto& b) {
            return usage_key(a) >= usage_key(b);
        }) != entries.end()) {
        return std::unexpected(BodyError::not_increasing);
    }
    return {};
}

}  // namespace

auto UsagePager::take(Snapshot fresh) -> void {
    if (_open) {
        // The last read stopped part way: its final readings were taken
        // from the switch already, so they must not be lost.
        for (const auto& e : _snapshot) {
            if (e.detached) {
                fresh.push_back(e);
            }
        }
    }
    std::ranges::sort(fresh, {}, usage_key);
    const auto dup = std::ranges::unique(fresh, {}, usage_key);
    fresh.erase(dup.begin(), dup.end());
    if (fresh.size() > max_usage_entries) {
        // Keep final readings first: they cannot be read again.
        std::ranges::stable_partition(fresh, [](const UsageEntry& e) { return e.detached; });
        fresh.resize(max_usage_entries);
        std::ranges::sort(fresh, {}, usage_key);
    }
    _snapshot = std::move(fresh);
    _open = true;
}

auto UsagePager::serve(std::uint16_t cursor) -> std::expected<UsagePage, Status> {
    const std::size_t total = _snapshot.size();
    if (!_open || cursor > total || (cursor == total && cursor != 0)) {
        return std::unexpected(Status::bad_request);
    }
    const std::size_t count = std::min(max_usage_page, total - cursor);
    UsagePage page{.total = static_cast<std::uint16_t>(total), .entries = {}};
    const auto first = _snapshot.begin() + cursor;
    page.entries.assign(first, first + static_cast<std::ptrdiff_t>(count));
    if (cursor + count == total) {
        _open = false;
    }
    return page;
}

auto encode_usage_page(const UsagePage& page, std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (page.total > max_usage_entries || page.entries.size() > max_usage_page) {
        return std::unexpected(BodyError::too_many_entries);
    }
    if (std::size_t{cursor} + page.entries.size() > page.total ||
        (page.entries.empty() && page.total != 0)) {
        return std::unexpected(BodyError::bad_chunk);
    }
    if (auto ok = check_usage_entries(page.entries); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(usage_head_size + (page.entries.size() * usage_entry_size));
    wire::Writer w{out};
    w.le16(page.total);
    w.le16(static_cast<std::uint16_t>(page.entries.size()));
    w.le32(0);
    for (const auto& e : page.entries) {
        w.le64(e.nic_id);
        w.le32(e.vni);
        w.u8(e.detached ? usage_detached : zero8);
        w.u8(zero8);
        w.le16(0);
        w.le64(e.attachment);
        for (const std::uint64_t v :
             {e.frames, e.bytes, e.replicas_remote, e.replica_bytes_remote, e.replicas_local,
              e.replica_bytes_local, e.drop_policy, e.drop_rate, e.drop_fanout}) {
            w.le64(v);
        }
    }
    return out;
}

auto decode_usage_page(std::span<const std::byte> body, std::uint16_t cursor)
    -> std::expected<UsagePage, BodyError> {
    if (body.size() < usage_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    UsagePage page;
    page.total = r.le16().value_or(0);
    const std::size_t count = r.le16().value_or(0);
    if (r.le32().value_or(1) != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (page.total > max_usage_entries || count > max_usage_page) {
        return std::unexpected(BodyError::too_many_entries);
    }
    if (auto ok = check_size(body, usage_head_size + (count * usage_entry_size)); !ok) {
        return std::unexpected(ok.error());
    }
    if (std::size_t{cursor} + count > page.total || (count == 0 && page.total != 0)) {
        return std::unexpected(BodyError::bad_chunk);
    }
    page.entries.resize(count);
    for (auto& e : page.entries) {
        e.nic_id = r.le64().value_or(0);
        e.vni = r.le32().value_or(0);
        const auto flags = r.u8().value_or(0);
        const auto pad8 = r.u8().value_or(0);
        const auto pad16 = r.le16().value_or(0);
        if ((flags & ~usage_detached) != 0 || pad8 != 0 || pad16 != 0) {
            return std::unexpected(BodyError::reserved_not_zero);
        }
        e.detached = (flags & usage_detached) != 0;
        e.attachment = r.le64().value_or(0);
        for (std::uint64_t* v :
             {&e.frames, &e.bytes, &e.replicas_remote, &e.replica_bytes_remote, &e.replicas_local,
              &e.replica_bytes_local, &e.drop_policy, &e.drop_rate, &e.drop_fanout}) {
            *v = r.le64().value_or(0);
        }
    }
    if (auto ok = check_usage_entries(page.entries); !ok) {
        return std::unexpected(ok.error());
    }
    return page;
}

namespace {

auto membership_key(const MembershipEntry& e) noexcept {
    return std::tuple{e.nic_id, e.ipv6, e.group};
}

auto check_membership_entries(std::span<const MembershipEntry> entries) noexcept
    -> std::expected<void, BodyError> {
    for (const auto& e : entries) {
        if (e.nic_id == 0) {
            return std::unexpected(BodyError::zero_id);
        }
        if (e.vni == 0 || e.vni > max_vni) {
            return std::unexpected(BodyError::bad_vni);
        }
        if (!e.ipv6 && std::ranges::any_of(std::span{e.group}.subspan(4),
                                           [](std::byte b) { return b != std::byte{0}; })) {
            return std::unexpected(BodyError::bad_group);
        }
    }
    if (std::ranges::adjacent_find(entries, [](const auto& a, const auto& b) {
            return membership_key(a) >= membership_key(b);
        }) != entries.end()) {
        return std::unexpected(BodyError::not_increasing);
    }
    return {};
}

constexpr std::uint8_t family_ipv4 = 4;
constexpr std::uint8_t family_ipv6 = 6;

}  // namespace

auto MembershipPager::take(std::uint32_t generation, Snapshot fresh) -> void {
    std::ranges::sort(fresh, {}, membership_key);
    const auto dup = std::ranges::unique(fresh, {}, membership_key);
    fresh.erase(dup.begin(), dup.end());
    if (fresh.size() > max_memberships) {
        fresh.resize(max_memberships);
    }
    _generation = generation;
    _snapshot = std::move(fresh);
    _open = true;
}

auto MembershipPager::serve(std::uint16_t cursor) -> std::expected<MembershipPage, Status> {
    const std::size_t total = _snapshot.size();
    if (!_open || cursor > total || (cursor == total && cursor != 0)) {
        return std::unexpected(Status::bad_request);
    }
    const std::size_t count = std::min(max_membership_page, total - cursor);
    MembershipPage page{.generation = _generation,
                        .unchanged = false,
                        .total = static_cast<std::uint16_t>(total),
                        .entries = {}};
    const auto first = _snapshot.begin() + cursor;
    page.entries.assign(first, first + static_cast<std::ptrdiff_t>(count));
    if (cursor + count == total) {
        _open = false;
    }
    return page;
}

auto encode_membership_request(const MembershipRequest& request)
    -> std::expected<std::vector<std::byte>, BodyError> {
    std::vector<std::byte> out;
    out.reserve(membership_request_size);
    wire::Writer w{out};
    w.le16(request.cursor);
    w.le16(request.since ? membership_since : std::uint16_t{0});
    w.le32(request.since.value_or(0));
    return out;
}

auto decode_membership_request(std::span<const std::byte> body) noexcept
    -> std::expected<MembershipRequest, BodyError> {
    if (auto ok = check_size(body, membership_request_size); !ok) {
        return std::unexpected(ok.error());
    }
    wire::Reader r{body};
    MembershipRequest request;
    request.cursor = r.le16().value_or(0);
    const auto flags = r.le16().value_or(0);
    const auto since = r.le32().value_or(0);
    if ((flags & ~membership_since) != 0 || ((flags & membership_since) == 0 && since != 0)) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if ((flags & membership_since) != 0) {
        request.since = since;
    }
    return request;
}

auto encode_membership_page(const MembershipPage& page, std::uint16_t cursor)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (page.total > max_memberships || page.entries.size() > max_membership_page) {
        return std::unexpected(BodyError::too_many_entries);
    }
    if ((page.unchanged && (cursor != 0 || page.total != 0 || !page.entries.empty())) ||
        std::size_t{cursor} + page.entries.size() > page.total ||
        (page.entries.empty() && page.total != 0)) {
        return std::unexpected(BodyError::bad_chunk);
    }
    if (auto ok = check_membership_entries(page.entries); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(membership_head_size + (page.entries.size() * membership_entry_size));
    wire::Writer w{out};
    w.le32(page.generation);
    w.le16(page.total);
    w.le16(static_cast<std::uint16_t>(page.entries.size()));
    w.u8(page.unchanged ? membership_unchanged : zero8);
    w.u8(zero8);
    w.le16(0);
    for (const auto& e : page.entries) {
        w.le64(e.nic_id);
        w.le32(e.vni);
        w.u8(e.ipv6 ? family_ipv6 : family_ipv4);
        w.u8(zero8);
        w.le16(0);
        w.bytes(e.group);
    }
    return out;
}

auto decode_membership_page(std::span<const std::byte> body, std::uint16_t cursor)
    -> std::expected<MembershipPage, BodyError> {
    if (body.size() < membership_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    MembershipPage page;
    page.generation = r.le32().value_or(0);
    page.total = r.le16().value_or(0);
    const std::size_t count = r.le16().value_or(0);
    const auto flags = r.u8().value_or(0xFF);
    const auto pad8 = r.u8().value_or(1);
    const auto pad16 = r.le16().value_or(1);
    if ((flags & ~membership_unchanged) != 0 || pad8 != 0 || pad16 != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    page.unchanged = (flags & membership_unchanged) != 0;
    if (page.total > max_memberships || count > max_membership_page) {
        return std::unexpected(BodyError::too_many_entries);
    }
    if (auto ok = check_size(body, membership_head_size + (count * membership_entry_size)); !ok) {
        return std::unexpected(ok.error());
    }
    if ((page.unchanged && (cursor != 0 || page.total != 0 || count != 0)) ||
        std::size_t{cursor} + count > page.total || (count == 0 && page.total != 0)) {
        return std::unexpected(BodyError::bad_chunk);
    }
    page.entries.resize(count);
    for (auto& e : page.entries) {
        e.nic_id = r.le64().value_or(0);
        e.vni = r.le32().value_or(0);
        const auto family = r.u8().value_or(0);
        const auto p8 = r.u8().value_or(1);
        const auto p16 = r.le16().value_or(1);
        if (p8 != 0 || p16 != 0) {
            return std::unexpected(BodyError::reserved_not_zero);
        }
        if (family != family_ipv4 && family != family_ipv6) {
            return std::unexpected(BodyError::bad_group);
        }
        e.ipv6 = family == family_ipv6;
        const auto group = r.bytes(e.group.size());
        if (!group) {
            return std::unexpected(BodyError::truncated);
        }
        std::ranges::copy(*group, e.group.begin());
    }
    if (auto ok = check_membership_entries(page.entries); !ok) {
        return std::unexpected(ok.error());
    }
    return page;
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
        case Role::hold:
            return "hold";
        case Role::khold:
            return "khold";
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
        case BodyError::zero_key:
            return "zero_key";
        case BodyError::bad_image:
            return "bad_image";
        case BodyError::bad_csr:
            return "bad_csr";
        case BodyError::bad_group:
            return "bad_group";
        case BodyError::bad_secret:
            return "bad_secret";
        case BodyError::bad_text:
            return "bad_text";
        case BodyError::status_with_body:
            return "status_with_body";
    }
    return "unknown";
}

// ---- instance_secrets ------------------------------------------------------------

auto encode_instance_secrets(const InstanceSecrets& s)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (s.nic_id == 0 || s.vm_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    if (s.secrets.size() > proto::max_instance_secrets) {
        return std::unexpected(BodyError::too_many_entries);
    }
    std::size_t size = instance_secrets_head_size;
    for (std::size_t i = 0; i < s.secrets.size(); ++i) {
        const auto& e = s.secrets[i];
        if (!proto::detail::valid_secret_name(e.name) || e.value.empty() ||
            e.value.size() > proto::max_secret_size || (i > 0 && s.secrets[i - 1].name >= e.name)) {
            return std::unexpected(BodyError::bad_secret);
        }
        size += instance_secret_entry_head_size + e.name.size() + e.value.size();
    }
    std::vector<std::byte> out;
    out.reserve(size);  // never reallocated: no stray copy of a value
    wire::Writer w{out};
    w.le64(s.nic_id);
    w.le64(s.vm_id);
    w.u8(static_cast<std::uint8_t>(s.secrets.size()));
    for (int i = 0; i < 7; ++i) {
        w.u8(0);
    }
    for (const auto& e : s.secrets) {
        w.u8(static_cast<std::uint8_t>(e.name.size()));
        w.u8(0);
        w.le16(static_cast<std::uint16_t>(e.value.size()));
        for (const char c : e.name) {
            w.u8(static_cast<std::uint8_t>(c));
        }
        w.bytes(e.value);
    }
    return out;
}

auto decode_instance_secrets(std::span<const std::byte> frame)
    -> std::expected<InstanceSecrets, BodyError> {
    if (frame.size() > max_instance_secrets_frame) {
        return std::unexpected(BodyError::trailing_bytes);
    }
    wire::Reader r{frame};
    if (r.remaining() < instance_secrets_head_size) {
        return std::unexpected(BodyError::truncated);
    }
    InstanceSecrets s;
    s.nic_id = r.le64().value_or(0);
    s.vm_id = r.le64().value_or(0);
    const auto count = r.u8().value_or(0);
    const auto reserved = r.bytes(7).value_or(std::span<const std::byte>{});
    if (!all_zero(reserved)) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (s.nic_id == 0 || s.vm_id == 0) {
        return std::unexpected(BodyError::zero_id);
    }
    if (count > proto::max_instance_secrets) {
        return std::unexpected(BodyError::too_many_entries);
    }
    // On any failure the values decoded so far are wiped.
    auto fail = [&s](BodyError e) -> std::expected<InstanceSecrets, BodyError> {
        wipe(s);
        return std::unexpected(e);
    };
    s.secrets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (r.remaining() < instance_secret_entry_head_size) {
            return fail(BodyError::truncated);
        }
        const auto name_size = r.u8().value_or(0);
        const auto pad = r.u8().value_or(0);
        const auto value_size = r.le16().value_or(0);
        if (pad != 0) {
            return fail(BodyError::reserved_not_zero);
        }
        auto name = r.bytes(name_size);
        auto value = name ? r.bytes(value_size) : name;
        if (!name || !value) {
            return fail(BodyError::truncated);
        }
        InstanceSecretValue e;
        e.name.reserve(name_size);
        for (const auto b : *name) {
            e.name.push_back(static_cast<char>(b));
        }
        if (!proto::detail::valid_secret_name(e.name) || value_size == 0 ||
            value_size > proto::max_secret_size || (i > 0 && s.secrets.back().name >= e.name)) {
            return fail(BodyError::bad_secret);
        }
        e.value.assign(value->begin(), value->end());
        s.secrets.push_back(std::move(e));
    }
    if (r.remaining() != 0) {
        return fail(BodyError::trailing_bytes);
    }
    return s;
}

auto wipe(InstanceSecrets& s) noexcept -> void {
    for (auto& e : s.secrets) {
        secure_zero(e.value);
    }
    s.secrets.clear();
}

// ---- Role identity ----------------------------------------------------------

namespace {

auto check_role_identity(const RoleIdentity& id) -> std::expected<void, BodyError> {
    if (!proto::detail::valid_text(id.serial) || proto::detail::empty_text(id.serial) ||
        !proto::detail::valid_text(id.firmware)) {
        return std::unexpected(BodyError::bad_text);
    }
    if (id.drives.size() > max_role_drives) {
        return std::unexpected(BodyError::too_many_entries);
    }
    for (std::size_t i = 0; i < id.drives.size(); ++i) {
        const auto& d = id.drives[i];
        if (!proto::detail::valid_text(d.serial) || proto::detail::empty_text(d.serial)) {
            return std::unexpected(BodyError::bad_text);
        }
        if (d.size_bytes == 0) {
            return std::unexpected(BodyError::bad_geometry);
        }
        if (i > 0 && id.drives[i - 1].serial >= d.serial) {
            return std::unexpected(BodyError::not_increasing);
        }
    }
    return {};
}

auto read_text(wire::Reader& r) -> proto::IdentityText {
    proto::IdentityText t{};
    const auto bytes = r.bytes(t.size()).value_or(std::span<const std::byte>{});
    std::ranges::transform(bytes, t.begin(), [](std::byte b) { return static_cast<char>(b); });
    return t;
}

auto write_text(wire::Writer& w, const proto::IdentityText& t) -> void {
    std::array<std::byte, proto::identity_text_size> bytes{};
    std::ranges::transform(t, bytes.begin(), [](char c) { return static_cast<std::byte>(c); });
    w.bytes(bytes);
}

}  // namespace

auto encode_role_identity(const RoleIdentity& identity)
    -> std::expected<std::vector<std::byte>, BodyError> {
    if (auto ok = check_role_identity(identity); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(role_identity_fixed_size + (identity.drives.size() * role_drive_size));
    wire::Writer w{out};
    w.le16(0);
    w.le16(static_cast<std::uint16_t>(identity.drives.size()));
    w.le16(0);
    write_text(w, identity.serial);
    write_text(w, identity.firmware);
    for (const auto& d : identity.drives) {
        write_text(w, d.serial);
        w.le64(d.size_bytes);
    }
    return out;
}

auto decode_role_identity(std::span<const std::byte> body)
    -> std::expected<RoleIdentity, BodyError> {
    if (body.size() < role_identity_fixed_size) {
        return std::unexpected(BodyError::truncated);
    }
    wire::Reader r{body};
    const auto reserved1 = r.le16().value_or(0);
    const auto count = r.le16().value_or(0);
    const auto reserved2 = r.le16().value_or(0);
    if (reserved1 != 0 || reserved2 != 0) {
        return std::unexpected(BodyError::reserved_not_zero);
    }
    if (count > max_role_drives) {
        return std::unexpected(BodyError::too_many_entries);
    }
    const auto want = role_identity_fixed_size + (std::size_t{count} * role_drive_size);
    if (body.size() < want) {
        return std::unexpected(BodyError::truncated);
    }
    if (body.size() > want) {
        return std::unexpected(BodyError::trailing_bytes);
    }
    RoleIdentity id;
    id.serial = read_text(r);
    id.firmware = read_text(r);
    id.drives.resize(count);
    for (auto& d : id.drives) {
        d.serial = read_text(r);
        d.size_bytes = r.le64().value_or(0);
    }
    if (auto ok = check_role_identity(id); !ok) {
        return std::unexpected(ok.error());
    }
    return id;
}

auto parse_identity_option(std::string_view flag, std::string_view value, RoleIdentity& out)
    -> std::optional<bool> {
    const auto text = [](std::string_view v, proto::IdentityText& t) {
        if (v.size() > proto::identity_text_size) {
            return false;
        }
        t = proto::identity_text(v);
        return proto::detail::valid_text(t);
    };
    if (flag == "--serial") {
        return text(value, out.serial) && !proto::detail::empty_text(out.serial);
    }
    if (flag == "--firmware") {
        return text(value, out.firmware);
    }
    if (flag == "--drive-serial") {
        const auto colon = value.rfind(':');
        if (colon == std::string_view::npos) {
            return false;
        }
        RoleDrive d;
        const auto size = value.substr(colon + 1);
        const auto [p, ec] = std::from_chars(size.data(), size.data() + size.size(), d.size_bytes);
        if (ec != std::errc{} || p != size.data() + size.size() || d.size_bytes == 0 ||
            !text(value.substr(0, colon), d.serial) || proto::detail::empty_text(d.serial)) {
            return false;
        }
        // Kept in serial order, as the response needs them.
        const auto at = std::ranges::lower_bound(out.drives, d.serial, {}, &RoleDrive::serial);
        if (at != out.drives.end() && at->serial == d.serial) {
            return false;
        }
        if (out.drives.size() >= max_role_drives) {
            return false;
        }
        out.drives.insert(at, d);
        return true;
    }
    return std::nullopt;
}

auto valid_role_identity(const RoleIdentity& identity) -> bool {
    return check_role_identity(identity).has_value();
}

}  // namespace ak::helm::oar
