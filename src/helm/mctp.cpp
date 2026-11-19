// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/mctp.hpp"

#include <algorithm>
#include <utility>

#include "common/wire.hpp"

namespace ak::helm::mctp {

namespace {

constexpr std::uint8_t rw_bit = 0x01;  // SMBus R/W bit in an address byte
constexpr std::uint8_t pec_polynomial = 0x07;
constexpr std::uint8_t msb = 0x80;
constexpr unsigned bits_per_byte = 8;

constexpr unsigned version_bits = 4;
constexpr std::uint8_t version_mask = 0x0F;
constexpr std::uint8_t som_bit = 0x80;
constexpr std::uint8_t eom_bit = 0x40;
constexpr unsigned seq_shift = 4;
constexpr std::uint8_t seq_mask = 0x03;
constexpr unsigned tag_owner_shift = 3;
constexpr std::uint8_t tag_mask = 0x07;
constexpr std::size_t tags_per_owner = max_tag + 1;

constexpr std::size_t min_packet_size = smbus_prefix_size + counted_overhead + pec_size;
constexpr std::uint8_t reserved_byte = 0;

constexpr auto reserved_eid(std::uint8_t eid) noexcept -> bool {
    return eid != null_eid && eid < first_assignable_eid;
}

constexpr auto valid_dest_eid(std::uint8_t eid) noexcept -> bool {
    return !reserved_eid(eid);
}

constexpr auto valid_src_eid(std::uint8_t eid) noexcept -> bool {
    return !reserved_eid(eid) && eid != broadcast_eid;
}

constexpr auto flags_byte(const TransportHeader& h) noexcept -> std::uint8_t {
    std::uint8_t b = 0;
    if (h.som) {
        b |= som_bit;
    }
    if (h.eom) {
        b |= eom_bit;
    }
    b |= static_cast<std::uint8_t>((h.seq & seq_mask) << seq_shift);
    if (h.tag_owner) {
        b |= static_cast<std::uint8_t>(1U << tag_owner_shift);
    }
    b |= static_cast<std::uint8_t>(h.tag & tag_mask);
    return b;
}

constexpr auto known_vendor_type(std::uint8_t raw) noexcept -> bool {
    switch (static_cast<VendorType>(raw)) {
        case VendorType::function_inventory:
        case VendorType::prepare_function:
        case VendorType::clean_function:
        case VendorType::deliver_key:
        case VendorType::drop_key:
        case VendorType::map_update:
        case VendorType::health:
        case VendorType::create_volume:
        case VendorType::delete_volume:
        case VendorType::rewrap_volume:
            return true;
    }
    return false;
}

constexpr auto context_index(bool tag_owner, std::uint8_t tag) noexcept -> std::size_t {
    return (tag_owner ? tags_per_owner : 0) + (tag & tag_mask);
}

}  // namespace

auto pec(std::span<const std::byte> bytes) noexcept -> std::uint8_t {
    std::uint8_t crc = 0;
    for (const auto b : bytes) {
        crc ^= std::to_integer<std::uint8_t>(b);
        for (unsigned i = 0; i < bits_per_byte; ++i) {
            crc = (crc & msb) != 0 ? static_cast<std::uint8_t>((crc << 1U) ^ pec_polynomial)
                                   : static_cast<std::uint8_t>(crc << 1U);
        }
    }
    return crc;
}

auto decode_packet(std::span<const std::byte> bytes) noexcept
    -> std::expected<Packet, PacketError> {
    if (bytes.size() < min_packet_size) {
        return std::unexpected(PacketError::truncated);
    }
    const auto byte_count = std::to_integer<std::size_t>(bytes[2]);
    if (byte_count < counted_overhead) {
        return std::unexpected(PacketError::truncated);
    }
    const std::size_t covered = smbus_prefix_size + byte_count;
    if (bytes.size() < covered + pec_size) {
        return std::unexpected(PacketError::truncated);
    }
    if (bytes.size() > covered + pec_size) {
        return std::unexpected(PacketError::trailing_bytes);
    }
    if (pec(bytes.first(covered)) != std::to_integer<std::uint8_t>(bytes[covered])) {
        return std::unexpected(PacketError::bad_pec);
    }

    // Lengths were checked above, so these reads cannot fail.
    wire::Reader r{bytes.first(covered)};
    const auto dest = *r.u8();
    const auto command = *r.u8();
    (void)*r.u8();  // byte count
    const auto src = *r.u8();
    const auto ver = *r.u8();
    const auto dest_eid = *r.u8();
    const auto src_eid = *r.u8();
    const auto flags = *r.u8();

    if (command != smbus_command_code) {
        return std::unexpected(PacketError::bad_command);
    }
    if ((dest & rw_bit) != 0 || (src & rw_bit) == 0) {
        return std::unexpected(PacketError::bad_rw_bit);
    }
    if ((ver >> version_bits) != 0) {
        return std::unexpected(PacketError::reserved_not_zero);
    }
    if ((ver & version_mask) != header_version) {
        return std::unexpected(PacketError::bad_version);
    }
    if (!valid_dest_eid(dest_eid) || !valid_src_eid(src_eid)) {
        return std::unexpected(PacketError::bad_eid);
    }

    Packet p;
    p.dest_addr = static_cast<std::uint8_t>(dest >> 1U);
    p.src_addr = static_cast<std::uint8_t>(src >> 1U);
    p.header.dest_eid = dest_eid;
    p.header.src_eid = src_eid;
    p.header.som = (flags & som_bit) != 0;
    p.header.eom = (flags & eom_bit) != 0;
    p.header.seq = static_cast<std::uint8_t>((flags >> seq_shift) & seq_mask);
    p.header.tag_owner = ((flags >> tag_owner_shift) & 1U) != 0;
    p.header.tag = static_cast<std::uint8_t>(flags & tag_mask);
    const auto payload = r.rest();
    p.payload_len = payload.size();
    std::ranges::copy(payload, p.payload_buf.begin());
    return p;
}

auto encode_packet(std::uint8_t dest_addr, std::uint8_t src_addr, const TransportHeader& header,
                   std::span<const std::byte> payload)
    -> std::expected<std::vector<std::byte>, PacketError> {
    if (dest_addr > max_smbus_address || src_addr > max_smbus_address ||
        header.seq > max_packet_seq || header.tag > max_tag) {
        return std::unexpected(PacketError::invalid_field);
    }
    if (!valid_dest_eid(header.dest_eid) || !valid_src_eid(header.src_eid)) {
        return std::unexpected(PacketError::bad_eid);
    }
    if (payload.size() > max_packet_payload) {
        return std::unexpected(PacketError::payload_too_long);
    }

    std::vector<std::byte> out;
    out.reserve(smbus_prefix_size + counted_overhead + payload.size() + pec_size);
    wire::Writer w{out};
    w.u8(static_cast<std::uint8_t>(dest_addr << 1U));
    w.u8(smbus_command_code);
    w.u8(static_cast<std::uint8_t>(counted_overhead + payload.size()));
    w.u8(static_cast<std::uint8_t>((src_addr << 1U) | rw_bit));
    w.u8(header_version);
    w.u8(header.dest_eid);
    w.u8(header.src_eid);
    w.u8(flags_byte(header));
    w.bytes(payload);
    w.u8(pec(out));
    return out;
}

auto fragment(const Route& route, std::span<const std::byte> message, std::size_t mtu,
              std::uint8_t first_seq)
    -> std::expected<std::vector<std::vector<std::byte>>, PacketError> {
    if (message.empty() || mtu < baseline_mtu || mtu > max_packet_payload ||
        first_seq > max_packet_seq) {
        return std::unexpected(PacketError::invalid_field);
    }
    if (message.size() > max_message_size) {
        return std::unexpected(PacketError::payload_too_long);
    }

    std::vector<std::vector<std::byte>> packets;
    packets.reserve((message.size() + mtu - 1) / mtu);
    TransportHeader h{.dest_eid = route.dest_eid,
                      .src_eid = route.src_eid,
                      .som = true,
                      .eom = false,
                      .seq = first_seq,
                      .tag_owner = route.tag_owner,
                      .tag = route.tag};
    for (std::size_t off = 0; off < message.size(); off += mtu) {
        const auto chunk = message.subspan(off, std::min(mtu, message.size() - off));
        h.eom = off + chunk.size() == message.size();
        auto pkt = encode_packet(route.dest_addr, route.src_addr, h, chunk);
        if (!pkt) {
            return std::unexpected(pkt.error());
        }
        packets.push_back(std::move(*pkt));
        h.som = false;
        h.seq = static_cast<std::uint8_t>((h.seq + 1U) & seq_mask);
    }
    return packets;
}

Assembler::Assembler(std::uint8_t local_eid, std::size_t max_message)
    : _local_eid{local_eid}, _max_message{std::min(max_message, max_message_size)} {}

auto Assembler::drop(Context& ctx) noexcept -> void {
    // Best effort only: deliver_key messages pass through here, so do not
    // leave a dropped message's bytes in the buffer. Key material proper is
    // held by the KeyStore's ScopedKey, not here.
    std::ranges::fill(ctx.bytes, std::byte{0});
    ctx.bytes.clear();
    ctx.active = false;
}

auto Assembler::in_progress() const noexcept -> std::size_t {
    return static_cast<std::size_t>(
        std::ranges::count_if(_contexts, [](const Context& c) { return c.active; }));
}

auto Assembler::push(const Packet& packet) -> std::expected<std::optional<Message>, AssemblyError> {
    const auto& h = packet.header;
    if (h.dest_eid != _local_eid && h.dest_eid != null_eid && h.dest_eid != broadcast_eid) {
        return std::unexpected(AssemblyError::wrong_destination);
    }
    auto& ctx = _contexts.at(context_index(h.tag_owner, h.tag));
    const auto payload = packet.payload();

    if (h.som) {
        // A new start supersedes whatever was in progress for this tag.
        drop(ctx);
        if (payload.empty()) {
            return std::unexpected(AssemblyError::empty_message);
        }
        if (payload.size() > _max_message) {
            return std::unexpected(AssemblyError::message_too_long);
        }
        ctx.active = true;
        ctx.route = Route{.dest_addr = packet.dest_addr,
                          .src_addr = packet.src_addr,
                          .dest_eid = h.dest_eid,
                          .src_eid = h.src_eid,
                          .tag_owner = h.tag_owner,
                          .tag = h.tag};
        ctx.packet_size = payload.size();
        ctx.bytes.assign(payload.begin(), payload.end());
    } else {
        if (!ctx.active) {
            return std::unexpected(AssemblyError::unexpected_packet);
        }
        if (h.src_eid != ctx.route.src_eid || packet.src_addr != ctx.route.src_addr) {
            // Not this message's packet: reject it, keep the message.
            return std::unexpected(AssemblyError::source_mismatch);
        }
        if (h.seq != ctx.next_seq) {
            drop(ctx);
            return std::unexpected(AssemblyError::out_of_sequence);
        }
        const bool size_ok = h.eom ? !payload.empty() && payload.size() <= ctx.packet_size
                                   : payload.size() == ctx.packet_size;
        if (!size_ok) {
            drop(ctx);
            return std::unexpected(AssemblyError::packet_size_mismatch);
        }
        if (ctx.bytes.size() + payload.size() > _max_message) {
            drop(ctx);
            return std::unexpected(AssemblyError::message_too_long);
        }
        ctx.bytes.insert(ctx.bytes.end(), payload.begin(), payload.end());
    }
    ctx.next_seq = static_cast<std::uint8_t>((h.seq + 1U) & seq_mask);

    if (!h.eom) {
        return std::nullopt;
    }
    Message msg{.route = ctx.route, .bytes = std::move(ctx.bytes)};
    ctx.bytes = {};
    ctx.active = false;
    return msg;
}

auto type_byte(std::span<const std::byte> message) noexcept
    -> std::expected<TypeByte, VendorError> {
    if (message.empty()) {
        return std::unexpected(VendorError::truncated);
    }
    const auto b = std::to_integer<std::uint8_t>(message.front());
    return TypeByte{.type = static_cast<std::uint8_t>(b & message_type_mask),
                    .integrity_check = (b & integrity_check_bit) != 0};
}

auto decode_vendor(std::span<const std::byte> message) noexcept
    -> std::expected<VendorMessage, VendorError> {
    const auto tb = type_byte(message);
    if (!tb) {
        return std::unexpected(tb.error());
    }
    if (tb->type != std::to_underlying(MessageType::vendor_pci)) {
        return std::unexpected(VendorError::not_vendor_pci);
    }
    if (tb->integrity_check) {
        return std::unexpected(VendorError::integrity_check);
    }
    if (message.size() < vendor_header_size) {
        return std::unexpected(VendorError::truncated);
    }

    wire::Reader r{message};
    (void)*r.u8();  // type byte
    const auto vendor = *r.be16();
    const auto version = *r.u8();
    const auto type = *r.u8();
    const auto flags = *r.u8();
    const auto reserved = *r.u8();

    if (vendor != ak_vendor_id) {
        return std::unexpected(VendorError::wrong_vendor);
    }
    if (version != ak_vendor_version) {
        return std::unexpected(VendorError::bad_version);
    }
    if (!known_vendor_type(type)) {
        return std::unexpected(VendorError::unknown_type);
    }
    if ((flags & ~vendor_flags_known) != 0 || reserved != reserved_byte) {
        return std::unexpected(VendorError::reserved_not_zero);
    }
    return VendorMessage{
        .header = {.type = static_cast<VendorType>(type),
                   .response = (flags & vendor_flag_response) != 0},
        .body = r.rest(),
    };
}

auto encode_vendor(const VendorHeader& header, std::span<const std::byte> body)
    -> std::expected<std::vector<std::byte>, VendorError> {
    if (body.size() > max_message_size - vendor_header_size) {
        return std::unexpected(VendorError::body_too_long);
    }
    if (!known_vendor_type(std::to_underlying(header.type))) {
        return std::unexpected(VendorError::unknown_type);
    }
    std::vector<std::byte> out;
    out.reserve(vendor_header_size + body.size());
    wire::Writer w{out};
    w.u8(std::to_underlying(MessageType::vendor_pci));
    w.be16(ak_vendor_id);
    w.u8(ak_vendor_version);
    w.u8(std::to_underlying(header.type));
    w.u8(header.response ? vendor_flag_response : std::uint8_t{0});
    w.u8(reserved_byte);
    w.bytes(body);
    return out;
}

auto to_string(PacketError e) noexcept -> const char* {
    switch (e) {
        case PacketError::truncated:
            return "truncated";
        case PacketError::trailing_bytes:
            return "trailing_bytes";
        case PacketError::bad_command:
            return "bad_command";
        case PacketError::bad_rw_bit:
            return "bad_rw_bit";
        case PacketError::bad_pec:
            return "bad_pec";
        case PacketError::bad_version:
            return "bad_version";
        case PacketError::reserved_not_zero:
            return "reserved_not_zero";
        case PacketError::bad_eid:
            return "bad_eid";
        case PacketError::payload_too_long:
            return "payload_too_long";
        case PacketError::invalid_field:
            return "invalid_field";
    }
    return "unknown";
}

auto to_string(AssemblyError e) noexcept -> const char* {
    switch (e) {
        case AssemblyError::wrong_destination:
            return "wrong_destination";
        case AssemblyError::unexpected_packet:
            return "unexpected_packet";
        case AssemblyError::out_of_sequence:
            return "out_of_sequence";
        case AssemblyError::source_mismatch:
            return "source_mismatch";
        case AssemblyError::packet_size_mismatch:
            return "packet_size_mismatch";
        case AssemblyError::message_too_long:
            return "message_too_long";
        case AssemblyError::empty_message:
            return "empty_message";
    }
    return "unknown";
}

auto to_string(VendorError e) noexcept -> const char* {
    switch (e) {
        case VendorError::truncated:
            return "truncated";
        case VendorError::not_vendor_pci:
            return "not_vendor_pci";
        case VendorError::integrity_check:
            return "integrity_check";
        case VendorError::wrong_vendor:
            return "wrong_vendor";
        case VendorError::bad_version:
            return "bad_version";
        case VendorError::unknown_type:
            return "unknown_type";
        case VendorError::reserved_not_zero:
            return "reserved_not_zero";
        case VendorError::body_too_long:
            return "body_too_long";
    }
    return "unknown";
}

}  // namespace ak::helm::mctp
