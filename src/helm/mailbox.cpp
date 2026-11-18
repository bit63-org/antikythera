// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/mailbox.hpp"

#include <algorithm>
#include <utility>

#include "common/wire.hpp"

namespace ak::helm::mailbox {

namespace {

constexpr std::size_t create_vm_body_len = 16;
constexpr std::size_t destroy_vm_body_len = 9;
constexpr std::uint16_t max_vcpus = 1024;

constexpr auto known_type(std::uint16_t raw) noexcept -> bool {
    switch (static_cast<Type>(raw)) {
        case Type::create_vm:
        case Type::destroy_vm:
        case Type::list_vms:
        case Type::vm_status:
        case Type::attach_device:
        case Type::detach_device:
        case Type::create_volume:
        case Type::delete_volume:
        case Type::attach_volume:
        case Type::detach_volume:
        case Type::rewrap_volume:
        case Type::create_network:
        case Type::delete_network:
        case Type::gpu_vf_config:
        case Type::response:
        case Type::vm_exited:
        case Type::device_released:
        case Type::host_fault:
        case Type::scrub_done:
            return true;
    }
    return false;
}

auto all_zero(std::span<const std::byte> b) noexcept -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

}  // namespace

auto is_command(Type t) noexcept -> bool {
    return std::to_underlying(t) < std::to_underlying(Type::response);
}

auto to_string(DecodeError e) noexcept -> const char* {
    switch (e) {
        case DecodeError::bad_magic:
            return "bad_magic";
        case DecodeError::bad_version:
            return "bad_version";
        case DecodeError::unknown_type:
            return "unknown_type";
        case DecodeError::body_too_long:
            return "body_too_long";
        case DecodeError::reserved_not_zero:
            return "reserved_not_zero";
    }
    return "unknown";
}

auto to_string(BodyError e) noexcept -> const char* {
    switch (e) {
        case BodyError::wrong_type:
            return "wrong_type";
        case BodyError::wrong_length:
            return "wrong_length";
        case BodyError::invalid_field:
            return "invalid_field";
    }
    return "unknown";
}

auto decode(const Slot& slot) noexcept -> std::expected<Message, DecodeError> {
    wire::Reader r{slot};
    // The slot is a fixed 256 bytes, so none of these header reads can fail.
    Message msg;
    msg.header.magic = *r.le32();
    msg.header.version = *r.le16();
    const std::uint16_t raw_type = *r.le16();
    msg.header.seq = *r.le64();
    msg.header.body_len = *r.le16();
    const auto reserved = *r.bytes(header_reserved_size);

    if (msg.header.magic != magic) {
        return std::unexpected(DecodeError::bad_magic);
    }
    if (msg.header.version != protocol_version) {
        return std::unexpected(DecodeError::bad_version);
    }
    if (!known_type(raw_type)) {
        return std::unexpected(DecodeError::unknown_type);
    }
    msg.header.type = static_cast<Type>(raw_type);
    if (msg.header.body_len > max_body) {
        return std::unexpected(DecodeError::body_too_long);
    }
    if (!all_zero(reserved)) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }

    const auto body_region = std::span{slot}.subspan(header_size, max_body);
    // Bytes past body_len must be zero: no hidden data in the signed region.
    if (!all_zero(body_region.subspan(msg.header.body_len))) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    std::ranges::copy(body_region, msg.body.begin());
    std::ranges::copy(std::span{slot}.subspan(signature_offset, signature_size),
                      msg.signature.begin());
    return msg;
}

auto encode(const Header& header, std::span<const std::byte> body,
            std::span<const std::byte, signature_size> signature)
    -> std::expected<Slot, DecodeError> {
    if (body.size() > max_body || header.body_len != body.size()) {
        return std::unexpected(DecodeError::body_too_long);
    }
    if (!known_type(std::to_underlying(header.type))) {
        return std::unexpected(DecodeError::unknown_type);
    }
    Slot slot{};
    wire::SpanWriter w{slot};
    // Fixed-size slot: these writes cannot overflow.
    (void)w.write(header.magic, wire::Order::little);
    (void)w.write(header.version, wire::Order::little);
    (void)w.write(std::to_underlying(header.type), wire::Order::little);
    (void)w.write(header.seq, wire::Order::little);
    (void)w.write(header.body_len, wire::Order::little);
    std::ranges::copy(body, slot.begin() + header_size);
    std::ranges::copy(signature, slot.begin() + signature_offset);
    return slot;
}

auto decode_create_vm(const Message& msg) noexcept -> std::expected<CreateVm, BodyError> {
    if (msg.header.type != Type::create_vm) {
        return std::unexpected(BodyError::wrong_type);
    }
    if (msg.header.body_len != create_vm_body_len) {
        return std::unexpected(BodyError::wrong_length);
    }
    // body: vm_id u64 | vcpus u16 | memory_mib u32 | boot_mode u8 | rsvd u8
    wire::Reader r{msg.body_bytes()};
    CreateVm out;
    out.vm_id = *r.le64();
    out.vcpus = *r.le16();
    out.memory_mib = *r.le32();
    const std::uint8_t boot = *r.u8();
    const std::uint8_t rsvd = *r.u8();
    if (out.vm_id == 0 || out.vcpus == 0 || out.vcpus > max_vcpus || out.memory_mib == 0 ||
        boot != std::to_underlying(BootMode::volume) || rsvd != 0) {
        return std::unexpected(BodyError::invalid_field);
    }
    out.boot_mode = BootMode::volume;
    return out;
}

auto decode_destroy_vm(const Message& msg) noexcept -> std::expected<DestroyVm, BodyError> {
    if (msg.header.type != Type::destroy_vm) {
        return std::unexpected(BodyError::wrong_type);
    }
    if (msg.header.body_len != destroy_vm_body_len) {
        return std::unexpected(BodyError::wrong_length);
    }
    // body: vm_id u64 | flags u8 (bit 0 = persist volumes; others must be 0)
    wire::Reader r{msg.body_bytes()};
    DestroyVm out;
    out.vm_id = *r.le64();
    const std::uint8_t flags = *r.u8();
    if (out.vm_id == 0 || (flags & static_cast<std::uint8_t>(~destroy_flags_known)) != 0) {
        return std::unexpected(BodyError::invalid_field);
    }
    out.persist_volumes = (flags & destroy_flag_persist_volumes) != 0;
    return out;
}

}  // namespace ak::helm::mailbox
