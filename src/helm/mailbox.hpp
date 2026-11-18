// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Control-plane mailbox: the only channel between the control-plane role
// (helm) and the host agent (hull). It is a register file in the control
// device's BAR0; the agent maps it through VFIO and never gives the device
// any DMA mapping, so every message lives in device memory and is copied
// out once with MMIO before it is parsed.
//
// All multi-byte fields are little-endian (PCIe native order).
//
// BAR0 layout:
//   0x000  MAGIC        RO  'AKMB'
//   0x004  VERSION      RO  protocol version
//   0x008  CMD_DOORBELL RO  device->host: incremented when CMD_SLOT holds a new command
//   0x00C  RSP_DOORBELL WO  host->device: response written to RSP_SLOT
//   0x010  EVT_DOORBELL WO  host->device: event written to EVT_SLOT
//   0x100  CMD_SLOT     256 bytes, device writes, host reads
//   0x200  RSP_SLOT     256 bytes, host writes, device reads
//   0x300  EVT_SLOT     256 bytes, host writes, device reads
//
// Slot layout (256 bytes):
//   0x00  header (24 bytes)
//   0x18  body   (up to 168 bytes; body_len says how much is meaningful)
//   0xC0  Ed25519 signature (64 bytes) over bytes [0x00, 0xC0) -- commands only

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

namespace ak::helm::mailbox {

inline constexpr std::uint32_t magic = 0x424D'4B41;  // "AKMB" read as little-endian bytes
inline constexpr std::uint16_t protocol_version = 1;

namespace reg {
inline constexpr std::size_t magic = 0x000;
inline constexpr std::size_t version = 0x004;
inline constexpr std::size_t cmd_doorbell = 0x008;
inline constexpr std::size_t rsp_doorbell = 0x00C;
inline constexpr std::size_t evt_doorbell = 0x010;
inline constexpr std::size_t cmd_slot = 0x100;
inline constexpr std::size_t rsp_slot = 0x200;
inline constexpr std::size_t evt_slot = 0x300;
inline constexpr std::size_t bar0_size = 0x1000;
}  // namespace reg

inline constexpr std::size_t slot_size = 256;
inline constexpr std::size_t header_size = 24;
inline constexpr std::size_t signature_size = 64;
inline constexpr std::size_t signature_offset = slot_size - signature_size;  // 0xC0
inline constexpr std::size_t max_body = signature_offset - header_size;      // 168
inline constexpr std::size_t header_reserved_size = 6;

using Slot = std::array<std::byte, slot_size>;

// Message types. Values are part of the wire protocol: never renumber.
enum class Type : std::uint16_t {
    // Commands (operator -> control plane -> host agent).
    create_vm = 0x0001,
    destroy_vm = 0x0002,
    list_vms = 0x0003,
    vm_status = 0x0004,
    attach_device = 0x0010,  // NIC VF, storage function, GPU / GPU VF
    detach_device = 0x0011,
    create_volume = 0x0020,
    delete_volume = 0x0021,
    attach_volume = 0x0022,
    detach_volume = 0x0023,
    rewrap_volume = 0x0024,
    create_network = 0x0030,  // VPC
    delete_network = 0x0031,
    gpu_vf_config = 0x0040,  // reserved: GPU support is designed, not yet built

    // Responses (host agent -> control plane).
    response = 0x0100,

    // Events (host agent -> control plane).
    vm_exited = 0x0200,
    device_released = 0x0201,  // slot/function reset done; control plane wipes or scrubs next
    host_fault = 0x0202,
    scrub_done = 0x0203,  // reserved for GPU scrub
};

[[nodiscard]] auto is_command(Type t) noexcept -> bool;

struct Header {
    std::uint32_t magic{mailbox::magic};
    std::uint16_t version{protocol_version};
    Type type{Type::response};
    std::uint64_t seq{0};
    std::uint16_t body_len{0};
};

// A message copied out of a slot. Owns its bytes, so it stays valid after
// the device overwrites the slot.
struct Message {
    Header header;
    std::array<std::byte, max_body> body{};
    std::array<std::byte, signature_size> signature{};

    [[nodiscard]] auto body_bytes() const noexcept -> std::span<const std::byte> {
        return std::span{body}.first(header.body_len);
    }
};

enum class DecodeError : std::uint8_t {
    bad_magic,
    bad_version,
    unknown_type,
    body_too_long,
    reserved_not_zero,  // reserved header bytes or bytes past body_len are non-zero
};

[[nodiscard]] auto to_string(DecodeError e) noexcept -> const char*;

// Strict decode of one slot. Rejects anything not exactly well-formed;
// does not check signatures or sequence numbers (the agent does both).
[[nodiscard]] auto decode(const Slot& slot) noexcept -> std::expected<Message, DecodeError>;

// Encodes a message into a slot, zero-filling everything unused.
[[nodiscard]] auto encode(const Header& header, std::span<const std::byte> body,
                          std::span<const std::byte, signature_size> signature)
    -> std::expected<Slot, DecodeError>;

// ---- Command bodies -------------------------------------------------------

enum class BootMode : std::uint8_t {
    volume = 1,  // boot from an attached (endpoint-provided) volume via guest firmware
};

struct CreateVm {
    std::uint64_t vm_id{0};
    std::uint16_t vcpus{0};
    std::uint32_t memory_mib{0};
    BootMode boot_mode{BootMode::volume};
};

inline constexpr std::uint8_t destroy_flag_persist_volumes = 0x01;
inline constexpr std::uint8_t destroy_flags_known = destroy_flag_persist_volumes;

struct DestroyVm {
    std::uint64_t vm_id{0};
    bool persist_volumes{false};
};

enum class BodyError : std::uint8_t {
    wrong_type,
    wrong_length,
    invalid_field,
};

[[nodiscard]] auto to_string(BodyError e) noexcept -> const char*;

[[nodiscard]] auto decode_create_vm(const Message& msg) noexcept
    -> std::expected<CreateVm, BodyError>;
[[nodiscard]] auto decode_destroy_vm(const Message& msg) noexcept
    -> std::expected<DestroyVm, BodyError>;

}  // namespace ak::helm::mailbox
