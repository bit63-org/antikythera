// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MCTP framing for the helm <-> oar sideband (helm-control-plane
// Requirement 5.2). Three layers, each a strict codec over ak::wire:
//
// 1. SMBus/I2C binding (DMTF DSP0237). One packet on the wire:
//      0  dest slave address  (7-bit address << 1, R/W bit 0 = write)
//      1  command code        0x0F (MCTP)
//      2  byte count          bytes that follow, excluding the PEC
//      3  source slave address (7-bit address << 1 | 1)
//      4  MCTP transport header (4 bytes, below)
//      8  packet payload      (byte count - 5 bytes)
//      .  PEC                 CRC-8 (poly 0x07) over bytes [0, end of payload)
//
// 2. MCTP transport header (DSP0236), 4 bytes:
//      0  reserved (4 bits, zero) | header version (4 bits, 1)
//      1  destination EID
//      2  source EID
//      3  SOM | EOM | packet sequence (2 bits) | TO | message tag (3 bits)
//    A message larger than one packet is split into packets whose payloads
//    are all the size of the first packet, except the last. Assembler and
//    fragment() implement that.
//
// 3. Message body. The first byte of a message is IC (1 bit) | message
//    type (7 bits). helm<->oar traffic is PCI vendor-defined (type 0x7E):
//      0  0x7E (IC must be 0: no integrity check)
//      1  PCI vendor ID, big-endian (ak_vendor_id)
//      3  ak protocol version (1)
//      4  VendorType
//      5  flags (bit 0: response; others zero)
//      6  reserved (zero)
//      7  body
//    MCTP control (0x00) and SPDM (0x05, 0x06) keep their DMTF numbers so
//    the sideband has room for SPDM attestation and sessions later
//    (Requirement 5.3); this layer only names them.
//
// The sideband is not authenticated in the first release (Requirement 5.3):
// segment isolation is the boundary, so every byte here is still untrusted
// and parsed with the same strictness as the mailbox.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace ak::helm::mctp {

// ---- SMBus binding --------------------------------------------------------

inline constexpr std::uint8_t smbus_command_code = 0x0F;
inline constexpr std::uint8_t max_smbus_address = 0x7F;  // 7-bit addresses
inline constexpr std::size_t smbus_prefix_size = 3;      // dest, command, byte count
inline constexpr std::size_t pec_size = 1;
inline constexpr std::size_t max_byte_count = 255;
inline constexpr std::size_t transport_header_size = 4;
// Bytes counted by the byte count that are not payload: source address and
// transport header.
inline constexpr std::size_t counted_overhead = 1 + transport_header_size;
inline constexpr std::size_t max_packet_payload = max_byte_count - counted_overhead;  // 250
inline constexpr std::size_t max_packet_size = smbus_prefix_size + max_byte_count + pec_size;
// Every MCTP endpoint must accept packets with this much payload (DSP0236
// baseline transmission unit). Larger units need negotiation.
inline constexpr std::size_t baseline_mtu = 64;

// ---- Transport header -----------------------------------------------------

inline constexpr std::uint8_t header_version = 0x01;
inline constexpr std::uint8_t null_eid = 0x00;
inline constexpr std::uint8_t broadcast_eid = 0xFF;
inline constexpr std::uint8_t first_assignable_eid = 0x08;  // 0x01-0x07 are reserved
inline constexpr std::uint8_t max_packet_seq = 3;
inline constexpr std::uint8_t max_tag = 7;
inline constexpr std::size_t tag_contexts = 2 * (max_tag + 1);  // per tag-owner bit

struct TransportHeader {
    std::uint8_t dest_eid{null_eid};
    std::uint8_t src_eid{null_eid};
    bool som{true};
    bool eom{true};
    std::uint8_t seq{0};
    bool tag_owner{false};
    std::uint8_t tag{0};

    friend auto operator==(const TransportHeader&, const TransportHeader&) -> bool = default;
};

// One decoded SMBus packet. Owns its payload so it can outlive the receive
// buffer, and never allocates.
struct Packet {
    std::uint8_t dest_addr{0};  // 7-bit
    std::uint8_t src_addr{0};   // 7-bit
    TransportHeader header;
    std::size_t payload_len{0};
    std::array<std::byte, max_packet_payload> payload_buf{};

    [[nodiscard]] auto payload() const noexcept -> std::span<const std::byte> {
        return std::span{payload_buf}.first(payload_len);
    }
};

enum class PacketError : std::uint8_t {
    truncated,          // shorter than the byte count says, or than the minimum packet
    trailing_bytes,     // longer than the byte count says
    bad_command,        // command code is not MCTP
    bad_rw_bit,         // dest address has the read bit, or source lacks it
    bad_pec,            // PEC does not match
    bad_version,        // transport header version is not 1
    reserved_not_zero,  // transport header reserved bits set
    bad_eid,            // reserved EID, or broadcast source
    payload_too_long,   // encode only: more than max_packet_payload
    invalid_field,      // encode only: address, sequence or tag out of range
};

[[nodiscard]] auto to_string(PacketError e) noexcept -> const char*;

// SMBus PEC: CRC-8, polynomial x^8 + x^2 + x + 1, initial value 0.
[[nodiscard]] auto pec(std::span<const std::byte> bytes) noexcept -> std::uint8_t;

// Strict decode of one packet: exactly smbus_prefix_size + byte count +
// pec_size bytes, correct PEC, valid header. Does not check that the
// destination is this endpoint (Assembler does).
[[nodiscard]] auto decode_packet(std::span<const std::byte> bytes) noexcept
    -> std::expected<Packet, PacketError>;

[[nodiscard]] auto encode_packet(std::uint8_t dest_addr, std::uint8_t src_addr,
                                 const TransportHeader& header, std::span<const std::byte> payload)
    -> std::expected<std::vector<std::byte>, PacketError>;

// ---- Messages -------------------------------------------------------------

// Upper bound on a reassembled message. helm<->oar messages are small
// (the largest planned is a map_update batch); the bound keeps a peer from
// making helm buffer without limit.
inline constexpr std::size_t max_message_size = 4096;

// Message types (first byte of a message, low 7 bits). DMTF numbering.
enum class MessageType : std::uint8_t {
    control = 0x00,
    spdm = 0x05,
    secured = 0x06,  // SPDM secured messages
    vendor_pci = 0x7E,
    vendor_iana = 0x7F,
};

inline constexpr std::uint8_t integrity_check_bit = 0x80;
inline constexpr std::uint8_t message_type_mask = 0x7F;

// Where a message goes: both bus addresses, both EIDs, and the tag.
struct Route {
    std::uint8_t dest_addr{0};
    std::uint8_t src_addr{0};
    std::uint8_t dest_eid{null_eid};
    std::uint8_t src_eid{null_eid};
    bool tag_owner{false};
    std::uint8_t tag{0};

    friend auto operator==(const Route&, const Route&) -> bool = default;
};

// A whole message, reassembled. bytes[0] is the IC | message type byte.
struct Message {
    Route route;
    std::vector<std::byte> bytes;
};

// Splits a message into encoded packets of at most mtu payload bytes each,
// with sequence numbers starting at first_seq. The message must be
// non-empty (it carries at least the type byte) and at most
// max_message_size; mtu must be in [baseline_mtu, max_packet_payload].
[[nodiscard]] auto fragment(const Route& route, std::span<const std::byte> message,
                            std::size_t mtu = baseline_mtu, std::uint8_t first_seq = 0)
    -> std::expected<std::vector<std::vector<std::byte>>, PacketError>;

enum class AssemblyError : std::uint8_t {
    wrong_destination,     // dest EID is not this endpoint, null or broadcast
    unexpected_packet,     // middle or end packet with no message in progress
    out_of_sequence,       // packet sequence number skipped; message dropped
    source_mismatch,       // packet for a message in progress came from another source
    packet_size_mismatch,  // non-final packet differs from the first, or final is larger
    message_too_long,      // reassembled message would exceed the limit; dropped
    empty_message,         // start packet with no payload (no message type byte)
};

[[nodiscard]] auto to_string(AssemblyError e) noexcept -> const char*;

// Reassembles packets into messages, one context per (tag owner, tag) as
// DSP0236 requires. A start packet for a context that already has a message
// in progress drops the old one and starts again; any error drops the
// message in progress for that context. Not thread-safe: one per link.
class Assembler {
public:
    explicit Assembler(std::uint8_t local_eid, std::size_t max_message = max_message_size);

    // Feeds one decoded packet. Returns a message when it completes one,
    // std::nullopt while one is still in progress.
    [[nodiscard]] auto push(const Packet& packet)
        -> std::expected<std::optional<Message>, AssemblyError>;

    // Messages currently being reassembled.
    [[nodiscard]] auto in_progress() const noexcept -> std::size_t;

private:
    struct Context {
        bool active{false};
        Route route;
        std::uint8_t next_seq{0};
        std::size_t packet_size{0};
        std::vector<std::byte> bytes;
    };

    auto drop(Context& ctx) noexcept -> void;

    std::uint8_t _local_eid;
    std::size_t _max_message;
    std::array<Context, tag_contexts> _contexts{};
};

// ---- ak vendor-defined messages ------------------------------------------

// PCI vendor ID carried in every ak vendor-defined message. 0xFFFF is never
// assigned to a vendor (it is what an absent PCI function reads as), so it
// cannot collide with another vendor's messages on a shared segment. Replace
// it with an assigned ID if ak gets one; it is a protocol constant.
inline constexpr std::uint16_t ak_vendor_id = 0xFFFF;
inline constexpr std::uint8_t ak_vendor_version = 1;
inline constexpr std::size_t vendor_header_size = 7;
inline constexpr std::uint8_t vendor_flag_response = 0x01;
inline constexpr std::uint8_t vendor_flags_known = vendor_flag_response;

// OarLink operations (helm-control-plane design, OarLink). Values are part
// of the wire protocol: never renumber.
enum class VendorType : std::uint8_t {
    function_inventory = 0x01,
    prepare_function = 0x02,
    clean_function = 0x03,
    deliver_key = 0x04,
    drop_key = 0x05,
    map_update = 0x06,
    health = 0x07,
    create_volume = 0x08,
    delete_volume = 0x09,
    rewrap_volume = 0x0A,
};

struct VendorHeader {
    VendorType type{VendorType::health};
    bool response{false};

    friend auto operator==(const VendorHeader&, const VendorHeader&) -> bool = default;
};

// A decoded vendor message. body views into the message it came from.
struct VendorMessage {
    VendorHeader header;
    std::span<const std::byte> body;
};

enum class VendorError : std::uint8_t {
    truncated,        // shorter than the vendor header
    not_vendor_pci,   // another message type: route it elsewhere
    integrity_check,  // IC bit set; ak messages carry no MCTP integrity check
    wrong_vendor,     // another vendor's message
    bad_version,
    unknown_type,
    reserved_not_zero,  // unknown flag bits or reserved byte set
    body_too_long,      // encode only: message would exceed max_message_size
};

[[nodiscard]] auto to_string(VendorError e) noexcept -> const char*;

// The message type byte, split. Fails only on an empty message.
struct TypeByte {
    std::uint8_t type{0};
    bool integrity_check{false};
};

[[nodiscard]] auto type_byte(std::span<const std::byte> message) noexcept
    -> std::expected<TypeByte, VendorError>;

[[nodiscard]] auto decode_vendor(std::span<const std::byte> message) noexcept
    -> std::expected<VendorMessage, VendorError>;

[[nodiscard]] auto encode_vendor(const VendorHeader& header, std::span<const std::byte> body)
    -> std::expected<std::vector<std::byte>, VendorError>;

}  // namespace ak::helm::mctp
