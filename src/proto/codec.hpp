// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Shared pieces of the controller wire formats (.kiro/specs/controller-interface/):
// the error type, the Ed25519 sizes, and the key ID rule.
//
// src/proto/ is header-only and depends only on src/common/wire.hpp, so the
// controller (kythira's EC2 module) can include it without linking any
// antikythera library. It encodes and decodes frames and says which bytes
// are signed; it never signs or verifies. Signing is the controller's job
// (kythira's HSM/KMS) and verification is the receiver's (hull for slots,
// helm/oar-net for mapping updates), each with its own Ed25519
// implementation.
//
// All multi-byte fields are little-endian, matching the mailbox slot.

#include <cstddef>
#include <cstdint>

#include "common/wire.hpp"

namespace ak::proto {

// Controller signing key ID (Requirement 1.3). 0 means "unsigned" and is
// never valid on a frame the controller signs, as in the mailbox slot.
using KeyId = std::uint16_t;
inline constexpr KeyId no_key_id = 0;

inline constexpr std::size_t ed25519_signature_size = 64;

enum class DecodeError : std::uint8_t {
    truncated,              // the frame ended before a field did
    trailing_bytes,         // bytes after the end of the frame
    bad_magic,              //
    bad_version,            // a frame format version this code does not speak
    bad_key_id,             // key_id is no_key_id
    key_id_mismatch,        // envelope key_id differs from the slot header's key_id
    bad_server_id,          // server_id 0 (never allocated)
    reserved_not_zero,      // a reserved byte is non-zero
    bad_vni,                // VNI 0 or wider than 24 bits
    bad_map_version,        // mapping version 0 (versions start at 1)
    too_many_entries,       // more than max_map_entries
    bad_nic_id,             // NIC ID 0
    nic_ids_not_ascending,  // entries not in strictly increasing NIC ID order
    bad_mac,                // MAC not a locally administered unicast address
    bad_vtep,               // owner VTEP address unspecified (all zero) or multicast
    bad_report_seq,         // report sequence number 0
    bad_boot_id,            // inventory boot ID 0
    bad_id,                 // a VM, volume or command identifier that must be non-zero is 0
    unknown_value,          // an enum field holds a value the protocol does not define
    bad_capacity,           // a free count larger than its total
    not_ascending,          // a list that must be in strictly increasing key order is not
    bad_owner,              // a function's owner VM disagrees with its state
    bad_record_type,        // a link record type this code does not speak
    record_too_large,       // a link record longer than max_record_payload
};

[[nodiscard]] inline constexpr auto to_string(DecodeError e) noexcept -> const char* {
    switch (e) {
        case DecodeError::truncated:
            return "truncated";
        case DecodeError::trailing_bytes:
            return "trailing bytes";
        case DecodeError::bad_magic:
            return "bad magic";
        case DecodeError::bad_version:
            return "unsupported format version";
        case DecodeError::bad_key_id:
            return "missing key id";
        case DecodeError::key_id_mismatch:
            return "envelope key id differs from slot key id";
        case DecodeError::bad_server_id:
            return "server id 0";
        case DecodeError::reserved_not_zero:
            return "reserved bytes not zero";
        case DecodeError::bad_vni:
            return "VNI 0 or wider than 24 bits";
        case DecodeError::bad_map_version:
            return "mapping version 0";
        case DecodeError::too_many_entries:
            return "too many mapping entries";
        case DecodeError::bad_nic_id:
            return "NIC id 0";
        case DecodeError::nic_ids_not_ascending:
            return "NIC ids not strictly ascending";
        case DecodeError::bad_mac:
            return "MAC not locally administered unicast";
        case DecodeError::bad_vtep:
            return "owner VTEP unspecified or multicast";
        case DecodeError::bad_report_seq:
            return "report sequence 0";
        case DecodeError::bad_boot_id:
            return "boot id 0";
        case DecodeError::bad_id:
            return "identifier 0";
        case DecodeError::unknown_value:
            return "unknown enum value";
        case DecodeError::bad_capacity:
            return "free count exceeds total";
        case DecodeError::not_ascending:
            return "list not strictly ascending";
        case DecodeError::bad_owner:
            return "function owner disagrees with its state";
        case DecodeError::bad_record_type:
            return "unknown link record type";
        case DecodeError::record_too_large:
            return "link record too large";
    }
    return "unknown";
}

}  // namespace ak::proto
