// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Signing test vectors for the controller wire formats. Any controller
// implementation (kythira's EC2 module) must reproduce these bytes exactly:
// encode the listed fields, sign with the listed RFC 8032 section 7.1 test
// key, and compare. Ed25519 is deterministic, so the signatures are fixed.
// tests/proto_vectors_test.cpp checks antikythera against them, including
// that hull accepts the envelope's slot.
//
// The keys are RFC 8032's published test keys and must never be compiled
// into a real host image.

#include <cstdint>
#include <string_view>

namespace ak::proto::vectors {

// RFC 8032 7.1 TEST 1 and TEST 2 key pairs (secret, public), hex.
inline constexpr std::string_view key1_secret =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
inline constexpr std::string_view key1_public =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
inline constexpr std::string_view key2_secret =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
inline constexpr std::string_view key2_public =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

// Vector 1: an Envelope for server 7 holding a CREATE_VM command slot
// (mailbox v2, seq 1, key_id 1; body vm_id 0x1001, vcpus 4,
// memory_mib 8192, boot_mode volume) signed over slot bytes [0x00, 0xC0)
// with key 1.
inline constexpr std::uint64_t envelope1_server_id = 7;
inline constexpr std::uint16_t envelope1_key_id = 1;
inline constexpr std::uint64_t envelope1_seq = 1;
inline constexpr std::uint64_t envelope1_vm_id = 0x1001;
inline constexpr std::uint16_t envelope1_vcpus = 4;
inline constexpr std::uint32_t envelope1_memory_mib = 8192;
inline constexpr std::string_view envelope1 =
    "414b4556010001000700000000000000414b4d42020001000100000000000000100001000000000001100000"
    "0000000004000020000001000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000099970893c1198627e171f849"
    "8ecee53bc4b8e4da19c82e35746e5eea0397b914e0d5402d8ceb15b80e88c8ece883a965d613c5e691e2244d"
    "8d13a074384ca601";
inline constexpr std::string_view envelope1_signature =
    "99970893c1198627e171f8498ecee53bc4b8e4da19c82e35746e5eea0397b914e0d5402d8ceb15b80e88c8ec"
    "e883a965d613c5e691e2244d8d13a074384ca601";

// Vector 2: a MapUpdate for server 7, VNI 0xABCD, map_version 3, signed
// with key 1 (key_id 1), two entries:
//   NIC 0x10, MAC 02:00:00:00:00:10, owner VTEP fd00::1
//   NIC 0x11, MAC 02:00:00:00:00:11, owner VTEP fd00::2
inline constexpr std::uint64_t map2_server_id = 7;
inline constexpr std::uint16_t map2_key_id = 1;
inline constexpr std::uint32_t map2_vni = 0xABCD;
inline constexpr std::uint64_t map2_map_version = 3;
inline constexpr std::string_view map2 =
    "414b4d55010001000700000000000000cdab0000020000000300000000000000100000000000000002000000"
    "00100000fd00000000000000000000000000000111000000000000000200000000110000fd00000000000000"
    "0000000000000002a3114d12fe9f37aa231df1d68186d79dc8a090cc08bf9350642c19f646791005dc598ec3"
    "3d4b8112762cf9ed905c727b7be8f2d5fd08e9fd49c59ef4925bf007";
inline constexpr std::string_view map2_signature =
    "a3114d12fe9f37aa231df1d68186d79dc8a090cc08bf9350642c19f646791005dc598ec33d4b8112762cf9ed"
    "905c727b7be8f2d5fd08e9fd49c59ef4925bf007";

// Vector 3: an empty MapUpdate for server 7, VNI 1, map_version 1, signed
// with key 2 (key_id 2): a rotated key, and a VPC with no NICs left.
inline constexpr std::uint64_t map0_server_id = 7;
inline constexpr std::uint16_t map0_key_id = 2;
inline constexpr std::uint32_t map0_vni = 1;
inline constexpr std::uint64_t map0_map_version = 1;
inline constexpr std::string_view map0 =
    "414b4d5501000200070000000000000001000000000000000100000000000000e2caebe54593367947ff51cb"
    "4e043dbb8f1d28d69b1fd076d8132367c444f859687afc2a8b20e1b02e1152299125e3f7e1189cb7c06f983b"
    "b2dd6b09ca8b9102";
inline constexpr std::string_view map0_signature =
    "e2caebe54593367947ff51cb4e043dbb8f1d28d69b1fd076d8132367c444f859687afc2a8b20e1b02e115229"
    "9125e3f7e1189cb7c06f983bb2dd6b09ca8b9102";

}  // namespace ak::proto::vectors
