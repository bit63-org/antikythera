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
// (mailbox v3, seq 1, key_id 1, server_id 7; body vm_id 0x1001, vcpus 4,
// memory_mib 8192, boot_mode volume) signed over slot bytes [0x00, 0xC0)
// with key 1.
inline constexpr std::uint64_t envelope1_server_id = 7;
inline constexpr std::uint16_t envelope1_key_id = 1;
inline constexpr std::uint64_t envelope1_seq = 1;
inline constexpr std::uint64_t envelope1_vm_id = 0x1001;
inline constexpr std::uint16_t envelope1_vcpus = 4;
inline constexpr std::uint32_t envelope1_memory_mib = 8192;
inline constexpr std::string_view envelope1 =
    "414b4556010001000700000000000000414b4d42030001000100000000000000100001000000000007000000"
    "0000000001100000000000000400002000000100000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000022f1660eee31a22542f5056f"
    "222ad4637d6fdc7cf632f3ac2bb0a97f5923fdc4a4be97819da48f126ce22ea886873d9f4f9f1bc84adf4824"
    "28ed660e90513303";
inline constexpr std::string_view envelope1_signature =
    "22f1660eee31a22542f5056f222ad4637d6fdc7cf632f3ac2bb0a97f5923fdc4a4be97819da48f126ce22ea8"
    "86873d9f4f9f1bc84adf482428ed660e90513303";

// Vector 2: a MapUpdate (format v2) for server 7, VNI 0xABCD, map_version
// 3, signed with key 1 (key_id 1), two entries:
//   NIC 0x10, MAC 02:00:00:00:00:10, owner VTEP fd00::1
//   NIC 0x11, MAC 02:00:00:00:00:11, owner VTEP fd00::2
// and guest addresses 10.0.0.16 (NIC 0x10), 10.0.0.17 (NIC 0x11) and
// fd12::10 (NIC 0x10).
inline constexpr std::uint64_t map2_server_id = 7;
inline constexpr std::uint16_t map2_key_id = 1;
inline constexpr std::uint32_t map2_vni = 0xABCD;
inline constexpr std::uint64_t map2_map_version = 3;
inline constexpr std::string_view map2 =
    "414b4d55020001000700000000000000cdab0000020002000300000000000000010000000000000010000000"
    "000000000200000000100000fd00000000000000000000000000000111000000000000000200000000110000"
    "fd00000000000000000000000000000210000000000000000a0000100000000011000000000000000a000011"
    "000000001000000000000000fd1200000000000000000000000000107399462eea4d7abde776a6360424604b"
    "883a05d6e4b61f697190165634c84edc306e156572e31ed5a318b3d1c4bfc1535a556e61bf9370a51882c45d"
    "23ae880b";
inline constexpr std::string_view map2_signature =
    "7399462eea4d7abde776a6360424604b883a05d6e4b61f697190165634c84edc306e156572e31ed5a318b3d1"
    "c4bfc1535a556e61bf9370a51882c45d23ae880b";

// Vector 3: an empty MapUpdate (format v2) for server 7, VNI 1, map_version 1, signed
// with key 2 (key_id 2): a rotated key, and a VPC with no NICs left.
inline constexpr std::uint64_t map0_server_id = 7;
inline constexpr std::uint16_t map0_key_id = 2;
inline constexpr std::uint32_t map0_vni = 1;
inline constexpr std::uint64_t map0_map_version = 1;
inline constexpr std::string_view map0 =
    "414b4d55020002000700000000000000010000000000000001000000000000000000000000000000da5b98d1"
    "fd9b4e0923f8a7452c722df82d2bb10dc19de1bd4de6f5203be17976c070c3fb029da4b75be5a130ec6ede28"
    "d0b8b1293c7611e94f49088651987d04";
inline constexpr std::string_view map0_signature =
    "da5b98d1fd9b4e0923f8a7452c722df82d2bb10dc19de1bd4de6f5203be17976c070c3fb029da4b75be5a130"
    "ec6ede28d0b8b1293c7611e94f49088651987d04";

// Vector 4: a ReplicaConfig (format v1) for server 7, signed with key 1
// (key_id 1): volume 0x100 at epoch 9, lineage 0x1EE, 2^18 blocks of 4096
// bytes, flags multi_attach, QoS 3000 IOPS / 125 MiB/s (burst 16000 /
// 1000), lease 4000 ms, resync window 900 s, no source;
//   members  0x21 primary   fd00::21 port 7300 replica_gen 1
//            0x22 secondary fd00::22 port 7300 replica_gen 1
//   attachments 0xA1 on server 7 generation 2 rw
//               0xA2 on server 8 generation 1 rw
inline constexpr std::uint64_t rcfg4_server_id = 7;
inline constexpr std::uint16_t rcfg4_key_id = 1;
inline constexpr std::uint64_t rcfg4_volume_id = 0x100;
inline constexpr std::uint64_t rcfg4_epoch = 9;
inline constexpr std::string_view rcfg4 =
    "414b5243464700000100010002020000070000000000000000010000000000000900000000000000ee010000"
    "0000000000000400000000000010000001000000b80b00007d000000803e0000e8030000a00f000084030000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000002100000000000000fd000000000000000000000000000021841c0100010000002200000000000000"
    "fd000000000000000000000000000022841c020001000000a100000000000000070000000000000002000000"
    "01000000a20000000000000008000000000000000100000001000000059e3fd0723e3754a1c7a8b8a0c7db12"
    "36956a9c4c6ca3e116680db6db78258980c609423e73c08f7e7c2166eaac5b51ab6b22512e30c45a3dfc53f6"
    "d2713a0d";
inline constexpr std::string_view rcfg4_signature =
    "059e3fd0723e3754a1c7a8b8a0c7db1236956a9c4c6ca3e116680db6db78258980c609423e73c08f7e7c2166"
    "eaac5b51ab6b22512e30c45a3dfc53f6d2713a0d";

// Vector 5: a VolumeOp (format v1) for server 0x22, signed with key 2
// (key_id 2): snapshot_commit of cut 0xC07 with server 0x22 as uploader,
// volume 0x100, epoch 9, op_id 0x0B.
inline constexpr std::uint64_t vop5_server_id = 0x22;
inline constexpr std::uint16_t vop5_key_id = 2;
inline constexpr std::uint64_t vop5_volume_id = 0x100;
inline constexpr std::uint64_t vop5_epoch = 9;
inline constexpr std::uint64_t vop5_op_id = 0x0B;
inline constexpr std::uint64_t vop5_cut_id = 0xC07;
inline constexpr std::string_view vop5 =
    "414b564f010002002200000000000000000100000000000009000000000000000b0000000000000002000000"
    "00000000070c0000000000002200000000000000000000000000000000000000000000000000000000000000"
    "000000000000000020cb5073f3685e09b14ab126d8e2a9901ad23310e03c5dd751b7819d629a0a14094074ca"
    "9cd484d6e506f1650ccfc942a1c72d55992f059f6b5eb9dccfc6dd0d";
inline constexpr std::string_view vop5_signature =
    "20cb5073f3685e09b14ab126d8e2a9901ad23310e03c5dd751b7819d629a0a14094074ca9cd484d6e506f165"
    "0ccfc942a1c72d55992f059f6b5eb9dccfc6dd0d";

}  // namespace ak::proto::vectors
