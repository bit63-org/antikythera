// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Signing test vectors for the controller wire formats. Any controller
// implementation (kythira's EC2 and khold modules) must reproduce these bytes exactly:
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

// Vector 2: a MapUpdate (format v4) for server 7, VNI 0xABCD, map_version
// 3, signed with key 1 (key_id 1), two entries:
//   NIC 0x10, MAC 02:00:00:00:00:10, owner VTEP fd00::1, subnet 0x5B01,
//             security groups enforced
//   NIC 0x11, MAC 02:00:00:00:00:11, owner VTEP fd00::2, subnet 0x5B02,
//             source/destination check off
// and guest addresses 10.0.0.16 (NIC 0x10), 10.0.0.17 (NIC 0x11) and
// fd12::10 (NIC 0x10).
inline constexpr std::uint64_t map2_server_id = 7;
inline constexpr std::uint16_t map2_key_id = 1;
inline constexpr std::uint32_t map2_vni = 0xABCD;
inline constexpr std::uint64_t map2_map_version = 3;
inline constexpr std::string_view map2 =
    "414b4d55040001000700000000000000cdab0000020002000300000000000000010000000000000010000000"
    "000000000200000000100200fd000000000000000000000000000001015b0000000000001100000000000000"
    "0200000000110100fd000000000000000000000000000002025b00000000000010000000000000000a000010"
    "0000000011000000000000000a000011000000001000000000000000fd120000000000000000000000000010"
    "484909ed0783dca932f8df7e245dcf3ad8357f5b33f5f465ea5ab5c83cef8e4f85e091cc42d69f32398de7db"
    "a665edd723565656938d9584a0948c4f068dd301";
inline constexpr std::string_view map2_signature =
    "484909ed0783dca932f8df7e245dcf3ad8357f5b33f5f465ea5ab5c83cef8e4f85e091cc42d69f32398de7db"
    "a665edd723565656938d9584a0948c4f068dd301";

// Vector 3: an empty MapUpdate (format v4) for server 7, VNI 1, map_version 1, signed
// with key 2 (key_id 2): a rotated key, and a VPC with no NICs left.
inline constexpr std::uint64_t map0_server_id = 7;
inline constexpr std::uint16_t map0_key_id = 2;
inline constexpr std::uint32_t map0_vni = 1;
inline constexpr std::uint64_t map0_map_version = 1;
inline constexpr std::string_view map0 =
    "414b4d550400020007000000000000000100000000000000010000000000000000000000000000002217709d"
    "c24cdcf470a0b2899522ebedbadd04ae094f1e4ea8bd91079a457f4ed92ffdb932a579373b61831698854ccb"
    "ca6f9f101bd0e88fd438f1729ec2c003";
inline constexpr std::string_view map0_signature =
    "2217709dc24cdcf470a0b2899522ebedbadd04ae094f1e4ea8bd91079a457f4ed92ffdb932a579373b618316"
    "98854ccbca6f9f101bd0e88fd438f1729ec2c003";

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

// Vectors 6 to 11: khold (kythira .kiro/specs/khold-block-service/). The
// hold wire version 2 frames and the reports are unsigned; they pin the
// layout, the header CRC32C and the payloads byte for byte.
//
// Vector 6: a VolumeLayout (format v1) for server 0x21, signed with key 1
// (key_id 1): volume 0x200 at epoch 3, lineage 0x2EE, 2^20 blocks of 4096
// bytes, stripe unit 1 MiB, commit rule all_in_sync, group skew 10 %, QoS
// 3000 IOPS / 125 MiB/s (burst 16000 / 1000), member deadline 1000 ms,
// election minimum 1000 ms, resync window 900 s, no flags, no mirror, no
// gateways; endpoints fd00::<server> port 7400;
//   group 0x5001: 0x21 data drive 0, 0x22 data drive 1, 0x23 witness drive 0
//   group 0x5002: 0x22 data drive 0, 0x23 data drive 1, 0x24 witness drive 0
//   attachment 0xA1 on server 7 generation 2 rw
inline constexpr std::uint64_t layout6_server_id = 0x21;
inline constexpr std::uint16_t layout6_key_id = 1;
inline constexpr std::uint64_t layout6_volume_id = 0x200;
inline constexpr std::uint64_t layout6_epoch = 3;
inline constexpr std::string_view layout6 =
    "414b564c415900000100010002000001210000000000000000020000000000000300000000000000ee020000"
    "000000000000100000000000001000000000100000000000010a0000b80b00007d000000803e0000e8030000"
    "e8030000e8030000840300000000000000000000000000000000000000000000015000000000000003000000"
    "000000002100000000000000fd000000000000000000000000000021e81c0100000000002200000000000000"
    "fd000000000000000000000000000022e81c0101000000002300000000000000fd0000000000000000000000"
    "00000023e81c020000000000025000000000000003000000000000002200000000000000fd00000000000000"
    "0000000000000022e81c0100000000002300000000000000fd000000000000000000000000000023e81c0101"
    "000000002400000000000000fd000000000000000000000000000024e81c020000000000a100000000000000"
    "0700000000000000020000000100000053f9be2f5b21570c923182a0188a0c9c3b98ebdf5ea68324fe92ba18"
    "543cb5bf0f9001c59e6b1a7f2d54f8d9ec429e2228618387c35509c74c34c27d8879ed0a";
inline constexpr std::string_view layout6_signature =
    "53f9be2f5b21570c923182a0188a0c9c3b98ebdf5ea68324fe92ba18543cb5bf0f9001c59e6b1a7f2d54f8d9"
    "ec429e2228618387c35509c74c34c27d8879ed0a";

// Vector 7: a hold v2 write request: request 77, volume 0x200, epoch 3,
// attachment 0xA1 generation 2, group 0x5001, term 4, one 512-byte block
// at LBA 0x1000 whose byte i is (i * 13 + 1) mod 256.
inline constexpr std::string_view hold_v2_write7 =
    "414b48570204000004020000000000004d0000000000000000020000000000000300000000000000a1000000"
    "0000000002000000010000000010000000000000015000000000000004000000000000000000000055f02a80"
    "da2a7083010e1b2835424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc"
    "091623303d4a5764717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b38"
    "45525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774"
    "818e9ba8b5c2cfdce9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0"
    "bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfec"
    "f90613202d3a4754616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4010e1b28"
    "35424f5c697683909daab7c4d1deebf805121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764"
    "717e8b98a5b2bfccd9e6f3000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0"
    "adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdc"
    "e9f603101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b18"
    "25323f4c596673808d9aa7b4c1cedbe8f5020f1c293643505d6a7784919eabb8c5d2dfecf90613202d3a4754"
    "616e7b8895a2afbcc9d6e3f0fd0a1724313e4b5865727f8c99a6b3c0cddae7f4";

// Vector 8: a hold v2 redirect answering request 78 (status not_leader):
// volume 0x200, epoch 3, attachment 0xA1 generation 2, group 0x5001,
// responder term 5; leader server 0x22 at fd00::22 port 7400, term 5.
inline constexpr std::string_view hold_v2_redirect8 =
    "414b4857020e010028000000030000004e0000000000000000020000000000000300000000000000a1000000"
    "000000000200000000000000000000000000000001500000000000000500000000000000000000003ebcd961"
    "2200000000000000fd000000000000000000000000000022e81c0000000000000500000000000000";

// Vector 9: a hold v2 hello_ok answering request 1: volume 0x200, epoch 3,
// attachment 0xA1 generation 2, block size 4096, 2^20 blocks, stripe unit
// 1 MiB, stripe width 2.
inline constexpr std::string_view hold_v2_hello_ok9 =
    "414b4857020201001800000000000000010000000000000000020000000000000300000000000000a1000000"
    "0000000002000000000000000000000000000000000000000000000000000000000000000000000079b52a85"
    "001000000000000000001000000000000000100002000000";

// Vector 10: an unsigned group_status report (format v2) from server 0x21,
// report_seq 5: slot 3, one member: volume 0x200, group 0x5001, epoch 3,
// term 4, commit index 90, applied index 88, kind data, state leader, one
// lagging member, drive 0, 1 GiB allocated.
inline constexpr std::string_view report_group_status10 =
    "414b525002001100210000000000000005000000000000004800000000000000030001000000000000020000"
    "000000000150000000000000030000000000000004000000000000005a000000000000005800000000000000"
    "01010100000000000000004000000000";

// Vector 11: an unsigned group_fault report (format v2) from server 0x21,
// report_seq 6: volume 0x200, group 0x5001, epoch 3, term 4, suspect 0x22,
// kind lagging, slot 3, drive 0.
inline constexpr std::string_view report_group_fault11 =
    "414b525002001300210000000000000006000000000000003000000000000000000200000000000001500000"
    "000000000300000000000000040000000000000022000000000000000103000000000000";

// Vector 12: a VpcConfig (format v2, .kiro/specs/vpc-subnets-routing/) for
// server 7, VNI 0xABCD, config_version 2, signed with key 1 (key_id 1):
// gateway MAC 02:00:00:00:ff:01, block 10.0.0.0/16, IPv6 block
// 2001:db8:1200::/56, DNS 10.0.0.2, domain ec2.internal, lease 3600 s;
//   subnet 0x5B01  10.0.1.0/24, 2001:db8:1200:1::/64, table 1
//   subnet 0x5B02  10.0.2.0/24, no IPv6,               table 2
//   table 1 (main)  local 10.0.0.0/16, 10.0.2.0/24 -> NIC 0x11,
//                   local 2001:db8:1200::/56
//   table 2         local 10.0.0.0/16, local 2001:db8:1200::/56
inline constexpr std::uint64_t vpc12_server_id = 7;
inline constexpr std::uint16_t vpc12_key_id = 1;
inline constexpr std::uint32_t vpc12_vni = 0xABCD;
inline constexpr std::uint64_t vpc12_config_version = 2;
inline constexpr std::string_view vpc12 =
    "414b5643020001000700000000000000cdab000001010100020000000000000002000000ff010c00100e0000"
    "02000200050000000000000020010db81200000000000000000000000a000000100000000a000002015b0000"
    "00000000010001180a00010020010db8120000010000000000000000025b000000000000020000180a000200"
    "0000000000000000000000000000000001000100030000000200000002000000000000000000000001041000"
    "000000000a000000000000000000000000000000110000000000000002041800000000000a00020000000000"
    "00000000000000000000000000000000010638000000000020010db812000000000000000000000000000000"
    "0000000001041000000000000a00000000000000000000000000000000000000000000000106380000000000"
    "20010db81200000000000000000000006563322e696e7465726e616c9e493bd539d96f0178ca155a4c2724a3"
    "e0243a65cdc8b7f953fa4ffbb2290c0927a1289b07e9d82cf47b7d8fe1f7ed59f121474ae992757c8904eac8"
    "21760104";
inline constexpr std::string_view vpc12_signature =
    "9e493bd539d96f0178ca155a4c2724a3e0243a65cdc8b7f953fa4ffbb2290c0927a1289b07e9d82cf47b7d8f"
    "e1f7ed59f121474ae992757c8904eac821760104";

}  // namespace ak::proto::vectors
