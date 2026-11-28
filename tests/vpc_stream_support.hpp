// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Builders for VpcStream record bodies (proto/vpc_stream.hpp), shared by
// the codec, vector and applier tests.

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>
#include <vector>

#include "proto/vpc_stream.hpp"

namespace ak::test::stream {

using proto::StreamOp;
using proto::StreamRecord;
using proto::StreamRecordType;

class Body {
public:
    auto u8(std::uint64_t v) -> Body& {
        _b.push_back(static_cast<std::byte>(v & 0xFFU));
        return *this;
    }
    auto le16(std::uint64_t v) -> Body& { return le(v, 2); }
    auto le32(std::uint64_t v) -> Body& { return le(v, 4); }
    auto le64(std::uint64_t v) -> Body& { return le(v, 8); }
    auto zero(std::size_t n) -> Body& {
        _b.insert(_b.end(), n, std::byte{0});
        return *this;
    }
    auto bytes(std::initializer_list<std::uint8_t> v) -> Body& {
        for (auto x : v) {
            _b.push_back(std::byte{x});
        }
        return *this;
    }
    auto bytes(std::span<const std::byte> v) -> Body& {
        _b.insert(_b.end(), v.begin(), v.end());
        return *this;
    }
    auto text(std::string_view s) -> Body& { return bytes(std::as_bytes(std::span{s})); }
    [[nodiscard]] auto take() -> std::vector<std::byte> { return std::move(_b); }

private:
    auto le(std::uint64_t v, unsigned n) -> Body& {
        for (unsigned i = 0; i < n; ++i) {
            _b.push_back(static_cast<std::byte>((v >> (8U * i)) & 0xFFU));
        }
        return *this;
    }
    std::vector<std::byte> _b;
};

// fd00::<low>
inline auto ula(std::uint8_t low) -> std::array<std::byte, 16> {
    std::array<std::byte, 16> a{};
    a[0] = std::byte{0xFD};
    a[15] = std::byte{low};
    return a;
}

inline auto put(StreamRecordType t, std::vector<std::byte> body) -> StreamRecord {
    return {.type = t, .op = StreamOp::put, .body = std::move(body)};
}

// A remove: the first key-size bytes of a put body.
inline auto remove_of(const StreamRecord& r) -> StreamRecord {
    const auto n = proto::stream_key_size(r.type);
    return {.type = r.type,
            .op = StreamOp::remove,
            .body = {r.body.begin(), r.body.begin() + static_cast<std::ptrdiff_t>(n)}};
}

inline auto nic_binding(std::uint64_t nic, std::uint64_t subnet, std::uint8_t vtep_low,
                        std::uint8_t mac_low, std::uint8_t flags = 0) -> StreamRecord {
    return put(StreamRecordType::nic_binding, Body{}
                                                  .le64(nic)
                                                  .le64(subnet)
                                                  .bytes(ula(vtep_low))
                                                  .bytes({0x02, 0, 0, 0, 0, mac_low})
                                                  .u8(flags)
                                                  .u8(0)
                                                  .take());
}

inline auto ipv4_address(std::array<std::uint8_t, 4> a, std::uint64_t nic) -> StreamRecord {
    return put(StreamRecordType::ipv4_address,
               Body{}.bytes({a[0], a[1], a[2], a[3]}).le64(nic).take());
}

inline auto ipv6_address(std::uint8_t low, std::uint64_t nic) -> StreamRecord {
    return put(StreamRecordType::ipv6_address, Body{}.bytes(ula(low)).le64(nic).take());
}

// Gateway MAC 02:00:00:00:ff:01, block 10.0.0.0/16, IPv6 block
// fd12:3400::/56, DNS 10.0.0.2, domain ec2.internal, lease 3600 s.
inline auto vpc_settings() -> StreamRecord {
    constexpr std::string_view domain = "ec2.internal";
    return put(StreamRecordType::vpc_settings,
               Body{}
                   .bytes({0x02, 0, 0, 0, 0xFF, 0x01})
                   .u8(1)  // blocks
                   .u8(1)  // ipv6
                   .u8(1)  // dns4
                   .u8(0)  // dns6
                   .u8(domain.size())
                   .u8(0)
                   .le32(3600)
                   .le32(0)
                   .bytes({0xFD, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
                   .bytes({10, 0, 0, 0})
                   .u8(16)
                   .zero(3)
                   .bytes({10, 0, 0, 2})
                   .text(domain)
                   .take());
}

inline auto subnet(std::uint64_t id, std::uint8_t third_octet, std::uint16_t table)
    -> StreamRecord {
    return put(
        StreamRecordType::subnet,
        Body{}.le64(id).bytes({10, 0, third_octet, 0}).le16(table).u8(0).u8(24).zero(16).take());
}

inline auto route_table(std::uint16_t table, bool main) -> StreamRecord {
    return put(StreamRecordType::route_table, Body{}.le16(table).u8(main ? 1 : 0).zero(5).take());
}

// An IPv4 route in `table` to 10.0.<third>.0/24.
inline auto route4(std::uint16_t table, std::uint8_t third, proto::StreamRouteKind kind,
                   std::uint64_t target) -> StreamRecord {
    return put(StreamRecordType::route, Body{}
                                            .le16(table)
                                            .u8(4)
                                            .u8(24)
                                            .bytes({10, 0, third, 0})
                                            .zero(12)
                                            .u8(static_cast<std::uint8_t>(kind))
                                            .zero(3)
                                            .le64(target)
                                            .take());
}

inline auto nat_gateway(std::uint64_t id, std::uint64_t subnet_id,
                        std::initializer_list<std::array<std::uint8_t, 4>> addresses)
    -> StreamRecord {
    Body b;
    b.le64(id).le64(subnet_id).u8(3).u8(addresses.size()).zero(6);
    for (const auto& a : addresses) {
        b.bytes({a[0], a[1], a[2], a[3]});
    }
    return put(StreamRecordType::gateway, b.take());
}

inline auto internet_gateway(std::uint64_t id) -> StreamRecord {
    return put(StreamRecordType::gateway, Body{}.le64(id).le64(0).u8(1).u8(0).zero(6).take());
}

inline auto nat_block(std::uint64_t gateway, std::uint8_t address_index, std::uint8_t block,
                      std::uint64_t owner) -> StreamRecord {
    return put(StreamRecordType::nat_port_block,
               Body{}.le64(gateway).u8(address_index).u8(block).zero(6).le64(owner).take());
}

inline auto security_group(std::uint64_t id) -> StreamRecord {
    return put(StreamRecordType::security_group, Body{}.le64(id).take());
}

// Inbound TCP from..to from 10.0.0.0/16 in `group`.
inline auto sg_rule_tcp(std::uint64_t group, std::uint16_t from, std::uint16_t to) -> StreamRecord {
    return put(StreamRecordType::sg_rule, Body{}
                                              .le64(group)
                                              .u8(1)
                                              .zero(7)
                                              .u8(6)
                                              .u8(0)
                                              .u8(4)
                                              .u8(16)
                                              .le16(from)
                                              .le16(to)
                                              .zero(8)
                                              .bytes({10, 0, 0, 0})
                                              .zero(12)
                                              .take());
}

inline auto membership(std::uint64_t nic, std::initializer_list<std::uint64_t> groups)
    -> StreamRecord {
    Body b;
    b.le64(nic).u8(groups.size()).zero(7);
    for (auto g : groups) {
        b.le64(g);
    }
    return put(StreamRecordType::membership, b.take());
}

inline auto tracking(std::uint64_t nic) -> StreamRecord {
    return put(StreamRecordType::tracking,
               Body{}.le64(nic).le32(432'000).le16(180).le16(30).le32(0).le32(0).take());
}

inline auto group_policy(std::uint64_t subnet_id) -> StreamRecord {
    return put(StreamRecordType::group_policy, Body{}
                                                   .le64(subnet_id)
                                                   .le32(100)
                                                   .le32(200)
                                                   .le64(65536)
                                                   .le64(131072)
                                                   .le32(4)
                                                   .le16(8)
                                                   .le16(0)
                                                   .take());
}

// 239.1.2.<last> flooded to fd00::<v> for each v.
inline auto member_list4(std::uint8_t last, std::initializer_list<std::uint8_t> vteps)
    -> StreamRecord {
    Body b;
    b.u8(4).zero(7).bytes({239, 1, 2, last}).zero(12).le16(vteps.size()).zero(6);
    for (auto v : vteps) {
        b.bytes(ula(v));
    }
    return put(StreamRecordType::group_member_list, b.take());
}

inline auto lookup_interest(std::uint64_t nic) -> StreamRecord {
    return put(StreamRecordType::lookup_interest, Body{}.le64(nic).take());
}

// A snapshot part's fields, records to be filled in.
inline auto snapshot(std::uint64_t to_sequence) -> proto::VpcStream {
    return {.key_id = 1,
            .vpc_id = 0x0FC0'0001,
            .vni = 0xABCD,
            .incarnation = 1,
            .cell_scope = 0,
            .kind = proto::StreamKind::snapshot,
            .lookup = false,
            .part = 0,
            .part_count = 1,
            .snapshot_id = 0x5A,
            .from_sequence = 0,
            .to_sequence = to_sequence,
            .records = {},
            .signature = {}};
}

inline auto delta(std::uint64_t from, std::uint64_t to) -> proto::VpcStream {
    auto s = snapshot(to);
    s.kind = proto::StreamKind::delta;
    s.snapshot_id = 0;
    s.from_sequence = from;
    return s;
}

// One of every record type, in snapshot order.
inline auto every_type() -> std::vector<StreamRecord> {
    using K = proto::StreamRouteKind;
    return {nic_binding(0x11, 0x5B01, 1, 0x11),
            nic_binding(0x12, 0x5B01, 2, 0x12, proto::map_entry_security_groups_enforced),
            ipv4_address({10, 0, 1, 5}, 0x11),
            ipv4_address({10, 0, 1, 6}, 0x12),
            ipv6_address(5, 0x11),
            vpc_settings(),
            subnet(0x5B01, 1, 1),
            route_table(1, true),
            route4(1, 2, K::nic, 0x11),
            route4(1, 9, K::nat, 0x6A),
            nat_gateway(0x6A, 0x5B01, {{10, 0, 1, 9}}),
            internet_gateway(0x6B),
            nat_block(0x6A, 0, 0, 7),
            security_group(0x5600),
            sg_rule_tcp(0x5600, 22, 22),
            membership(0x11, {0x5600}),
            tracking(0x11),
            group_policy(0x5B01),
            member_list4(3, {1, 2}),
            lookup_interest(0x12)};
}

}  // namespace ak::test::stream
