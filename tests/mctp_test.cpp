// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirements 5.2 and 10.1: MCTP over the
// SMBus binding, packet reassembly, and the ak vendor-defined messages.

#define BOOST_TEST_MODULE mctp_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

#include "helm/mctp.hpp"
#include "test_support.hpp"

namespace mctp = ak::helm::mctp;
using ak::test::bytes_of;
using ak::test::unit_timeout_seconds;
using mctp::AssemblyError;
using mctp::PacketError;
using mctp::VendorError;

namespace {

// CRC-8/SMBUS catalogue check value: the CRC of the ASCII string "123456789".
constexpr std::string_view crc_check_input = "123456789";
constexpr std::uint8_t crc_check_value = 0xF4;

constexpr std::uint8_t helm_addr = 0x08;  // 7-bit
constexpr std::uint8_t oar_addr = 0x10;
constexpr std::uint8_t helm_eid = 0x08;
constexpr std::uint8_t oar_eid = 0x09;
constexpr std::uint8_t other_eid = 0x0A;
constexpr std::uint8_t other_addr = 0x11;
constexpr std::uint8_t reserved_eid = 0x03;
constexpr std::uint8_t sample_tag = 2;
constexpr std::uint8_t other_tag = 5;
constexpr std::uint8_t last_seq = 3;

// Byte offsets inside an SMBus packet (see mctp.hpp).
constexpr std::size_t dest_offset = 0;
constexpr std::size_t command_offset = 1;
constexpr std::size_t count_offset = 2;
constexpr std::size_t src_offset = 3;
constexpr std::size_t version_offset = 4;
constexpr std::size_t dest_eid_offset = 5;
constexpr std::size_t src_eid_offset = 6;
constexpr std::size_t flags_offset = 7;
constexpr std::size_t payload_offset = 8;

constexpr std::uint8_t not_mctp_command = 0x0E;
constexpr std::uint8_t read_bit = 0x01;
constexpr std::uint8_t version_two = 0x02;
constexpr std::uint8_t reserved_high_nibble = 0x11;
constexpr std::uint8_t too_small_count = 4;
constexpr std::uint8_t bad_address = 0x80;
constexpr std::uint8_t bad_seq = 4;
constexpr std::uint8_t bad_tag = 8;
constexpr std::size_t small_mtu = 63;
constexpr std::size_t large_mtu = 250;
constexpr std::size_t too_large_mtu = 251;
constexpr std::uint8_t pec_flip = 0x01;

constexpr std::size_t one_byte = 1;
constexpr std::size_t exactly_one_packet = 64;
constexpr std::size_t just_over_one_packet = 65;
constexpr std::size_t several_packets = 300;  // 5 packets at 64: sequence wraps
constexpr std::size_t five_packets = 5;
constexpr std::size_t tiny_limit = 100;

constexpr std::uint8_t control_type = 0x00;
constexpr std::uint8_t spdm_type = 0x05;
constexpr std::uint8_t vendor_pci_type = 0x7E;
constexpr std::uint8_t vendor_pci_with_ic = 0xFE;
constexpr std::uint8_t ak_vendor_hi = 0xFF;
constexpr std::uint8_t ak_vendor_lo = 0xFF;
constexpr std::uint8_t other_vendor_hi = 0x80;
constexpr std::uint8_t other_vendor_lo = 0x86;
constexpr std::uint8_t ak_version = 1;
constexpr std::uint8_t unknown_version = 2;
constexpr std::uint8_t health_type = 0x07;
constexpr std::uint8_t unknown_vendor_type = 0x19;  // one past vpc_config
constexpr std::uint8_t zero = 0x00;
constexpr std::uint8_t response_flag = 0x01;
constexpr std::uint8_t unknown_flag = 0x02;
constexpr std::uint8_t body_byte = 0xAB;
constexpr std::uint8_t sample_payload_a = 0xDE;
constexpr std::uint8_t sample_payload_b = 0xAD;

// Deterministic, position-dependent filler so misordered packets show up.
auto pattern(std::size_t n) -> std::vector<std::byte> {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::byte>((i * 7 + 3) & 0xFF);  // NOLINT(readability-magic-numbers)
    }
    return v;
}

auto helm_to_oar() -> mctp::Route {
    return {.dest_addr = oar_addr,
            .src_addr = helm_addr,
            .dest_eid = oar_eid,
            .src_eid = helm_eid,
            .tag_owner = true,
            .tag = sample_tag};
}

auto single_header() -> mctp::TransportHeader {
    return {.dest_eid = oar_eid,
            .src_eid = helm_eid,
            .som = true,
            .eom = true,
            .seq = 0,
            .tag_owner = true,
            .tag = sample_tag};
}

auto sample_packet() -> std::vector<std::byte> {
    auto p = mctp::encode_packet(oar_addr, helm_addr, single_header(),
                                 bytes_of(sample_payload_a, sample_payload_b));
    BOOST_REQUIRE(p.has_value());
    return *p;
}

// Rewrites the PEC after a test edits a field, so the field check is what fails.
auto repec(std::vector<std::byte>& pkt) -> void {
    pkt.back() = static_cast<std::byte>(mctp::pec(std::span{pkt}.first(pkt.size() - 1)));
}

auto decode_all(const std::vector<std::vector<std::byte>>& encoded) -> std::vector<mctp::Packet> {
    std::vector<mctp::Packet> out;
    for (const auto& e : encoded) {
        auto p = mctp::decode_packet(e);
        BOOST_REQUIRE(p.has_value());
        out.push_back(*p);
    }
    return out;
}

auto packets_for(std::size_t size, std::size_t mtu = mctp::baseline_mtu)
    -> std::vector<mctp::Packet> {
    auto encoded = mctp::fragment(helm_to_oar(), pattern(size), mtu);
    BOOST_REQUIRE(encoded.has_value());
    return decode_all(*encoded);
}

auto packet_error(std::vector<std::byte> pkt) -> PacketError {
    auto r = mctp::decode_packet(pkt);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto vendor_error(const std::vector<std::byte>& msg) -> VendorError {
    auto r = mctp::decode_vendor(msg);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

// ---- PEC and packets ------------------------------------------------------

BOOST_AUTO_TEST_CASE(pec_matches_crc8_smbus_check_value,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::byte> input;
    for (const char c : crc_check_input) {
        input.push_back(static_cast<std::byte>(c));
    }
    BOOST_TEST(mctp::pec(input) == crc_check_value);
    BOOST_TEST(mctp::pec({}) == zero);
}

BOOST_AUTO_TEST_CASE(encode_matches_hand_written_image,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // dest 0x10<<1, MCTP, count 7, src 0x08<<1|1, v1, EIDs, SOM|EOM|TO|tag 2.
    auto expected = bytes_of(0x20, 0x0F, 0x07, 0x11, 0x01, oar_eid, helm_eid, 0xCA,
                             sample_payload_a, sample_payload_b, 0x00);
    repec(expected);
    BOOST_TEST(sample_packet() == expected);
}

BOOST_AUTO_TEST_CASE(decode_round_trips, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto pkt = sample_packet();
    auto p = mctp::decode_packet(pkt);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(p->dest_addr == oar_addr);
    BOOST_TEST(p->src_addr == helm_addr);
    BOOST_TEST((p->header == single_header()));
    BOOST_TEST(p->payload_len == 2U);
    auto again = mctp::encode_packet(p->dest_addr, p->src_addr, p->header, p->payload());
    BOOST_REQUIRE(again.has_value());
    BOOST_TEST(*again == pkt);
}

BOOST_AUTO_TEST_CASE(decode_accepts_empty_and_maximum_payloads,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::size_t n : {std::size_t{0}, mctp::max_packet_payload}) {
        auto pkt = mctp::encode_packet(oar_addr, helm_addr, single_header(), pattern(n));
        BOOST_REQUIRE(pkt.has_value());
        BOOST_TEST(pkt->size() ==
                   mctp::smbus_prefix_size + mctp::counted_overhead + n + mctp::pec_size);
        auto p = mctp::decode_packet(*pkt);
        BOOST_REQUIRE(p.has_value());
        BOOST_TEST(p->payload_len == n);
    }
    BOOST_TEST(mctp::max_packet_size == 259U);
}

BOOST_AUTO_TEST_CASE(decode_rejects_bad_lengths, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pkt = sample_packet();
    BOOST_TEST((packet_error(std::vector(pkt.begin(), pkt.begin() + 4)) == PacketError::truncated));
    BOOST_TEST((packet_error(std::vector(pkt.begin(), pkt.end() - 1)) == PacketError::truncated));

    auto longer = pkt;
    longer.push_back(std::byte{zero});
    BOOST_TEST((packet_error(longer) == PacketError::trailing_bytes));

    auto small_count = pkt;
    small_count[count_offset] = std::byte{too_small_count};
    BOOST_TEST((packet_error(small_count) == PacketError::truncated));
}

BOOST_AUTO_TEST_CASE(decode_rejects_bad_pec, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pkt = sample_packet();
    pkt.back() ^= std::byte{pec_flip};
    BOOST_TEST((packet_error(pkt) == PacketError::bad_pec));

    auto payload_flip = sample_packet();
    payload_flip[payload_offset] ^= std::byte{pec_flip};
    BOOST_TEST((packet_error(payload_flip) == PacketError::bad_pec));
}

BOOST_AUTO_TEST_CASE(decode_rejects_bad_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto edited = [](std::size_t offset, std::uint8_t value) {
        auto pkt = sample_packet();
        pkt[offset] = std::byte{value};
        repec(pkt);
        return packet_error(pkt);
    };
    BOOST_TEST((edited(command_offset, not_mctp_command) == PacketError::bad_command));
    BOOST_TEST((edited(dest_offset, (oar_addr << 1U) | read_bit) == PacketError::bad_rw_bit));
    BOOST_TEST((edited(src_offset, helm_addr << 1U) == PacketError::bad_rw_bit));
    BOOST_TEST((edited(version_offset, version_two) == PacketError::bad_version));
    BOOST_TEST((edited(version_offset, reserved_high_nibble) == PacketError::reserved_not_zero));
    BOOST_TEST((edited(dest_eid_offset, reserved_eid) == PacketError::bad_eid));
    BOOST_TEST((edited(src_eid_offset, reserved_eid) == PacketError::bad_eid));
    BOOST_TEST((edited(src_eid_offset, mctp::broadcast_eid) == PacketError::bad_eid));
}

BOOST_AUTO_TEST_CASE(decode_accepts_null_and_broadcast_destinations,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::uint8_t eid : {mctp::null_eid, mctp::broadcast_eid}) {
        auto h = single_header();
        h.dest_eid = eid;
        auto pkt = mctp::encode_packet(oar_addr, helm_addr, h, {});
        BOOST_REQUIRE(pkt.has_value());
        BOOST_TEST(mctp::decode_packet(*pkt).has_value());
    }
    auto h = single_header();
    h.src_eid = mctp::null_eid;  // allowed before EID assignment
    auto pkt = mctp::encode_packet(oar_addr, helm_addr, h, {});
    BOOST_REQUIRE(pkt.has_value());
    BOOST_TEST(mctp::decode_packet(*pkt).has_value());
}

BOOST_AUTO_TEST_CASE(decode_reads_every_flag, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pkt = sample_packet();
    pkt[flags_offset] = std::byte{0x35};  // !SOM !EOM seq 3, TO 0, tag 5
    repec(pkt);
    auto p = mctp::decode_packet(pkt);
    BOOST_REQUIRE(p.has_value());
    BOOST_TEST(!p->header.som);
    BOOST_TEST(!p->header.eom);
    BOOST_TEST(p->header.seq == last_seq);
    BOOST_TEST(!p->header.tag_owner);
    BOOST_TEST(p->header.tag == other_tag);
}

BOOST_AUTO_TEST_CASE(encode_rejects_bad_fields, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto h = single_header();
    BOOST_TEST(
        (mctp::encode_packet(bad_address, helm_addr, h, {}).error() == PacketError::invalid_field));
    BOOST_TEST(
        (mctp::encode_packet(oar_addr, bad_address, h, {}).error() == PacketError::invalid_field));
    auto seq = h;
    seq.seq = bad_seq;
    BOOST_TEST(
        (mctp::encode_packet(oar_addr, helm_addr, seq, {}).error() == PacketError::invalid_field));
    auto tag = h;
    tag.tag = bad_tag;
    BOOST_TEST(
        (mctp::encode_packet(oar_addr, helm_addr, tag, {}).error() == PacketError::invalid_field));
    auto eid = h;
    eid.src_eid = mctp::broadcast_eid;
    BOOST_TEST((mctp::encode_packet(oar_addr, helm_addr, eid, {}).error() == PacketError::bad_eid));
    BOOST_TEST((mctp::encode_packet(oar_addr, helm_addr, h, pattern(mctp::max_packet_payload + 1))
                    .error() == PacketError::payload_too_long));
}

// ---- Fragmentation and reassembly ----------------------------------------

BOOST_AUTO_TEST_CASE(fragment_sizes_packets_to_the_mtu,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto packets = packets_for(several_packets);
    BOOST_REQUIRE(packets.size() == five_packets);
    for (std::size_t i = 0; i < packets.size(); ++i) {
        const auto& h = packets[i].header;
        BOOST_TEST(h.som == (i == 0));
        BOOST_TEST(h.eom == (i + 1 == packets.size()));
        BOOST_TEST(h.seq == (i & last_seq));
        BOOST_TEST(h.tag == sample_tag);
        BOOST_TEST(h.tag_owner);
        if (i + 1 < packets.size()) {
            BOOST_TEST(packets[i].payload_len == mctp::baseline_mtu);
        }
    }
    BOOST_TEST(packets.back().payload_len == several_packets - 4 * mctp::baseline_mtu);
}

BOOST_AUTO_TEST_CASE(fragment_starts_at_the_given_sequence,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto encoded =
        mctp::fragment(helm_to_oar(), pattern(just_over_one_packet), mctp::baseline_mtu, last_seq);
    BOOST_REQUIRE(encoded.has_value());
    const auto packets = decode_all(*encoded);
    BOOST_REQUIRE(packets.size() == 2U);
    BOOST_TEST(packets[0].header.seq == last_seq);
    BOOST_TEST(packets[1].header.seq == 0);
}

BOOST_AUTO_TEST_CASE(fragment_rejects_bad_arguments,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto r = helm_to_oar();
    BOOST_TEST((mctp::fragment(r, {}).error() == PacketError::invalid_field));
    BOOST_TEST(
        (mctp::fragment(r, pattern(one_byte), small_mtu).error() == PacketError::invalid_field));
    BOOST_TEST((mctp::fragment(r, pattern(one_byte), too_large_mtu).error() ==
                PacketError::invalid_field));
    BOOST_TEST((mctp::fragment(r, pattern(one_byte), mctp::baseline_mtu, bad_seq).error() ==
                PacketError::invalid_field));
    BOOST_TEST((mctp::fragment(r, pattern(mctp::max_message_size + 1)).error() ==
                PacketError::payload_too_long));
    auto bad_eid = r;
    bad_eid.src_eid = reserved_eid;
    BOOST_TEST((mctp::fragment(bad_eid, pattern(one_byte)).error() == PacketError::bad_eid));
}

BOOST_AUTO_TEST_CASE(fragment_and_assemble_round_trip,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const std::size_t mtu : {mctp::baseline_mtu, large_mtu}) {
        for (const std::size_t size : {one_byte, exactly_one_packet, just_over_one_packet,
                                       several_packets, mctp::max_message_size}) {
            BOOST_TEST_CONTEXT("mtu " << mtu << " size " << size) {
                mctp::Assembler asm_oar{oar_eid};
                const auto packets = packets_for(size, mtu);
                for (std::size_t i = 0; i + 1 < packets.size(); ++i) {
                    auto r = asm_oar.push(packets[i]);
                    BOOST_REQUIRE(r.has_value());
                    BOOST_TEST(!r->has_value());
                    BOOST_TEST(asm_oar.in_progress() == 1U);
                }
                auto last = asm_oar.push(packets.back());
                BOOST_REQUIRE(last.has_value());
                BOOST_REQUIRE(last->has_value());
                BOOST_TEST((**last).bytes == pattern(size));
                BOOST_TEST(((**last).route == helm_to_oar()));
                BOOST_TEST(asm_oar.in_progress() == 0U);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(assembler_filters_destination,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mctp::Assembler asm_other{other_eid};
    BOOST_TEST(
        (asm_other.push(packets_for(one_byte)[0]).error() == AssemblyError::wrong_destination));

    for (const std::uint8_t eid : {mctp::null_eid, mctp::broadcast_eid}) {
        auto route = helm_to_oar();
        route.dest_eid = eid;
        auto encoded = mctp::fragment(route, pattern(one_byte));
        BOOST_REQUIRE(encoded.has_value());
        auto r = asm_other.push(decode_all(*encoded)[0]);
        BOOST_REQUIRE(r.has_value());
        BOOST_TEST(r->has_value());
    }
}

BOOST_AUTO_TEST_CASE(assembler_rejects_middle_without_start,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mctp::Assembler a{oar_eid};
    const auto packets = packets_for(several_packets);
    BOOST_TEST((a.push(packets[1]).error() == AssemblyError::unexpected_packet));
    BOOST_TEST((a.push(packets.back()).error() == AssemblyError::unexpected_packet));
}

BOOST_AUTO_TEST_CASE(assembler_drops_on_lost_packet,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mctp::Assembler a{oar_eid};
    const auto packets = packets_for(several_packets);
    BOOST_REQUIRE(a.push(packets[0]).has_value());
    BOOST_TEST((a.push(packets[2]).error() == AssemblyError::out_of_sequence));
    BOOST_TEST(a.in_progress() == 0U);
    // The rest of the broken message is now unexpected.
    BOOST_TEST((a.push(packets[3]).error() == AssemblyError::unexpected_packet));
}

BOOST_AUTO_TEST_CASE(assembler_checks_packet_sizes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto middle = [](std::size_t len, bool eom) {
        mctp::Packet p;
        p.dest_addr = oar_addr;
        p.src_addr = helm_addr;
        p.header = single_header();
        p.header.som = false;
        p.header.eom = eom;
        p.header.seq = 1;
        p.payload_len = len;
        return p;
    };
    const auto first = packets_for(several_packets)[0];

    for (const auto& bad :
         {middle(mctp::baseline_mtu - 1, false), middle(mctp::baseline_mtu + 1, false),
          middle(mctp::baseline_mtu + 1, true), middle(0, true)}) {
        mctp::Assembler a{oar_eid};
        BOOST_REQUIRE(a.push(first).has_value());
        BOOST_TEST((a.push(bad).error() == AssemblyError::packet_size_mismatch));
        BOOST_TEST(a.in_progress() == 0U);
    }
    mctp::Assembler a{oar_eid};
    BOOST_REQUIRE(a.push(first).has_value());
    auto short_last = a.push(middle(one_byte, true));
    BOOST_REQUIRE(short_last.has_value());
    BOOST_TEST((**short_last).bytes.size() == mctp::baseline_mtu + one_byte);
}

BOOST_AUTO_TEST_CASE(assembler_keeps_message_on_foreign_packet,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mctp::Assembler a{oar_eid};
    const auto packets = packets_for(just_over_one_packet);
    BOOST_REQUIRE(a.push(packets[0]).has_value());

    auto foreign_eid = packets[1];
    foreign_eid.header.src_eid = other_eid;
    BOOST_TEST((a.push(foreign_eid).error() == AssemblyError::source_mismatch));
    auto foreign_addr = packets[1];
    foreign_addr.src_addr = other_addr;
    BOOST_TEST((a.push(foreign_addr).error() == AssemblyError::source_mismatch));

    auto done = a.push(packets[1]);
    BOOST_REQUIRE(done.has_value());
    BOOST_TEST((**done).bytes == pattern(just_over_one_packet));
}

BOOST_AUTO_TEST_CASE(assembler_restarts_on_new_start,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mctp::Assembler a{oar_eid};
    const auto abandoned = packets_for(several_packets);
    const auto fresh = packets_for(just_over_one_packet);
    BOOST_REQUIRE(a.push(abandoned[0]).has_value());
    BOOST_REQUIRE(a.push(abandoned[1]).has_value());
    BOOST_REQUIRE(a.push(fresh[0]).has_value());
    auto done = a.push(fresh[1]);
    BOOST_REQUIRE(done.has_value());
    BOOST_TEST((**done).bytes == pattern(just_over_one_packet));
}

BOOST_AUTO_TEST_CASE(assembler_keeps_tags_apart, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto route_b = helm_to_oar();
    route_b.tag = other_tag;
    auto route_c = helm_to_oar();
    route_c.tag_owner = false;  // same tag, other owner bit: a separate context
    auto enc_b = mctp::fragment(route_b, pattern(just_over_one_packet));
    auto enc_c = mctp::fragment(route_c, pattern(several_packets));
    BOOST_REQUIRE(enc_b.has_value());
    BOOST_REQUIRE(enc_c.has_value());
    const auto a_pkts = packets_for(several_packets);
    const auto b_pkts = decode_all(*enc_b);
    const auto c_pkts = decode_all(*enc_c);

    mctp::Assembler a{oar_eid};
    BOOST_REQUIRE(a.push(a_pkts[0]).has_value());
    BOOST_REQUIRE(a.push(b_pkts[0]).has_value());
    BOOST_REQUIRE(a.push(c_pkts[0]).has_value());
    BOOST_TEST(a.in_progress() == 3U);
    auto b_done = a.push(b_pkts[1]);
    BOOST_REQUIRE(b_done.has_value());
    BOOST_TEST((**b_done).route.tag == other_tag);
    for (std::size_t i = 1; i < a_pkts.size(); ++i) {
        BOOST_REQUIRE(a.push(a_pkts[i]).has_value());
        BOOST_REQUIRE(a.push(c_pkts[i]).has_value());
    }
    BOOST_TEST(a.in_progress() == 0U);
}

BOOST_AUTO_TEST_CASE(assembler_enforces_message_limit,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    mctp::Assembler a{oar_eid, tiny_limit};
    const auto packets = packets_for(several_packets);
    BOOST_REQUIRE(a.push(packets[0]).has_value());
    BOOST_TEST((a.push(packets[1]).error() == AssemblyError::message_too_long));
    BOOST_TEST(a.in_progress() == 0U);

    auto big_first = packets_for(several_packets, large_mtu);
    BOOST_TEST((a.push(big_first[0]).error() == AssemblyError::message_too_long));
}

BOOST_AUTO_TEST_CASE(assembler_rejects_empty_start,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto pkt = mctp::encode_packet(oar_addr, helm_addr, single_header(), {});
    BOOST_REQUIRE(pkt.has_value());
    auto p = mctp::decode_packet(*pkt);
    BOOST_REQUIRE(p.has_value());
    mctp::Assembler a{oar_eid};
    BOOST_TEST((a.push(*p).error() == AssemblyError::empty_message));
}

// ---- Vendor-defined messages ---------------------------------------------

BOOST_AUTO_TEST_CASE(vendor_round_trips_every_type,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    using enum mctp::VendorType;
    const auto body = bytes_of(body_byte, body_byte);
    for (const auto type : {function_inventory, prepare_function, clean_function, deliver_key,
                            drop_key, map_update, health}) {
        for (const bool response : {false, true}) {
            const mctp::VendorHeader h{.type = type, .response = response};
            auto msg = mctp::encode_vendor(h, body);
            BOOST_REQUIRE(msg.has_value());
            BOOST_TEST(msg->size() == mctp::vendor_header_size + body.size());
            auto decoded = mctp::decode_vendor(*msg);
            BOOST_REQUIRE(decoded.has_value());
            BOOST_TEST((decoded->header == h));
            BOOST_TEST(std::ranges::equal(decoded->body, body));
        }
    }
}

BOOST_AUTO_TEST_CASE(vendor_matches_hand_written_image,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto msg = mctp::encode_vendor({.type = mctp::VendorType::health, .response = true}, {});
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(*msg == bytes_of(vendor_pci_type, ak_vendor_hi, ak_vendor_lo, ak_version,
                                health_type, response_flag, zero));
}

BOOST_AUTO_TEST_CASE(vendor_rejects_malformed, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto msg = [](std::uint8_t type, std::uint8_t hi, std::uint8_t lo, std::uint8_t ver,
                        std::uint8_t vtype, std::uint8_t flags, std::uint8_t rsvd) {
        return bytes_of(type, hi, lo, ver, vtype, flags, rsvd);
    };
    BOOST_TEST((vendor_error({}) == VendorError::truncated));
    BOOST_TEST((vendor_error(bytes_of(vendor_pci_type, ak_vendor_hi)) == VendorError::truncated));
    BOOST_TEST((vendor_error(msg(control_type, ak_vendor_hi, ak_vendor_lo, ak_version, health_type,
                                 zero, zero)) == VendorError::not_vendor_pci));
    BOOST_TEST((vendor_error(msg(spdm_type, ak_vendor_hi, ak_vendor_lo, ak_version, health_type,
                                 zero, zero)) == VendorError::not_vendor_pci));
    BOOST_TEST((vendor_error(msg(vendor_pci_with_ic, ak_vendor_hi, ak_vendor_lo, ak_version,
                                 health_type, zero, zero)) == VendorError::integrity_check));
    BOOST_TEST((vendor_error(msg(vendor_pci_type, other_vendor_hi, other_vendor_lo, ak_version,
                                 health_type, zero, zero)) == VendorError::wrong_vendor));
    BOOST_TEST((vendor_error(msg(vendor_pci_type, ak_vendor_hi, ak_vendor_lo, unknown_version,
                                 health_type, zero, zero)) == VendorError::bad_version));
    BOOST_TEST((vendor_error(msg(vendor_pci_type, ak_vendor_hi, ak_vendor_lo, ak_version,
                                 unknown_vendor_type, zero, zero)) == VendorError::unknown_type));
    BOOST_TEST((vendor_error(msg(vendor_pci_type, ak_vendor_hi, ak_vendor_lo, ak_version, zero,
                                 zero, zero)) == VendorError::unknown_type));
    BOOST_TEST(
        (vendor_error(msg(vendor_pci_type, ak_vendor_hi, ak_vendor_lo, ak_version, health_type,
                          unknown_flag, zero)) == VendorError::reserved_not_zero));
    BOOST_TEST((vendor_error(msg(vendor_pci_type, ak_vendor_hi, ak_vendor_lo, ak_version,
                                 health_type, zero, body_byte)) == VendorError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(vendor_encode_bounds_the_body,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const mctp::VendorHeader h{};
    BOOST_TEST(mctp::encode_vendor(h, pattern(mctp::max_message_size - mctp::vendor_header_size))
                   .has_value());
    BOOST_TEST(
        (mctp::encode_vendor(h, pattern(mctp::max_message_size - mctp::vendor_header_size + 1))
             .error() == VendorError::body_too_long));
    BOOST_TEST(
        (mctp::encode_vendor({.type = static_cast<mctp::VendorType>(unknown_vendor_type)}, {})
             .error() == VendorError::unknown_type));
}

BOOST_AUTO_TEST_CASE(type_byte_splits_ic, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto tb = mctp::type_byte(bytes_of(vendor_pci_with_ic));
    BOOST_REQUIRE(tb.has_value());
    BOOST_TEST(tb->type == vendor_pci_type);
    BOOST_TEST(tb->integrity_check);
    auto spdm = mctp::type_byte(bytes_of(spdm_type));
    BOOST_REQUIRE(spdm.has_value());
    BOOST_TEST(spdm->type == std::to_underlying(mctp::MessageType::spdm));
    BOOST_TEST(!spdm->integrity_check);
    BOOST_TEST((mctp::type_byte({}).error() == VendorError::truncated));
}

BOOST_AUTO_TEST_CASE(vendor_message_survives_the_bus,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto body = pattern(several_packets);
    auto msg = mctp::encode_vendor({.type = mctp::VendorType::map_update}, body);
    BOOST_REQUIRE(msg.has_value());
    auto encoded = mctp::fragment(helm_to_oar(), *msg);
    BOOST_REQUIRE(encoded.has_value());

    mctp::Assembler a{oar_eid};
    std::optional<mctp::Message> got;
    for (const auto& pkt : decode_all(*encoded)) {
        auto r = a.push(pkt);
        BOOST_REQUIRE(r.has_value());
        if (r->has_value()) {
            got = std::move(**r);
        }
    }
    BOOST_REQUIRE(got.has_value());
    auto decoded = mctp::decode_vendor(got->bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST((decoded->header.type == mctp::VendorType::map_update));
    BOOST_TEST(!decoded->header.response);
    BOOST_TEST(std::ranges::equal(decoded->body, body));
}

BOOST_AUTO_TEST_CASE(error_names_are_distinct, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(std::string_view{mctp::to_string(PacketError::bad_pec)} == "bad_pec");
    BOOST_TEST(std::string_view{mctp::to_string(AssemblyError::out_of_sequence)} ==
               "out_of_sequence");
    BOOST_TEST(std::string_view{mctp::to_string(VendorError::wrong_vendor)} == "wrong_vendor");
}
