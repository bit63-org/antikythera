// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 7.1 (task 1): the
// host_power and decommission link records and the hardware_identity and
// decommission_progress reports. Layouts, rules both ways, strict
// decoding, signing, and the record and report plumbing that carries them.

#define BOOST_TEST_MODULE proto_host_lifecycle_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ed25519_test_support.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/host_lifecycle.hpp"
#include "proto/link.hpp"
#include "proto/report.hpp"
#include "proto/test_vectors.hpp"
#include "test_support.hpp"

namespace proto = ak::proto;
namespace vec = ak::proto::vectors;
using ak::test::from_hex;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t server = 7;
constexpr proto::KeyId key = 1;
constexpr std::size_t off_action = 0x18;
constexpr std::size_t off_force = 0x19;
constexpr std::size_t off_reserved = 0x1A;

auto power(proto::HostPowerAction action = proto::HostPowerAction::cycle, bool force = false)
    -> proto::HostPower {
    return {.key_id = key, .server_id = server, .seq = 0x40, .action = action, .force = force};
}

auto encoded(const proto::HostPower& p) -> std::vector<std::byte> {
    auto b = proto::encode_host_power(p);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto encoded(const proto::Decommission& d) -> std::vector<std::byte> {
    auto b = proto::encode_decommission(d);
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto power_error(std::span<const std::byte> b) -> DecodeError {
    auto p = proto::decode_host_power(b);
    BOOST_REQUIRE(!p.has_value());
    return p.error();
}

auto decommission_error(std::span<const std::byte> b) -> DecodeError {
    auto d = proto::decode_decommission(b);
    BOOST_REQUIRE(!d.has_value());
    return d.error();
}

auto ek(std::uint8_t v) -> proto::ImageDigest {
    proto::ImageDigest d{};
    d.fill(std::byte{v});
    return d;
}

auto identity() -> proto::HardwareIdentity {
    using proto::identity_text;
    return {.ek_hash = ek(0xE7),
            .board_serial = identity_text("AKB-0001"),
            .firmware = identity_text("helm 1.4.2"),
            .memory_bytes = 512ULL << 30,
            .cpu_count = 64,
            .flags =
                proto::identity_host_reported | proto::identity_secure_boot | proto::identity_iommu,
            .slots = {{.slot = 1,
                       .kind = proto::SlotKind::network,
                       .serial = identity_text("OAR-N-11"),
                       .firmware = identity_text("oar-net 2.0")},
                      {.slot = 2,
                       .kind = proto::SlotKind::storage,
                       .serial = identity_text("OAR-S-22"),
                       .firmware = identity_text("hold 3.1")}},
            .drives = {{.slot = 2, .size_bytes = 3840ULL << 30, .serial = identity_text("NVA")},
                       {.slot = 2, .size_bytes = 3840ULL << 30, .serial = identity_text("NVB")}}};
}

auto progress(proto::DecommissionStep step, std::optional<proto::SanitizeResult> result = {},
              std::uint8_t slot = 0, std::string_view serial = {}) -> proto::DecommissionProgress {
    return {
        .step = step, .result = result, .slot = slot, .drive_serial = proto::identity_text(serial)};
}

auto report_error(const proto::ReportBody& body) -> DecodeError {
    auto b = proto::encode_report({.server_id = server, .report_seq = 1, .body = body});
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto round_trip(const proto::ReportBody& body) -> proto::ReportBody {
    auto b = proto::encode_report({.server_id = server, .report_seq = 1, .body = body});
    BOOST_REQUIRE(b.has_value());
    auto r = proto::decode_report(*b);
    BOOST_REQUIRE(r.has_value());
    return r->body;
}

// The body of an encoded report, for corrupting.
auto report_bytes(const proto::ReportBody& body) -> std::vector<std::byte> {
    auto b = proto::encode_report({.server_id = server, .report_seq = 1, .body = body});
    BOOST_REQUIRE(b.has_value());
    return *b;
}

auto decoded_error(std::span<const std::byte> report) -> DecodeError {
    auto r = proto::decode_report(report);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

}  // namespace

BOOST_AUTO_TEST_SUITE(host_power, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_every_action) {
    using A = proto::HostPowerAction;
    for (auto a : {A::on, A::off, A::cycle, A::hold}) {
        for (bool force : {false, true}) {
            if (a == A::on && force) {
                continue;
            }
            const auto p = power(a, force);
            const auto b = encoded(p);
            BOOST_TEST(b.size() == proto::host_power_size);
            auto d = proto::decode_host_power(b);
            BOOST_REQUIRE(d.has_value());
            BOOST_TEST((*d == p));
        }
    }
}

BOOST_AUTO_TEST_CASE(layout_is_pinned) {
    auto p = power(proto::HostPowerAction::hold, true);
    p.signature.fill(std::byte{0x5A});
    const auto b = encoded(p);
    const auto head = from_hex(
        "414b485001000100"    // magic, version, key_id
        "0700000000000000"    // server_id
        "4000000000000000"    // seq
        "0401000000000000");  // action hold, force, reserved
    BOOST_TEST(std::ranges::equal(std::span{b}.first(0x20), head));
    BOOST_TEST(std::ranges::all_of(std::span{b}.subspan(0x20),
                                   [](std::byte x) { return x == std::byte{0x5A}; }));
    BOOST_TEST(static_cast<std::uint16_t>(proto::RecordType::host_power) == 21U);
    BOOST_TEST(static_cast<std::uint16_t>(proto::RecordType::decommission) == 22U);
}

BOOST_AUTO_TEST_CASE(encode_refuses_what_decode_refuses) {
    auto p = power();
    p.key_id = proto::no_key_id;
    BOOST_TEST((proto::encode_host_power(p).error() == DecodeError::bad_key_id));
    p = power();
    p.server_id = 0;
    BOOST_TEST((proto::encode_host_power(p).error() == DecodeError::bad_server_id));
    p = power();
    p.seq = 0;
    BOOST_TEST((proto::encode_host_power(p).error() == DecodeError::bad_id));
    p = power(proto::HostPowerAction::on, true);
    BOOST_TEST((proto::encode_host_power(p).error() == DecodeError::unknown_value));
    p = power();
    p.action = static_cast<proto::HostPowerAction>(5);
    BOOST_TEST((proto::encode_host_power(p).error() == DecodeError::unknown_value));
}

BOOST_AUTO_TEST_CASE(decode_is_strict) {
    const auto good = encoded(power());
    auto b = good;
    b[0] ^= std::byte{1};
    BOOST_TEST((power_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((power_error(b) == DecodeError::bad_version));
    b = good;
    b[off_reserved + 3] = std::byte{1};
    BOOST_TEST((power_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_force] = std::byte{2};
    BOOST_TEST((power_error(b) == DecodeError::unknown_value));
    b = good;
    b[off_action] = std::byte{0};
    BOOST_TEST((power_error(b) == DecodeError::unknown_value));
    b = good;
    b[off_action] = std::byte{1};  // on
    b[off_force] = std::byte{1};
    BOOST_TEST((power_error(b) == DecodeError::unknown_value));
    BOOST_TEST((power_error(std::span{good}.first(good.size() - 1)) == DecodeError::truncated));
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((power_error(b) == DecodeError::trailing_bytes));
    // A decommission frame is not a host_power frame, and the other way.
    const auto d = encoded(proto::Decommission{.key_id = key, .server_id = server, .seq = 0x40});
    BOOST_TEST((power_error(d) == DecodeError::bad_magic));
    BOOST_TEST((decommission_error(good) == DecodeError::bad_magic));
}

// Signed like the controller signs it, verified like helm verifies it.
BOOST_AUTO_TEST_CASE(signature_covers_every_field) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());

    auto frame = encoded(power());
    proto::set_host_lifecycle_signature(frame,
                                        signer.sign(proto::host_lifecycle_signed_bytes(frame)));
    const auto decoded = proto::decode_host_power(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(
        verifier
            ->verify(proto::host_lifecycle_signed_bytes(frame), decoded->signature, decoded->key_id)
            .has_value());
    // Turning a cycle into an off after signing breaks it.
    auto tampered = frame;
    tampered[off_action] = std::byte{2};
    const auto t = proto::decode_host_power(tampered);
    BOOST_REQUIRE(t.has_value());
    BOOST_TEST(
        !verifier->verify(proto::host_lifecycle_signed_bytes(tampered), t->signature, t->key_id)
             .has_value());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(decommission, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_and_is_strict) {
    proto::Decommission d{.key_id = key, .server_id = server, .seq = 0x41};
    d.signature.fill(std::byte{0x33});
    const auto good = encoded(d);
    BOOST_TEST(good.size() == proto::decommission_size);
    auto got = proto::decode_decommission(good);
    BOOST_REQUIRE(got.has_value());
    BOOST_TEST((*got == d));

    auto b = good;
    b[0x18 + 7] = std::byte{1};
    BOOST_TEST((decommission_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[4] = std::byte{0};
    BOOST_TEST((decommission_error(b) == DecodeError::bad_version));
    BOOST_TEST((decommission_error(std::span{good}.first(10)) == DecodeError::truncated));
    b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decommission_error(b) == DecodeError::trailing_bytes));

    auto bad = d;
    bad.seq = 0;
    BOOST_TEST((proto::encode_decommission(bad).error() == DecodeError::bad_id));
    bad = d;
    bad.server_id = 0;
    BOOST_TEST((proto::encode_decommission(bad).error() == DecodeError::bad_server_id));
    bad = d;
    bad.key_id = proto::no_key_id;
    BOOST_TEST((proto::encode_decommission(bad).error() == DecodeError::bad_key_id));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(hardware_identity, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips) {
    const auto h = identity();
    const auto body = round_trip(h);
    BOOST_TEST((proto::report_kind(body) == proto::ReportKind::hardware_identity));
    BOOST_TEST((std::get<proto::HardwareIdentity>(body) == h));
    // Unknown CPU and memory, no host report, no slots.
    proto::HardwareIdentity bare{};
    bare.ek_hash = ek(1);
    bare.board_serial = proto::identity_text("B");
    BOOST_TEST((std::get<proto::HardwareIdentity>(round_trip(bare)) == bare));
}

BOOST_AUTO_TEST_CASE(text_helpers) {
    const auto t = proto::identity_text("abc");
    BOOST_TEST(proto::identity_text_view(t) == "abc");
    const std::string longer(40, 'x');
    BOOST_TEST(proto::identity_text_view(proto::identity_text(longer)) == std::string(32, 'x'));
}

BOOST_AUTO_TEST_CASE(refuses_broken_bodies) {
    auto h = identity();
    h.ek_hash = {};
    BOOST_TEST((report_error(h) == DecodeError::bad_public_key));
    h = identity();
    h.board_serial = {};
    BOOST_TEST((report_error(h) == DecodeError::bad_text));
    h = identity();
    h.firmware = proto::identity_text("bad\x01");
    BOOST_TEST((report_error(h) == DecodeError::bad_text));
    h = identity();
    h.firmware[0] = '\0';
    h.firmware[1] = 'x';  // text after padding
    BOOST_TEST((report_error(h) == DecodeError::bad_text));
    h = identity();
    h.flags = proto::identity_secure_boot;  // without the host-reported bit
    BOOST_TEST((report_error(h) == DecodeError::unknown_value));
    h = identity();
    h.flags = 0x08;
    BOOST_TEST((report_error(h) == DecodeError::unknown_value));
    h = identity();
    h.slots[1].slot = 1;
    BOOST_TEST((report_error(h) == DecodeError::not_ascending));
    h = identity();
    h.slots[0].kind = static_cast<proto::SlotKind>(9);
    BOOST_TEST((report_error(h) == DecodeError::unknown_value));
    h = identity();
    h.slots[0].serial = {};
    BOOST_TEST((report_error(h) == DecodeError::bad_text));
    h = identity();
    h.drives[1].serial = proto::identity_text("NVA");
    BOOST_TEST((report_error(h) == DecodeError::not_ascending));
    h = identity();
    h.drives[0].size_bytes = 0;
    BOOST_TEST((report_error(h) == DecodeError::bad_capacity));
    h = identity();
    h.drives[0].slot = 1;  // a network slot
    BOOST_TEST((report_error(h) == DecodeError::bad_id));
    h = identity();
    h.drives[1].slot = 3;  // not listed
    BOOST_TEST((report_error(h) == DecodeError::bad_id));
    h = identity();
    h.slots.resize(proto::max_identity_slots + 1);
    BOOST_TEST((report_error(h) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(decode_is_strict) {
    const auto good = report_bytes(identity());
    constexpr std::size_t body = proto::report_header_size;
    const std::size_t first_slot = body + proto::hardware_identity_fixed_size;
    auto b = good;
    b[first_slot + 2] = std::byte{1};  // slot reserved
    BOOST_TEST((decoded_error(b) == DecodeError::reserved_not_zero));
    b = good;
    const std::size_t first_drive = first_slot + (2 * proto::identity_slot_size);
    b[first_drive + 1] = std::byte{1};  // drive reserved
    BOOST_TEST((decoded_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[body + 96 + 13] = std::byte{3};  // slot count 3: truncated
    BOOST_TEST((decoded_error(b) == DecodeError::truncated));
    b = good;
    b[body + 96 + 13] = std::byte{17};
    BOOST_TEST((decoded_error(b) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(decommission_progress, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(round_trips_every_step) {
    using S = proto::DecommissionStep;
    const auto keys = progress(S::keys_destroyed);
    const auto media = progress(S::media, proto::SanitizeResult::failed, 2, "NVB");
    const auto cleared = progress(S::identity_cleared);
    for (const auto& p : {keys, media, cleared}) {
        const auto body = round_trip(p);
        BOOST_TEST((proto::report_kind(body) == proto::ReportKind::decommission_progress));
        BOOST_TEST((std::get<proto::DecommissionProgress>(body) == p));
    }
}

BOOST_AUTO_TEST_CASE(refuses_broken_bodies) {
    using S = proto::DecommissionStep;
    // Media without a result or serial; a result or serial on another step.
    BOOST_TEST((report_error(progress(S::media)) == DecodeError::unknown_value));
    BOOST_TEST((report_error(progress(S::media, proto::SanitizeResult::sanitized_crypto)) ==
                DecodeError::unknown_value));
    BOOST_TEST((report_error(progress(S::keys_destroyed, proto::SanitizeResult::failed)) ==
                DecodeError::unknown_value));
    BOOST_TEST(
        (report_error(progress(S::identity_cleared, {}, 0, "X")) == DecodeError::unknown_value));
    BOOST_TEST((report_error(progress(S::keys_destroyed, {}, 1)) == DecodeError::unknown_value));
    BOOST_TEST((report_error(progress(static_cast<S>(4))) == DecodeError::unknown_value));

    const auto media = progress(S::media, proto::SanitizeResult::sanitized_block, 2, "NVB");
    const auto good = report_bytes(media);
    auto b = good;
    b[proto::report_header_size + 1] = std::byte{4};
    BOOST_TEST((decoded_error(b) == DecodeError::unknown_value));
    b = good;
    b[proto::report_header_size + 4] = std::byte{1};
    BOOST_TEST((decoded_error(b) == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(vectors, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(reports_reproduce) {
    auto b = proto::encode_report({.server_id = server, .report_seq = 3, .body = identity()});
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST((*b == from_hex(vec::report_hardware_identity19)));
    const auto media =
        progress(proto::DecommissionStep::media, proto::SanitizeResult::sanitized_crypto, 2, "NVA");
    b = proto::encode_report({.server_id = server, .report_seq = 4, .body = media});
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST((*b == from_hex(vec::report_decommission_progress20)));
    for (auto h : {vec::report_hardware_identity19, vec::report_decommission_progress20}) {
        BOOST_TEST(proto::decode_report(from_hex(h)).has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(records, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(link_frames_the_new_records) {
    for (auto t : {proto::RecordType::host_power, proto::RecordType::decommission}) {
        const auto payload = std::vector<std::byte>(8, std::byte{1});
        auto framed = proto::encode_record(t, payload);
        BOOST_REQUIRE(framed.has_value());
        proto::RecordDecoder d;
        d.feed(*framed);
        auto r = d.next();
        BOOST_REQUIRE(r.has_value());
        BOOST_REQUIRE(r->has_value());
        BOOST_TEST(((*r)->type == t));
    }
}

BOOST_AUTO_TEST_SUITE_END()
