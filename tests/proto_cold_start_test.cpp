// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 8.3 (task 1): the standing_set and
// power_policy link records and the cold_start and boot_cache reports.
// Layouts, rules both ways, strict decoding, signing, and the record and
// report plumbing that carries them.

#define BOOST_TEST_MODULE proto_cold_start_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/link.hpp"
#include "proto/power_policy.hpp"
#include "proto/report.hpp"
#include "proto/standing_set.hpp"
#include "proto/test_vectors.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
namespace vec = ak::proto::vectors;
using ak::test::from_hex;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t server = 7;
constexpr proto::KeyId key = 1;
constexpr std::size_t off_count = 0x20;
constexpr std::size_t off_reserved = 0x22;
constexpr std::size_t off_instances = 0x28;
constexpr std::uint16_t layout_port = 7400;

auto filled(std::uint8_t v) -> proto::ImageDigest {
    proto::ImageDigest d{};
    d.fill(std::byte{v});
    return d;
}

auto member(std::uint64_t id, proto::MemberKind kind, std::uint8_t drive) -> proto::LayoutMember {
    proto::LayoutMember m{
        .server_id = id, .endpoint = {}, .port = layout_port, .kind = kind, .drive = drive};
    m.endpoint[0] = std::byte{0xFD};
    m.endpoint[15] = std::byte{static_cast<std::uint8_t>(id)};
    return m;
}

// A khold layout for this server's blk role: attachment 0xA1 generation 2.
auto layout_frame(std::uint64_t recipient = server) -> std::vector<std::byte> {
    using K = proto::MemberKind;
    const proto::VolumeLayout l{
        .key_id = key,
        .server_id = recipient,
        .volume_id = 0x200,
        .epoch = 3,
        .lineage_id = 0x2EE,
        .capacity_blocks = 1U << 20,
        .block_size = proto::block_size_4096,
        .stripe_unit = 1U << 20,
        .flags = 0,
        .commit_rule = proto::CommitRule::all_in_sync,
        .group_skew_pct = 10,
        .qos = {.iops = 3000, .mib_per_s = 125, .burst_iops = 16000, .burst_mib = 1000},
        .timings = {.member_deadline_ms = 1000, .election_min_ms = 1000, .resync_window_s = 900},
        .mirror = {},
        .groups = {{.group_id = 0x5001,
                    .members = {member(0x21, K::data, 0), member(0x22, K::data, 1),
                                member(0x23, K::witness, 0)}}},
        .gateways = {},
        .attachments = {{.attachment_id = 0xA1,
                         .server_id = server,
                         .generation = 2,
                         .mode = proto::AttachMode::rw}},
        .signature = {}};
    auto b = proto::encode_volume_layout(l);
    BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : proto::to_string(b.error())));
    return *b;
}

auto volume_key(std::uint64_t volume, std::uint64_t attachment) -> proto::VolumeKey {
    proto::VolumeKey k{
        .server_id = server, .volume_id = volume, .attachment_id = attachment, .generation = 2};
    k.hpke_enc.fill(std::byte{0x42});
    k.wrapped_key.fill(std::byte{0x17});
    return k;
}

auto create_vm_body(std::uint64_t vm) -> std::vector<std::byte> {
    return mb::encode_body(mb::CreateVm{
        .vm_id = vm, .vcpus = 2, .memory_mib = 4096, .boot_mode = mb::BootMode::volume});
}

auto secret(std::string name, std::uint8_t fill, std::size_t plain = 32) -> proto::InstanceSecret {
    proto::InstanceSecret s{.name = std::move(name), .hpke_enc = {}, .ciphertext = {}};
    s.hpke_enc.fill(std::byte{0x33});
    s.ciphertext.assign(plain + proto::aead_tag_size, std::byte{fill});
    return s;
}

auto instance(std::uint64_t vm) -> proto::StandingInstance {
    proto::StandingInstance in{};
    in.vm_id = vm;
    in.manifest_digest = filled(0xD1);
    in.commands = {
        {.type = proto::StandingCommandType::create_vm, .body = create_vm_body(vm)},
        {.type = proto::StandingCommandType::attach_volume, .body = std::vector<std::byte>(24)},
        {.type = proto::StandingCommandType::attach_device, .body = std::vector<std::byte>(40)},
    };
    in.volumes = {
        {.frame_type = proto::StandingVolumeFrame::replica_config,
         .frame = from_hex(vec::rcfg4),
         .key = volume_key(vec::rcfg4_volume_id, 0xA0)},
        {.frame_type = proto::StandingVolumeFrame::volume_layout,
         .frame = layout_frame(),
         .key = volume_key(0x200, 0xA1)},
    };
    in.nics = {{.nic_id = 0x10, .vni = 0xABCD}, {.nic_id = 0x11, .vni = 0xABCD}};
    in.secrets = {secret("hsm-share", 0x51), secret("raft.tls-key", 0x52)};
    return in;
}

auto sample() -> proto::StandingSet {
    return proto::StandingSet{.server_id = server,
                              .key_id = key,
                              .generation = 5,
                              .time_floor = 1'795'000'000,
                              .instances = {instance(0x1001), instance(0x1002)},
                              .signature = {}};
}

auto encoded(const proto::StandingSet& s) -> std::vector<std::byte> {
    auto b = proto::encode_standing_set(s);
    BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : proto::to_string(b.error())));
    return *b;
}

auto encode_error(const proto::StandingSet& s) -> DecodeError {
    auto r = proto::encode_standing_set(s);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto decode_error(std::span<const std::byte> b) -> DecodeError {
    auto r = proto::decode_standing_set(b);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto policy() -> proto::PowerPolicy {
    proto::PowerPolicy p{.server_id = server,
                         .key_id = key,
                         .policy_version = 4,
                         .time_floor = 1'795'000'000,
                         .tier = 1,
                         .slot = 3,
                         .tier_delay_s = 60,
                         .slot_interval_ms = 5000,
                         .max_jitter_ms = 2000,
                         .keep_image = filled(0xAB),
                         .signature = {}};
    return p;
}

auto policy_error(const proto::PowerPolicy& p) -> DecodeError {
    auto r = proto::encode_power_policy(p);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto report_round_trip(proto::ReportBody body) -> std::vector<std::byte> {
    const proto::Report r{.server_id = server, .report_seq = 9, .body = std::move(body)};
    auto b = proto::encode_report(r);
    BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : proto::to_string(b.error())));
    auto back = proto::decode_report(*b);
    BOOST_REQUIRE_MESSAGE(back.has_value(), (back ? "" : proto::to_string(back.error())));
    BOOST_TEST((*back == r));
    return *b;
}

auto report_error(proto::ReportBody body) -> DecodeError {
    auto b = proto::encode_report({.server_id = server, .report_seq = 9, .body = std::move(body)});
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto cold_start() -> proto::ColdStart {
    return proto::ColdStart{
        .power_return_time = 1'795'000'100,
        .time_floor = 1'795'000'000,
        .waited_ms = 63'500,
        .boot_source = proto::BootSource::lkg,
        .flags = proto::cold_start_rtc_below_floor,
        .store_faults = 1,
        .standing = {
            {.vm_id = 0x1001, .result = proto::StandingResult::started, .attempts = 1},
            {.vm_id = 0x1002, .result = proto::StandingResult::volume_refused, .attempts = 7}}};
}

auto boot_cache() -> proto::BootCache {
    return proto::BootCache{.lkg_image = filled(0xAB),
                            .previous_image = filled(0xAA),
                            .standing_generation = 5,
                            .policy_version = 4,
                            .store_free_bytes = 1U << 30,
                            .store_total_bytes = 2U << 30};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(standing_set, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(enum_values_pinned_to_the_mailbox_and_link) {
    using T = proto::StandingCommandType;
    BOOST_TEST(static_cast<std::uint16_t>(T::create_vm) ==
               static_cast<std::uint16_t>(mb::Type::create_vm));
    BOOST_TEST(static_cast<std::uint16_t>(T::attach_device) ==
               static_cast<std::uint16_t>(mb::Type::attach_device));
    BOOST_TEST(static_cast<std::uint16_t>(T::attach_volume) ==
               static_cast<std::uint16_t>(mb::Type::attach_volume));
    BOOST_TEST(proto::max_standing_command_body == mb::max_body);
    using F = proto::StandingVolumeFrame;
    BOOST_TEST(static_cast<std::uint16_t>(F::replica_config) ==
               static_cast<std::uint16_t>(proto::RecordType::replica_config));
    BOOST_TEST(static_cast<std::uint16_t>(F::volume_layout) ==
               static_cast<std::uint16_t>(proto::RecordType::volume_layout));
    BOOST_TEST(static_cast<std::uint16_t>(proto::RecordType::standing_set) == 23U);
    BOOST_TEST(static_cast<std::uint16_t>(proto::RecordType::power_policy) == 24U);
}

BOOST_AUTO_TEST_CASE(layout) {
    static_assert(proto::max_standing_set_size <= proto::max_record_payload);
    const auto s = sample();
    const auto b = encoded(s);
    const auto header = ak::test::bytes_of('A', 'K', 'S', 'S', 0x01, 0x00, 0x01, 0x00, 0x07, 0, 0,
                                           0, 0, 0, 0, 0, 0x05, 0, 0, 0, 0, 0, 0, 0, 0xC0, 0x86,
                                           0xFD, 0x6A, 0, 0, 0, 0, 0x02, 0x00, 0, 0, 0, 0, 0, 0);
    BOOST_TEST(std::ranges::equal(std::span{b}.first(proto::standing_set_header_size), header));
    // The first instance: vm_id, digest, counts.
    const auto in = std::span{b}.subspan(off_instances);
    BOOST_TEST(std::to_integer<int>(in[0]) == 0x01);
    BOOST_TEST(std::to_integer<int>(in[1]) == 0x10);
    BOOST_TEST(std::to_integer<int>(in[8]) == 0xD1);
    BOOST_TEST(std::to_integer<int>(in[0x28]) == 3);  // commands
    BOOST_TEST(std::to_integer<int>(in[0x29]) == 2);  // volumes
    BOOST_TEST(std::to_integer<int>(in[0x2A]) == 2);  // NICs
    BOOST_TEST(std::to_integer<int>(in[0x2B]) == 2);  // secrets
    // The first command: CREATE_VM with a 16-byte body.
    BOOST_TEST(std::to_integer<int>(in[0x30]) == 0x01);
    BOOST_TEST(std::to_integer<int>(in[0x32]) == 16);
    std::size_t want = proto::min_standing_set_size;
    for (const auto& i : s.instances) {
        want += proto::detail::standing_instance_size(i);
    }
    BOOST_TEST(b.size() == want);
}

BOOST_AUTO_TEST_CASE(round_trips_including_empty) {
    auto empty = sample();
    empty.instances.clear();  // unpins every instance
    for (auto s : {sample(), empty}) {
        s.signature[0] = std::byte{0x5A};
        const auto b = encoded(s);
        const auto back = proto::decode_standing_set(b);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == s));
        BOOST_TEST((encoded(*back) == b));
    }
    BOOST_TEST(encoded(empty).size() == proto::min_standing_set_size);
}

BOOST_AUTO_TEST_CASE(largest_secrets_and_size_cap) {
    auto s = sample();
    s.instances[0].secrets.clear();
    for (std::size_t i = 0; i < proto::max_instance_secrets; ++i) {
        s.instances[0].secrets.push_back(
            secret("s" + std::to_string(i), static_cast<std::uint8_t>(i), proto::max_secret_size));
    }
    BOOST_TEST(proto::decode_standing_set(encoded(s)).has_value());
    s.instances[0].secrets[0].ciphertext.push_back(std::byte{0});  // 4097 bytes of plaintext
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    // Sixteen instances of eight full secrets each pass every count limit
    // but not the frame's size cap.
    s = sample();
    s.instances.clear();
    for (std::uint64_t vm = 1; vm <= proto::max_standing_instances; ++vm) {
        proto::StandingInstance in{};
        in.vm_id = vm;
        in.manifest_digest = filled(1);
        in.commands = {{.type = proto::StandingCommandType::create_vm, .body = create_vm_body(vm)}};
        for (std::size_t i = 0; i < proto::max_instance_secrets; ++i) {
            in.secrets.push_back(secret("s" + std::to_string(i), 1, proto::max_secret_size));
        }
        s.instances.push_back(in);
    }
    BOOST_TEST((encode_error(s) == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(rules_both_ways) {
    auto s = sample();
    s.key_id = proto::no_key_id;
    BOOST_TEST((encode_error(s) == DecodeError::bad_key_id));
    s = sample();
    s.server_id = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_server_id));
    s = sample();
    s.generation = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_generation));
    s = sample();
    std::swap(s.instances[0], s.instances[1]);
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));
    s = sample();
    s.instances[1].vm_id = s.instances[0].vm_id;
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));
    s = sample();
    s.instances[0].vm_id = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_id));
    s = sample();
    s.instances[0].manifest_digest = {};
    BOOST_TEST((encode_error(s) == DecodeError::bad_id));

    // Commands: CREATE_VM first and only first, known types, mailbox-sized bodies.
    s = sample();
    s.instances[0].commands.clear();
    BOOST_TEST((encode_error(s) == DecodeError::too_many_entries));
    s = sample();
    std::swap(s.instances[0].commands[0], s.instances[0].commands[1]);
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    s.instances[0].commands[2].type = proto::StandingCommandType::create_vm;
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    s.instances[0].commands[1].type = static_cast<proto::StandingCommandType>(mb::Type::destroy_vm);
    BOOST_TEST((encode_error(s) == DecodeError::unknown_value));
    s = sample();
    s.instances[0].commands[1].body.resize(proto::max_standing_command_body + 1);
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));

    // Volumes: frames and keys for this server, ascending attachments.
    s = sample();
    std::swap(s.instances[0].volumes[0], s.instances[0].volumes[1]);
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));
    s = sample();
    s.instances[0].volumes[0].key.server_id = server + 1;
    BOOST_TEST((encode_error(s) == DecodeError::server_id_mismatch));
    s = sample();
    s.instances[0].volumes[1].frame = layout_frame(server + 1);
    BOOST_TEST((encode_error(s) == DecodeError::server_id_mismatch));
    s = sample();
    s.instances[0].volumes[0].key.generation = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_id));
    s = sample();
    s.instances[0].volumes[1].frame_type = proto::StandingVolumeFrame::replica_config;
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    s.instances[0].volumes[1].frame.back() ^= std::byte{1};  // signature bytes: still decodes
    BOOST_TEST(proto::encode_standing_set(s).has_value());
    s.instances[0].volumes[1].frame.push_back(std::byte{0});
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    s.instances[0].volumes[0].frame_type = static_cast<proto::StandingVolumeFrame>(9);
    BOOST_TEST((encode_error(s) == DecodeError::unknown_value));

    // NICs.
    s = sample();
    std::swap(s.instances[0].nics[0], s.instances[0].nics[1]);
    BOOST_TEST((encode_error(s) == DecodeError::nic_ids_not_ascending));
    s = sample();
    s.instances[0].nics[0].nic_id = 0;
    BOOST_TEST((encode_error(s) == DecodeError::bad_nic_id));
    s = sample();
    s.instances[0].nics[0].vni = proto::max_vni + 1;
    BOOST_TEST((encode_error(s) == DecodeError::bad_vni));

    // Secrets.
    for (std::string_view bad :
         std::array<std::string_view, 4>{"", "has space", "slash/no", "\xFF"}) {
        s = sample();
        s.instances[0].secrets[0].name = std::string{bad};
        BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    }
    s = sample();
    s.instances[0].secrets[0].name = std::string(proto::max_secret_name_size + 1, 'a');
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    s.instances[0].secrets[0].hpke_enc = {};
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    s.instances[0].secrets[0].ciphertext.resize(proto::aead_tag_size);  // empty plaintext
    BOOST_TEST((encode_error(s) == DecodeError::bad_standing_entry));
    s = sample();
    std::swap(s.instances[0].secrets[0], s.instances[0].secrets[1]);
    BOOST_TEST((encode_error(s) == DecodeError::not_ascending));
}

BOOST_AUTO_TEST_CASE(strict_decode) {
    const auto good = encoded(sample());
    BOOST_REQUIRE(proto::decode_standing_set(good).has_value());
    for (std::size_t n = 0; n < good.size(); n += 7) {
        BOOST_TEST((decode_error(std::span{good}.first(n)) == DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
    b = good;
    b[0] = std::byte{'X'};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    b = good;
    b[off_reserved] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_instances + 0x2C] = std::byte{1};  // an instance's reserved word
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[off_count] = std::byte{17};
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    b[off_instances + 0x28] = std::byte{17};  // command_count
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    b[off_instances + 0x32] = std::byte{161};  // CREATE_VM body_len
    BOOST_TEST((decode_error(b) == DecodeError::bad_standing_entry));
    std::vector<std::byte> huge(proto::max_standing_set_size + 1);
    BOOST_TEST((decode_error(huge) == DecodeError::trailing_bytes));
}

// Signed like the controller signs it, verified like hull and helm verify it.
BOOST_AUTO_TEST_CASE(signature_covers_every_entry) {
    const ak::test::TestSigner signer{ak::test::rfc_test1_secret};
    const std::array keys{ak::test::controller_key(key, ak::test::rfc_test1_public)};
    auto verifier = ak::hull::SignatureVerifier::create(keys);
    BOOST_REQUIRE(verifier.has_value());

    auto frame = encoded(sample());
    proto::set_standing_set_signature(frame, signer.sign(proto::standing_set_signed_bytes(frame)));
    const auto decoded = proto::decode_standing_set(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(
        verifier
            ->verify(proto::standing_set_signed_bytes(frame), decoded->signature, decoded->key_id)
            .has_value());
    // Changing a secret's ciphertext after signing breaks it.
    auto tampered = frame;
    tampered[frame.size() - proto::ed25519_signature_size - 1] ^= std::byte{1};
    const auto t = proto::decode_standing_set(tampered);
    BOOST_REQUIRE(t.has_value());
    BOOST_TEST(
        !verifier->verify(proto::standing_set_signed_bytes(tampered), t->signature, t->key_id)
             .has_value());
}

BOOST_AUTO_TEST_CASE(secret_aad_binds_server_instance_and_name) {
    const auto a = proto::instance_secret_aad(server, 0x1001, "hsm-share");
    BOOST_TEST(a.size() == 16U + 9U);
    BOOST_TEST((a == ak::test::bytes_of(7, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x10, 0, 0, 0, 0, 0, 0, 'h',
                                        's', 'm', '-', 's', 'h', 'a', 'r', 'e')));
    BOOST_TEST((a != proto::instance_secret_aad(server, 0x1002, "hsm-share")));
    BOOST_TEST((a != proto::instance_secret_aad(server + 1, 0x1001, "hsm-share")));
    BOOST_TEST(proto::instance_secret_info != proto::volume_key_info);
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_generation, DecodeError::bad_standing_entry,
                   DecodeError::bad_power_policy}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(power_policy, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(layout_and_round_trip) {
    static_assert(proto::power_policy_size == 0x90);
    auto p = policy();
    p.signature[63] = std::byte{0x77};
    auto b = proto::encode_power_policy(p);
    BOOST_REQUIRE(b.has_value());
    BOOST_REQUIRE_EQUAL(b->size(), proto::power_policy_size);
    const auto want = ak::test::bytes_of('A', 'K', 'P', 'P', 1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4,
                                         0, 0, 0, 0, 0, 0, 0, 0xC0, 0x86, 0xFD, 0x6A, 0, 0, 0, 0, 1,
                                         0, 3, 0, 60, 0, 0x88, 0x13, 0xD0, 0x07, 0, 0, 0, 0, 0, 0);
    BOOST_TEST(std::ranges::equal(std::span{*b}.first(0x30), want));
    BOOST_TEST(std::to_integer<int>((*b)[0x30]) == 0xAB);
    BOOST_TEST(proto::power_policy_signed_bytes(*b).size() == 0x50U);
    auto back = proto::decode_power_policy(*b);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == p));
}

BOOST_AUTO_TEST_CASE(defaults_and_wait) {
    const auto d = proto::default_power_policy(server);
    BOOST_TEST(d.tier == 3);
    BOOST_TEST(d.slot == 0);
    BOOST_TEST(proto::power_wait_ms(d) == 300'000U);
    BOOST_TEST(d.max_jitter_ms == 2000);
    BOOST_TEST(proto::power_wait_ms(policy()) == 60'000U + 15'000U);
}

BOOST_AUTO_TEST_CASE(rules_both_ways) {
    auto p = policy();
    p.key_id = proto::no_key_id;
    BOOST_TEST((policy_error(p) == DecodeError::bad_key_id));
    p = policy();
    p.server_id = 0;
    BOOST_TEST((policy_error(p) == DecodeError::bad_server_id));
    p = policy();
    p.policy_version = 0;
    BOOST_TEST((policy_error(p) == DecodeError::bad_generation));
    p = policy();
    p.tier = 4;
    BOOST_TEST((policy_error(p) == DecodeError::bad_power_policy));
    p = policy();
    p.tier_delay_s = proto::max_tier_delay_s + 1;
    BOOST_TEST((policy_error(p) == DecodeError::bad_power_policy));
    p = policy();
    p.slot_interval_ms = proto::max_slot_interval_ms + 1;
    BOOST_TEST((policy_error(p) == DecodeError::bad_power_policy));
    p = policy();
    p.max_jitter_ms = proto::max_power_jitter_ms + 1;
    BOOST_TEST((policy_error(p) == DecodeError::bad_power_policy));
    // The hold may be at most an hour before jitter.
    p = policy();
    p.tier_delay_s = proto::max_tier_delay_s;
    p.slot_interval_ms = 30'000;
    p.slot = 60;
    BOOST_TEST(proto::encode_power_policy(p).has_value());
    p.slot = 61;
    BOOST_TEST((policy_error(p) == DecodeError::bad_power_policy));
}

BOOST_AUTO_TEST_CASE(strict_decode) {
    const auto good = *proto::encode_power_policy(policy());
    for (std::size_t n = 0; n < good.size(); ++n) {
        BOOST_TEST((proto::decode_power_policy(std::span{good}.first(n)).error() ==
                    DecodeError::truncated));
    }
    auto b = good;
    b.push_back(std::byte{0});
    BOOST_TEST((proto::decode_power_policy(b).error() == DecodeError::trailing_bytes));
    b = good;
    b[3] = std::byte{0};
    BOOST_TEST((proto::decode_power_policy(b).error() == DecodeError::bad_magic));
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((proto::decode_power_policy(b).error() == DecodeError::bad_version));
    for (std::size_t off : {std::size_t{0x21}, std::size_t{0x2A}, std::size_t{0x2F}}) {
        b = good;
        b[off] = std::byte{1};
        BOOST_TEST((proto::decode_power_policy(b).error() == DecodeError::reserved_not_zero));
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(cold_start_reports, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(kinds_map_to_their_numbers) {
    BOOST_TEST(static_cast<std::uint16_t>(proto::report_kind(cold_start())) == 27U);
    BOOST_TEST(static_cast<std::uint16_t>(proto::report_kind(boot_cache())) == 28U);
    BOOST_TEST(static_cast<std::uint16_t>(proto::report_kind(proto::ConversionProgress{})) == 20U);
}

BOOST_AUTO_TEST_CASE(cold_start_layout_and_rules) {
    const auto b = report_round_trip(cold_start());
    constexpr std::size_t body = proto::report_header_size;
    BOOST_TEST(b.size() ==
               body + proto::cold_start_fixed_size + (2 * proto::cold_start_entry_size));
    BOOST_TEST(std::to_integer<int>(b[6]) == 27);
    BOOST_TEST(std::to_integer<int>(b[body + 0x14]) == 1);            // boot source lkg
    BOOST_TEST(std::to_integer<int>(b[body + 0x15]) == 2);            // RTC below floor
    BOOST_TEST(std::to_integer<int>(b[body + 0x16]) == 2);            // count
    BOOST_TEST(std::to_integer<int>(b[body + 0x20 + 16 + 8]) == 3);   // volume_refused
    BOOST_TEST(std::to_integer<int>(b[body + 0x20 + 16 + 10]) == 7);  // attempts

    auto c = cold_start();
    c.boot_source = static_cast<proto::BootSource>(4);
    BOOST_TEST((report_error(c) == DecodeError::unknown_value));
    c = cold_start();
    c.flags = 0x04;
    BOOST_TEST((report_error(c) == DecodeError::unknown_value));
    c = cold_start();
    c.standing[1].vm_id = c.standing[0].vm_id;
    BOOST_TEST((report_error(c) == DecodeError::not_ascending));
    c = cold_start();
    c.standing[0].vm_id = 0;
    BOOST_TEST((report_error(c) == DecodeError::bad_id));
    c = cold_start();
    c.standing[0].result = static_cast<proto::StandingResult>(0);
    BOOST_TEST((report_error(c) == DecodeError::unknown_value));
    c = cold_start();
    c.standing.resize(proto::max_standing_instances + 1);
    BOOST_TEST((report_error(c) == DecodeError::too_many_entries));
    c = cold_start();
    c.standing.clear();  // a server with no standing instances
    report_round_trip(c);

    // Strict decode of the body.
    for (std::size_t off : {body + 0x1C, body + 0x20 + 9, body + 0x20 + 12, body + 0x20 + 15}) {
        auto bad = b;
        bad[off] = std::byte{1};
        BOOST_TEST((proto::decode_report(bad).error() == DecodeError::reserved_not_zero));
    }
    auto bad = b;
    bad[body + 0x16] = std::byte{3};  // count larger than the body
    BOOST_TEST((proto::decode_report(bad).error() == DecodeError::truncated));
    bad[body + 0x16] = std::byte{1};
    BOOST_TEST((proto::decode_report(bad).error() == DecodeError::trailing_bytes));
    bad[body + 0x16] = std::byte{17};
    BOOST_TEST((proto::decode_report(bad).error() == DecodeError::too_many_entries));
}

BOOST_AUTO_TEST_CASE(boot_cache_layout_and_rules) {
    const auto b = report_round_trip(boot_cache());
    constexpr std::size_t body = proto::report_header_size;
    BOOST_TEST(b.size() == body + proto::boot_cache_size);
    BOOST_TEST(std::to_integer<int>(b[6]) == 28);
    BOOST_TEST(std::to_integer<int>(b[body]) == 0xAB);
    BOOST_TEST(std::to_integer<int>(b[body + 32]) == 0xAA);
    BOOST_TEST(std::to_integer<int>(b[body + 64]) == 5);
    BOOST_TEST(std::to_integer<int>(b[body + 72]) == 4);

    auto c = boot_cache();
    c.lkg_image = {};
    BOOST_TEST((report_error(c) == DecodeError::bad_id));
    c.previous_image = {};
    report_round_trip(c);  // a server with no LKG yet
    c = boot_cache();
    c.store_free_bytes = c.store_total_bytes + 1;
    BOOST_TEST((report_error(c) == DecodeError::bad_capacity));

    auto bad = b;
    bad.pop_back();
    bad[0x18] = std::byte{static_cast<std::uint8_t>(proto::boot_cache_size - 1)};
    BOOST_TEST((proto::decode_report(bad).error() == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(report_vectors_reproduce) {
    const proto::ColdStart c{
        .power_return_time = 1'795'000'100,
        .time_floor = 1'795'000'000,
        .waited_ms = 1500,
        .boot_source = proto::BootSource::lkg,
        .flags = 0,
        .store_faults = 0,
        .standing = {{.vm_id = 0x1001, .result = proto::StandingResult::started, .attempts = 1}}};
    auto b = proto::encode_report({.server_id = server, .report_seq = 1, .body = c});
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST((*b == from_hex(vec::report_cold_start15)));
    proto::BootCache bc{};
    bc.lkg_image.fill(std::byte{0xAB});
    bc.standing_generation = 5;
    bc.policy_version = 4;
    bc.store_free_bytes = 1ULL << 30;
    bc.store_total_bytes = 2ULL << 30;
    b = proto::encode_report({.server_id = server, .report_seq = 2, .body = bc});
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST((*b == from_hex(vec::report_boot_cache16)));
    for (auto h : {vec::report_cold_start15, vec::report_boot_cache16}) {
        BOOST_TEST(proto::decode_report(from_hex(h)).has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(records, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(link_frames_the_new_records) {
    for (auto t : {proto::RecordType::standing_set, proto::RecordType::power_policy}) {
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
    // 19-20 and 26-29 belong to no record yet, and stay unknown here.
    for (int t : {19, 20, 26, 29}) {
        BOOST_TEST(!proto::encode_record(static_cast<proto::RecordType>(t), {}).has_value());
    }
}

BOOST_AUTO_TEST_SUITE_END()
