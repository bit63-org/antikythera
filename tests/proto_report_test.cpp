// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 3 and design "Inventory and
// status reports": the report codec, its canonical form, its strict decode,
// and agreement of its enums with helm's. Also the network volume reports
// of .kiro/specs/block-volume-service/ design "Reports" (Requirement 13.4).

#define BOOST_TEST_MODULE proto_report_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "helm/device_pool.hpp"
#include "helm/mailbox.hpp"
#include "proto/report.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using proto::DecodeError;

namespace {

constexpr std::uint64_t sample_server = 0x0102'0304'0506'0708;
constexpr std::uint64_t sample_seq = 42;
constexpr std::uint64_t sample_boot = 0xB007'B007'B007'B007;
constexpr std::uint8_t ula_prefix = 0xFD;
constexpr std::size_t last = 15;

// Header offsets.
constexpr std::size_t off_kind = 0x06;
constexpr std::size_t off_server = 0x08;
constexpr std::size_t off_seq = 0x10;
constexpr std::size_t off_body_len = 0x18;
constexpr std::size_t off_reserved = 0x1C;
constexpr std::size_t body = proto::report_header_size;

auto vtep(std::uint8_t tag) -> proto::VtepAddress {
    proto::VtepAddress a{};
    a[0] = std::byte{ula_prefix};
    a[last] = std::byte{tag};
    return a;
}

auto tunnel_key(std::uint8_t fill) -> proto::TunnelPublicKey {
    proto::TunnelPublicKey k{};
    k.fill(std::byte{fill});
    return k;
}

auto sample_inventory() -> proto::Inventory {
    return proto::Inventory{
        .boot_id = sample_boot,
        .last_command_seq = 17,
        .cores_total = 64,
        .cores_free = 48,
        .health = proto::Health::ok,
        .pages_1g_total = 256,
        .pages_1g_free = 192,
        .vteps = {vtep(1), vtep(2)},
        // The second VTEP has no key pair yet.
        .tunnel_keys = {tunnel_key(0xA1), proto::TunnelPublicKey{}},
        .functions = {{.slot = 1,
                       .type = proto::FunctionType::nic_vf,
                       .function = 0,
                       .state = proto::FunctionState::assigned,
                       .owner_vm = 7},
                      {.slot = 1,
                       .type = proto::FunctionType::nic_vf,
                       .function = 1,
                       .state = proto::FunctionState::free,
                       .owner_vm = 0},
                      {.slot = 2,
                       .type = proto::FunctionType::blk_fn,
                       .function = 0,
                       .state = proto::FunctionState::releasing,
                       .owner_vm = 7}},
        .vms = {{.vm_id = 7, .vcpus = 4, .memory_mib = 8192},
                {.vm_id = 9, .vcpus = 2, .memory_mib = 4096}},
        .volumes = {{.volume_id = 100, .owner_vm = 7, .size_gib = 20}},
        .networks = {{.vni = 5, .map_version = 3}, {.vni = 6, .map_version = 0}},
    };
}

auto minimal_inventory() -> proto::Inventory {
    proto::Inventory inv;
    inv.boot_id = 1;
    return inv;
}

auto make_report(proto::ReportBody b) -> proto::Report {
    return {.server_id = sample_server, .report_seq = sample_seq, .body = std::move(b)};
}

auto encoded(const proto::Report& r) -> std::vector<std::byte> {
    auto bytes = proto::encode_report(r);
    BOOST_REQUIRE(bytes.has_value());
    return *bytes;
}

auto decode_error(const std::vector<std::byte>& b) -> DecodeError {
    auto r = proto::decode_report(b);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto encode_error(const proto::Report& r) -> DecodeError {
    auto b = proto::encode_report(r);
    BOOST_REQUIRE(!b.has_value());
    return b.error();
}

auto le64_at(const std::vector<std::byte>& b, std::size_t off) -> std::uint64_t {
    ak::wire::Reader r{std::span<const std::byte>{b}.subspan(off)};
    return r.le64().value_or(0);
}

auto set_le32(std::vector<std::byte>& b, std::size_t off, std::uint32_t v) -> void {
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(off)};
    BOOST_REQUIRE(w.write(v, ak::wire::Order::little).has_value());
}

auto set_le16(std::vector<std::byte>& b, std::size_t off, std::uint16_t v) -> void {
    ak::wire::SpanWriter w{std::span<std::byte>{b}.subspan(off)};
    BOOST_REQUIRE(w.write(v, ak::wire::Order::little).has_value());
}

auto usage_entry(std::uint8_t slot, std::uint64_t nic, std::uint64_t attachment)
    -> proto::GroupUsageEntry {
    return {.slot = slot,
            .nic_id = nic,
            .vni = 5,
            .detached = false,
            .attachment = attachment,
            .frames = 10,
            .bytes = 1000,
            .replicas_remote = 30,
            .replica_bytes_remote = 3000,
            .replicas_local = 10,
            .replica_bytes_local = 1000,
            .drop_policy = 1,
            .drop_rate = 2,
            .drop_fanout = 3};
}

auto sample_usage() -> proto::GroupUsage {
    auto detached = usage_entry(1, 0x22, 4);
    detached.detached = true;
    return {.entries = {usage_entry(1, 0x11, 3), detached, usage_entry(2, 0x11, 1)}};
}

auto replica_entry(std::uint8_t slot, std::uint64_t volume, std::uint32_t gen)
    -> proto::ReplicaStatusEntry {
    return {.volume_id = volume,
            .epoch = 9,
            .replica_gen = gen,
            .slot = slot,
            .role = proto::ReplicaRole::primary,
            .state = proto::ReplicaState::in_sync,
            .last_seq = 1000,
            .commit_seq = 998,
            .synced_bytes = 1 << 20,
            .total_bytes = 1 << 30,
            .hydrated_bytes = 1 << 30,
            .lease_remaining_ms = 3500,
            .checksum_errors = 2,
            .checksum_repairs = 2,
            .reads = 11,
            .writes = 12,
            .read_bytes = 13,
            .write_bytes = 14,
            .throttled_us = 15};
}

auto sample_replicas() -> proto::ReplicaStatus {
    auto joining = replica_entry(1, 0x200, 1);
    joining.role = proto::ReplicaRole::joining;
    joining.state = proto::ReplicaState::joining;
    joining.lease_remaining_ms = 0;
    return {.entries = {replica_entry(1, 0x100, 3), replica_entry(1, 0x100, 4), joining,
                        replica_entry(2, 0x100, 1)}};
}

auto manifest(std::uint8_t tag) -> proto::ManifestName {
    proto::ManifestName m{};
    m[0] = std::byte{tag};
    m[proto::manifest_name_size - 1] = std::byte{tag};
    return m;
}

auto sample_fault() -> proto::VolumeFault {
    return {.volume_id = 0x100,
            .epoch = 9,
            .suspect = 0x55,
            .kind = proto::VolumeFaultKind::member_timeout,
            .reporter = proto::FaultReporter::hold,
            .slot = 3};
}

auto sample_attachment() -> proto::AttachmentStatus {
    return {.attachment_id = 0xA77,
            .volume_id = 0x100,
            .generation = 2,
            .state = proto::AttachmentState::eject_requested,
            .slot = 4,
            .in_flight = 6};
}

auto sample_outcome() -> proto::OpOutcome {
    return {.volume_id = 0x100,
            .op_id = 0x0B,
            .epoch = 9,
            .detail = 1000,
            .kind = proto::VolumeOpKind::snapshot_prepare,
            .status = proto::OpStatus::ok,
            .slot = 3};
}

auto sample_progress() -> proto::SnapshotProgress {
    return {.volume_id = 0x100,
            .cut_id = 0xC07,
            .chunks_done = 1024,
            .chunks_total = 1024,
            .bytes_uploaded = 1 << 20,
            .state = proto::SnapshotState::completed,
            .slot = 3,
            .manifest_name = manifest(0xAB)};
}

auto volume_bodies() -> std::vector<proto::ReportBody> {
    return {
        sample_replicas(),
        proto::ReplicaStatus{},
        sample_fault(),
        proto::VolumeFault{.volume_id = 1,
                           .epoch = 1,
                           .suspect = 0,
                           .kind = proto::VolumeFaultKind::media_error,
                           .reporter = proto::FaultReporter::initiator,
                           .slot = 0},
        sample_attachment(),
        proto::DemotionConfirmed{.volume_id = 0x100, .epoch = 10, .last_seq = 1000, .slot = 3},
        sample_outcome(),
        proto::OpOutcome{.volume_id = 0x100,
                         .op_id = 0x0C,
                         .epoch = 9,
                         .detail = 0,
                         .kind = proto::VolumeOpKind::delete_replica,
                         .status = proto::OpStatus::unsupported,
                         .slot = 0},
        sample_progress(),
        proto::SnapshotProgress{.volume_id = 0x100,
                                .cut_id = 0xC07,
                                .chunks_done = 3,
                                .chunks_total = 10,
                                .bytes_uploaded = 0,
                                .state = proto::SnapshotState::uploading,
                                .slot = 3,
                                .manifest_name = {}},
    };
}

auto all_bodies() -> std::vector<proto::ReportBody> {
    return {
        sample_inventory(),
        minimal_inventory(),
        proto::CommandOutcome{.in_reply_to = 18,
                              .command = static_cast<std::uint16_t>(mb::Type::vm_status),
                              .status = proto::CommandStatus::ok,
                              .payload = ak::test::bytes_of(1, 2, 3)},
        proto::CommandOutcome{.in_reply_to = 19,
                              .command = 1,
                              .status = proto::CommandStatus::stale_sequence,
                              .payload = {}},
        proto::PoolStateChange{.slot = 2,
                               .type = proto::FunctionType::blk_fn,
                               .function = 3,
                               .from = proto::FunctionState::releasing,
                               .to = proto::FunctionState::cleaning,
                               .owner_vm = 7},
        proto::VmExitedReport{
            .vm_id = 7, .exit_status = 1, .reason = proto::ExitReason::guest_fault},
        proto::MapApplied{.vni = 5, .map_version = 4},
        proto::HostFaultReport{
            .code = proto::FaultCode::iommu_fault, .slot = 3, .detail = 0xDEAD'BEEF},
        sample_usage(),
        proto::GroupUsage{},
    };
}

auto every_body() -> std::vector<proto::ReportBody> {
    auto all = all_bodies();
    std::ranges::move(volume_bodies(), std::back_inserter(all));
    return all;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(reports, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(enums_match_helm_and_the_mailbox) {
    for (auto t : helm::all_function_types) {
        BOOST_TEST(static_cast<int>(t) == static_cast<int>(static_cast<proto::FunctionType>(t)));
    }
    static_assert(static_cast<int>(proto::FunctionType::gpu_vf) ==
                  static_cast<int>(helm::FunctionType::gpu_vf));
    static_assert(static_cast<int>(proto::FunctionState::free) ==
                  static_cast<int>(helm::FunctionState::free));
    static_assert(static_cast<int>(proto::FunctionState::assigned) ==
                  static_cast<int>(helm::FunctionState::assigned));
    static_assert(static_cast<int>(proto::FunctionState::releasing) ==
                  static_cast<int>(helm::FunctionState::releasing));
    static_assert(static_cast<int>(proto::FunctionState::cleaning) ==
                  static_cast<int>(helm::FunctionState::cleaning));
    static_assert(static_cast<int>(proto::FunctionState::faulted) ==
                  static_cast<int>(helm::FunctionState::faulted));
    static_assert(static_cast<int>(proto::CommandStatus::ok) == static_cast<int>(mb::Status::ok));
    static_assert(static_cast<int>(proto::CommandStatus::stale_sequence) ==
                  static_cast<int>(mb::Status::stale_sequence));
    static_assert(static_cast<int>(proto::CommandStatus::unsupported) ==
                  static_cast<int>(mb::Status::unsupported));
    static_assert(static_cast<int>(proto::CommandStatus::wrong_server) ==
                  static_cast<int>(mb::Status::wrong_server));
    static_assert(static_cast<int>(proto::ExitReason::vmm_failure) ==
                  static_cast<int>(mb::ExitReason::vmm_failure));
    static_assert(static_cast<int>(proto::FaultCode::resources_exhausted) ==
                  static_cast<int>(mb::FaultCode::resources_exhausted));
    static_assert(proto::max_outcome_payload == mb::max_response_payload);
    static_assert(proto::max_report_size < 128 * 1024);
}

BOOST_AUTO_TEST_CASE(every_kind_round_trips) {
    for (const auto& b : every_body()) {
        const auto r = make_report(b);
        const auto bytes = encoded(r);
        auto back = proto::decode_report(bytes);
        BOOST_REQUIRE(back.has_value());
        BOOST_TEST((*back == r));
        auto again = proto::encode_report(*back);
        BOOST_REQUIRE(again.has_value());
        BOOST_TEST((*again == bytes));
    }
}

BOOST_AUTO_TEST_CASE(header_layout_is_little_endian) {
    const auto b = encoded(make_report(proto::MapApplied{.vni = 5, .map_version = 4}));
    BOOST_TEST(b.size() == proto::report_header_size + proto::fixed_event_size);
    BOOST_TEST(std::to_integer<int>(b[0]) == 'A');
    BOOST_TEST(std::to_integer<int>(b[3]) == 'P');
    BOOST_TEST(std::to_integer<int>(b[off_kind]) ==
               static_cast<int>(proto::ReportKind::map_applied));
    BOOST_TEST(le64_at(b, off_server) == sample_server);
    BOOST_TEST(le64_at(b, off_seq) == sample_seq);
    BOOST_TEST(std::to_integer<int>(b[off_body_len]) == 16);
    BOOST_TEST(std::to_integer<int>(b[body]) == 5);
    BOOST_TEST(le64_at(b, body + 8) == 4U);
}

BOOST_AUTO_TEST_CASE(inventory_size_follows_its_counts) {
    const auto inv = sample_inventory();
    const auto b = encoded(make_report(inv));
    BOOST_TEST(proto::inventory_vtep_size == 48U);
    BOOST_TEST(b.size() == proto::report_header_size + proto::inventory_fixed_size + (2 * 48) +
                               (3 * 16) + (2 * 16) + (1 * 24) + (2 * 16));
}

BOOST_AUTO_TEST_CASE(every_short_length_is_truncated) {
    for (const auto& body_variant : every_body()) {
        const auto b = encoded(make_report(body_variant));
        for (std::size_t n = 0; n < b.size(); ++n) {
            auto r = proto::decode_report(std::span{b}.first(n));
            BOOST_REQUIRE(!r.has_value());
            BOOST_TEST((r.error() == DecodeError::truncated));
        }
    }
}

BOOST_AUTO_TEST_CASE(trailing_bytes_are_rejected) {
    auto b = encoded(make_report(sample_inventory()));
    b.push_back(std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(body_len_must_cover_the_body_exactly) {
    auto b = encoded(make_report(proto::MapApplied{.vni = 5, .map_version = 4}));
    set_le32(b, off_body_len, 15);
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
    set_le32(b, off_body_len, 17);
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
    // A fixed body of the wrong length, consistent with body_len.
    b.pop_back();
    set_le32(b, off_body_len, 15);
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(header_rules) {
    const auto good = encoded(make_report(proto::MapApplied{.vni = 5, .map_version = 4}));
    auto b = good;
    b[0] = std::byte{0};
    BOOST_TEST((decode_error(b) == DecodeError::bad_magic));
    // Format 1 (16-byte VTEP entries) and anything newer are refused.
    for (const auto v : {std::byte{1}, std::byte{3}}) {
        b = good;
        b[4] = v;
        BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    }
    b = good;
    set_le16(b, off_kind, 0);
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    set_le16(b, off_kind, 14);
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    b = good;
    b[off_reserved + 3] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    std::ranges::fill(std::span{b}.subspan(off_server, 8), std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_server_id));
    b = good;
    std::ranges::fill(std::span{b}.subspan(off_seq, 8), std::byte{0});
    BOOST_TEST((decode_error(b) == DecodeError::bad_report_seq));

    auto r = make_report(proto::MapApplied{.vni = 5, .map_version = 4});
    r.server_id = 0;
    BOOST_TEST((encode_error(r) == DecodeError::bad_server_id));
    r.server_id = sample_server;
    r.report_seq = 0;
    BOOST_TEST((encode_error(r) == DecodeError::bad_report_seq));
}

BOOST_AUTO_TEST_CASE(kind_and_body_must_agree) {
    // A pool_state body relabelled as host_fault: the same 16 bytes, but
    // the `to` state lands in host_fault's reserved bytes.
    auto b = encoded(make_report(proto::PoolStateChange{.slot = 1,
                                                        .type = proto::FunctionType::nic_vf,
                                                        .function = 0,
                                                        .from = proto::FunctionState::free,
                                                        .to = proto::FunctionState::assigned,
                                                        .owner_vm = 7}));
    set_le16(b, off_kind, static_cast<std::uint16_t>(proto::ReportKind::host_fault));
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(inventory_rules_are_enforced_both_ways) {
    struct Case {
        void (*mutate)(proto::Inventory&);
        DecodeError want;
    };
    const Case cases[] = {
        {[](proto::Inventory& i) { i.boot_id = 0; }, DecodeError::bad_boot_id},
        {[](proto::Inventory& i) { i.health = static_cast<proto::Health>(3); },
         DecodeError::unknown_value},
        {[](proto::Inventory& i) { i.cores_free = 65; }, DecodeError::bad_capacity},
        {[](proto::Inventory& i) { i.pages_1g_free = 257; }, DecodeError::bad_capacity},
        {[](proto::Inventory& i) { i.vteps[1] = i.vteps[0]; }, DecodeError::not_ascending},
        {[](proto::Inventory& i) { i.vteps[0] = proto::VtepAddress{}; }, DecodeError::bad_vtep},
        {[](proto::Inventory& i) { i.vteps[0][0] = std::byte{0xFF}; }, DecodeError::bad_vtep},
        {[](proto::Inventory& i) { std::swap(i.functions[0], i.functions[1]); },
         DecodeError::not_ascending},
        {[](proto::Inventory& i) { i.functions[1].owner_vm = 7; }, DecodeError::bad_owner},
        {[](proto::Inventory& i) { i.functions[0].owner_vm = 0; }, DecodeError::bad_owner},
        {[](proto::Inventory& i) { i.functions[0].type = static_cast<proto::FunctionType>(0); },
         DecodeError::unknown_value},
        {[](proto::Inventory& i) { i.functions[0].state = static_cast<proto::FunctionState>(5); },
         DecodeError::unknown_value},
        {[](proto::Inventory& i) { i.vms[0].vm_id = 0; }, DecodeError::bad_id},
        {[](proto::Inventory& i) { i.vms[1].vm_id = 7; }, DecodeError::not_ascending},
        {[](proto::Inventory& i) { i.volumes[0].owner_vm = 0; }, DecodeError::bad_id},
        {[](proto::Inventory& i) { i.volumes[0].size_gib = 0; }, DecodeError::bad_id},
        {[](proto::Inventory& i) { i.volumes.push_back(i.volumes[0]); },
         DecodeError::not_ascending},
        {[](proto::Inventory& i) { i.networks[0].vni = 0; }, DecodeError::bad_vni},
        {[](proto::Inventory& i) { i.networks[0].vni = 0x0100'0000; }, DecodeError::bad_vni},
        {[](proto::Inventory& i) { i.networks[1].vni = 5; }, DecodeError::not_ascending},
        {[](proto::Inventory& i) { i.vteps.resize(proto::max_vteps + 1, i.vteps[0]); },
         DecodeError::too_many_entries},
        {[](proto::Inventory& i) { i.tunnel_keys.pop_back(); }, DecodeError::bad_public_key},
        {[](proto::Inventory& i) { i.tunnel_keys.push_back(tunnel_key(1)); },
         DecodeError::bad_public_key},
    };
    for (const auto& c : cases) {
        auto inv = sample_inventory();
        c.mutate(inv);
        BOOST_TEST((encode_error(make_report(inv)) == c.want));
    }

    // The decoder enforces the same rules on bytes the encoder refused to
    // make: patch a good frame. Function 1 (free) gets an owner VM.
    auto b = encoded(make_report(sample_inventory()));
    const std::size_t fn1 =
        body + proto::inventory_fixed_size + (2 * proto::inventory_vtep_size) + 16;
    b[fn1 + 8] = std::byte{7};
    BOOST_TEST((decode_error(b) == DecodeError::bad_owner));
}

// Format 2: each VTEP entry is its address, then its tunnel public key.
BOOST_AUTO_TEST_CASE(inventory_carries_vtep_tunnel_keys) {
    const auto inv = sample_inventory();
    const auto b = encoded(make_report(inv));
    BOOST_TEST((b[4] == std::byte{proto::report_version}));
    BOOST_TEST(proto::report_version == 2U);
    const std::size_t entry0 = body + proto::inventory_fixed_size;
    const std::size_t entry1 = entry0 + proto::inventory_vtep_size;
    BOOST_TEST((b[entry0] == std::byte{ula_prefix}));
    BOOST_TEST((b[entry0 + 16] == std::byte{0xA1}));
    BOOST_TEST((b[entry0 + 47] == std::byte{0xA1}));
    BOOST_TEST((b[entry1 + last] == std::byte{2}));
    BOOST_TEST((b[entry1 + 16] == std::byte{0}));

    // No keys at all encodes as zeros and decodes as empty again, so the
    // encoding stays canonical.
    auto keyless = inv;
    keyless.tunnel_keys.clear();
    auto zeros = keyless;
    zeros.tunnel_keys = {proto::TunnelPublicKey{}, proto::TunnelPublicKey{}};
    const auto kb = encoded(make_report(keyless));
    BOOST_TEST(kb == encoded(make_report(zeros)));
    auto back = proto::decode_report(kb);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST(std::get<proto::Inventory>(back->body).tunnel_keys.empty());
    BOOST_TEST((back->body == proto::ReportBody{keyless}));
}

BOOST_AUTO_TEST_CASE(inventory_reserved_bytes_must_be_zero) {
    const auto good = encoded(make_report(sample_inventory()));
    const std::size_t lists = body + proto::inventory_fixed_size;
    const std::size_t fns = lists + (2 * proto::inventory_vtep_size);
    const std::size_t vms = fns + (3 * 16);
    const std::size_t vols = vms + (2 * 16);
    const std::size_t nets = vols + 24;
    for (const std::size_t off :
         {body + 0x16, body + 0x17, fns + 5, fns + 7, vms + 10, vols + 20, nets + 4, nets + 7}) {
        auto b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
}

BOOST_AUTO_TEST_CASE(hostile_counts_cost_nothing) {
    auto b = encoded(make_report(minimal_inventory()));
    // function_count = max + 1, with no bytes behind it.
    set_le16(b, body + 0x20, static_cast<std::uint16_t>(proto::max_functions + 1));
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    // A legal count the frame does not hold.
    set_le16(b, body + 0x20, 1);
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
}

BOOST_AUTO_TEST_CASE(event_rules) {
    using B = proto::ReportBody;
    const std::pair<B, DecodeError> cases[] = {
        {proto::CommandOutcome{.in_reply_to = 0, .command = 1, .payload = {}}, DecodeError::bad_id},
        {proto::CommandOutcome{.in_reply_to = 1, .command = 0, .payload = {}}, DecodeError::bad_id},
        {proto::CommandOutcome{.in_reply_to = 1,
                               .command = 1,
                               .status = static_cast<proto::CommandStatus>(14),
                               .payload = {}},
         DecodeError::unknown_value},
        {proto::CommandOutcome{.in_reply_to = 1,
                               .command = 1,
                               .payload = std::vector<std::byte>(proto::max_outcome_payload + 1)},
         DecodeError::too_many_entries},
        {proto::PoolStateChange{.to = static_cast<proto::FunctionState>(9)},
         DecodeError::unknown_value},
        {proto::VmExitedReport{.vm_id = 0}, DecodeError::bad_id},
        {proto::VmExitedReport{.vm_id = 1, .reason = static_cast<proto::ExitReason>(0)},
         DecodeError::unknown_value},
        {proto::MapApplied{.vni = 0, .map_version = 1}, DecodeError::bad_vni},
        {proto::MapApplied{.vni = 1, .map_version = 0}, DecodeError::bad_map_version},
        {proto::HostFaultReport{.code = static_cast<proto::FaultCode>(0)},
         DecodeError::unknown_value},
    };
    for (const auto& [b, want] : cases) {
        BOOST_TEST((encode_error(make_report(b)) == want));
    }

    auto b =
        encoded(make_report(proto::CommandOutcome{.in_reply_to = 1, .command = 1, .payload = {}}));
    b[body + 13] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = encoded(make_report(proto::VmExitedReport{.vm_id = 1}));
    b[body + 15] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = encoded(make_report(proto::HostFaultReport{}));
    b[body + 3] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(group_usage_layout) {
    const auto b = encoded(make_report(sample_usage()));
    constexpr std::size_t body = proto::report_header_size;
    BOOST_TEST(b.size() ==
               body + proto::group_usage_fixed_size + (3 * proto::group_usage_entry_size));
    BOOST_TEST(std::to_integer<int>(b[body]) == 3);  // count
    const std::size_t second = body + proto::group_usage_fixed_size + proto::group_usage_entry_size;
    BOOST_TEST(le64_at(b, second) == 0x22U);                 // nic_id
    BOOST_TEST(std::to_integer<int>(b[second + 12]) == 1);   // flags: detached
    BOOST_TEST(std::to_integer<int>(b[second + 13]) == 1);   // slot
    BOOST_TEST(le64_at(b, second + 16) == 4U);               // attachment
    BOOST_TEST(le64_at(b, second + 24 + (3 * 8)) == 3000U);  // replica_bytes_remote
    static_assert(proto::max_group_usage_size < proto::max_report_size);
}

BOOST_AUTO_TEST_CASE(group_usage_rules_are_enforced_both_ways) {
    const auto refused = [](proto::GroupUsage u, DecodeError want) {
        BOOST_TEST((encode_error(make_report(u)) == want));
    };
    auto u = sample_usage();
    u.entries[0].nic_id = 0;
    refused(u, DecodeError::bad_id);
    u = sample_usage();
    u.entries[0].attachment = 0;
    refused(u, DecodeError::bad_id);
    u = sample_usage();
    u.entries[0].vni = proto::max_vni + 1;
    refused(u, DecodeError::bad_vni);
    u = sample_usage();
    std::swap(u.entries[0], u.entries[1]);
    refused(u, DecodeError::not_ascending);
    u = sample_usage();
    u.entries.push_back(u.entries.back());  // duplicate key
    refused(u, DecodeError::not_ascending);
    u = {};
    for (std::uint64_t i = 1; i <= proto::max_group_usage_entries + 1; ++i) {
        u.entries.push_back(usage_entry(0, i, 1));
    }
    refused(u, DecodeError::too_many_entries);

    // Decode: unknown flag bits and reserved bytes, counts and lengths.
    constexpr std::size_t body = proto::report_header_size;
    constexpr std::size_t first = body + proto::group_usage_fixed_size;
    const auto good = encoded(make_report(sample_usage()));
    auto b = good;
    b[first + 12] = std::byte{0x02};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[first + 14] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    b[body + 2] = std::byte{1};
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
    b = good;
    set_le16(b, body, 0xFFFF);  // hostile count, checked before allocating
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    set_le16(b, body, 4);
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
    b = good;
    set_le16(b, body, 2);
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
}

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e : {DecodeError::bad_report_seq, DecodeError::bad_boot_id, DecodeError::bad_id,
                   DecodeError::unknown_value, DecodeError::bad_capacity,
                   DecodeError::not_ascending, DecodeError::bad_owner, DecodeError::bad_record_type,
                   DecodeError::record_too_large, DecodeError::server_id_mismatch,
                   DecodeError::bad_epoch, DecodeError::bad_source, DecodeError::bad_peers_version,
                   DecodeError::bad_public_key, DecodeError::duplicate_public_key}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_CASE(volume_kinds_are_numbered_by_the_spec) {
    // The variant order is the wire numbering: pin both.
    const std::pair<proto::ReportBody, std::uint16_t> cases[] = {
        {sample_replicas(), 8},    {sample_fault(), 9},
        {sample_attachment(), 10}, {proto::DemotionConfirmed{.volume_id = 1, .epoch = 1}, 11},
        {sample_outcome(), 12},    {sample_progress(), 13},
    };
    for (const auto& [b, kind] : cases) {
        BOOST_TEST(static_cast<std::uint16_t>(proto::report_kind(b)) == kind);
        const auto bytes = encoded(make_report(b));
        BOOST_TEST(std::to_integer<int>(bytes[off_kind]) == kind);
    }
}

BOOST_AUTO_TEST_CASE(volume_event_layouts) {
    auto b = encoded(make_report(sample_fault()));
    BOOST_TEST(b.size() == body + proto::volume_fault_size);
    BOOST_TEST(le64_at(b, body) == 0x100U);               // volume_id
    BOOST_TEST(le64_at(b, body + 8) == 9U);               // epoch
    BOOST_TEST(le64_at(b, body + 16) == 0x55U);           // suspect
    BOOST_TEST(std::to_integer<int>(b[body + 24]) == 1);  // member_timeout
    BOOST_TEST(std::to_integer<int>(b[body + 25]) == 1);  // hold
    BOOST_TEST(std::to_integer<int>(b[body + 26]) == 3);  // slot

    b = encoded(make_report(sample_attachment()));
    BOOST_TEST(b.size() == body + proto::attachment_status_size);
    BOOST_TEST(le64_at(b, body) == 0xA77U);
    BOOST_TEST(std::to_integer<int>(b[body + 16]) == 2);  // generation
    BOOST_TEST(std::to_integer<int>(b[body + 20]) == 2);  // eject_requested
    BOOST_TEST(std::to_integer<int>(b[body + 24]) == 6);  // in_flight

    b = encoded(make_report(sample_outcome()));
    BOOST_TEST(b.size() == body + proto::op_outcome_size);
    BOOST_TEST(le64_at(b, body + 24) == 1000U);           // detail
    BOOST_TEST(std::to_integer<int>(b[body + 32]) == 1);  // snapshot_prepare

    b = encoded(make_report(sample_progress()));
    BOOST_TEST(b.size() == body + proto::snapshot_progress_size);
    BOOST_TEST(std::to_integer<int>(b[body + 40]) == 3);     // completed
    BOOST_TEST(std::to_integer<int>(b[body + 48]) == 0xAB);  // manifest_name

    b = encoded(make_report(sample_replicas()));
    BOOST_TEST(b.size() ==
               body + proto::replica_status_fixed_size + (4 * proto::replica_status_entry_size));
    const std::size_t first = body + proto::replica_status_fixed_size;
    BOOST_TEST(std::to_integer<int>(b[body]) == 4);          // count
    BOOST_TEST(le64_at(b, first) == 0x100U);                 // volume_id
    BOOST_TEST(std::to_integer<int>(b[first + 0x10]) == 3);  // replica_gen
    BOOST_TEST(std::to_integer<int>(b[first + 0x15]) == 1);  // role primary
    BOOST_TEST(le64_at(b, first + 0x20) == 998U);            // commit_seq
    BOOST_TEST(le64_at(b, first + 0x78) == 15U);             // throttled_us
    static_assert(proto::max_replica_status_size < proto::max_report_size);
}

BOOST_AUTO_TEST_CASE(volume_event_rules_are_enforced_both_ways) {
    using B = proto::ReportBody;
    auto fault = sample_fault();
    auto no_suspect = fault;
    no_suspect.suspect = 0;
    auto primary_no_suspect = no_suspect;
    primary_no_suspect.kind = proto::VolumeFaultKind::primary_timeout;
    auto fault_epoch = fault;
    fault_epoch.epoch = 0;
    auto fault_kind = fault;
    fault_kind.kind = static_cast<proto::VolumeFaultKind>(7);
    auto fault_reporter = fault;
    fault_reporter.reporter = static_cast<proto::FaultReporter>(0);
    auto att_gen = sample_attachment();
    att_gen.generation = 0;
    auto att_state = sample_attachment();
    att_state.state = static_cast<proto::AttachmentState>(6);
    auto out_kind = sample_outcome();
    out_kind.kind = static_cast<proto::VolumeOpKind>(8);
    auto out_status = sample_outcome();
    out_status.status = static_cast<proto::OpStatus>(8);
    auto out_op = sample_outcome();
    out_op.op_id = 0;
    auto prog_chunks = sample_progress();
    prog_chunks.chunks_done = prog_chunks.chunks_total + 1;
    auto prog_unnamed = sample_progress();
    prog_unnamed.manifest_name = {};
    auto prog_named_early = sample_progress();
    prog_named_early.state = proto::SnapshotState::uploading;
    auto prog_cut = sample_progress();
    prog_cut.cut_id = 0;

    const std::pair<B, DecodeError> cases[] = {
        {no_suspect, DecodeError::bad_server_id},
        {primary_no_suspect, DecodeError::bad_server_id},
        {fault_epoch, DecodeError::bad_epoch},
        {fault_kind, DecodeError::unknown_value},
        {fault_reporter, DecodeError::unknown_value},
        {att_gen, DecodeError::bad_id},
        {att_state, DecodeError::unknown_value},
        {proto::DemotionConfirmed{.volume_id = 0, .epoch = 1}, DecodeError::bad_id},
        {proto::DemotionConfirmed{.volume_id = 1, .epoch = 0}, DecodeError::bad_epoch},
        {out_kind, DecodeError::unknown_value},
        {out_status, DecodeError::unknown_value},
        {out_op, DecodeError::bad_id},
        {prog_chunks, DecodeError::bad_capacity},
        {prog_unnamed, DecodeError::bad_source},
        {prog_named_early, DecodeError::bad_source},
        {prog_cut, DecodeError::bad_id},
    };
    for (const auto& [b, want] : cases) {
        BOOST_TEST((encode_error(make_report(b)) == want));
    }

    // Reserved bytes of each fixed body, and a body relabelled with the
    // wrong kind (same length, different layout).
    const std::pair<B, std::size_t> reserved[] = {
        {sample_fault(), 27},
        {sample_fault(), 31},
        {sample_attachment(), 22},
        {sample_attachment(), 28},
        {proto::DemotionConfirmed{.volume_id = 1, .epoch = 1}, 25},
        {sample_outcome(), 35},
        {sample_progress(), 42},
    };
    for (const auto& [rb, off] : reserved) {
        auto b = encoded(make_report(rb));
        b[body + off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
    auto b = encoded(make_report(sample_fault()));
    b[body + 24] = std::byte{9};  // unknown fault kind
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    b = encoded(make_report(sample_fault()));
    set_le16(b, off_kind, static_cast<std::uint16_t>(proto::ReportKind::demotion_confirmed));
    BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero));
}

BOOST_AUTO_TEST_CASE(replica_status_rules_are_enforced_both_ways) {
    struct Case {
        void (*mutate)(proto::ReplicaStatus&);
        DecodeError want;
    };
    const Case cases[] = {
        {[](proto::ReplicaStatus& s) { s.entries[0].volume_id = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaStatus& s) { s.entries[0].replica_gen = 0; }, DecodeError::bad_id},
        {[](proto::ReplicaStatus& s) { s.entries[0].epoch = 0; }, DecodeError::bad_epoch},
        {[](proto::ReplicaStatus& s) { s.entries[0].role = static_cast<proto::ReplicaRole>(5); },
         DecodeError::unknown_value},
        {[](proto::ReplicaStatus& s) { s.entries[0].state = static_cast<proto::ReplicaState>(0); },
         DecodeError::unknown_value},
        {[](proto::ReplicaStatus& s) { s.entries[0].commit_seq = s.entries[0].last_seq + 1; },
         DecodeError::bad_capacity},
        {[](proto::ReplicaStatus& s) { s.entries[0].synced_bytes = s.entries[0].total_bytes + 1; },
         DecodeError::bad_capacity},
        {[](proto::ReplicaStatus& s) {
             s.entries[0].hydrated_bytes = s.entries[0].total_bytes + 1;
         },
         DecodeError::bad_capacity},
        {[](proto::ReplicaStatus& s) { std::swap(s.entries[0], s.entries[1]); },
         DecodeError::not_ascending},
        {[](proto::ReplicaStatus& s) { s.entries[1] = s.entries[0]; }, DecodeError::not_ascending},
        {[](proto::ReplicaStatus& s) {
             s.entries.clear();
             for (std::uint64_t v = 1; v <= proto::max_replica_status_entries + 1; ++v) {
                 s.entries.push_back(replica_entry(0, v, 1));
             }
         },
         DecodeError::too_many_entries},
    };
    for (const auto& c : cases) {
        auto s = sample_replicas();
        c.mutate(s);
        BOOST_TEST((encode_error(make_report(s)) == c.want));
    }

    const std::size_t first = body + proto::replica_status_fixed_size;
    const auto good = encoded(make_report(sample_replicas()));
    for (const std::size_t off : {body + 2, body + 7, first + 0x17, first + 0x44, first + 0x47}) {
        auto b = good;
        b[off] = std::byte{1};
        BOOST_TEST((decode_error(b) == DecodeError::reserved_not_zero), "offset " << off);
    }
    auto b = good;
    set_le16(b, body, 0xFFFF);  // hostile count, checked before allocating
    BOOST_TEST((decode_error(b) == DecodeError::too_many_entries));
    b = good;
    set_le16(b, body, 5);
    BOOST_TEST((decode_error(b) == DecodeError::truncated));
    b = good;
    set_le16(b, body, 3);
    BOOST_TEST((decode_error(b) == DecodeError::trailing_bytes));
    // Decode re-checks the rules: commit_seq above last_seq.
    b = good;
    b[first + 0x27] = std::byte{0xFF};
    BOOST_TEST((decode_error(b) == DecodeError::bad_capacity));
}

BOOST_AUTO_TEST_SUITE_END()
