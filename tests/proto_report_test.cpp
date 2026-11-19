// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/controller-interface/ Requirement 3 and design "Inventory and
// status reports": the report codec, its canonical form, its strict decode,
// and agreement of its enums with helm's.

#define BOOST_TEST_MODULE proto_report_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
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
    };
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
    static_assert(static_cast<int>(proto::ExitReason::vmm_failure) ==
                  static_cast<int>(mb::ExitReason::vmm_failure));
    static_assert(static_cast<int>(proto::FaultCode::resources_exhausted) ==
                  static_cast<int>(mb::FaultCode::resources_exhausted));
    static_assert(proto::max_outcome_payload == mb::max_response_payload);
    static_assert(proto::max_report_size < 128 * 1024);
}

BOOST_AUTO_TEST_CASE(every_kind_round_trips) {
    for (const auto& b : all_bodies()) {
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
    BOOST_TEST(b.size() == proto::report_header_size + proto::inventory_fixed_size + (2 * 16) +
                               (3 * 16) + (2 * 16) + (1 * 24) + (2 * 16));
}

BOOST_AUTO_TEST_CASE(every_short_length_is_truncated) {
    for (const auto& body_variant : all_bodies()) {
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
    b = good;
    b[4] = std::byte{2};
    BOOST_TEST((decode_error(b) == DecodeError::bad_version));
    b = good;
    set_le16(b, off_kind, 0);
    BOOST_TEST((decode_error(b) == DecodeError::unknown_value));
    set_le16(b, off_kind, 7);
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
    };
    for (const auto& c : cases) {
        auto inv = sample_inventory();
        c.mutate(inv);
        BOOST_TEST((encode_error(make_report(inv)) == c.want));
    }

    // The decoder enforces the same rules on bytes the encoder refused to
    // make: patch a good frame. Function 1 (free) gets an owner VM.
    auto b = encoded(make_report(sample_inventory()));
    const std::size_t fn1 = body + proto::inventory_fixed_size + (2 * 16) + 16;
    b[fn1 + 8] = std::byte{7};
    BOOST_TEST((decode_error(b) == DecodeError::bad_owner));
}

BOOST_AUTO_TEST_CASE(inventory_reserved_bytes_must_be_zero) {
    const auto good = encoded(make_report(sample_inventory()));
    const std::size_t lists = body + proto::inventory_fixed_size;
    const std::size_t fns = lists + (2 * 16);
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
                               .status = static_cast<proto::CommandStatus>(13),
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

BOOST_AUTO_TEST_CASE(errors_have_names) {
    for (auto e :
         {DecodeError::bad_report_seq, DecodeError::bad_boot_id, DecodeError::bad_id,
          DecodeError::unknown_value, DecodeError::bad_capacity, DecodeError::not_ascending,
          DecodeError::bad_owner, DecodeError::bad_record_type, DecodeError::record_too_large}) {
        BOOST_TEST(std::string_view{proto::to_string(e)} != "unknown");
    }
}

BOOST_AUTO_TEST_SUITE_END()
