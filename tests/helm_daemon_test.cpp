// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// helm's daemon wiring (HelmDaemon): slots attach over real OarLinks when the
// PowerSequencer brings them up, controller traffic and hull's slots reach
// the CommandRouter on the loop thread, mapping updates reach net roles,
// sidebands are retried and reopened, and the whole stack serves harbor's
// test controller end to end over mTLS.

#define BOOST_TEST_MODULE helm_daemon_test
#include <boost/test/unit_test.hpp>

#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include "ed25519_test_support.hpp"
#include "harbor/test_controller.hpp"
#include "helm/audit_log.hpp"
#include "helm/controller_link.hpp"
#include "helm/helm_daemon.hpp"
#include "helm/key_store.hpp"
#include "helm/mailbox.hpp"
#include "helm/oar_link.hpp"
#include "helm/secure_element.hpp"
#include "helm/sideband_binding.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/test_vectors.hpp"
#include "test_support.hpp"
#include "tls_test_support.hpp"

namespace harbor = ak::harbor;
namespace helm = ak::helm;
namespace hull = ak::hull;
namespace mb = ak::helm::mailbox;
namespace oar = ak::helm::oar;
namespace proto = ak::proto;
namespace tls = ak::tls;
namespace vectors = ak::proto::vectors;

using ak::test::unit_timeout_seconds;
using helm::FunctionState;
using helm::FunctionType;
using helm::SlotNumber;
using namespace std::chrono_literals;

namespace {

constexpr unsigned e2e_timeout_seconds = 60;
constexpr SlotNumber net_slot = 1;
constexpr SlotNumber blk_slot = 2;
constexpr SlotNumber hold_slot = 3;
constexpr std::uint16_t net_functions = 2;
constexpr std::uint16_t blk_functions = 1;
constexpr std::uint64_t server = 7;
constexpr std::uint64_t boot_id = 0xB007;
constexpr helm::VmId vm_one = 0x1001;
constexpr std::uint16_t vcpus = 2;
constexpr std::uint32_t memory_mib = 1024;
constexpr std::uint32_t vni = 5;
constexpr std::uint64_t nic_id = 0x10;
constexpr std::uint64_t map_version = 3;
constexpr std::uint8_t vtep_last = 0x01;
constexpr std::uint8_t vtep_first = 0xFD;
constexpr std::uint8_t sig_fill = 0x5A;
constexpr std::size_t frame_size = 300;
constexpr auto serve_poll = 10ms;
constexpr auto sideband_timeout = 2s;
constexpr auto link_timeout = 2s;
constexpr auto short_link_timeout = 50ms;
constexpr auto settle = 1ms;
const std::string loopback = "127.0.0.1";

struct IgnoreSigpipe {
    IgnoreSigpipe() { (void)std::signal(SIGPIPE, SIG_IGN); }
};
const IgnoreSigpipe ignore_sigpipe;

auto helm_side(SlotNumber slot) -> helm::LinkAddress {
    return {.local_addr = 0x08,
            .peer_addr = static_cast<std::uint8_t>(0x10 + slot),
            .local_eid = 0x08,
            .peer_eid = static_cast<std::uint8_t>(0x10 + slot)};
}

// ---- a data-plane role on its own thread --------------------------------------

class Role final : public helm::OarHandler {
public:
    Role(oar::Role role, FunctionType type, std::uint16_t count) {
        for (std::uint16_t fn = 0; fn < count; ++fn) {
            _inventory.functions.push_back({.fn = fn, .type = type});
        }
        _inventory.role = role;
        if (role == oar::Role::net) {
            _inventory.vtep.front() = std::byte{vtep_first};
            _inventory.vtep.back() = std::byte{vtep_last};
        }
    }

    std::atomic<oar::Status> map_status{oar::Status::ok};

    [[nodiscard]] auto cleaned() const -> std::size_t {
        const std::scoped_lock lock{_mutex};
        return _cleaned;
    }
    [[nodiscard]] auto prepared() const -> std::vector<oar::PrepareFunction> {
        const std::scoped_lock lock{_mutex};
        return _prepared;
    }
    [[nodiscard]] auto frames() const -> std::vector<std::vector<std::byte>> {
        const std::scoped_lock lock{_mutex};
        return _frames;
    }

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return _inventory;
    }
    auto prepare_function(const oar::PrepareFunction& r) -> oar::Status override {
        const std::scoped_lock lock{_mutex};
        _prepared.push_back(r);
        return oar::Status::ok;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        const std::scoped_lock lock{_mutex};
        ++_cleaned;
        return oar::Status::ok;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::ok;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override { return oar::Status::ok; }
    auto map_update(std::span<const std::byte> frame) -> oar::Status override {
        const std::scoped_lock lock{_mutex};
        _frames.emplace_back(frame.begin(), frame.end());
        return map_status.load();
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }

    // A hold role's side.
    std::atomic<oar::Status> config_status{oar::Status::ok};
    [[nodiscard]] auto configs() const -> std::vector<std::vector<std::byte>> {
        const std::scoped_lock lock{_mutex};
        return _configs;
    }
    [[nodiscard]] auto ops() const -> std::vector<std::vector<std::byte>> {
        const std::scoped_lock lock{_mutex};
        return _ops;
    }
    [[nodiscard]] auto grants() const -> std::vector<oar::LeaseGrant> {
        const std::scoped_lock lock{_mutex};
        return _grants;
    }
    auto queue_report(std::uint64_t seq, std::vector<std::byte> report) -> bool {
        const std::scoped_lock lock{_mutex};
        return _reports.push(seq, std::move(report));
    }
    auto replica_config(std::span<const std::byte> frame) -> oar::Status override {
        const std::scoped_lock lock{_mutex};
        _configs.emplace_back(frame.begin(), frame.end());
        return config_status.load();
    }
    auto volume_op(std::span<const std::byte> frame) -> oar::Status override {
        const std::scoped_lock lock{_mutex};
        _ops.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
    auto lease_grant(const oar::LeaseGrant& g) -> oar::Status override {
        const std::scoped_lock lock{_mutex};
        _grants.push_back(g);
        return oar::Status::ok;
    }
    auto hold_reports(const oar::ReportRequest& r)
        -> std::expected<oar::ReportChunk, oar::Status> override {
        const std::scoped_lock lock{_mutex};
        return _reports.serve(r);  // the chunk outlives the lock: one helm, one request at a time
    }

private:
    oar::Inventory _inventory;
    mutable std::mutex _mutex;
    std::vector<std::vector<std::byte>> _configs;
    std::vector<std::vector<std::byte>> _ops;
    std::vector<oar::LeaseGrant> _grants;
    oar::ReportQueue _reports;
    std::size_t _cleaned{0};
    std::vector<oar::PrepareFunction> _prepared;
    std::vector<std::vector<std::byte>> _frames;
};

// One slot's board: every connect() opens a fresh in-process sideband and
// serves the role's end on a thread until helm closes its end.
class Board {
public:
    Board(SlotNumber slot, oar::Role kind, FunctionType type, std::uint16_t count)
        : role{kind, type, count}, _slot{slot} {}

    Role role;
    std::atomic<int> connects{0};
    std::atomic<bool> refuse{false};  // connect fails while set

    auto connect() -> std::expected<std::unique_ptr<helm::Binding>, helm::BindingError> {
        ++connects;
        if (refuse) {
            return std::unexpected(helm::BindingError::disconnected);
        }
        auto [helm_end, role_end] = helm::InProcessBinding::make_pair();
        auto session = std::make_unique<Session>();
        session->binding = std::move(role_end);
        session->endpoint = std::make_unique<helm::OarEndpoint>(
            *session->binding, helm::LinkConfig{.address = helm_side(_slot).reversed(),
                                                .mtu = ak::helm::mctp::baseline_mtu,
                                                .timeout = sideband_timeout});
        session->thread =
            std::jthread{[ep = session->endpoint.get(), this](const std::stop_token& stop) {
                while (!stop.stop_requested()) {
                    auto r = ep->serve_one(role, serve_poll);
                    if (!r && r.error() != helm::BindingError::timed_out) {
                        return;
                    }
                }
            }};
        const std::scoped_lock lock{_mutex};
        _sessions.push_back(std::move(session));
        return std::unique_ptr<helm::Binding>{std::move(helm_end)};
    }

private:
    struct Session {
        std::unique_ptr<helm::Binding> binding;
        std::unique_ptr<helm::OarEndpoint> endpoint;
        std::jthread thread;  // declared last: stops before the endpoint goes
    };
    SlotNumber _slot;
    std::mutex _mutex;
    std::vector<std::unique_ptr<Session>> _sessions;
};

// Slots come up as soon as they are powered, unless dead (never) or
// dropped (link lost until the next power-off).
struct FakeBackplane final : helm::Backplane {
    std::set<SlotNumber> powered;
    std::set<SlotNumber> dead;
    std::set<SlotNumber> dropped;
    bool host{false};

    auto set_slot_power(SlotNumber slot, bool on) -> bool override {
        if (on) {
            powered.insert(slot);
        } else {
            powered.erase(slot);
            dropped.erase(slot);
        }
        return true;
    }
    auto link_ready(SlotNumber slot) -> bool override {
        return powered.contains(slot) && !dead.contains(slot) && !dropped.contains(slot);
    }
    auto set_host_power(bool on) -> bool override {
        host = on;
        return true;
    }
};

struct FakeHost final : helm::HostPort {
    std::vector<mb::Slot> posted;
    auto post_command(const mb::Slot& slot) -> bool override {
        posted.push_back(slot);
        return true;
    }
};

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-daemon-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

auto make_se() -> helm::SoftwareSecureElement {
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se);
    return std::move(*se);
}

auto make_audit(const TempDir& dir) -> helm::AuditLog {
    auto log =
        helm::AuditLog::open((dir.path / "audit.log").string(), {.sync = false, .clock = {}});
    BOOST_REQUIRE(log);
    return std::move(*log);
}

auto command_slot(std::uint64_t seq, const mb::Body& body) -> mb::Slot {
    const auto bytes = mb::encode_body(body);
    std::array<std::byte, mb::signature_size> sig{};
    sig.fill(std::byte{sig_fill});
    auto slot = mb::encode({.type = mb::type_of(body),
                            .seq = seq,
                            .body_len = static_cast<std::uint16_t>(bytes.size()),
                            .key_id = 1,
                            .server_id = server},
                           bytes, sig);
    BOOST_REQUIRE(slot);
    return *slot;
}

auto envelope(std::uint64_t seq, const mb::Body& body) -> proto::Envelope {
    proto::Envelope env{.server_id = server, .key_id = 1, .slot = {}};
    const auto slot = command_slot(seq, body);
    std::ranges::copy(slot, env.slot.begin());
    return env;
}

// Without Boost.Test assertions, which are not safe off the test thread.
auto try_response(std::uint64_t seq, mb::Type command) -> std::optional<mb::Slot> {
    const mb::Body body =
        mb::Response{.in_reply_to = seq, .command = command, .status = mb::Status::ok};
    const auto bytes = mb::encode_body(body);
    const std::array<std::byte, mb::signature_size> sig{};
    auto slot = mb::encode({.type = mb::type_of(body),
                            .seq = 0,
                            .body_len = static_cast<std::uint16_t>(bytes.size()),
                            .key_id = mb::no_key_id},
                           bytes, sig);
    if (!slot) {
        return std::nullopt;
    }
    return *slot;
}

auto response(std::uint64_t seq, mb::Type command) -> mb::Slot {
    auto slot = try_response(seq, command);
    BOOST_REQUIRE(slot);
    return *slot;
}

// A daemon over two boards (net: two NIC VFs, blk: one function) and fakes.
struct Rig {
    TempDir dir;
    helm::SoftwareSecureElement se = make_se();
    helm::KeyStore keys{se};
    helm::AuditLog audit = make_audit(dir);
    FakeHost host;
    FakeBackplane backplane;
    Board net{net_slot, oar::Role::net, FunctionType::nic_vf, net_functions};
    Board blk{blk_slot, oar::Role::blk, FunctionType::blk_fn, blk_functions};
    Board hold{hold_slot, oar::Role::hold, FunctionType::blk_fn, 0};
    std::vector<proto::ReportBody> reports;  // loop thread only (the test thread)
    helm::HelmDaemon daemon;

    explicit Rig(std::chrono::milliseconds slot_link_timeout = link_timeout,
                 helm::HostPort* host_port = nullptr, bool with_hold = false)
        : daemon{config(slot_link_timeout, with_hold),
                 keys,
                 audit,
                 host_port != nullptr ? *host_port : host,
                 backplane,
                 [this](SlotNumber s) {
                     return s == net_slot ? net.connect()
                                          : (s == blk_slot ? blk.connect() : hold.connect());
                 },
                 [this](proto::ReportBody b) { reports.push_back(std::move(b)); }} {}

    static auto config(std::chrono::milliseconds slot_link_timeout, bool with_hold = false)
        -> helm::DaemonConfig {
        helm::DaemonConfig c;
        std::vector<SlotNumber> slots{net_slot, blk_slot};
        if (with_hold) {
            slots.push_back(hold_slot);
        }
        c.report_interval = 0ms;  // every pass takes hold reports
        for (const auto s : slots) {
            c.slots.push_back({.slot = s,
                               .link = {.address = helm_side(s),
                                        .mtu = ak::helm::mctp::baseline_mtu,
                                        .timeout = sideband_timeout}});
        }
        c.sequencer.link_timeout = slot_link_timeout;
        c.sequencer.poll_interval = settle;
        c.sequencer.off_time = settle;
        c.sequencer.max_recoveries = 1;
        c.check_interval = 0ms;  // every pass checks
        return c;
    }

    template<typename T> [[nodiscard]] auto count() const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count_if(
            reports, [](const proto::ReportBody& b) { return std::holds_alternative<T>(b); }));
    }
    template<typename T> [[nodiscard]] auto last() const -> T {
        for (const auto& report : std::ranges::reverse_view(reports)) {
            if (const auto* t = std::get_if<T>(&report)) {
                return *t;
            }
        }
        BOOST_FAIL("no such report");
        return {};
    }
    [[nodiscard]] auto free_functions() const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count_if(
            daemon.pool().all(),
            [](const helm::FunctionInfo& f) { return f.state == FunctionState::free; }));
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(helm_daemon, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(boot_attaches_every_slot_and_cleans_its_functions) {
    Rig r;
    const auto booted = r.daemon.boot();
    BOOST_TEST(booted.host_released);
    BOOST_TEST(booted.ready.size() == 2U);
    BOOST_TEST(r.daemon.attached(net_slot));
    BOOST_TEST(r.daemon.attached(blk_slot));
    BOOST_TEST(r.net.role.cleaned() == net_functions);
    BOOST_TEST(r.blk.role.cleaned() == blk_functions);
    BOOST_TEST(r.free_functions() == std::size_t{net_functions + blk_functions});

    // The published snapshot is what the controller registers.
    const auto inv = r.daemon.inventory();
    BOOST_TEST(inv.functions.size() == std::size_t{net_functions + blk_functions});
    BOOST_REQUIRE(inv.vteps.size() == 1U);
    BOOST_TEST(std::to_integer<int>(inv.vteps[0].front()) == vtep_first);
    BOOST_TEST(r.count<proto::PoolStateChange>() > 0U);
}

BOOST_AUTO_TEST_CASE(envelopes_and_host_slots_cross_threads_to_the_router) {
    Rig r;
    (void)r.daemon.boot();
    const mb::CreateVm create{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib};
    std::thread{[&] { r.daemon.on_envelope(envelope(1, create)); }}.join();
    r.daemon.run_once(0ms);
    BOOST_REQUIRE(r.host.posted.size() == 1U);
    BOOST_TEST((r.host.posted[0] == command_slot(1, create)));

    std::thread{[&] { r.daemon.post_host_slot(response(1, mb::Type::create_vm)); }}.join();
    r.daemon.run_once(0ms);
    const auto outcome = r.last<proto::CommandOutcome>();
    BOOST_TEST(outcome.in_reply_to == 1U);
    BOOST_TEST((outcome.status == proto::CommandStatus::ok));
    const auto inv = r.daemon.inventory();
    BOOST_REQUIRE(inv.vms.size() == 1U);
    BOOST_TEST(inv.vms[0].vm_id == vm_one);
    BOOST_TEST(inv.last_command_seq == 1U);
    BOOST_TEST(r.daemon.stats().envelopes == 1U);
    BOOST_TEST(r.daemon.stats().host_slots == 1U);
}

BOOST_AUTO_TEST_CASE(nic_attach_prepares_the_vf_over_the_sideband) {
    Rig r;
    (void)r.daemon.boot();
    r.daemon.on_envelope(
        envelope(1, mb::CreateVm{.vm_id = vm_one, .vcpus = vcpus, .memory_mib = memory_mib}));
    r.daemon.run_once(0ms);
    r.daemon.post_host_slot(response(1, mb::Type::create_vm));
    mb::AttachDevice attach{
        .vm_id = vm_one,
        .device = {.slot = net_slot, .type = mb::DeviceType::nic_vf, .function = 0},
        .vni = vni,
        .nic_id = nic_id,
        .mac = {}};
    attach.mac[0] = std::byte{0x02};
    r.daemon.on_envelope(envelope(2, attach));
    r.daemon.run_once(0ms);
    BOOST_REQUIRE(r.host.posted.size() == 2U);
    const auto prepared = r.net.role.prepared();
    BOOST_REQUIRE(prepared.size() == 1U);
    BOOST_TEST(prepared[0].vm_id == vm_one);
    // The VF is configured from the signed ATTACH_DEVICE body (mailbox v3).
    const auto* nic = std::get_if<oar::NicConfig>(&prepared[0].config);
    BOOST_REQUIRE(nic != nullptr);
    BOOST_TEST(nic->vni == vni);
    BOOST_TEST(nic->nic_id == nic_id);
}

BOOST_AUTO_TEST_CASE(map_updates_reach_net_roles_only) {
    Rig r;
    (void)r.daemon.boot();
    std::vector<std::byte> frame(frame_size, std::byte{0x42});
    const proto::MapUpdate update{.server_id = server,
                                  .key_id = 1,
                                  .vni = vni,
                                  .map_version = map_version,
                                  .entries = {},
                                  .ipv4 = {},
                                  .ipv6 = {},
                                  .signature = {}};
    r.daemon.on_map_update(update, frame);
    r.daemon.run_once(0ms);
    BOOST_REQUIRE(r.net.role.frames().size() == 1U);
    BOOST_TEST((r.net.role.frames()[0] == frame));
    BOOST_TEST(r.blk.role.frames().empty());
    const auto applied = r.last<proto::MapApplied>();
    BOOST_TEST(applied.vni == vni);
    BOOST_TEST(applied.map_version == map_version);
    const auto inv = r.daemon.inventory();
    BOOST_REQUIRE(inv.networks.size() == 1U);
    BOOST_TEST(inv.networks[0].map_version == map_version);

    // A role that refuses the frame (bad signature, say): not applied.
    r.net.role.map_status = oar::Status::failed;
    r.daemon.on_map_update(update, frame);
    r.daemon.run_once(0ms);
    BOOST_TEST(r.count<proto::MapApplied>() == 1U);
    BOOST_TEST(r.daemon.stats().maps_refused == 1U);
}

namespace {

auto hold_config(std::uint64_t epoch) -> std::pair<proto::ReplicaConfig, std::vector<std::byte>> {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.server_id = server;
    c.volume_id = 0x100;
    c.epoch = epoch;
    c.lineage_id = 0x1EE;
    c.capacity_blocks = 1024;
    c.block_size = proto::block_size_4096;
    c.lease_ms = 4000;
    c.qos = {.iops = 100, .mib_per_s = 10, .burst_iops = 100, .burst_mib = 10};
    proto::ReplicaMember m;
    m.server_id = server;
    m.endpoint[0] = std::byte{0xFD};
    m.endpoint[15] = std::byte{1};
    m.port = 7300;
    m.role = proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    auto b = proto::encode_replica_config(c);
    BOOST_REQUIRE(b.has_value());
    return {c, *b};
}

auto hold_report(proto::ReportBody body) -> std::vector<std::byte> {
    auto b = proto::encode_report({.server_id = server, .report_seq = 1, .body = std::move(body)});
    BOOST_REQUIRE(b.has_value());
    return *b;
}

}  // namespace

BOOST_AUTO_TEST_CASE(block_volume_frames_reach_hold_roles_only) {
    Rig r{link_timeout, nullptr, true};
    (void)r.daemon.boot();
    BOOST_TEST(r.daemon.attached(hold_slot));
    BOOST_TEST(r.free_functions() == net_functions + blk_functions);  // the hold role adds none
    const auto [c2, f2] = hold_config(2);
    const auto [c1, f1] = hold_config(1);
    r.daemon.on_replica_config(c2, f2);
    r.daemon.on_replica_config(c1, f1);  // older: kept back
    const proto::VolumeOp op{.key_id = 1,
                             .server_id = server,
                             .volume_id = 0x100,
                             .epoch = 2,
                             .op_id = 9,
                             .args = proto::ScrubVolume{.mib_per_s = 50},
                             .signature = {}};
    const auto op_frame = proto::encode_volume_op(op).value();
    r.daemon.on_volume_op(op, op_frame);
    r.daemon.on_lease_grant({.server_id = server, .volume_id = 0x100, .epoch = 2});
    r.daemon.run_once(0ms);
    BOOST_REQUIRE(r.hold.role.configs().size() == 1U);
    BOOST_TEST((r.hold.role.configs()[0] == f2));
    BOOST_REQUIRE(r.hold.role.ops().size() == 1U);
    BOOST_TEST((r.hold.role.ops()[0] == op_frame));
    BOOST_REQUIRE(r.hold.role.grants().size() == 1U);
    BOOST_TEST((r.hold.role.grants()[0] == oar::LeaseGrant{.volume_id = 0x100, .epoch = 2}));
    BOOST_TEST(r.net.role.frames().empty());
    BOOST_TEST(r.daemon.stats().replica_configs == 2U);
    BOOST_TEST(r.daemon.stats().hold_refused == 0U);

    // A role that refuses a config (a bad signature, say) is counted.
    r.hold.role.config_status = oar::Status::failed;
    const auto [c3, f3] = hold_config(3);
    r.daemon.on_replica_config(c3, f3);
    r.daemon.run_once(0ms);
    BOOST_TEST(r.daemon.stats().hold_refused == 1U);
}

BOOST_AUTO_TEST_CASE(a_restarted_hold_role_gets_every_config_again) {
    Rig r{link_timeout, nullptr, true};
    (void)r.daemon.boot();
    const auto [c, f] = hold_config(4);
    r.daemon.on_replica_config(c, f);
    r.daemon.run_once(0ms);
    BOOST_TEST(r.hold.role.configs().size() == 1U);
    r.daemon.on_slot_recovered(hold_slot);
    BOOST_REQUIRE(r.hold.role.configs().size() == 2U);
    BOOST_TEST((r.hold.role.configs()[1] == f));
    BOOST_TEST(r.hold.connects == 2);
}

BOOST_AUTO_TEST_CASE(hold_reports_are_relayed_by_kind) {
    Rig r{link_timeout, nullptr, true};
    (void)r.daemon.boot();
    const auto before = r.reports.size();
    const proto::VolumeFault fault{.volume_id = 0x100,
                                   .epoch = 2,
                                   .suspect = 9,
                                   .kind = proto::VolumeFaultKind::member_timeout,
                                   .reporter = proto::FaultReporter::hold,
                                   .slot = 0};
    BOOST_REQUIRE(r.hold.role.queue_report(50, hold_report(fault)));
    BOOST_REQUIRE(r.hold.role.queue_report(
        51, hold_report(proto::VmExitedReport{
                .vm_id = 1, .exit_status = 0, .reason = proto::ExitReason::guest_shutdown})));
    BOOST_REQUIRE(r.hold.role.queue_report(52, std::vector<std::byte>(40, std::byte{1})));
    r.daemon.run_once(0ms);
    BOOST_REQUIRE(r.reports.size() == before + 1);
    BOOST_TEST((std::get<proto::VolumeFault>(r.reports.back()) == fault));
    BOOST_TEST(r.daemon.stats().hold_reports == 1U);
    BOOST_TEST(r.daemon.stats().hold_reports_dropped == 2U);
    r.daemon.run_once(0ms);
    BOOST_TEST(r.reports.size() == before + 1);  // each once
}

BOOST_AUTO_TEST_CASE(an_unreachable_sideband_is_reported_and_retried) {
    Rig r;
    r.blk.refuse = true;
    (void)r.daemon.boot();
    BOOST_TEST(r.daemon.attached(net_slot));
    BOOST_TEST(!r.daemon.attached(blk_slot));
    BOOST_TEST(r.count<proto::HostFaultReport>() == 1U);
    BOOST_TEST(r.last<proto::HostFaultReport>().slot == blk_slot);

    r.daemon.run_once(0ms);  // still refusing: retried, reported only once
    BOOST_TEST(r.count<proto::HostFaultReport>() == 1U);
    BOOST_TEST(r.blk.connects.load() == 2);

    r.blk.refuse = false;
    r.daemon.run_once(0ms);
    BOOST_TEST(r.daemon.attached(blk_slot));
    BOOST_TEST(r.free_functions() == std::size_t{net_functions + blk_functions});
}

BOOST_AUTO_TEST_CASE(a_recovered_slot_gets_a_new_sideband) {
    Rig r;
    (void)r.daemon.boot();
    BOOST_TEST(r.net.connects.load() == 1);
    r.backplane.dropped.insert(net_slot);
    r.daemon.run_once(0ms);  // check: power cycle, link back
    BOOST_TEST(r.net.connects.load() == 2);
    BOOST_TEST(r.daemon.attached(net_slot));
    BOOST_TEST((r.daemon.sequencer().health(net_slot) == helm::SlotHealth::ready));
    // The reopened sideband works.
    std::vector<std::byte> frame(frame_size, std::byte{0x24});
    r.daemon.on_map_update({.server_id = server,
                            .key_id = 1,
                            .vni = vni,
                            .map_version = 1,
                            .entries = {},
                            .ipv4 = {},
                            .ipv6 = {},
                            .signature = {}},
                           frame);
    r.daemon.run_once(0ms);
    BOOST_TEST(r.net.role.frames().size() == 1U);
}

BOOST_AUTO_TEST_CASE(a_faulted_slot_is_detached_and_reported) {
    Rig r{short_link_timeout};
    (void)r.daemon.boot();
    r.backplane.dropped.insert(net_slot);
    r.backplane.dead.insert(net_slot);
    r.daemon.run_once(0ms);
    BOOST_TEST((r.daemon.sequencer().health(net_slot) == helm::SlotHealth::faulted));
    BOOST_TEST(!r.daemon.attached(net_slot));
    BOOST_TEST(r.last<proto::HostFaultReport>().slot == net_slot);
    // Map updates have no net role to go to.
    std::vector<std::byte> frame(frame_size, std::byte{0x24});
    r.daemon.on_map_update({.server_id = server,
                            .key_id = 1,
                            .vni = vni,
                            .map_version = 1,
                            .entries = {},
                            .ipv4 = {},
                            .ipv6 = {},
                            .signature = {}},
                           frame);
    r.daemon.run_once(0ms);
    BOOST_TEST(r.count<proto::MapApplied>() == 0U);
}

BOOST_AUTO_TEST_CASE(shutdown_holds_the_host_and_powers_slots_off) {
    Rig r;
    (void)r.daemon.boot();
    r.daemon.shutdown();
    BOOST_TEST(!r.backplane.host);
    BOOST_TEST(r.backplane.powered.empty());
    BOOST_TEST(!r.daemon.attached(net_slot));
}

BOOST_AUTO_TEST_SUITE_END()

// ---- end to end ---------------------------------------------------------------

namespace {

auto signer() -> harbor::Signer {
    const auto secret = ak::test::fixed_from_hex<harbor::ed25519_secret_size>(vectors::key1_secret);
    auto s = harbor::Signer::from_raw(secret);
    BOOST_REQUIRE(s.has_value());
    return std::move(*s);
}

// hull's side of the mailbox: verifies each command as hull will and
// answers ok through the daemon's MailboxDevice entry point. Runs on the
// loop thread.
struct VerifyingHull final : helm::HostPort {
    hull::SignatureVerifier verify = [] {
        const std::array keys{ak::test::controller_key(1, vectors::key1_public)};
        auto v = hull::SignatureVerifier::create(keys);
        if (!v) {
            throw std::runtime_error("verifier");
        }
        return std::move(*v);
    }();
    helm::HelmDaemon* daemon = nullptr;
    std::atomic<int> verified{0};
    std::atomic<int> problems{0};

    auto post_command(const mb::Slot& slot) -> bool override {
        auto msg = mb::decode(slot);
        if (!msg || !verify.verify_slot(slot, msg->header.key_id)) {
            ++problems;
            return true;
        }
        auto rsp = try_response(msg->header.seq, msg->header.type);
        if (!rsp) {
            ++problems;
            return true;
        }
        ++verified;
        daemon->post_host_slot(*rsp);
        return true;
    }
};

auto run_line(harbor::TestController& c, std::string_view line) -> void {
    auto a = harbor::parse_line(line);
    BOOST_REQUIRE(a.has_value() && a->has_value());
    auto ok = c.run(**a);
    BOOST_REQUIRE_MESSAGE(ok.has_value(), std::string{line} + ": " + (ok ? "" : ok.error()));
}

}  // namespace

BOOST_AUTO_TEST_SUITE(end_to_end, *boost::unit_test::timeout(e2e_timeout_seconds))

BOOST_AUTO_TEST_CASE(serves_the_harbor_test_controller) {
    ak::test::TestCa controller_ca{"kythira test CA"};
    ak::test::TestCa server_ca{"server CA"};
    const auto controller_cert = controller_ca.issue("controller", "IP:127.0.0.1");
    const auto helm_cert = server_ca.issue("server-7", "DNS:server-7");

    auto controller = harbor::TestController::create({.tls = {.role = tls::Role::server,
                                                              .ca_pem = server_ca.cert_pem(),
                                                              .cert_pem = controller_cert.cert,
                                                              .key_pem = controller_cert.key,
                                                              .peer_name = "server-7"},
                                                      .server_id = server,
                                                      .key_id = 1,
                                                      .timeout = 10s,
                                                      .on_report = {}},
                                                     signer());
    BOOST_REQUIRE_MESSAGE(controller.has_value(),
                          (controller ? std::string{} : controller.error()));
    auto listener = tls::Listener::bind(loopback, 0);
    BOOST_REQUIRE(listener.has_value());

    VerifyingHull hull_side;
    std::unique_ptr<helm::ControllerLink> link;
    TempDir dir;
    auto se = make_se();
    helm::KeyStore keys{se};
    auto audit = make_audit(dir);
    FakeBackplane backplane;
    Board net{net_slot, oar::Role::net, FunctionType::nic_vf, net_functions};
    Board blk{blk_slot, oar::Role::blk, FunctionType::blk_fn, blk_functions};
    helm::HelmDaemon daemon{
        Rig::config(link_timeout),
        keys,
        audit,
        hull_side,
        backplane,
        [&](SlotNumber s) { return s == net_slot ? net.connect() : blk.connect(); },
        [&link](proto::ReportBody b) { (void)link->report(std::move(b)); }};
    hull_side.daemon = &daemon;
    helm::ControllerSession session{server, boot_id, [&daemon] { return daemon.inventory(); },
                                    daemon};
    auto created = helm::ControllerLink::create({.host = loopback,
                                                 .port = listener->port(),
                                                 .tls = {.role = tls::Role::client,
                                                         .ca_pem = controller_ca.cert_pem(),
                                                         .cert_pem = helm_cert.cert,
                                                         .key_pem = helm_cert.key,
                                                         .peer_name = loopback},
                                                 .min_backoff = 20ms,
                                                 .max_backoff = 100ms,
                                                 .io_timeout = 5s},
                                                session);
    BOOST_REQUIRE(created.has_value());
    link = std::move(*created);

    // ak-helm's order: boot and attach, then the link, then the loop.
    BOOST_REQUIRE(daemon.boot().host_released);
    std::jthread link_runner{[&link](const std::stop_token& st) { link->run(st); }};
    std::jthread loop{[&daemon](const std::stop_token& st) { daemon.run(st); }};

    auto registered = controller->accept(*listener);
    BOOST_REQUIRE_MESSAGE(registered.has_value(),
                          (registered ? std::string{} : registered.error()));
    BOOST_TEST(controller->boot_id() == boot_id);
    BOOST_REQUIRE(controller->inventory().has_value());
    BOOST_TEST(controller->inventory()->functions.size() ==
               std::size_t{net_functions + blk_functions});

    for (const auto* line : {"create-vm 0x1001 2 1024", "expect ok",
                             "attach-device 0x1001 1 nic 0 5 0x10 02:00:00:00:00:10", "expect ok",
                             "map-update 5 1 0x10,02:00:00:00:00:10,fd00::1", "wait map_applied"}) {
        run_line(*controller, line);
    }
    loop.request_stop();
    loop.join();
    link_runner.request_stop();
    link_runner.join();

    BOOST_TEST(hull_side.verified.load() == 2);
    BOOST_TEST(hull_side.problems.load() == 0);
    BOOST_TEST(net.role.prepared().size() == 1U);
    BOOST_REQUIRE(net.role.frames().size() == 1U);
    // The frame reached oar-net exactly as the controller signed it.
    const auto frame = net.role.frames()[0];
    auto decoded = proto::decode_map_update(frame);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_TEST(decoded->vni == vni);
}

BOOST_AUTO_TEST_SUITE_END()
