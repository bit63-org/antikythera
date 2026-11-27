// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 8 (Requirements 6 and 8.1): the
// VmSupervisor's create, destroy, exit, list and status paths, the
// AgentHandler's dispatch and the LIST_VMS / VM_STATUS payload codecs,
// with a fake launcher, VMM and resetter. The real launcher and jail are
// in vmm_launcher_test.

#define BOOST_TEST_MODULE vm_supervisor_test
#include <boost/test/unit_test.hpp>

#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "helm/mailbox.hpp"
#include "hull/agent_handler.hpp"
#include "hull/cpu_topology.hpp"
#include "hull/json.hpp"
#include "hull/resource_allocator.hpp"
#include "hull/vm_supervisor.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::hull::Allocation;
using ak::hull::BootPayload;
using ak::hull::CpuTopology;
using ak::hull::DeviceInventory;
using ak::hull::InventoryEntry;
using ak::hull::LaunchError;
using ak::hull::LaunchFailure;
using ak::hull::ResetMethod;
using ak::hull::ResourceAllocator;
using ak::hull::VmmApi;
using ak::hull::VmmApiError;
using ak::hull::VmmApiFailure;
using ak::hull::VmmHandle;
using ak::hull::VmmInfo;
using ak::hull::VmmState;
using ak::hull::VmSupervisor;
using ak::test::unit_timeout_seconds;

BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<std::uint64_t>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<bool>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<ak::hull::json::JsonError>)

namespace {

// What every fake VMM did, kept after the VMM is gone.
struct VmmLog {
    std::vector<std::string> calls;
    std::string config;
    bool killed{false};
    bool destroyed{false};
};

class FakeApi final : public VmmApi {
public:
    explicit FakeApi(VmmLog& log) : _log{&log} {}
    bool fail_create{false};
    bool fail_boot{false};
    std::optional<VmmApiError> fail_add;  // with timed_out, the add still happens
    bool eject_at_once{false};            // a running guest ejects on request
    std::vector<std::string> devices;
    bool running{false};

    auto create(std::string_view config) -> Result override {
        _log->calls.emplace_back("create");
        _log->config = config;
        if (fail_create) {
            return std::unexpected(
                VmmApiFailure{.error = VmmApiError::refused, .http_status = 400});
        }
        return {};
    }
    auto boot() -> Result override {
        _log->calls.emplace_back("boot");
        if (fail_boot) {
            return std::unexpected(
                VmmApiFailure{.error = VmmApiError::refused, .http_status = 500});
        }
        running = true;
        return {};
    }
    auto add_device(std::string_view id, const std::filesystem::path& path) -> Result override {
        _log->calls.push_back("add " + std::string{id} + " " + path.native());
        if (fail_add == VmmApiError::refused) {
            return std::unexpected(
                VmmApiFailure{.error = VmmApiError::refused, .http_status = 500});
        }
        devices.emplace_back(id);
        if (fail_add) {
            return std::unexpected(VmmApiFailure{.error = *fail_add});
        }
        return {};
    }
    auto remove_device(std::string_view id) -> Result override {
        _log->calls.push_back("remove " + std::string{id});
        const auto it = std::ranges::find(devices, id);
        if (it == devices.end()) {
            return std::unexpected(
                VmmApiFailure{.error = VmmApiError::refused, .http_status = 404});
        }
        if (!running || eject_at_once) {
            devices.erase(it);
        }
        return {};
    }
    auto info() -> std::expected<VmmInfo, VmmApiFailure> override {
        return VmmInfo{.state = running ? VmmState::running : VmmState::created,
                       .device_ids = devices};
    }
    auto shutdown_vmm() -> Result override { return {}; }

    // The guest acknowledges an eject request.
    auto guest_ejects(const std::string& id) -> void { std::erase(devices, id); }

private:
    VmmLog* _log;
};

// A VMM whose "exit" is an eventfd the test writes to.
class FakeVmm final : public VmmHandle {
public:
    FakeVmm(VmmLog& log, int wait_status)
        : _log{&log},
          _api{log},
          _status{wait_status},
          _fd{::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)} {}
    FakeVmm(const FakeVmm&) = delete;
    auto operator=(const FakeVmm&) -> FakeVmm& = delete;
    FakeVmm(FakeVmm&&) = delete;
    auto operator=(FakeVmm&&) -> FakeVmm& = delete;
    ~FakeVmm() override {
        _log->destroyed = true;
        ::close(_fd);
    }

    [[nodiscard]] auto pidfd() const noexcept -> int override { return _fd; }
    auto api() -> VmmApi& override { return _api; }
    auto kill() -> void override {
        _log->killed = true;
        exit_now(SIGKILL);  // what the kernel reports for a SIGKILLed process
    }
    auto wait() -> std::expected<int, int> override { return _status; }
    auto grant_group(std::uint32_t g) -> bool override {
        _log->calls.push_back("grant " + std::to_string(g));
        return true;
    }
    auto revoke_group(std::uint32_t g) -> bool override {
        _log->calls.push_back("revoke " + std::to_string(g));
        return true;
    }

    auto exit_now(int wait_status) -> void {
        _status = wait_status;
        static_cast<void>(::eventfd_write(_fd, 1));
    }
    FakeApi& fake_api() { return _api; }

private:
    VmmLog* _log;
    FakeApi _api;
    int _status;
    int _fd{-1};
};

class FakeLauncher final : public ak::hull::VmmLauncher {
public:
    std::map<std::uint64_t, VmmLog> logs;
    std::map<std::uint64_t, FakeVmm*> live;  // valid until the supervisor drops the VM
    bool fail_next{false};
    bool fail_create_next{false};

    auto launch(const Allocation& a)
        -> std::expected<std::unique_ptr<VmmHandle>, LaunchFailure> override {
        if (fail_next) {
            fail_next = false;
            return std::unexpected(LaunchFailure{.error = LaunchError::exited, .detail = {}});
        }
        auto& log = logs[a.vm_id];
        log = {};
        auto vmm = std::make_unique<FakeVmm>(log, 0);
        vmm->fake_api().fail_create = fail_create_next;
        fail_create_next = false;
        live[a.vm_id] = vmm.get();
        return vmm;
    }
};

class FakeResetter final : public ak::hull::FunctionResetter {
public:
    std::vector<std::string> resets;
    std::set<std::string> failing;  // BDFs whose reset fails
    auto reset(const InventoryEntry& f) -> bool override {
        resets.push_back(f.bdf);
        return !failing.contains(f.bdf);
    }
};

// Four whole 2-thread cores (cpus 0-7) for guests, 8 huge pages.
auto topology() -> CpuTopology {
    return CpuTopology::from_cores({{0, 1}, {2, 3}, {4, 5}, {6, 7}}).value();
}

struct Harness {
    Harness()
        : topo{topology()},
          allocator{topo, std::vector<ak::hull::CpuId>{0, 1, 2, 3, 4, 5, 6, 7}, 8},
          inventory{std::vector<InventoryEntry>{
              {.ref = nic, .bdf = "0000:03:00.1", .iommu_group = 11, .reset = ResetMethod::flr},
              {.ref = blk, .bdf = "0000:04:00.0", .iommu_group = 12, .reset = ResetMethod::bus},
          }},
          supervisor{allocator,
                     launcher,
                     resetter,
                     inventory,
                     {.firmware = "/fw", .kernel = {}, .cmdline = {}, .initramfs = {}}} {}

    static constexpr mb::DeviceRef nic{.slot = 3, .type = mb::DeviceType::nic_vf, .function = 1};
    static constexpr mb::DeviceRef blk{.slot = 4, .type = mb::DeviceType::blk_fn, .function = 0};

    CpuTopology topo;
    ResourceAllocator allocator;
    DeviceInventory inventory;
    FakeLauncher launcher;
    FakeResetter resetter;
    VmSupervisor supervisor;
};

}  // namespace

BOOST_AUTO_TEST_CASE(create_starts_a_vmm_with_the_allocation,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST(
        (h.supervisor.create({.vm_id = 5, .vcpus = 3, .memory_mib = 1500}) == mb::Status::ok));
    BOOST_TEST(h.supervisor.contains(5));
    BOOST_TEST(h.allocator.free_cores() == 2U);      // 3 vCPUs: two whole cores
    BOOST_TEST(h.allocator.free_hugepages() == 6U);  // 1500 MiB rounds up to 2 GiB
    const auto& log = h.launcher.logs[5];
    BOOST_TEST((log.calls == std::vector<std::string>{"create"}));
    const auto config = ak::hull::json::parse(log.config);
    BOOST_TEST_REQUIRE(config.has_value());
    BOOST_TEST(config->find("cpus")->find("boot_vcpus")->as_u64() ==
               std::optional<std::uint64_t>{3});
    BOOST_TEST(*config->find("payload")->find("firmware")->as_string() == "/fw");
    BOOST_TEST(h.supervisor.take_events().empty());
}

BOOST_AUTO_TEST_CASE(create_refuses_without_partial_allocation,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST((h.supervisor.create({.vm_id = 1, .vcpus = 9, .memory_mib = 1024}) ==
                mb::Status::insufficient_resources));
    BOOST_TEST((h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 9 * 1024}) ==
                mb::Status::insufficient_resources));
    BOOST_TEST(h.allocator.free_cores() == 4U);
    BOOST_TEST(h.allocator.free_hugepages() == 8U);
    BOOST_TEST(h.launcher.logs.empty());  // nothing was started
}

BOOST_AUTO_TEST_CASE(create_twice_is_a_conflict, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST((h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) ==
                mb::Status::conflict));
    BOOST_TEST(h.allocator.free_cores() == 3U);
}

BOOST_AUTO_TEST_CASE(create_rolls_back_a_failed_launch_or_vm_create,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    h.launcher.fail_next = true;
    BOOST_TEST((h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) ==
                mb::Status::internal_error));
    BOOST_TEST(!h.supervisor.contains(1));
    BOOST_TEST(h.allocator.free_cores() == 4U);

    h.launcher.fail_create_next = true;
    BOOST_TEST((h.supervisor.create({.vm_id = 2, .vcpus = 2, .memory_mib = 1024}) ==
                mb::Status::internal_error));
    BOOST_TEST(!h.supervisor.contains(2));
    BOOST_TEST(h.launcher.logs[2].destroyed);  // the VMM was killed and released
    BOOST_TEST(h.allocator.free_cores() == 4U);
    BOOST_TEST(h.allocator.free_hugepages() == 8U);
    BOOST_TEST(h.supervisor.stats().launch_failures == 1U);
    BOOST_TEST(h.supervisor.stats().api_failures == 1U);
}

BOOST_AUTO_TEST_CASE(destroy_kills_and_frees, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST((h.supervisor.destroy({.vm_id = 1}) == mb::Status::ok));
    BOOST_TEST(h.launcher.logs[1].killed);
    BOOST_TEST(h.launcher.logs[1].destroyed);
    BOOST_TEST(!h.supervisor.contains(1));
    BOOST_TEST(h.allocator.free_cores() == 4U);
    // No functions were held, so nothing is released, and a VM hull
    // destroyed does not report VM_EXITED.
    BOOST_TEST(h.supervisor.take_events().empty());
    BOOST_TEST(h.supervisor.poll_exits() == 0U);
    BOOST_TEST((h.supervisor.destroy({.vm_id = 1}) == mb::Status::unknown_vm));
}

BOOST_AUTO_TEST_CASE(unexpected_exit_reports_vm_exited,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST(
        (h.supervisor.create({.vm_id = 2, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST(h.supervisor.exit_fds().size() == 2U);
    BOOST_TEST(h.supervisor.poll_exits() == 0U);

    h.launcher.live[2]->exit_now(0);  // the guest powered off: exit status 0
    BOOST_TEST(h.supervisor.poll_exits() == 1U);
    auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST(
        (std::get<mb::VmExited>(events[0]) ==
         mb::VmExited{.vm_id = 2, .exit_status = 0, .reason = mb::ExitReason::guest_shutdown}));
    BOOST_TEST(!h.supervisor.contains(2));
    BOOST_TEST(h.supervisor.contains(1));
    BOOST_TEST(h.allocator.free_cores() == 3U);

    h.launcher.live[1]->exit_now(SIGSEGV);  // the VMM crashed
    BOOST_TEST(h.supervisor.poll_exits() == 1U);
    events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST(
        (std::get<mb::VmExited>(events[0]) == mb::VmExited{.vm_id = 1,
                                                           .exit_status = 128 + SIGSEGV,
                                                           .reason = mb::ExitReason::vmm_failure}));
    BOOST_TEST(h.supervisor.stats().exited == 2U);
    BOOST_TEST(h.supervisor.vm_count() == 0U);
}

BOOST_AUTO_TEST_CASE(exit_report_maps_wait_statuses,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    using ak::hull::exit_report;
    // waitpid(2) encodings: exit code in bits 8-15, signal in bits 0-6.
    BOOST_TEST((exit_report(0).first == mb::ExitReason::guest_shutdown));
    BOOST_TEST((exit_report(3 << 8) == std::pair{mb::ExitReason::vmm_failure, std::uint32_t{3}}));
    BOOST_TEST(
        (exit_report(SIGKILL) == std::pair{mb::ExitReason::vmm_failure, std::uint32_t{137}}));
}

BOOST_AUTO_TEST_CASE(list_and_status, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    auto empty = h.supervisor.list();
    BOOST_TEST((empty.status == mb::Status::ok));
    BOOST_TEST((mb::decode_vm_list_payload(empty.payload)->vm_ids.empty()));

    BOOST_TEST(
        (h.supervisor.create({.vm_id = 9, .vcpus = 1, .memory_mib = 512}) == mb::Status::ok));
    BOOST_TEST(
        (h.supervisor.create({.vm_id = 4, .vcpus = 2, .memory_mib = 2048}) == mb::Status::ok));
    const auto list = mb::decode_vm_list_payload(h.supervisor.list().payload);
    BOOST_TEST_REQUIRE(list.has_value());
    BOOST_TEST(list->total == 2U);
    BOOST_TEST((list->vm_ids == std::vector<std::uint64_t>{4, 9}));

    const auto st = h.supervisor.status({.vm_id = 4});
    BOOST_TEST((st.status == mb::Status::ok));
    BOOST_TEST((mb::decode_vm_status_payload(st.payload).value() ==
                mb::VmStatusInfo{.vm_id = 4,
                                 .state = mb::VmRunState::created,
                                 .devices = 0,
                                 .vcpus = 2,
                                 .hugepages = 2}));
    BOOST_TEST((h.supervisor.status({.vm_id = 5}).status == mb::Status::unknown_vm));
    BOOST_TEST(h.supervisor.status({.vm_id = 5}).payload.empty());
}

// --- Payload codecs ----------------------------------------------------------

BOOST_AUTO_TEST_CASE(vm_status_payload_round_trip_and_checks,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const mb::VmStatusInfo info{.vm_id = 0x1122334455667788,
                                .state = mb::VmRunState::running,
                                .devices = 3,
                                .vcpus = 0x0102,
                                .hugepages = 0x0A0B0C0D};
    const auto bytes = mb::encode_vm_status_payload(info);
    BOOST_TEST((bytes == ak::test::bytes_of(0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x02,
                                            0x03, 0x02, 0x01, 0x0D, 0x0C, 0x0B, 0x0A)));
    BOOST_TEST((mb::decode_vm_status_payload(bytes).value() == info));

    auto bad = bytes;
    bad[8] = std::byte{3};  // unknown state
    BOOST_TEST(!mb::decode_vm_status_payload(bad).has_value());
    BOOST_TEST(!mb::decode_vm_status_payload(std::span{bytes}.first(15)).has_value());
    auto zero_id = mb::encode_vm_status_payload({.vm_id = 0, .vcpus = 1, .hugepages = 1});
    BOOST_TEST(!mb::decode_vm_status_payload(zero_id).has_value());
}

BOOST_AUTO_TEST_CASE(vm_list_payload_cuts_to_the_slot,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::vector<std::uint64_t> ids;
    for (std::uint64_t i = 1; i <= 40; ++i) {
        ids.push_back(i * 10);
    }
    const auto bytes = mb::encode_vm_list_payload(ids);
    BOOST_TEST(bytes.size() <= mb::max_response_payload);
    const auto list = mb::decode_vm_list_payload(bytes);
    BOOST_TEST_REQUIRE(list.has_value());
    BOOST_TEST(list->total == 40U);
    BOOST_TEST(list->vm_ids.size() == mb::max_listed_vms);
    BOOST_TEST(list->vm_ids.front() == 10U);

    // Not ascending, zero IDs, reserved bits, a short list that claims more.
    auto two = mb::encode_vm_list_payload(std::vector<std::uint64_t>{5, 6});
    auto swapped = two;
    std::swap_ranges(swapped.begin() + 8, swapped.begin() + 16, swapped.begin() + 16);
    BOOST_TEST(!mb::decode_vm_list_payload(swapped).has_value());
    auto rsvd = two;
    rsvd[4] = std::byte{1};
    BOOST_TEST(!mb::decode_vm_list_payload(rsvd).has_value());
    auto claims_more = two;
    claims_more[0] = std::byte{3};
    BOOST_TEST(!mb::decode_vm_list_payload(claims_more).has_value());
    BOOST_TEST(!mb::decode_vm_list_payload(std::span{two}.first(20)).has_value());
}

// --- AgentHandler --------------------------------------------------------------

BOOST_AUTO_TEST_CASE(handler_dispatches_every_command,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    ak::hull::AgentHandler handler{h.supervisor};
    const mb::Message msg{};
    auto status = [&](const mb::Body& b) { return handler.handle(msg, b).status; };

    BOOST_TEST(
        (status(mb::CreateVm{.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST(h.supervisor.contains(1));
    BOOST_TEST((handler.handle(msg, mb::ListVms{}).payload.size() == mb::vm_list_fixed_size + 8));
    BOOST_TEST((status(mb::VmStatus{.vm_id = 1}) == mb::Status::ok));
    BOOST_TEST((status(mb::AttachDevice{
                    .vm_id = 1, .device = Harness::nic, .vni = 1, .nic_id = 1, .mac = {}}) ==
                mb::Status::ok));
    BOOST_TEST((status(mb::AttachVolume{.volume_id = 3, .vm_id = 1, .device = Harness::blk}) ==
                mb::Status::ok));
    BOOST_TEST(
        (status(mb::DetachDevice{.vm_id = 1,
                                 .device = Harness::nic,
                                 .timeout_s = 5,
                                 .policy = mb::DetachPolicy::force}) == mb::Status::accepted));
    BOOST_TEST(
        (status(mb::DetachVolume{.volume_id = 3,
                                 .vm_id = 1,
                                 .device = Harness::blk,
                                 .timeout_s = 5,
                                 .policy = mb::DetachPolicy::force}) == mb::Status::accepted));
    BOOST_TEST(
        (status(mb::CreateVolume{.volume_id = 1, .owner_vm = 1, .size_gib = 1}) == mb::Status::ok));
    BOOST_TEST((status(mb::CreateNetwork{.vni = 7}) == mb::Status::ok));
    // helm answers WITHDRAW_DETACH itself and never relays it.
    BOOST_TEST((status(mb::WithdrawDetach{.volume_id = 3, .vm_id = 1, .device = Harness::blk}) ==
                mb::Status::unsupported));
    // helm runs a conversion's copy once hull has checked the signature.
    BOOST_TEST((status(mb::ConvertVolume{.local_volume_id = 1,
                                         .owner_vm = 1,
                                         .network_volume_id = 2,
                                         .direction = mb::ConvertDirection::to_network,
                                         .mib_per_s = 0}) == mb::Status::ok));
    BOOST_TEST((status(mb::DestroyVm{.vm_id = 1}) == mb::Status::ok));
    BOOST_TEST(!h.supervisor.contains(1));
    BOOST_TEST((status(mb::VmExited{.vm_id = 1}) == mb::Status::malformed));
}

// --- Attach and detach (task 9) -------------------------------------------------

namespace {

auto calls(Harness& h, std::uint64_t vm) -> const std::vector<std::string>& {
    return h.launcher.logs[vm].calls;
}

auto released(const mb::Body& e) -> mb::DeviceReleased {
    return std::get<mb::DeviceReleased>(e);
}

// A harness clock the test moves by hand.
struct ManualClock {
    VmSupervisor::Clock::time_point t{};
    auto operator()() const { return t; }
};

}  // namespace

BOOST_AUTO_TEST_CASE(attach_cold_plugs_and_boots_on_the_volume,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    // A NIC first: cold-plugged, nothing boots.
    BOOST_TEST((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    auto st = mb::decode_vm_status_payload(h.supervisor.status({.vm_id = 1}).payload).value();
    BOOST_TEST((st.state == mb::VmRunState::created));
    BOOST_TEST(st.devices == 1U);
    // The volume: cold-plugged, then the VM boots from it.
    BOOST_TEST((h.supervisor.attach(1, Harness::blk) == mb::Status::ok));
    st = mb::decode_vm_status_payload(h.supervisor.status({.vm_id = 1}).payload).value();
    BOOST_TEST((st.state == mb::VmRunState::running));
    BOOST_TEST((calls(h, 1) == std::vector<std::string>{
                                   "create",
                                   "grant 11",
                                   "add ak-s3-nic-f1 /sys/bus/pci/devices/0000:03:00.1",
                                   "grant 12",
                                   "add ak-s4-blk-f0 /sys/bus/pci/devices/0000:04:00.0",
                                   "boot",
                               }));
    BOOST_TEST(h.supervisor.stats().attached == 2U);
}

BOOST_AUTO_TEST_CASE(attach_checks_vm_inventory_and_ownership,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 2, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST((h.supervisor.attach(7, Harness::nic) == mb::Status::unknown_vm));
    // Not in the inventory, and in it but under another type.
    BOOST_TEST(
        (h.supervisor.attach(1, {.slot = 9, .type = mb::DeviceType::nic_vf, .function = 0}) ==
         mb::Status::unknown_device));
    BOOST_TEST(
        (h.supervisor.attach(1, {.slot = 3, .type = mb::DeviceType::gpu_vf, .function = 1}) ==
         mb::Status::unknown_device));
    BOOST_TEST((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    BOOST_TEST((h.supervisor.attach(2, Harness::nic) == mb::Status::conflict));
    BOOST_TEST((h.supervisor.attach(1, Harness::nic) == mb::Status::conflict));
}

BOOST_AUTO_TEST_CASE(attach_failures_undo_the_grant,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    auto& api = h.launcher.live[1]->fake_api();

    api.fail_add = VmmApiError::refused;
    BOOST_TEST((h.supervisor.attach(1, Harness::nic) == mb::Status::internal_error));
    BOOST_TEST(calls(h, 1).back() == "revoke 11");

    // A timeout after which the VMM does list the device: it is attached.
    api.fail_add = VmmApiError::timed_out;
    BOOST_TEST((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    api.fail_add.reset();

    // The boot fails: the volume comes out of the configuration again.
    api.fail_boot = true;
    BOOST_TEST((h.supervisor.attach(1, Harness::blk) == mb::Status::internal_error));
    BOOST_TEST(calls(h, 1).back() == "revoke 12");
    BOOST_TEST((api.devices == std::vector<std::string>{"ak-s3-nic-f1"}));
    BOOST_TEST((mb::decode_vm_status_payload(h.supervisor.status({.vm_id = 1}).payload)->state ==
                mb::VmRunState::created));
}

BOOST_AUTO_TEST_CASE(detach_before_boot_releases_at_once,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    BOOST_TEST(
        (h.supervisor.detach(1, Harness::nic, 10, mb::DetachPolicy::force) == mb::Status::ok));
    const auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST(
        (released(events[0]) ==
         mb::DeviceReleased{.vm_id = 1, .device = Harness::nic, .reset = mb::ResetResult::ok}));
    BOOST_TEST((h.resetter.resets == std::vector<std::string>{"0000:03:00.1"}));
    BOOST_TEST(calls(h, 1).back() == "revoke 11");
    BOOST_TEST(!h.supervisor.has_pending_detaches());
    BOOST_TEST((h.supervisor.detach(1, Harness::nic, 10, mb::DetachPolicy::force) ==
                mb::Status::unknown_device));
    BOOST_TEST((h.supervisor.detach(5, Harness::nic, 10, mb::DetachPolicy::force) ==
                mb::Status::unknown_vm));
}

BOOST_AUTO_TEST_CASE(detach_waits_for_the_guest_to_eject,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    ManualClock clock;
    h.supervisor.set_clock(std::ref(clock));
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::blk) == mb::Status::ok));  // boots
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));  // hot-plug
    auto& api = h.launcher.live[1]->fake_api();

    BOOST_TEST((h.supervisor.detach(1, Harness::nic, 30, mb::DetachPolicy::force) ==
                mb::Status::accepted));
    BOOST_TEST((h.supervisor.detach(1, Harness::nic, 30, mb::DetachPolicy::force) ==
                mb::Status::conflict));  // already under way
    BOOST_TEST(h.supervisor.has_pending_detaches());
    clock.t += std::chrono::seconds{10};
    BOOST_TEST(h.supervisor.poll_detaches() == 0U);
    BOOST_TEST(h.supervisor.take_events().empty());

    api.guest_ejects("ak-s3-nic-f1");
    BOOST_TEST(h.supervisor.poll_detaches() == 1U);
    const auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST((released(events[0]).device == Harness::nic));
    BOOST_TEST(!h.supervisor.has_pending_detaches());
    BOOST_TEST(h.supervisor.stats().detached == 1U);
    BOOST_TEST(h.supervisor.stats().detach_timeouts == 0U);
    // The function can go to another VM now.
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 2, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST((h.supervisor.attach(2, Harness::nic) == mb::Status::ok));
}

BOOST_AUTO_TEST_CASE(detach_timeout_destroys_the_vm,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    ManualClock clock;
    h.supervisor.set_clock(std::ref(clock));
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::blk) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    BOOST_TEST((h.supervisor.detach(1, Harness::nic, 30, mb::DetachPolicy::destroy_vm) ==
                mb::Status::accepted));
    clock.t += std::chrono::seconds{29};
    BOOST_TEST(h.supervisor.poll_detaches() == 0U);
    BOOST_TEST(h.supervisor.contains(1));
    clock.t += std::chrono::seconds{1};
    BOOST_TEST(h.supervisor.poll_detaches() == 2U);
    BOOST_TEST(!h.supervisor.contains(1));
    BOOST_TEST(h.launcher.logs[1].killed);
    const auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 3U);
    BOOST_TEST(
        (std::get<mb::VmExited>(events[0]) == mb::VmExited{.vm_id = 1,
                                                           .exit_status = 128 + SIGKILL,
                                                           .reason = mb::ExitReason::vmm_failure}));
    BOOST_TEST((released(events[1]).device == Harness::blk));
    BOOST_TEST((released(events[2]).device == Harness::nic));
    BOOST_TEST(h.allocator.free_cores() == 4U);
    BOOST_TEST(h.supervisor.stats().detach_timeouts == 1U);
}

// `wait` reaches hull only after helm saw the guest release the volume
// (Requirement 7.2), so there is no deadline: the function is released
// whenever the guest's eject completes, however long that takes.
BOOST_AUTO_TEST_CASE(detach_wait_has_no_deadline,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    ManualClock clock;
    h.supervisor.set_clock(std::ref(clock));
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::blk) == mb::Status::ok));
    BOOST_TEST(
        (h.supervisor.detach(1, Harness::blk, 5, mb::DetachPolicy::wait) == mb::Status::accepted));
    clock.t += std::chrono::hours{1};
    BOOST_TEST(h.supervisor.poll_detaches() == 0U);
    BOOST_TEST(h.supervisor.contains(1));
    BOOST_TEST(h.resetter.resets.empty());
    BOOST_TEST(h.supervisor.stats().detach_timeouts == 0U);
    h.launcher.live[1]->fake_api().guest_ejects("ak-s4-blk-f0");
    BOOST_TEST(h.supervisor.poll_detaches() == 1U);
    const auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST((released(events[0]).device == Harness::blk));
}

BOOST_AUTO_TEST_CASE(detach_timeout_forces_in_place,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    ManualClock clock;
    h.supervisor.set_clock(std::ref(clock));
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::blk) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    BOOST_TEST(
        (h.supervisor.detach(1, Harness::nic, 5, mb::DetachPolicy::force) == mb::Status::accepted));
    clock.t += std::chrono::seconds{6};
    BOOST_TEST(h.supervisor.poll_detaches() == 0U);
    // Reset in place, not released: the VMM still has it open.
    BOOST_TEST((h.resetter.resets == std::vector<std::string>{"0000:03:00.1"}));
    BOOST_TEST(h.supervisor.take_events().empty());
    BOOST_TEST(h.supervisor.stats().forced_in_place == 1U);
    BOOST_TEST((h.supervisor.attach(1, Harness::nic) == mb::Status::conflict));
    // Polling again does not reset it again.
    clock.t += std::chrono::seconds{60};
    BOOST_TEST(h.supervisor.poll_detaches() == 0U);
    BOOST_TEST(h.resetter.resets.size() == 1U);

    // The guest ejects it at last: reset again (the guest may have touched
    // it since) and released.
    h.launcher.live[1]->fake_api().guest_ejects("ak-s3-nic-f1");
    BOOST_TEST(h.supervisor.poll_detaches() == 1U);
    BOOST_TEST(h.resetter.resets.size() == 2U);
    const auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 1U);
    BOOST_TEST((released(events[0]).device == Harness::nic));
}

BOOST_AUTO_TEST_CASE(destroy_and_exit_release_held_functions,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Harness h;
    h.resetter.failing.insert("0000:04:00.0");
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 1, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::blk) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(1, Harness::nic) == mb::Status::ok));
    BOOST_TEST(
        (h.supervisor.detach(1, Harness::nic, 5, mb::DetachPolicy::force) == mb::Status::accepted));
    // Destroy while the NIC's detach is still pending.
    BOOST_TEST((h.supervisor.destroy({.vm_id = 1}) == mb::Status::ok));
    auto events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 2U);
    BOOST_TEST(
        (released(events[0]) ==
         mb::DeviceReleased{.vm_id = 1, .device = Harness::blk, .reset = mb::ResetResult::failed}));
    BOOST_TEST(
        (released(events[1]) ==
         mb::DeviceReleased{.vm_id = 1, .device = Harness::nic, .reset = mb::ResetResult::ok}));
    BOOST_TEST(!h.supervisor.has_pending_detaches());
    BOOST_TEST(h.supervisor.stats().reset_failures == 1U);

    // An unexpected exit: VM_EXITED, then the releases.
    h.resetter.failing.clear();
    BOOST_TEST_REQUIRE(
        (h.supervisor.create({.vm_id = 2, .vcpus = 2, .memory_mib = 1024}) == mb::Status::ok));
    BOOST_TEST_REQUIRE((h.supervisor.attach(2, Harness::blk) == mb::Status::ok));
    h.launcher.live[2]->exit_now(0);
    BOOST_TEST(h.supervisor.poll_exits() == 1U);
    events = h.supervisor.take_events();
    BOOST_TEST_REQUIRE(events.size() == 2U);
    BOOST_TEST(std::holds_alternative<mb::VmExited>(events[0]));
    BOOST_TEST((released(events[1]).vm_id == 2U));
}
