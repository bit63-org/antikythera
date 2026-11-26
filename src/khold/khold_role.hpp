// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The khold role's end of helm's sideband (kythira
// .kiro/specs/khold-block-service/ task 17, design "Running on
// antikythera"): an OarHandler in front of the khold node it launched.
// helm relays the controller's VolumeLayout frames byte for byte, so the
// role checks each one itself, as the hold role checks a ReplicaConfig: it
// must decode, name this server, and verify under a controller key
// (Requirement 16.3). helm verifies nothing on this path.
//
//   function_inventory  role khold, no functions (a khold role serves the
//                       storage network, not guests)
//   volume_layout       decode, verify, refuse an epoch older than the
//                       newest kept for the volume (the same epoch again
//                       is accepted and changes nothing), keep it, and
//                       hand the exact frame to the node; a layout that no
//                       longer names this server still goes to the node,
//                       which lets the volume go, and is then forgotten
//   self_test           starts the storage self-test (self_test.hpp) in
//                       the background unless one runs; its result is the
//                       role's next capacity report
//   hold_reports        pump() moves the node's reports and finished
//                       self-tests into an oar::ReportQueue as encoded
//                       proto::Reports numbered from a random start,
//                       which helm drains and acknowledges
//   cert_request,       the role's storage identity (enrollment), when
//   role_certificate    set_enrollment gave it one; a certificate taken
//                       starts a self-test, so the controller has fresh
//                       measurements for a newly enrolled server
//   health              degraded (fault_code node_down) while the node is
//                       not running
//
// Replay. The role keeps the newest layout of each volume it serves; when
// the node's generation changes (it was restarted) the role hands them all
// over again, in volume order, so a restarted node catches up without
// helm or the controller. helm does the same for a restarted role.
//
// Capacity. The self-test knows each drive's size and speed and the link's
// speed; the node knows what it has placed on each drive. A capacity
// report from the node is not relayed as it is: the role merges it with
// the newest self-test (the node's state, allocated, reserved and replica
// figures; the test's capacity, IOPS, throughput and link) and reports the
// merge, so the controller always gets one consistent picture per slot.
// A drive the self-test found failed stays failed whatever the node says.
//
// A refusal answers failed (a frame that decodes but fails its checks or
// that the node would not take), bad_request (one that does not decode) or
// busy (too many volumes kept). Single-threaded, apart from the self-test,
// which runs on its own thread and touches nothing of the role's: call
// everything from the loop that serves the sideband.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "helm/oar_link.hpp"
#include "helm/role_enrollment.hpp"
#include "proto/report.hpp"

namespace ak::khold {

namespace oar = helm::oar;
using Clock = std::chrono::steady_clock;

// Verifies an Ed25519 signature over `message` under controller key `key_id`.
using FrameVerifier =
    std::function<bool(std::span<const std::byte> message, std::span<const std::byte, 64> signature,
                       std::uint16_t key_id)>;

// Runs the storage self-test (blocking; the role calls it on its own
// thread).
using SelfTestFn = std::function<proto::Capacity()>;

// The khold node the role launched and feeds (node_process.hpp in ak-khold;
// a fake in tests).
class KholdNode {
public:
    KholdNode() = default;
    KholdNode(const KholdNode&) = delete;
    auto operator=(const KholdNode&) -> KholdNode& = delete;
    KholdNode(KholdNode&&) = delete;
    auto operator=(KholdNode&&) -> KholdNode& = delete;
    virtual ~KholdNode() = default;

    // Hands the node a verified layout (the exact frame); false if it could
    // not take it.
    virtual auto apply_layout(std::uint64_t volume_id, std::uint64_t epoch,
                              std::span<const std::byte> frame) -> bool = 0;
    // What the node reported since the last call.
    virtual auto take_reports() -> std::vector<proto::ReportBody> = 0;
    // Changes every time the node (re)starts.
    [[nodiscard]] virtual auto generation() const -> std::uint64_t = 0;
    [[nodiscard]] virtual auto running() const -> bool = 0;
};

// health fault_code bits.
inline constexpr std::uint16_t fault_node_down = 0x1;
inline constexpr std::uint16_t fault_drive_failed = 0x2;

// Layouts kept for replay: one per volume this server serves.
inline constexpr std::size_t max_kept_layouts = 4096;

struct KholdRoleStats {
    std::uint64_t layouts{0};          // taken and handed to the node
    std::uint64_t layouts_dropped{0};  // no longer naming this server: forgotten
    std::uint64_t refused{0};          // failed a check, or the node would not take it
    std::uint64_t replays{0};          // layouts handed to a restarted node
    std::uint64_t self_tests{0};       // finished
    std::uint64_t reports{0};          // queued for helm
    std::uint64_t reports_dropped{0};  // node reports of a kind helm would not relay
};

class KholdRole final : public helm::OarHandler {
public:
    // `node` must outlive the role. `first_seq` numbers the first report
    // (non-zero; random, so a restarted role is not mistaken for a replay).
    // The role starts a self-test at once (enrollment: the first
    // measurements of this server).
    KholdRole(KholdNode& node, std::uint64_t server_id, FrameVerifier verify,
              std::uint64_t first_seq, SelfTestFn self_test,
              std::function<Clock::time_point()> clock = Clock::now);
    KholdRole(const KholdRole&) = delete;
    auto operator=(const KholdRole&) -> KholdRole& = delete;
    KholdRole(KholdRole&&) = delete;
    auto operator=(KholdRole&&) -> KholdRole& = delete;
    // Waits for a running self-test.
    ~KholdRole() override;

    // Replays layouts to a restarted node, and queues the node's reports
    // and a finished self-test for helm.
    auto pump() -> void;

    // Enrollment: answer cert_request and role_certificate through
    // `enrollment`, which must outlive the role.
    auto set_enrollment(helm::RoleEnrollment& enrollment) noexcept -> void {
        _enrollment = &enrollment;
    }

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override;
    auto prepare_function(const oar::PrepareFunction& request) -> oar::Status override;
    auto clean_function(const oar::CleanFunction& request) -> oar::Status override;
    auto deliver_key(const oar::DeliverKey& request) -> oar::Status override;
    auto drop_key(const oar::DropKey& request) -> oar::Status override;
    auto map_update(std::span<const std::byte> frame) -> oar::Status override;
    auto health() -> std::expected<oar::Health, oar::Status> override;
    auto volume_layout(std::span<const std::byte> frame) -> oar::Status override;
    auto self_test() -> oar::Status override;
    auto hold_reports(const oar::ReportRequest& request)
        -> std::expected<oar::ReportChunk, oar::Status> override;
    auto cert_request() -> std::expected<oar::CertAnswer, oar::Status> override;
    auto role_certificate(std::span<const std::byte> chain) -> oar::Status override;

    [[nodiscard]] auto stats() const noexcept -> const KholdRoleStats& { return _stats; }
    [[nodiscard]] auto queued_reports() const noexcept -> std::size_t { return _reports.size(); }
    [[nodiscard]] auto kept_layouts() const noexcept -> std::size_t { return _layouts.size(); }
    [[nodiscard]] auto self_test_running() const noexcept -> bool { return _test.valid(); }
    // The newest capacity picture (the merge), once there is one.
    [[nodiscard]] auto capacity() const noexcept -> const std::optional<proto::Capacity>& {
        return _merged;
    }

private:
    struct KeptLayout {
        std::uint64_t epoch{0};
        std::vector<std::byte> frame;
    };

    auto queue(proto::ReportBody body) -> void;
    auto start_self_test() -> void;
    auto merge_capacity() -> void;

    KholdNode& _node;
    std::uint64_t _server_id;
    FrameVerifier _verify;
    std::uint64_t _next_seq;
    SelfTestFn _run_test;
    std::function<Clock::time_point()> _clock;
    Clock::time_point _started;
    std::uint64_t _node_generation;
    std::map<std::uint64_t, KeptLayout> _layouts;  // by volume
    std::future<proto::Capacity> _test;
    std::optional<proto::Capacity> _measured;   // the newest self-test
    std::optional<proto::Capacity> _from_node;  // the node's newest capacity report
    std::optional<proto::Capacity> _merged;
    oar::ReportQueue _reports;
    KholdRoleStats _stats;
    helm::RoleEnrollment* _enrollment{nullptr};
};

}  // namespace ak::khold
