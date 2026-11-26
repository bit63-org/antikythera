// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// NodeProcess: how ak-khold launches and feeds the khold node (kythira
// .kiro/specs/khold-block-service/ task 17, "launch"). The node is
// kythira's `khold_node`, a separate program; this is the whole contract
// between the two, kept to files and signals so neither links the other:
//
//   launch      ak-khold runs `argv` (the node and its arguments, from
//               ak-khold's command line) as a child process and restarts
//               it when it exits, after restart_min, doubling up to
//               restart_max while it keeps exiting within restart_max of
//               its start. Each start is a new generation.
//   layouts     each verified VolumeLayout frame is written, exactly as
//               the controller signed it, to layout_dir/<volume>.vlay
//               (volume ID in 16 lowercase hex digits), through a
//               temporary file and a rename, so the node never sees half
//               a frame. The node reads every *.vlay when it starts and
//               watches the directory after that; it verifies each frame
//               itself and applies an epoch only if it is new.
//   reports     the node writes encoded proto::Report frames (any server
//               ID and sequence number: the role renumbers them) to
//               report_dir, each through a temporary name not ending in
//               .rpt and a rename to <anything>.rpt. ak-khold takes them
//               in name order and deletes each one it has read, so names
//               that sort by time (a zero-padded counter) keep the order.
//   certificate the node reads its TLS certificate and key from the files
//               ak-khold's storage identity keeps (--cert, --key); after
//               the role takes a new certificate, ak-khold sends the node
//               SIGHUP to read them again.
//   stop        SIGTERM, then SIGKILL after stop_grace.
//
// Not thread-safe: the role's loop owns it.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <sys/types.h>

#include "khold/khold_role.hpp"

namespace ak::khold {

struct NodeProcessConfig {
    std::vector<std::string> argv;  // the node program and its arguments
    std::filesystem::path layout_dir;
    std::filesystem::path report_dir;
    std::chrono::milliseconds restart_min{std::chrono::seconds{1}};
    std::chrono::milliseconds restart_max{std::chrono::seconds{30}};
    std::chrono::milliseconds stop_grace{std::chrono::seconds{5}};
    // Report files read per take_reports call.
    std::size_t max_reports{64};
};

struct NodeProcessStats {
    std::uint64_t starts{0};
    std::uint64_t exits{0};
    std::uint64_t start_failures{0};
    std::uint64_t layouts_written{0};
    std::uint64_t layout_write_failures{0};
    std::uint64_t reports_read{0};
    std::uint64_t reports_bad{0};  // did not decode: deleted
};

// The name a volume's layout has in layout_dir.
[[nodiscard]] auto layout_file_name(std::uint64_t volume_id) -> std::string;

class NodeProcess final : public KholdNode {
public:
    // Creates both directories. Does not start the node: poll() does.
    explicit NodeProcess(NodeProcessConfig config);
    NodeProcess(const NodeProcess&) = delete;
    auto operator=(const NodeProcess&) -> NodeProcess& = delete;
    NodeProcess(NodeProcess&&) = delete;
    auto operator=(NodeProcess&&) -> NodeProcess& = delete;
    // Stops the node.
    ~NodeProcess() override;

    // Reaps an exited node and starts it when it is due.
    auto poll(Clock::time_point now) -> void;
    // Asks the node to read its certificate again.
    auto reload() -> void;
    // Stops the node and does not start it again.
    auto stop() -> void;

    auto apply_layout(std::uint64_t volume_id, std::uint64_t epoch,
                      std::span<const std::byte> frame) -> bool override;
    auto take_reports() -> std::vector<proto::ReportBody> override;
    [[nodiscard]] auto generation() const -> std::uint64_t override { return _generation; }
    [[nodiscard]] auto running() const -> bool override { return _pid > 0; }

    [[nodiscard]] auto pid() const noexcept -> pid_t { return _pid; }
    [[nodiscard]] auto stats() const noexcept -> const NodeProcessStats& { return _stats; }

private:
    auto start(Clock::time_point now) -> void;

    NodeProcessConfig _config;
    pid_t _pid{-1};
    std::uint64_t _generation{0};
    bool _stopped{false};
    Clock::time_point _started_at{};
    Clock::time_point _next_start{};
    std::chrono::milliseconds _backoff;
    NodeProcessStats _stats;
};

}  // namespace ak::khold
