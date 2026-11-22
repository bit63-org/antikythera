// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A network volume as a BlockBackend (.kiro/specs/block-volume-service/
// task 7): the InitiatorCore (initiator.hpp) on the role thread, and one
// I/O thread that carries its frames to the volume's primary hold over
// mutually authenticated TLS 1.3 on the storage segment.
//
// Threads. The role thread owns the core: submits, poll() and set_route()
// run there, and so do completions. The I/O thread owns the connection.
// They share a small mailbox: the target session and the frames for it
// one way, connection events and received frames the other. The inbox's
// eventfd and a timerfd armed for the core's next wake sit in one epoll
// descriptor, which is wake_fd(); poll() drains both.
//
// Connecting (Requirement 13.1). Each session gets a fresh TLS context
// that pins the primary's address from the route (its IP SAN), and the
// connection is used only if the certificate's server URI names the
// server ID the route gives for the primary. Storage traffic carries DSCP
// AF41.
//
// Until set_route() delivers the first ReplicaConfig, requests are held
// (Requirement 2.2, the route's side of VirtioBlkFunction::await_key).
// Faults the core reports (primary timeout, fenced, checksum) wait in
// take_faults() for helm's report path.

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include "oar/blk/initiator.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "proto/replica_config.hpp"
#include "tls/tls.hpp"

namespace ak::oar::blk {

struct NetworkVolumeConfig {
    InitiatorConfig initiator;
    tls::Config tls;  // client; peer_name is set per connection
    std::chrono::milliseconds connect_timeout{2000};
    std::chrono::milliseconds write_timeout{2000};
};

enum class NetworkVolumeError : std::uint8_t {
    tls,     // the TLS configuration does not load
    system,  // an eventfd, timerfd, epoll descriptor or the thread failed
};

[[nodiscard]] auto to_string(NetworkVolumeError e) noexcept -> const char*;

class NetworkVolumeBackend final : public BlockBackend {
public:
    [[nodiscard]] static auto create(NetworkVolumeConfig config)
        -> std::expected<std::unique_ptr<NetworkVolumeBackend>, NetworkVolumeError>;

    NetworkVolumeBackend(const NetworkVolumeBackend&) = delete;
    auto operator=(const NetworkVolumeBackend&) -> NetworkVolumeBackend& = delete;
    NetworkVolumeBackend(NetworkVolumeBackend&&) = delete;
    auto operator=(NetworkVolumeBackend&&) -> NetworkVolumeBackend& = delete;
    // Stops the I/O thread (after at most one connect_timeout); requests
    // still pending are dropped without their completions.
    ~NetworkVolumeBackend() override;

    // helm: the volume's ReplicaConfig, first and after each change.
    [[nodiscard]] auto set_route(const proto::ReplicaConfig& c) -> std::expected<void, RouteError>;
    [[nodiscard]] auto routed() const noexcept -> bool;
    [[nodiscard]] auto fenced() const noexcept -> bool;
    [[nodiscard]] auto take_faults() -> std::vector<InitiatorFault>;
    [[nodiscard]] auto session_open() const noexcept -> bool;

    // BlockBackend. size_bytes() is 0 until the route arrives.
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override;
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done)
        -> void override;
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done)
        -> void override;
    auto submit_flush(BackendCompletion done) -> void override;
    [[nodiscard]] auto poll() -> bool override;
    [[nodiscard]] auto wake_fd() const noexcept -> int override;

private:
    struct Shared;
    NetworkVolumeBackend(NetworkVolumeConfig config, std::unique_ptr<Shared> shared) noexcept;

    auto publish() -> void;

    NetworkVolumeConfig _config;
    InitiatorCore _core;
    std::unique_ptr<Shared> _shared;
};

}  // namespace ak::oar::blk
