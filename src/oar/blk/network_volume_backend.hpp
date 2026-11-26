// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A network volume as a BlockBackend (.kiro/specs/block-volume-service/
// task 7): the InitiatorCore (initiator.hpp) on the role thread, and a
// HoldTransport (hold_transport.hpp) that carries its frames to the
// volume's primary hold over mutually authenticated TLS 1.3 on the storage
// segment, on an I/O thread of its own.
//
// The role thread owns the core: submits, poll() and set_route() run
// there, and so do completions. wake_fd() is the transport's: it becomes
// readable when the I/O thread posted connection events or frames, or at
// the core's next wake; poll() takes them.
//
// Connecting (Requirement 13.1). Each session gets a fresh TLS context
// that pins the primary's address from the route (its IP SAN), and the
// connection is used only if the certificate's server URI names the
// server ID the route gives for the primary. Storage traffic carries DSCP
// AF41.
//
// Until set_route() delivers the first ReplicaConfig, requests are held
// (Requirement 2.2, the route's side of VirtioBlkFunction::await_key).
// The process must ignore SIGPIPE, as the roles' mains do: a hold that
// hangs up mid-write would otherwise end it.
//
// Faults the core reports (primary timeout, fenced, checksum, media
// error) wait in take_faults(); BlkRole turns them into reports for helm.
//
// A volume restored from an image under another key answers reads of
// blocks not yet hydrated with BackendError::not_hydrated, and takes
// hydrate writes (submit_hydrate): HydratingBackend (task 23) sits in
// front of it for such a volume.

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include "oar/blk/hold_transport.hpp"
#include "oar/blk/hydration_target.hpp"
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

// What BlkRole needs of an attached network volume, whichever backend
// serves it (hold: NetworkVolumeBackend; khold: KholdVolumeBackend).
// It takes hydrate writes too, so HydratingBackend can sit in front of
// either; khold refuses them until its own hydration (phase 2).
class AttachedVolume : public HydrationTarget {
public:
    // A renewed storage certificate: the next connection presents it; an
    // open session keeps the one it was made with.
    virtual auto set_tls(const tls::Config& config) -> void = 0;
    [[nodiscard]] virtual auto routed() const noexcept -> bool = 0;
    [[nodiscard]] virtual auto fenced() const noexcept -> bool = 0;
    [[nodiscard]] virtual auto take_faults() -> std::vector<FaultEvent> = 0;
};

class NetworkVolumeBackend final : public AttachedVolume {
public:
    [[nodiscard]] static auto create(NetworkVolumeConfig config)
        -> std::expected<std::unique_ptr<NetworkVolumeBackend>, NetworkVolumeError>;

    NetworkVolumeBackend(const NetworkVolumeBackend&) = delete;
    auto operator=(const NetworkVolumeBackend&) -> NetworkVolumeBackend& = delete;
    NetworkVolumeBackend(NetworkVolumeBackend&&) = delete;
    auto operator=(NetworkVolumeBackend&&) -> NetworkVolumeBackend& = delete;
    // Stops the I/O threads (after at most one connect_timeout); requests
    // still pending are dropped without their completions.
    ~NetworkVolumeBackend() override;

    // helm: the volume's ReplicaConfig, first and after each change.
    [[nodiscard]] auto set_route(const proto::ReplicaConfig& c) -> std::expected<void, RouteError>;
    auto set_tls(const tls::Config& config) -> void override;
    [[nodiscard]] auto routed() const noexcept -> bool override;
    [[nodiscard]] auto fenced() const noexcept -> bool override;
    [[nodiscard]] auto take_faults() -> std::vector<FaultEvent> override;
    [[nodiscard]] auto session_open() const noexcept -> bool;

    // BlockBackend. size_bytes() is 0 until the route arrives.
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override;
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done)
        -> void override;
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done)
        -> void override;
    auto submit_flush(BackendCompletion done) -> void override;
    // HydrationTarget: InitiatorCore::submit_hydrate.
    auto submit_hydrate(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done)
        -> void override;
    [[nodiscard]] auto poll() -> bool override;
    [[nodiscard]] auto wake_fd() const noexcept -> int override;

private:
    NetworkVolumeBackend(NetworkVolumeConfig config,
                         std::unique_ptr<HoldTransport> transport) noexcept;

    auto publish() -> void;

    NetworkVolumeConfig _config;
    InitiatorCore _core;
    std::unique_ptr<HoldTransport> _transport;
};

}  // namespace ak::oar::blk
