// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A khold volume as a BlockBackend (kythira
// .kiro/specs/khold-block-service/ task 16): the KholdInitiatorCore
// (khold_initiator.hpp) on the role thread, and a HoldTransport speaking
// hold wire version 2 with one session per stripe group leader (or per
// gateway in a split layout), each on its own I/O thread, so a leader
// that hangs holds up only its own groups.
//
// The role thread owns the core: submits, poll() and set_layout() run
// there, and so do completions; wake_fd() is the transport's. Sessions
// are mutually authenticated TLS 1.3 like hold's: the certificate's
// server URI must name the server ID the layout gives the member.
//
// Until set_layout() delivers the first VolumeLayout, requests are held.
// The backend frees space (supports_trim): the function in front offers
// virtio-blk DISCARD and WRITE_ZEROES (Requirement 4.2). Faults wait in
// take_faults() for BlkRole's report path. The process must ignore
// SIGPIPE.

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

#include "oar/blk/hold_transport.hpp"
#include "oar/blk/khold_initiator.hpp"
#include "oar/blk/network_volume_backend.hpp"
#include "proto/volume_layout.hpp"
#include "tls/tls.hpp"

namespace ak::oar::blk {

struct KholdVolumeConfig {
    KholdInitiatorConfig initiator;
    tls::Config tls;  // client; peer_name is set per connection
    std::chrono::milliseconds connect_timeout{2000};
    std::chrono::milliseconds write_timeout{2000};
};

class KholdVolumeBackend final : public AttachedVolume {
public:
    [[nodiscard]] static auto create(KholdVolumeConfig config)
        -> std::expected<std::unique_ptr<KholdVolumeBackend>, NetworkVolumeError>;

    KholdVolumeBackend(const KholdVolumeBackend&) = delete;
    auto operator=(const KholdVolumeBackend&) -> KholdVolumeBackend& = delete;
    KholdVolumeBackend(KholdVolumeBackend&&) = delete;
    auto operator=(KholdVolumeBackend&&) -> KholdVolumeBackend& = delete;
    // Stops the I/O threads; requests still pending are dropped without
    // their completions.
    ~KholdVolumeBackend() override;

    // helm: the volume's VolumeLayout (verified by the role), first and
    // after each change.
    [[nodiscard]] auto set_layout(const proto::VolumeLayout& l) -> std::expected<void, RouteError>;

    // AttachedVolume
    auto set_tls(const tls::Config& config) -> void override;
    [[nodiscard]] auto routed() const noexcept -> bool override;
    [[nodiscard]] auto fenced() const noexcept -> bool override;
    [[nodiscard]] auto take_faults() -> std::vector<FaultEvent> override;
    [[nodiscard]] auto sessions_open() const noexcept -> std::size_t;

    // BlockBackend. size_bytes() is 0 until the layout arrives.
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override;
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done)
        -> void override;
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done)
        -> void override;
    auto submit_flush(BackendCompletion done) -> void override;
    [[nodiscard]] auto supports_trim() const noexcept -> bool override { return true; }
    auto submit_discard(std::uint64_t offset, std::uint64_t length, BackendCompletion done)
        -> void override;
    auto submit_write_zeroes(std::uint64_t offset, std::uint64_t length, BackendCompletion done)
        -> void override;
    // HydrationTarget: refused (io) until khold hydrates restores itself
    // (kythira khold spec phase 2); no layout names an image source yet.
    auto submit_hydrate(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done)
        -> void override;
    [[nodiscard]] auto poll() -> bool override;
    [[nodiscard]] auto wake_fd() const noexcept -> int override;

private:
    KholdVolumeBackend(KholdVolumeConfig config, std::unique_ptr<HoldTransport> transport) noexcept;

    auto publish() -> void;

    KholdVolumeConfig _config;
    KholdInitiatorCore _core;
    std::unique_ptr<HoldTransport> _transport;
};

}  // namespace ak::oar::blk
