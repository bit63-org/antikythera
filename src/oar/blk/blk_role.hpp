// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// BlkRole: the storage data-plane role as helm sees it over the sideband
// (.kiro/specs/oar-blk-data-plane/ Requirement 3, task 6): a fixed set of
// virtio-blk PCI functions and a directory of volume files (FileBackend),
// driven by helm's OarLink requests.
//
//   create_volume     a new volume file holding the wrapped key helm sent
//   prepare_function  open a volume for one VM and put it behind a function;
//                     the function holds the guest's I/O until the key comes
//                     (VirtioBlkFunction::await_key)
//   deliver_key       load the volume key into that function
//   drop_key          wipe it
//   clean_function    wipe the key and close the volume: the function is
//                     back to its empty placeholder
//   rewrap_volume     new owner and wrapped key in the volume's header
//   delete_volume     erase and unlink the volume file (closing it first if
//                     a function still has it: helm deletes the volumes of a
//                     destroyed VM before their functions are cleaned)
//   eject             cooperative detach of an attached function (block
//                     volume task 13): ask the guest to release it, withdraw
//                     that, or look (VirtioBlkFunction::eject_state)
//
// Each function sits on a FunctionTransport (vfio-user in harbor). The
// transport exists for the life of the role, since the client (L0 QEMU in
// harbor) attaches at boot; what it serves changes with each attachment.
// Between attachments it serves a placeholder: a virtio-blk function over
// an empty backend with no key, so nothing a stray driver does reaches a
// volume. Every function, placeholder or not, has the same queues and so
// the same PCI shape, which is what lets a transport swap them.
//
// Image volumes (Requirement 8, task 13): create_volume with an image
// source writes a header-only volume file naming the store and image;
// prepare_function fetches the image's manifest from that store, checks it
// against the name, and serves the volume with a LazyImageBackend over the
// shared chunk cache, with a fresh, empty overlay. The key helm delivers is
// the attachment's ephemeral key: it goes to the function and to the
// backend, which re-encrypts image blocks under it. Every way the key goes
// (drop_key, cleaning, FLR) discards the overlay with it, so an image
// volume never comes back with an earlier attachment's writes. Encrypted
// images (task 15) are refused until helm can deliver their image key.
//
// Network volumes (.kiro/specs/block-volume-service/ task 12): helm sends
// each ReplicaConfig whose attachments name this server (replica_config);
// the role verifies its signature under a controller key, checks that it
// names this server, and keeps the newest per volume. prepare_function
// with an attachment then serves the volume with a NetworkVolumeBackend
// (network_volume_backend.hpp) routed by that config, which opens its TLS
// session to the primary with the storage certificate; a later config for
// the volume re-routes the live attachment (a new primary, or fencing) and
// carries resizes and QoS changes to it: a larger capacity grows the
// function (VirtioBlkFunction::grow), so the guest sees it online.
// The geometry comes from the config, read-only for an ro attachment. The
// key helm delivers is the attachment's, opened in its secure element.
// Without verify_config the role takes no network volumes. Enrollment
// (set_enrollment): the role's storage certificate comes from the
// controller through helm; until it has one (storage_tls empty) network
// attachments are refused, and a renewed one goes to every live
// initiator for its next connection.
//
// The volume files are named vol-<16 hex digits>.akv in the volume
// directory. The role checks a volume's header against the request: a
// prepare for a VM other than the volume's owner is refused, as helm's
// KeyStore would refuse to unwrap its key anyway.
//
// Not thread-safe: the sideband and the transports share one thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "helm/oar_link.hpp"
#include "helm/role_enrollment.hpp"
#include "objstore/chunk_cache.hpp"
#include "objstore/fetcher.hpp"
#include "oar/blk/file_backend.hpp"
#include "oar/blk/lazy_image_backend.hpp"
#include "oar/blk/network_volume_backend.hpp"
#include "objstore/object_store.hpp"
#include "oar/blk/virtio_blk_function.hpp"

namespace ak::oar::blk {

// One PCI function's transport, as the role drives it.
class FunctionTransport {
public:
    FunctionTransport() = default;
    FunctionTransport(const FunctionTransport&) = delete;
    auto operator=(const FunctionTransport&) -> FunctionTransport& = delete;
    FunctionTransport(FunctionTransport&&) = delete;
    auto operator=(FunctionTransport&&) -> FunctionTransport& = delete;
    virtual ~FunctionTransport() = default;

    // The guest memory and interrupts every function on this transport uses.
    [[nodiscard]] virtual auto memory() -> const virtio::GuestMemory& = 0;
    [[nodiscard]] virtual auto interrupts() -> virtio::InterruptSink& = 0;
    // Serves `function` from now on; `on_flr` runs on the transport's
    // function-level reset instead of PciFunction::reset (it must wipe the
    // key: VirtioBlkFunction::function_reset). `function` stays valid until
    // the next serve().
    [[nodiscard]] virtual auto serve(virtio::PciFunction& function, std::function<void()> on_flr)
        -> std::expected<void, std::string> = 0;
};

// An object store image volumes can name, as the role is configured with
// it. Both pointers must outlive the role.
struct ImageStore {
    objstore::ObjectStore* store{nullptr};
    objstore::Fetcher* fetcher{nullptr};  // fetches from `store`
    std::string prefix;                   // object keys are <prefix>/<image name>/...
};

struct RoleConfig {
    using Clock = std::chrono::steady_clock;

    std::filesystem::path volume_dir;
    std::uint16_t num_queues{1};
    std::uint16_t queue_size{256};
    std::uint32_t seg_max{128};
    std::uint32_t max_transfer_bytes{1U << 20U};
    std::size_t budget{256};
    // Image volumes: the stores by ID, the chunk cache they share (must
    // outlive the role; null: no image volumes), and the overlays.
    std::map<std::uint16_t, ImageStore> image_stores;
    objstore::ChunkCache* image_cache{nullptr};
    std::filesystem::path overlay_dir;     // empty: volume_dir
    std::uint64_t overlay_limit_bytes{0};  // per volume; 0: up to its capacity
    std::uint32_t max_readahead_chunks{8};
    // Requests each queue of an image volume keeps in its backend at once
    // (BlkParams::max_in_flight, each with a max_transfer_bytes bounce
    // buffer), so a read waiting for a chunk does not hold up the reads
    // the cache can answer, or the writes and flushes, behind it. 1 to
    // queue_size. Disk volumes keep 1: their backend completes in the call.
    std::uint16_t image_max_in_flight{8};
    std::chrono::milliseconds manifest_deadline{10000};
    // Network volumes: this server, the controller-key check for their
    // ReplicaConfigs (message, signature, key ID), and the TLS client
    // configuration for sessions to hold roles (the storage certificate).
    std::uint64_t server_id{0};
    std::function<bool(std::span<const std::byte>, std::span<const std::byte, 64>, std::uint16_t)>
        verify_config;
    std::optional<tls::Config> storage_tls;
    InitiatorConfig initiator;  // attachment_id is set per attachment
    // Empty: steady_clock::now (health's uptime).
    std::function<Clock::time_point()> clock;
};

// Network volume configs a role keeps at once.
inline constexpr std::size_t max_network_configs = 1024;

// What a GET_ID returns for a volume: "akv-" and its ID in 16 hex digits,
// exactly the 20 bytes virtio-blk allows.
[[nodiscard]] auto volume_serial(std::uint64_t volume_id) -> std::string;

class BlkRole final : public helm::OarHandler {
public:
    // One function per transport, numbered from 0 in order; each starts on
    // its placeholder. Every transport must outlive the role.
    [[nodiscard]] static auto create(RoleConfig config,
                                     const std::vector<FunctionTransport*>& transports)
        -> std::expected<std::unique_ptr<BlkRole>, std::string>;

    BlkRole(const BlkRole&) = delete;
    auto operator=(const BlkRole&) -> BlkRole& = delete;
    BlkRole(BlkRole&&) = delete;
    auto operator=(BlkRole&&) -> BlkRole& = delete;
    ~BlkRole() override;

    // helm::OarHandler
    auto function_inventory() -> std::expected<helm::oar::Inventory, helm::oar::Status> override;
    auto prepare_function(const helm::oar::PrepareFunction& request) -> helm::oar::Status override;
    auto clean_function(const helm::oar::CleanFunction& request) -> helm::oar::Status override;
    auto deliver_key(const helm::oar::DeliverKey& request) -> helm::oar::Status override;
    auto drop_key(const helm::oar::DropKey& request) -> helm::oar::Status override;
    auto map_update(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto health() -> std::expected<helm::oar::Health, helm::oar::Status> override;
    auto create_volume(const helm::oar::CreateVolume& request) -> helm::oar::Status override;
    auto delete_volume(const helm::oar::DeleteVolume& request) -> helm::oar::Status override;
    auto rewrap_volume(const helm::oar::RewrapVolume& request) -> helm::oar::Status override;
    auto replica_config(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto cert_request() -> std::expected<helm::oar::CertAnswer, helm::oar::Status> override;
    auto role_certificate(std::span<const std::byte> chain) -> helm::oar::Status override;
    auto eject(const helm::oar::Eject& request)
        -> std::expected<helm::oar::EjectState, helm::oar::Status> override;

    // Enrollment through `enrollment` (must outlive the role); its Apply
    // should call set_storage_tls.
    auto set_enrollment(helm::RoleEnrollment& enrollment) noexcept -> void {
        _enrollment = &enrollment;
    }
    // The storage certificate, first or renewed: new attachments use it,
    // and live ones on their next connection.
    auto set_storage_tls(const tls::Config& config) -> void;

    // Serves deferred requests on every attached function; true if any
    // still has work (call again soon).
    auto poll() -> bool;
    // The backends' wake descriptors (VirtioBlkFunction::wake_fd) of the
    // attached functions, for the event loop to sleep on alongside the
    // transports; call poll() when one is readable.
    [[nodiscard]] auto wake_fds() const -> std::vector<int>;

    [[nodiscard]] auto volume_path(std::uint64_t volume_id) const -> std::filesystem::path;
    [[nodiscard]] auto function_count() const noexcept -> std::size_t { return _slots.size(); }
    // The volume function `fn` has open, if any.
    [[nodiscard]] auto attached(helm::oar::FunctionNumber fn) const -> std::optional<std::uint64_t>;
    // The attached function itself (tests, counters); null between attachments.
    [[nodiscard]] auto function(helm::oar::FunctionNumber fn) -> VirtioBlkFunction*;

private:
    struct Slot {
        FunctionTransport* transport{nullptr};
        std::unique_ptr<VirtioBlkFunction> placeholder;
        std::unique_ptr<VirtioBlkFunction> active;
        std::uint64_t volume{0};
        LazyImageBackend* image{nullptr};  // the active function's backend, for an image volume
        NetworkVolumeBackend* network{nullptr};  // ... for a network volume
    };

    explicit BlkRole(RoleConfig config) : _config{std::move(config)} {}

    [[nodiscard]] auto slot(helm::oar::FunctionNumber fn) -> Slot*;
    [[nodiscard]] auto slot_of_volume(std::uint64_t volume) -> Slot*;
    [[nodiscard]] auto params(const VolumeGeometry& geometry, std::string_view serial,
                              std::uint16_t max_in_flight = 1) const -> BlkParams;
    // Wipes the key, closes the volume and puts the placeholder back.
    auto close(Slot& s) -> bool;
    // The backend for an image volume, ready for its key.
    [[nodiscard]] auto open_image_volume(const VolumeMetadata& m)
        -> std::expected<std::unique_ptr<LazyImageBackend>, std::string>;
    auto prepare_network(Slot& s, const helm::oar::PrepareFunction& request,
                         const helm::oar::BlkConfig& cfg) -> helm::oar::Status;
    // Puts `f` behind the slot's transport (the placeholder back on failure).
    auto serve_active(Slot& s, std::unique_ptr<VirtioBlkFunction> f, std::uint64_t volume,
                      LazyImageBackend* image, NetworkVolumeBackend* network) -> helm::oar::Status;

    RoleConfig _config;
    std::vector<Slot> _slots;
    std::map<std::uint64_t, proto::ReplicaConfig> _configs;  // network volumes, newest
    RoleConfig::Clock::time_point _started;
    helm::RoleEnrollment* _enrollment{nullptr};
};

}  // namespace ak::oar::blk
