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
//   rewrap_volume     new owner and wrapped key in the volume's header (a
//                     disk volume, or an encrypted image volume's K_img)
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
// volume never comes back with an earlier attachment's writes.
//
// Encrypted images (task 15): the volume file holds the image key K_img
// wrapped by helm, as a disk volume holds its volume key, and
// prepare_function refuses an encrypted image whose volume has no key (or
// a plain image whose volume has one). deliver_key then carries K_img with
// the ephemeral key; the backend decrypts image blocks with it before
// re-encrypting them under the ephemeral key, and drops it with that key.
// rewrap_volume rewrites an encrypted image volume's owner and key like a
// disk volume's.
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
// Without verify_config the role takes no network volumes.
//
// Foreign-key restores (.kiro/specs/block-volume-service/ task 23): a
// config whose source is an image (a public image, or an encrypted one
// under another key) puts a HydratingBackend in front of the network
// backend. prepare_function opens the image from the store the source
// names, as for an image volume; deliver_key gives the volume key (and
// K_img for an encrypted image) to the function and to the hydrating
// backend, which fills unhydrated blocks under the volume key as the
// guest reads them and in the background at the source's rate. Every way
// the key goes takes the hydrating backend's copies with it. Enrollment
// (set_enrollment): the role's storage certificate comes from the
// controller through helm; until it has one (storage_tls empty) network
// attachments are refused, and a renewed one goes to every live
// initiator for its next connection.
//
// Local <-> network conversion (.kiro/specs/block-volume-service/
// Requirement 8.6, task 23.2): copy_volume start copies a detached local
// volume into a new network volume, or a network volume into a new local
// one, with a VolumeCopier (volume_copier.hpp) and no function: the local
// side is the volume file, the network side a NetworkVolumeBackend for
// the attachment the request names, which the newest ReplicaConfig must
// list for this server (read-write when it is the target). Both volumes
// must share a block size, neither may be attached or in another copy, a
// local volume must be a disk volume (not an image), and a network target
// must have no source (a restore's blocks await hydration, so it is not
// new). The copy runs in poll() beside the functions; a later config
// re-routes its network side as it would an attachment's, and a renewed
// storage certificate reaches it too. query answers its state and
// progress until release forgets it; prepare_function, rewrap_volume and
// a second copy of either volume are busy meanwhile, and delete_volume of
// either drops the copy first.
// khold volumes (kythira .kiro/specs/khold-block-service/ task 16): helm
// sends each VolumeLayout whose attachments name this server
// (volume_layout); the role verifies its signature under a controller key
// as it does a ReplicaConfig, checks that it names this server, and keeps
// the newest per volume. prepare_function with an attachment serves a
// volume that has a layout with a KholdVolumeBackend (hold wire version 2,
// one session per stripe group leader) and one that has a ReplicaConfig
// with a NetworkVolumeBackend; a later layout re-routes the live
// attachment (members, fencing, QoS, growth) like a later config. A khold
// function offers virtio-blk DISCARD and WRITE_ZEROES, ranges of at most
// RoleConfig::max_trim_bytes.
//
// Faults (kythira khold-block-service Requirement 9.9, closing the
// take_faults() gap for hold volumes too). poll() takes each network
// attachment's initiator faults and queues them as reports, which helm
// reads with hold_reports and relays to the controller: a leader or
// primary timeout, a checksum mismatch and a media error become a
// volume_fault (reporter initiator, suspect the server), and fencing an
// attachment_status (fenced). A report is evidence for the controller,
// never a membership change on its own.
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
#include "oar/blk/hydrating_backend.hpp"
#include "oar/blk/lazy_image_backend.hpp"
#include "oar/blk/khold_volume_backend.hpp"
#include "oar/blk/network_volume_backend.hpp"
#include "objstore/object_store.hpp"
#include "proto/report.hpp"
#include "proto/volume_layout.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "oar/blk/volume_copier.hpp"

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
    InitiatorConfig initiator;             // attachment_id is set per attachment
    KholdInitiatorConfig khold_initiator;  // likewise, for khold volumes
    // The longest DISCARD or WRITE_ZEROES range a khold function takes.
    std::uint32_t max_trim_bytes{std::uint32_t{16} << 20U};
    // Network volumes restored from an image under another key (block
    // volume task 23): regions each one's background walk keeps in flight.
    std::size_t hydrate_max_background{2};
    // Local <-> network copies (task 23.2): regions each keeps in flight.
    std::size_t copy_max_in_flight{2};
    // Empty: steady_clock::now (health's uptime).
    std::function<Clock::time_point()> clock;
};

// Network volume configs (ReplicaConfigs and VolumeLayouts together) a
// role keeps at once.
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
    auto volume_layout(std::span<const std::byte> frame) -> helm::oar::Status override;
    auto cert_request() -> std::expected<helm::oar::CertAnswer, helm::oar::Status> override;
    auto role_certificate(std::span<const std::byte> chain) -> helm::oar::Status override;
    auto eject(const helm::oar::Eject& request)
        -> std::expected<helm::oar::EjectState, helm::oar::Status> override;
    auto copy_volume(const helm::oar::CopyVolume& request)
        -> std::expected<helm::oar::CopyAnswer, helm::oar::Status> override;
    auto hold_reports(const helm::oar::ReportRequest& request)
        -> std::expected<helm::oar::ReportChunk, helm::oar::Status> override;

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
    // The copy whose local volume is `local_volume`, if any (tests).
    [[nodiscard]] auto copier(std::uint64_t local_volume) -> VolumeCopier*;

private:
    struct Slot {
        FunctionTransport* transport{nullptr};
        std::unique_ptr<VirtioBlkFunction> placeholder;
        std::unique_ptr<VirtioBlkFunction> active;
        std::uint64_t volume{0};
        LazyImageBackend* image{nullptr};  // the active function's backend, for an image volume
        NetworkVolumeBackend* network{nullptr};  // ... for a hold network volume
        HydratingBackend* hydrating{nullptr};    // ... in front of it, restoring from an image
        KholdVolumeBackend* khold{nullptr};      // ... for a khold volume
        std::uint64_t attachment_id{0};          // the network attachment, for reports
        std::uint32_t generation{0};
    };

    explicit BlkRole(RoleConfig config) : _config{std::move(config)} {}

    [[nodiscard]] auto slot(helm::oar::FunctionNumber fn) -> Slot*;
    [[nodiscard]] auto slot_of_volume(std::uint64_t volume) -> Slot*;
    [[nodiscard]] auto params(const VolumeGeometry& geometry, std::string_view serial,
                              std::uint16_t max_in_flight = 1) const -> BlkParams;
    // Wipes the key, closes the volume and puts the placeholder back.
    auto close(Slot& s) -> bool;
    struct OpenedImage {
        std::shared_ptr<objstore::CachedImage> image;
        objstore::Fetcher* fetcher{nullptr};
    };
    // An image (never a snapshot) from one of the configured stores, its
    // manifest checked against the name, opened in the chunk cache.
    [[nodiscard]] auto open_image(std::uint32_t store_id, const objstore::ImageDigest& name)
        -> std::expected<OpenedImage, std::string>;
    // The backend for an image volume, ready for its key.
    [[nodiscard]] auto open_image_volume(const VolumeMetadata& m)
        -> std::expected<std::unique_ptr<LazyImageBackend>, std::string>;
    auto prepare_network(Slot& s, const helm::oar::PrepareFunction& request,
                         const helm::oar::BlkConfig& cfg) -> helm::oar::Status;
    auto prepare_khold(Slot& s, const helm::oar::BlkConfig& cfg) -> helm::oar::Status;
    // The network attachment's backend, hold or khold; null otherwise.
    [[nodiscard]] static auto attached_volume(const Slot& s) -> AttachedVolume*;
    // Grows the slot's function to the backend's capacity, if larger.
    [[nodiscard]] static auto follow_capacity(Slot& s, const AttachedVolume& v) -> bool;
    // Puts `f` behind the slot's transport (the placeholder back on failure).
    auto serve_active(Slot& s, std::unique_ptr<VirtioBlkFunction> f, std::uint64_t volume,
                      LazyImageBackend* image, HydratingBackend* hydrating = nullptr)
        -> helm::oar::Status;
    // Queues the initiator faults of a network attachment as reports.
    auto report_faults(const Slot& s, const std::vector<FaultEvent>& faults) -> void;
    auto queue_report(proto::ReportBody body) -> void;

    // A local <-> network copy, by its local volume.
    struct Copy {
        std::uint64_t network_volume{0};
        NetworkVolumeBackend* network{nullptr};  // the copier's network side
        std::unique_ptr<VolumeCopier> copier;
    };
    [[nodiscard]] auto copying(std::uint64_t volume) const -> bool;
    [[nodiscard]] auto start_copy(const helm::oar::CopyVolume& request) -> helm::oar::Status;

    RoleConfig _config;
    std::vector<Slot> _slots;
    std::map<std::uint64_t, Copy> _copies;
    std::map<std::uint64_t, proto::ReplicaConfig> _configs;  // hold network volumes, newest
    std::map<std::uint64_t, proto::VolumeLayout> _layouts;   // khold volumes, newest
    RoleConfig::Clock::time_point _started;
    helm::RoleEnrollment* _enrollment{nullptr};
    helm::oar::ReportQueue _reports;
    std::uint64_t _next_report{1};
};

}  // namespace ak::oar::blk
