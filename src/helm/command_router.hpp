// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// CommandRouter: turns controller envelopes into device-pool reservations,
// key operations, data-plane requests and one mailbox command to hull, and
// hull's responses and events back into pool commits, cleaning and reports
// (.kiro/specs/helm-control-plane/ Requirements 1.5, 2.3, 3, 4, 9; design
// "CommandRouter").
//
// Per command:
//
//   1. Sequence. A slot sequence number not above the highest helm has
//      accepted is not relayed (Requirement 2.3). A retry of a command that
//      already finished gets its recorded outcome reported again, without
//      side effects; a retry of one still queued or in flight is ignored
//      (its outcome comes when it finishes); anything else is
//      stale_sequence.
//   2. Queue. The mailbox holds one command at a time (Requirement 1.5):
//      the next is dispatched when hull answers or the command times out.
//   3. Prepare. The slot is decoded (strictly; helm never checks the
//      signature, hull does) and the body's preconditions are checked
//      against helm's own state. Creative steps happen now, each with a
//      compensation: reserve a function (DevicePool::assign), prepare it on
//      its data-plane role, create a VM or volume key, store a new volume
//      on the storage role. A refused precondition or failed step undoes
//      the steps before it and reports the command without relaying it.
//   4. Relay. Audit, record the sequence number in the sealed store
//      (cold-start Requirement 6.3; RouterConfig::sequence_recorder), then
//      the slot goes to the mailbox unmodified.
//   5. Commit or compensate. On ok or accepted, the command's destructive
//      steps happen now, only after hull verified the controller's
//      signature: release functions, destroy or rewrap keys, erase or
//      rewrite volumes on the media. ATTACH_VOLUME delivers the volume key
//      now too (below). On any other status the prepare steps are undone.
//
// Volumes (oar-blk Requirement 3). The storage role keeps each volume with
// its wrapped key in the volume's metadata on the media:
//
//   CREATE_VOLUME  prepare: create the volume key, then create_volume on
//                  the storage slot (the lowest connected blk slot) with
//                  the wrapped key; compensate: delete_volume, destroy key.
//   ATTACH_VOLUME  prepare: reserve the blk function (on the volume's
//                  slot) and prepare_function, which opens the volume;
//                  commit: unwrap and deliver the key. hull answers ok
//                  once the VMM has opened the function, and opening a
//                  VFIO device resets it (FLR), which wipes any key the
//                  function held; a driver reset afterwards keeps the key.
//                  So the key goes after the answer, and the function
//                  holds the guest's I/O until it arrives. A delivery that
//                  fails leaves the VM with a disk it cannot read: it is
//                  audited and reported as a device_lost host fault naming
//                  the slot and the volume, so the controller can detach.
//   DETACH_VOLUME  commit: release the function; cleaning drops the key
//                  and closes the volume.
//   DELETE_VOLUME  commit: destroy the wrapped key (crypto-erase), then
//                  delete_volume releases the space. DESTROY_VM without
//                  persist_volumes does the same for each of its volumes.
//   REWRAP_VOLUME  commit: rewrap in the KeyStore, then rewrap_volume
//                  writes the new owner and wrapped key to the media.
//
// Image volumes (oar-blk Requirement 8, task 13): CREATE_VOLUME with an
// image source creates no volume key. The storage role gets the store ID
// and image name instead, and the router keeps the owner itself. At
// ATTACH_VOLUME's commit the key delivered is a fresh ephemeral one from
// the secure element (KeyStore::create_ephemeral_key), never wrapped or
// kept, so the overlay written under it is unreadable once the function
// drops it. DELETE_VOLUME has no key to destroy, and DESTROY_VM without
// persist_volumes deletes the VM's image volumes too. REWRAP_VOLUME of a
// plain image volume is unsupported: there is no key to rewrap.
//
// Encrypted images (task 15): the controller sends the image's key K_img
// as an ImageKey frame for the volume ahead of its CREATE_VOLUME
// (KeyStore::put_image_key). CREATE_VOLUME then re-wraps it under the
// owner's VM key as the volume's key (KeyStore::import_image_key; a frame
// naming another owner is a conflict) and relays that wrapped key with the
// image source, for the role to keep on the media. From there it is a
// volume key like a disk volume's: ATTACH_VOLUME unwraps it for the owner
// and delivers it as K_img alongside the ephemeral key, REWRAP_VOLUME
// rewraps it, DELETE_VOLUME and DESTROY_VM crypto-erase it. A failed
// CREATE_VOLUME destroys it with the rest of its undo, so a retry needs
// the frame again.
//
// Network volumes (.kiro/specs/block-volume-service/ task 12). The
// controller owns them: there is no CREATE_VOLUME, and helm learns of one
// from its ReplicaConfig (on_replica_config keeps the newest per volume
// whose attachments name this server) and its key from a VolumeKey
// (KeyStore::put_attachment_key). helm does not know the owning VM; hull
// checks the signed command, and helm remembers the VM that attached.
//
//   ATTACH_VOLUME  prepare: the config must list exactly one attachment
//                  for this server, and the KeyStore must hold its key at
//                  that generation; reserve the blk function, hand the
//                  config to that slot (replica_config), then
//                  prepare_function with the attachment, which opens the
//                  role's session to the primary; commit: open the key in
//                  the secure element and deliver it.
//   WITHDRAW_DETACH only by the VM that attached; answered by helm (see
//                  cooperative detach below).
//   DETACH_VOLUME  only by the VM that attached; under force or
//                  destroy_vm only once the newest config no longer lists
//                  the attachment's generation (the controller fenced it,
//                  Requirement 3.5), else conflict; commit: release the
//                  function (cleaning closes the session) and forget the
//                  attachment's key.
//   DELETE_VOLUME, REWRAP_VOLUME are the controller's (no mailbox command):
//                  unknown_volume, as for any volume helm does not hold.
//
// Local <-> network conversion (.kiro/specs/block-volume-service/
// Requirement 8.6, task 23.2). CONVERT_VOLUME copies a detached local
// disk volume into a network volume or back, on the storage role that
// holds the local volume (oar-blk's VolumeCopier rewraps every block from
// the source's key to the target's). The controller creates the target
// first (CREATE_VOLUME, or a network volume with a utility attachment for
// this server and its VolumeKey) and waits for a restored network source
// to be filled in (replica_status hydrated_bytes == total_bytes).
//
//   prepare  the local volume is a disk volume (an image: unsupported)
//            owned by owner_vm, stored here and not attached; the network
//            volume's newest config lists exactly one attachment for this
//            server, whose key helm holds at that generation, and nothing
//            attaches it; neither volume is converting already (conflict);
//            the config goes to the local volume's slot (replica_config).
//   commit   unwrap the local volume's key for owner_vm, open the
//            attachment's key, and start the copy (copy_volume) with both.
//            hull answers ok after checking the signature, so the command's
//            outcome is ok; a copy that does not start is reported failed
//            (`start`) in a conversion_progress.
//   poll     every conversion_poll_interval, query the copy and report its
//            progress (conversion_progress, `copying`). When it ends,
//            report `completed` or `failed`, release it on the role and
//            forget the attachment's key (the controller retires the
//            utility attachment either way). A role that no longer knows
//            the copy (it restarted), or that cannot be asked
//            max_conversion_query_failures times running, is `lost`.
//
// While a volume converts, DELETE_VOLUME, ATTACH_VOLUME and REWRAP_VOLUME
// of either volume are conflicts. The controller cancels a copy by
// publishing a config without the utility attachment: the role's copy
// then fails on the network side, and helm reports that. DESTROY_VM
// without persist_volumes deletes the local volume on the role, which
// drops the copy; helm reports it `lost` at its next query.
//
// Cooperative detach (.kiro/specs/block-volume-service/ Requirements
// 3.3-3.6, design "Detach blocked while mounted"). DETACH_VOLUME under the
// `wait` policy, for every volume kind:
//
//   1. Prepare as for any detach, then eject(request) on the storage role,
//      which sets eject_requested in the function's vendor capability and
//      interrupts the guest. A role that refuses fails the command.
//   2. Hold the command, unrelayed, while the mailbox waits (no other
//      command passes it: hull's sequence check would refuse it relayed
//      out of order). Every eject_poll_interval, query the role.
//   3. Released (the driver reset the device and left it alone, with no
//      request of its own still in the backend): relay the slot to hull
//      unmodified; it is in flight as usual from then on, and hull's
//      hot-unplug meets a device the guest already let go of.
//   4. Not released by timeout_s: answer `busy` without relaying. The
//      volume stays attached and serving, and the request stays set so a
//      guest that lets go later still can; helm keeps querying and reports
//      the release (an attachment_status for a network volume). The
//      controller then sends DETACH_VOLUME again, which finds the release
//      and relays at once, or a forced detach, or withdraws the request.
//   5. WITHDRAW_DETACH (only by the VM that attached; never relayed):
//      eject(cancel) on the role, which clears eject_requested, and helm
//      stops watching the function. A network volume reports its
//      attachment `attached` again. The role's cancel is idempotent, so
//      a withdraw with nothing pending (a retry, or a request helm lost
//      across a restart) still clears the role and answers ok. It also
//      withdraws a request the guest already acted on (`released`): the
//      function stays attached, and the guest may take it back by
//      rescanning its bus.
//
// Network volumes report attachment_status eject_requested, released and
// busy as they happen. Local and image volumes have no attachment to name
// (the report needs one), so for them the command's outcome is the report.
//
// A media step that fails after commit (delete or rewrap) cannot be undone
// either: it is counted in storage_failures. A failed delete leaves only
// ciphertext whose key is gone; a failed rewrap leaves the old wrapped key
// on the media, which matters once helm reloads keys from the media.
//
// Timeouts (Requirement 9.1). A command hull does not answer within
// command_timeout is reported timed_out and nothing else happens: helm
// cannot know whether hull applied it, so reservations stay held (a
// function hull may have attached is never handed to another VM) and the
// destructive steps, which wait for hull's ok, never run. Nothing is
// retried. The controller reconciles from the outcome and the inventory.
// A response that arrives later is audited and dropped. Data-plane
// requests time out inside OarLink and fail the command the same way.
//
// Releases and cleaning (Requirement 3.3, 3.4). A released function waits
// in `releasing` for hull's DEVICE_RELEASED (up to release_timeout; after
// DETACH_DEVICE or DETACH_VOLUME, timeout_s longer, because hull answers
// those `accepted` and may wait that long for the guest to eject), then
// its role cleans it: NIC and storage roles synchronously over the
// sideband; GPU functions wait for hull's SCRUB_DONE (up to
// clean_timeout). Failure or timeout faults the function until its slot is
// power-cycled (slot_power_cycled), after which it is cleaned again.
//
// Status (Requirement 9.2). Every command's outcome, every pool
// transition, VM exits and host faults go to the ReportSink as they
// happen; inventory() is the snapshot the ControllerSession sends on
// every connection.
//
// Audit (Requirement 9.3). Every accepted, refused, relayed and answered
// command and every key operation goes to the AuditLog. If a command's
// relay record cannot be written the command is not relayed (fails
// closed, internal_error); other audit failures are counted.
//
// NIC configuration. ATTACH_DEVICE for a NIC VF carries the VPC, NIC ID
// and MAC inside the signed command (mailbox v3), and the router hands
// exactly those to oar-net to prepare the VF (Requirement 8.1): helm adds
// no network identity of its own.
//
// Standing starts (.kiro/specs/cold-start/ Requirement 4.4-4.7, task 6).
// After helm's power returned, expect_standing() hands the router the
// standing set helm keeps, and from then on no controller envelope is
// dispatched until every standing instance has been tried once:
//
//   1. Wait for hull: its first message of a boot is HOST_FAULT
//      agent_restarted. Nothing comes within standing_ready_timeout:
//      every instance is reported timed_out and envelopes flow.
//   2. Upload the set's signed bytes to hull in STANDING_CHUNK commands
//      (helm's own, unsigned; hull verifies the set). A chunk hull
//      refuses, or that times out, ends the round: every instance is
//      reported with that status.
//   3. For each instance, in VM order: decode its commands, prepare each
//      exactly as for a live command (the VM key, the reserved and
//      prepared functions), send STANDING_START, then commit every step
//      on ok or compensate every step on failure. A start that times out
//      is not retried and keeps its reservations, as a timed-out command
//      does.
//   4. When every instance has been tried once, the round's results go to
//      the callback (for the cold_start report) and envelopes flow again.
//
// A failed start is retried after standing_retry_min, doubling up to
// standing_retry_max (4.7), while the mailbox is idle and no envelope is
// waiting. The first envelope dispatched ends standing starts: hull
// refuses them once it has accepted a signed command, and the controller
// starts what is left. None of this reports a command outcome or uses a
// controller sequence number.
//
// Not thread-safe: the router, the pool, the key store and the ports
// belong to helm's event-loop thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "helm/audit_log.hpp"
#include "helm/device_pool.hpp"
#include "helm/key_store.hpp"
#include "helm/mailbox.hpp"
#include "helm/oar_link.hpp"
#include "helm/oar_protocol.hpp"
#include "proto/envelope.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "proto/standing_set.hpp"

namespace ak::helm {

// Network volumes the router keeps configs for at once.
inline constexpr std::size_t max_network_volumes = 4096;

// helm's side of the mailbox as the router uses it (MailboxDevice
// implements it). post_command writes the slot completely, then rings
// CMD_DOORBELL and raises the MSI (Requirement 1.3).
class HostPort {
public:
    HostPort() = default;
    HostPort(const HostPort&) = delete;
    auto operator=(const HostPort&) -> HostPort& = delete;
    HostPort(HostPort&&) = delete;
    auto operator=(HostPort&&) -> HostPort& = delete;
    virtual ~HostPort() = default;

    // False if the slot could not be written.
    virtual auto post_command(const mailbox::Slot& slot) -> bool = 0;
};

// One data-plane role's sideband, as the router uses it. OarLinkPort
// adapts an OarLink; tests substitute a fake.
class OarPort {
public:
    OarPort() = default;
    OarPort(const OarPort&) = delete;
    auto operator=(const OarPort&) -> OarPort& = delete;
    OarPort(OarPort&&) = delete;
    auto operator=(OarPort&&) -> OarPort& = delete;
    virtual ~OarPort() = default;

    virtual auto prepare_function(const oar::PrepareFunction& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto clean_function(const oar::CleanFunction& request)
        -> std::expected<void, LinkError> = 0;
    // `image_key`: an encrypted image volume's K_img, delivered with its
    // ephemeral `key` (OarLink::deliver_key).
    virtual auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                             std::optional<ScopedKey> image_key)
        -> std::expected<void, LinkError> = 0;
    virtual auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> = 0;
    virtual auto create_volume(const oar::CreateVolume& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto delete_volume(const oar::DeleteVolume& request)
        -> std::expected<void, LinkError> = 0;
    virtual auto rewrap_volume(const oar::RewrapVolume& request)
        -> std::expected<void, LinkError> = 0;
    // The network role's group policy and meters (GroupUsageReporter).
    virtual auto group_policy(std::span<const std::byte> /*frame*/)
        -> std::expected<void, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    virtual auto group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    // Snooping (oar-net task 14): a controller GroupMembers frame, and the
    // role's join list unless it is still generation `since`.
    virtual auto group_members(std::span<const std::byte> /*frame*/)
        -> std::expected<void, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    virtual auto group_membership(std::optional<std::uint32_t> /*since*/)
        -> std::expected<std::optional<OarLink::Memberships>, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    // A network volume's ReplicaConfig, to the storage role that attaches it.
    virtual auto replica_config(std::span<const std::byte> /*frame*/)
        -> std::expected<void, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    // Cooperative detach, to the storage role.
    virtual auto eject(const oar::Eject& /*request*/) -> std::expected<oar::EjectState, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
    // Local <-> network conversion, to the storage role
    // (OarLink::copy_volume): the keys go with a start only.
    virtual auto copy_volume(const oar::CopyVolume& /*request*/,
                             std::optional<ScopedKey> /*local_key*/,
                             std::optional<ScopedKey> /*network_key*/)
        -> std::expected<oar::CopyAnswer, LinkError> {
        return std::unexpected(
            LinkError{.code = LinkErrc::refused, .status = oar::Status::unsupported});
    }
};

class OarLinkPort final : public OarPort {
public:
    explicit OarLinkPort(OarLink& link) noexcept : _link{&link} {}

    auto prepare_function(const oar::PrepareFunction& request)
        -> std::expected<void, LinkError> override;
    auto clean_function(const oar::CleanFunction& request)
        -> std::expected<void, LinkError> override;
    auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                     std::optional<ScopedKey> image_key) -> std::expected<void, LinkError> override;
    auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> override;
    auto create_volume(const oar::CreateVolume& request) -> std::expected<void, LinkError> override;
    auto delete_volume(const oar::DeleteVolume& request) -> std::expected<void, LinkError> override;
    auto rewrap_volume(const oar::RewrapVolume& request) -> std::expected<void, LinkError> override;
    auto group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError> override;
    auto group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> override;
    auto group_members(std::span<const std::byte> frame) -> std::expected<void, LinkError> override;
    auto group_membership(std::optional<std::uint32_t> since)
        -> std::expected<std::optional<OarLink::Memberships>, LinkError> override;
    auto replica_config(std::span<const std::byte> frame)
        -> std::expected<void, LinkError> override;
    auto eject(const oar::Eject& request) -> std::expected<oar::EjectState, LinkError> override;
    auto copy_volume(const oar::CopyVolume& request, std::optional<ScopedKey> local_key,
                     std::optional<ScopedKey> network_key)
        -> std::expected<oar::CopyAnswer, LinkError> override;

private:
    OarLink* _link;
};

// Where status reports go (ControllerLink::report in helm).
class ReportSink {
public:
    ReportSink() = default;
    ReportSink(const ReportSink&) = delete;
    auto operator=(const ReportSink&) -> ReportSink& = delete;
    ReportSink(ReportSink&&) = delete;
    auto operator=(ReportSink&&) -> ReportSink& = delete;
    virtual ~ReportSink() = default;

    virtual auto report(proto::ReportBody body) -> void = 0;
};

// Keeps the last sequence number helm relayed across power loss
// (.kiro/specs/cold-start/ Requirement 6.3): the next boot's provisioning
// file passes it to hull as its floor, so a command captured before the
// power cycle is refused after it. Implemented over the sealed store by
// StoreSequenceRecorder (helm/boot_state.hpp).
class SequenceRecorder {
public:
    SequenceRecorder() = default;
    SequenceRecorder(const SequenceRecorder&) = delete;
    auto operator=(const SequenceRecorder&) -> SequenceRecorder& = delete;
    SequenceRecorder(SequenceRecorder&&) = delete;
    auto operator=(SequenceRecorder&&) -> SequenceRecorder& = delete;
    virtual ~SequenceRecorder() = default;

    // Durably records `seq` as relayed; false if it could not.
    [[nodiscard]] virtual auto record(std::uint64_t seq) -> bool = 0;
};

// One standing instance's latest attempt (cold-start Requirement 4.7).
struct StandingAttempt {
    std::uint64_t vm_id{0};
    mailbox::Status status{mailbox::Status::ok};  // ok: started
    std::uint16_t attempts{0};
    friend auto operator==(const StandingAttempt&, const StandingAttempt&) -> bool = default;
};

// Called once, when every standing instance has been tried once (or the
// round ended without trying them). In VM order.
using StandingRoundDone = std::function<void(const std::vector<StandingAttempt>&)>;

struct RouterConfig {
    using Clock = std::chrono::steady_clock;

    // Highest sequence number already delivered (hull's floor, if known).
    std::uint64_t last_seq{0};
    // If set, every command's sequence number is recorded here before it
    // is relayed, and a command whose number cannot be recorded is
    // refused (internal_error) rather than relayed: a relayed command
    // missing from the record could be replayed after a power cycle. Not
    // owned; must outlive the router.
    SequenceRecorder* sequence_recorder{nullptr};
    std::chrono::milliseconds command_timeout{std::chrono::seconds{30}};
    // How long a released function may wait for DEVICE_RELEASED.
    std::chrono::milliseconds release_timeout{std::chrono::seconds{60}};
    // How long a GPU function may wait in `cleaning` for SCRUB_DONE.
    std::chrono::milliseconds clean_timeout{std::chrono::minutes{10}};
    // How often a cooperative detach asks the storage role whether the
    // guest released the function. The role needs 2 s of quiet to call a
    // function released, so finer polling buys little.
    std::chrono::milliseconds eject_poll_interval{std::chrono::milliseconds{500}};
    // How often a conversion's copy is queried and its progress reported.
    std::chrono::milliseconds conversion_poll_interval{std::chrono::seconds{1}};
    // Queries in a row that may fail before a conversion is reported lost.
    unsigned max_conversion_query_failures{3};
    // Standing starts: how long to wait for hull's first message after
    // expect_standing(), and the retry backoff of a failed start.
    std::chrono::milliseconds standing_ready_timeout{std::chrono::seconds{120}};
    std::chrono::milliseconds standing_retry_min{std::chrono::seconds{1}};
    std::chrono::milliseconds standing_retry_max{std::chrono::seconds{30}};
    // This server (the ControllerSession's): network volume attachments
    // naming it are the ones it serves.
    std::uint64_t server_id{0};
    // Envelopes waiting for the mailbox; more are refused.
    std::size_t max_queued{64};
    // Finished outcomes kept for answering retries.
    std::size_t outcome_history{256};
    // Empty: steady_clock::now.
    std::function<Clock::time_point()> clock;
};

struct RouterStats {
    std::uint64_t relayed{0};
    std::uint64_t refused{0};  // answered by helm without reaching hull
    std::uint64_t timed_out{0};
    std::uint64_t duplicates{0};      // retries answered from history or ignored
    std::uint64_t stray_messages{0};  // undecodable, unexpected or late hull messages
    std::uint64_t audit_failures{0};
    std::uint64_t sequence_record_failures{0};  // refused: the relayed sequence could not be kept
    std::uint64_t inconsistencies{0};        // hull confirmed something helm's state disagrees with
    std::uint64_t key_delivery_failures{0};  // ATTACH_VOLUME succeeded, the key did not arrive
    std::uint64_t storage_failures{0};       // a committed delete or rewrap failed on the media
    std::uint64_t detaches_released{0};      // cooperative detaches the guest released
    std::uint64_t detaches_busy{0};          // cooperative detaches answered busy
    std::uint64_t detaches_withdrawn{0};     // eject requests cleared by WITHDRAW_DETACH
    std::uint64_t conversions_completed{0};
    std::uint64_t conversions_failed{0};  // did not start, failed, or lost
    std::uint64_t standing_started{0};
    std::uint64_t standing_failed{0};     // attempts that failed (each may be retried)
    std::uint64_t standing_abandoned{0};  // never started: the controller took over
    std::uint64_t agent_restarts{0};      // HOST_FAULT agent_restarted: hull's agent came up
};

class CommandRouter {
public:
    using Clock = RouterConfig::Clock;

    // Every reference must outlive the router.
    CommandRouter(RouterConfig config, DevicePool& pool, KeyStore& keys, HostPort& host,
                  ReportSink& reports, AuditLog& audit);

    // Registers a data-plane role's sideband for `slot` (remembering its
    // role, so volumes go to a storage slot) and adds every
    // function its inventory lists; each starts in `cleaning` and is
    // cleaned now (PowerSequencer calls this once the slot is link-ready).
    auto add_slot(std::uint8_t slot, OarPort& port, const oar::Inventory& inventory) -> void;
    // The slot was power-cycled: faulted functions on it are cleaned again
    // and, if that succeeds, returned to the pool (Requirement 3.4, 6.3).
    auto slot_power_cycled(std::uint8_t slot) -> void;

    // A controller envelope (shape and server already checked by the
    // ControllerSession).
    auto on_envelope(const proto::Envelope& envelope) -> void;
    // A slot hull wrote: RSP_SLOT (a response) or EVT_SLOT (an event).
    auto on_host_slot(const mailbox::Slot& slot) -> void;
    // A ReplicaConfig from the controller (frame as received). Kept, newest
    // epoch per volume, when one of its attachments names this server;
    // returns whether it was (the daemon then hands it to the storage
    // roles, which follow epoch changes on live attachments).
    auto on_replica_config(std::span<const std::byte> frame) -> bool;
    // The newest kept ReplicaConfig of every network volume, for a storage
    // role whose sideband (re)opened.
    [[nodiscard]] auto network_configs() const -> std::vector<std::span<const std::byte>>;
    // Standing starts (see above): `frame` is the standing set's exact
    // signed bytes and `set` its decoding. Holds envelopes from now until
    // every instance has been tried once. Nothing happens for a set with
    // no instances.
    auto expect_standing(std::span<const std::byte> frame, const proto::StandingSet& set,
                         StandingRoundDone done) -> void;
    // Standing starts are held, running or may still retry.
    [[nodiscard]] auto standing() const noexcept -> bool { return _standing.has_value(); }
    // oar-net applied a mapping version (reported and kept for inventory).
    auto on_map_applied(std::uint32_t vni, std::uint64_t map_version) -> void;
    // Expires command, release and cleaning deadlines. Call it at least as
    // often as the shortest timeout's resolution you need.
    auto poll() -> void;

    // The inventory snapshot (Requirement 9.2); boot_id is left for the
    // ControllerSession to fill in, core and page counts for hull's report.
    [[nodiscard]] auto inventory() const -> proto::Inventory;
    [[nodiscard]] auto stats() const noexcept -> const RouterStats& { return _stats; }

    // ---- records helm acts on itself (server-provisioning Requirement 3) ----

    // Claims `seq` for a signed link record helm acts on (host_power,
    // decommission), in the envelopes' sequence space: stale_sequence at or
    // below the last number accepted; otherwise it becomes the last, is
    // recorded (sequence_recorder, so hull's next floor covers it) and
    // audited, and ok is returned. `command` is
    // proto::link_record_command(type). A failed record is internal_error
    // and claims nothing.
    auto claim_sequence(std::uint64_t seq, std::uint16_t command) -> proto::CommandStatus;
    // Audits a claimed record's outcome and reports it as a CommandOutcome.
    auto record_outcome(std::uint64_t seq, std::uint16_t command, proto::CommandStatus status)
        -> void;
    // VMs helm believes run (hull confirmed their CREATE_VM).
    [[nodiscard]] auto vm_count() const noexcept -> std::size_t { return _vms.size(); }
    // Network volumes attached here, or whose config still fences one here.
    [[nodiscard]] auto network_volume_count() const noexcept -> std::size_t {
        return _network.size();
    }
    [[nodiscard]] auto server_id() const noexcept -> std::uint64_t { return _config.server_id; }
    // The host was reset under its VMs (host_power off, cycle or hold with
    // force): every VM is gone. Each is forgotten as a DESTROY_VM that
    // keeps its volumes would, reported exited (vmm_failure), and the
    // functions it held go straight to cleaning: no hull is left to
    // reset them and say so.
    auto host_reset() -> void;
    // A command holds the mailbox: relayed and unanswered, or a
    // cooperative detach waiting for the guest.
    [[nodiscard]] auto busy() const noexcept -> bool {
        return _in_flight.has_value() || _waiting.has_value();
    }
    // Functions whose guest has been asked to release them and that are
    // still attached (waiting, busy or released but not yet detached).
    [[nodiscard]] auto ejecting() const noexcept -> std::size_t { return _ejecting.size(); }
    [[nodiscard]] auto queued() const noexcept -> std::size_t { return _queue.size(); }
    // Conversions whose copy runs on a storage role.
    [[nodiscard]] auto converting() const noexcept -> std::size_t { return _converting.size(); }

private:
    // What a command did before relay, so it can be undone.
    struct StoredVolume {
        VolumeId volume{0};
        std::uint8_t slot{0};
    };

    struct Undo {
        std::optional<FunctionId> reserved;  // assigned in the pool, maybe prepared
        std::optional<VmId> created_vm_key;
        std::optional<VolumeId> created_volume_key;
        std::optional<StoredVolume> stored_volume;  // created on the storage role
    };

    struct InFlight {
        std::uint64_t seq{0};
        mailbox::Body body;
        Undo undo;
        Clock::time_point deadline;
        // A STANDING_START: the instance and each command's prepare steps.
        std::optional<std::size_t> standing_entry;
        std::vector<std::pair<mailbox::Body, Undo>> steps;
    };

    struct StandingEntry {
        std::uint64_t vm_id{0};
        std::uint16_t attempts{0};
        mailbox::Status last{mailbox::Status::timed_out};
        bool started{false};
        bool given_up{false};  // not retried (timed out, or the round ended)
        Clock::time_point next_try;
        std::chrono::milliseconds backoff{0};
    };

    struct Standing {
        std::vector<std::byte> frame;
        proto::StandingSet set;
        StandingRoundDone done;
        Clock::time_point ready_deadline;
        bool ready{false};          // hull's first message arrived
        std::size_t sent{0};        // set bytes hull has taken
        std::size_t next_first{0};  // the next instance's first attempt
        bool round_done{false};
        std::vector<StandingEntry> entries;  // the set's order (VM order)
    };

    // A DETACH_VOLUME under `wait`, held until the guest releases the
    // function (relayed then) or timeout_s passes (busy).
    struct Waiting {
        std::uint64_t seq{0};
        mailbox::Slot slot{};
        mailbox::DetachVolume body;
        Clock::time_point deadline;
    };

    // A function whose guest was asked to release it.
    struct Ejecting {
        VolumeId volume{0};
        bool busy{false};      // a detach timed out on it
        bool released{false};  // the role said so (reported once)
        Clock::time_point next_query;
    };

    // A CONVERT_VOLUME's copy, by local volume.
    struct Conversion {
        VolumeId network{0};
        AttachmentId attachment{0};
        mailbox::ConvertDirection direction{mailbox::ConvertDirection::to_network};
        std::uint8_t slot{0};
        std::uint64_t seq{0};
        Clock::time_point next_query;
        unsigned failures{0};  // queries in a row the role did not answer
    };

    struct Vm {
        std::uint16_t vcpus{0};
        std::uint32_t memory_mib{0};
    };

    // A network volume as this server attaches it.
    struct NetworkVolume {
        std::uint64_t epoch{0};
        std::vector<std::byte> frame;  // the newest ReplicaConfig
        VmId attached_by{0};           // while attached
        AttachmentId attachment{0};    // while attached
        std::uint32_t generation{0};   // while attached
    };

    struct Volume {
        VmId owner{0};
        std::uint32_t size_gib{0};
        std::uint8_t slot{0};  // the storage slot holding it
        bool image{false};     // an image volume: owner kept here; a KeyStore entry
                               // only for an encrypted image (its K_img)
    };

    using Outcome = proto::CommandOutcome;

    [[nodiscard]] auto now() const -> Clock::time_point;
    auto pump() -> void;
    auto dispatch(const proto::Envelope& envelope) -> void;
    // Audits, writes the slot to the mailbox and puts the command in flight;
    // compensates and refuses if either fails.
    auto relay(std::uint64_t seq, const mailbox::Slot& slot, const mailbox::Body& body, Undo undo)
        -> void;
    // Cooperative detach: asks the guest to release, then relays or waits.
    auto start_wait(std::uint64_t seq, const mailbox::Slot& slot,
                    const mailbox::DetachVolume& detach) -> void;
    // WITHDRAW_DETACH: clears the eject request on the role and forgets it.
    auto withdraw(std::uint64_t seq, const mailbox::WithdrawDetach& withdraw) -> void;
    // The volume is attached here, to `vm`, on `device` (DETACH_VOLUME and
    // WITHDRAW_DETACH): unknown_volume or conflict otherwise.
    [[nodiscard]] auto check_attached(VolumeId volume, VmId vm,
                                      const mailbox::DeviceRef& device) const
        -> std::expected<void, mailbox::Status>;
    // Asks the role where a function stands; records and reports a release.
    // nullopt if the role could not be asked.
    auto query_eject(FunctionId id) -> std::optional<oar::EjectState>;
    // Records a role's answer: the first `released` is audited and reported.
    auto note_eject(FunctionId id, oar::EjectState state) -> void;
    auto poll_ejects(Clock::time_point t) -> void;
    // attachment_status for a network volume attached here (no-op otherwise).
    auto report_attachment(VolumeId volume, std::uint8_t slot, proto::AttachmentState state)
        -> void;
    // A network volume's attachment generation is gone from its newest config.
    [[nodiscard]] auto fenced(const NetworkVolume& net) const -> bool;
    auto prepare(std::uint64_t seq, const mailbox::Body& body, Undo& undo)
        -> std::expected<void, mailbox::Status>;
    // CONVERT_VOLUME's checks, and its config to the local volume's slot.
    auto prepare_convert(const mailbox::ConvertVolume& convert)
        -> std::expected<void, mailbox::Status>;
    // CONVERT_VOLUME's commit: both keys to the role, and the copy starts.
    auto start_conversion(std::uint64_t seq, const mailbox::ConvertVolume& convert) -> void;
    auto poll_conversions(Clock::time_point t) -> void;
    // Reports a conversion_progress for `local`'s copy.
    auto report_conversion(VolumeId local, const Conversion& c, const oar::CopyAnswer& answer,
                           proto::ConversionFailure failure) -> void;
    // The copy ended (or never started): audits, releases it on the role
    // and forgets the attachment's key.
    auto end_conversion(VolumeId local, const Conversion& c, proto::ConversionFailure failure,
                        std::uint64_t written) -> void;
    // Either volume of a running conversion.
    [[nodiscard]] auto is_converting(VolumeId volume) const -> bool;
    auto reserve(VmId vm, const mailbox::DeviceRef& device, Undo& undo)
        -> std::expected<FunctionId, mailbox::Status>;
    auto compensate(std::uint64_t seq, Undo& undo) -> void;
    auto commit(std::uint64_t seq, const mailbox::Body& body, const Undo& undo) -> void;
    auto deliver_volume_key(std::uint64_t seq, const mailbox::AttachVolume& attach) -> void;
    // Releases a volume's space on its storage role (after crypto-erase).
    auto erase_volume(VolumeId volume) -> void;
    // A volume's owner: the KeyStore's for a disk volume, ours for an image volume.
    [[nodiscard]] auto volume_owner(VolumeId volume) const -> std::optional<VmId>;
    [[nodiscard]] auto is_image_volume(VolumeId volume) const -> bool;
    // A network volume's attachment for this server in its newest config.
    [[nodiscard]] auto network_attachment(VolumeId volume) const
        -> std::expected<proto::VolumeAttachment, mailbox::Status>;
    auto prepare_network_attach(const mailbox::AttachVolume& attach, Undo& undo)
        -> std::expected<void, mailbox::Status>;
    // Detached: the key goes (the controller retires the generation).
    auto forget_attachment(NetworkVolume& net) -> void;
    // Forgets a detached network volume whose config no longer lists this server.
    auto drop_unattached(VolumeId volume) -> void;
    [[nodiscard]] auto storage_slot() const -> std::optional<std::uint8_t>;
    auto finish(std::uint64_t seq, mailbox::Type command, mailbox::Status status,
                std::span<const std::byte> payload = {}) -> void;
    auto refuse(std::uint64_t seq, mailbox::Type command, mailbox::Status status) -> void;

    // Standing starts: one step of the first round (true if it did
    // something), a due retry (true if one started), and their pieces.
    auto standing_step() -> bool;
    auto standing_retry(Clock::time_point t) -> bool;
    auto post_helm_command(const mailbox::Body& body) -> std::optional<std::uint64_t>;
    auto attempt_standing(std::size_t entry) -> void;
    auto standing_failed(std::size_t entry, mailbox::Status status) -> void;
    // Gives up every instance not yet started or tried with `status`.
    auto end_standing_round(mailbox::Status status) -> void;
    auto finish_standing_round() -> void;
    auto on_standing_response(InFlight done, mailbox::Status status) -> void;
    // The first envelope is dispatched: whatever has not started is left
    // to the controller.
    auto abandon_standing() -> void;

    auto on_response(const mailbox::Message& msg) -> void;
    auto on_event(const mailbox::Body& body) -> void;

    // Pool moves that report themselves.
    auto pool_event(FunctionId id, PoolEvent event) -> bool;
    auto assign(FunctionId id, VmId vm) -> bool;
    // `grace` extends the wait for DEVICE_RELEASED beyond release_timeout.
    auto release(FunctionId id, VmId vm, std::chrono::milliseconds grace = {}) -> bool;
    auto start_cleaning(FunctionId id) -> void;
    auto report_transition(FunctionId id, FunctionState from, const FunctionInfo& after,
                           std::optional<VmId> vm) -> void;

    auto audit(const AuditRecord& record) -> bool;
    auto port_for(std::uint8_t slot) -> OarPort*;

    RouterConfig _config;
    DevicePool* _pool;
    KeyStore* _keys;
    HostPort* _host;
    ReportSink* _reports;
    AuditLog* _audit;

    std::map<std::uint8_t, OarPort*> _ports;
    std::map<std::uint8_t, oar::Role> _roles;
    std::uint64_t _last_seq;
    std::deque<proto::Envelope> _queue;
    std::optional<InFlight> _in_flight;
    std::optional<Waiting> _waiting;
    std::map<FunctionId, Ejecting> _ejecting;
    std::set<std::uint64_t> _timed_out;         // relayed, timed out, answer not yet seen
    std::map<std::uint64_t, Outcome> _history;  // finished outcomes, for retries

    std::map<FunctionId, Clock::time_point> _deadlines;  // releasing / GPU cleaning
    std::map<VmId, Vm> _vms;
    std::map<VolumeId, Volume> _volumes;
    std::map<VolumeId, FunctionId> _attached;  // volume -> blk function serving it
    std::map<VolumeId, NetworkVolume> _network;
    std::map<VolumeId, Conversion> _converting;        // by local volume
    std::map<std::uint32_t, std::uint64_t> _networks;  // vni -> applied map version
    std::optional<Standing> _standing;
    std::uint64_t _helm_seq{0};  // header seq of helm's own commands

    RouterStats _stats;
};

}  // namespace ak::helm
