// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// OarLink: helm's request/response channel to one data-plane role over its
// own sideband segment (.kiro/specs/helm-control-plane/ Requirements 5 and 7,
// design "OarLink"), and OarEndpoint, the role's side of the same channel.
//
// Stack, from the top:
//   OarLink / OarEndpoint      operations, timeouts, request/response matching
//   helm/oar_protocol.hpp      message bodies
//   helm/mctp.hpp              vendor header, fragmentation, reassembly, SMBus packets
//   helm/sideband_binding.hpp  InProcessBinding, SocketBinding (SmbusBinding later)
//
// Matching. helm owns the MCTP tags: every request goes out with tag owner
// set and the next of the eight tags, and the role answers with tag owner
// clear and the same tag. helm has one request outstanding per link and
// waits up to the configured timeout for its answer. A response that
// arrives after its request timed out carries an old tag, so the next
// request discards it instead of mistaking it for its own answer. Packets
// that fail to decode, come from another address, or do not reassemble are
// dropped and counted; they never end a request early, so a noisy segment
// costs time, not correctness.
//
// Keys. deliver_key is the one path a plaintext volume key takes off the
// control board (Requirement 4.4): OarLink reads the ScopedKey (it is the
// only class allowed to) into exactly-sized buffers and wipes every one of
// them once sent, success or not. OarEndpoint wipes the reassembled request
// after the handler returns, so the handler must copy the key into its own
// key slot (oar-blk KeySlot) during the call. What a binding does with the
// bytes in flight (a kernel socket buffer, an InProcessBinding queue entry
// handed to the receiver) is outside this layer.
//
// Neither class is thread-safe; each link belongs to one thread.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <vector>

#include "helm/mctp.hpp"
#include "helm/oar_protocol.hpp"
#include "helm/scoped_key.hpp"
#include "helm/sideband_binding.hpp"

namespace ak::helm {

// Both ends of one sideband segment: bus addresses (7-bit) and EIDs, as seen
// from the side that holds this config.
struct LinkAddress {
    std::uint8_t local_addr{0};
    std::uint8_t peer_addr{0};
    std::uint8_t local_eid{mctp::null_eid};
    std::uint8_t peer_eid{mctp::null_eid};

    // The same segment seen from the other end.
    [[nodiscard]] constexpr auto reversed() const noexcept -> LinkAddress {
        return {.local_addr = peer_addr,
                .peer_addr = local_addr,
                .local_eid = peer_eid,
                .peer_eid = local_eid};
    }
};

struct LinkConfig {
    LinkAddress address;
    // Packet payload size this side sends; the receiver accepts any size.
    std::size_t mtu{mctp::baseline_mtu};
    // How long OarLink waits for each response.
    std::chrono::milliseconds timeout{std::chrono::seconds{1}};
};

enum class LinkErrc : std::uint8_t {
    timed_out,     // no matching response within the timeout
    disconnected,  // the binding's peer is gone
    transport,     // the binding failed otherwise (I/O error, peer queue full)
    bad_request,   // the request could not be encoded (invalid arguments)
    bad_response,  // a response with our tag that is malformed or for another operation
    refused,       // the role answered with a status other than ok
};

[[nodiscard]] auto to_string(LinkErrc e) noexcept -> const char*;

struct LinkError {
    LinkErrc code{LinkErrc::transport};
    oar::Status status{oar::Status::ok};  // set for refused
    friend auto operator==(const LinkError&, const LinkError&) -> bool = default;
};

// Counters for packets and messages a link threw away.
struct LinkStats {
    std::uint64_t dropped_packets{0};   // undecodable, misaddressed or not reassembling
    std::uint64_t dropped_messages{0};  // reassembled but stale or not for this side
};

class OarLink {
public:
    // `binding` must outlive the link.
    OarLink(Binding& binding, const LinkConfig& config);

    auto function_inventory() -> std::expected<oar::Inventory, LinkError>;
    auto prepare_function(const oar::PrepareFunction& request) -> std::expected<void, LinkError>;
    auto clean_function(const oar::CleanFunction& request) -> std::expected<void, LinkError>;
    // Consumes the keys: they are wiped on return whatever the outcome.
    // `image_key` is an encrypted image volume's K_img, sent in the same
    // request as its ephemeral `key` (oar-blk task 15).
    auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                     std::optional<ScopedKey> image_key = std::nullopt)
        -> std::expected<void, LinkError>;
    auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError>;
    // The storage role's volume store (oar-blk Requirement 3).
    auto create_volume(const oar::CreateVolume& request) -> std::expected<void, LinkError>;
    auto delete_volume(const oar::DeleteVolume& request) -> std::expected<void, LinkError>;
    auto rewrap_volume(const oar::RewrapVolume& request) -> std::expected<void, LinkError>;
    // The network role's WireGuard keys (oar-net Requirement 5.2). Every
    // buffer that held a key is wiped once sent, success or not; the
    // caller wipes its own copies.
    // A non-zero `grace_seconds` makes it a rotation: the role keeps the
    // old key that long (fleet-scale-networking Requirement 1.3).
    auto set_tunnel_key(std::span<const std::byte, oar::tunnel_key_size> private_key,
                        std::uint32_t grace_seconds = 0) -> std::expected<void, LinkError>;
    auto set_tunnel_peer(const oar::SetTunnelPeer& request) -> std::expected<void, LinkError>;
    auto remove_tunnel_peer(const oar::RemoveTunnelPeer& request) -> std::expected<void, LinkError>;
    // Sends one controller MapUpdate frame, in chunks. Fails without sending
    // if the frame is empty or larger than oar::max_map_frame. A failure part
    // way leaves the role's partial frame to be discarded by the next
    // transfer, which always starts again at offset 0.
    auto map_update(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // Sends one controller TunnelPeers frame the same way; fails without
    // sending if it is empty or larger than oar::max_tunnel_peers_frame.
    auto tunnel_peers(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // Sends the role its VTEP credential, or a cell's revocation list, in
    // chunks like tunnel_peers (fleet-scale-networking task 2).
    auto vtep_credential(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    auto credential_revocations(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    auto health() -> std::expected<oar::Health, LinkError>;
    // Forwards one controller GroupPolicy frame to a network role in
    // chunks, like map_update; fails without sending unless it is
    // oar::group_policy_frame_size bytes (version 1) or between
    // oar::min_group_policy_v2_frame and oar::max_group_policy_frame.
    auto group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // Reads every page of the role's group meters: one snapshot, in
    // (nic_id, attachment) order. A page that disagrees with the first
    // page's total, or a role that never finishes, is a bad_response.
    auto group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError>;
    // Sends one controller GroupMembers frame in chunks, like tunnel_peers;
    // fails without sending if it is empty or larger than
    // oar::max_group_members_frame.
    auto group_members(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // The role's snooped joins: nullopt when they are still the list of
    // generation `since`, otherwise every page of one snapshot. Pages that
    // disagree on the generation or total, or break the order, are a
    // bad_response.
    struct Memberships {
        std::uint32_t generation{0};
        std::vector<oar::MembershipEntry> entries;
    };
    auto group_membership(std::optional<std::uint32_t> since)
        -> std::expected<std::optional<Memberships>, LinkError>;
    // Sends one controller InstanceMetadata frame in chunks, like
    // tunnel_peers; fails without sending if it is empty or larger than
    // oar::max_instance_metadata_frame.
    auto instance_metadata(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // Sends one controller VolumeLayout frame in chunks, like tunnel_peers,
    // to a blk role (khold volumes); fails without sending if it is empty
    // or larger than oar::max_volume_layout_frame.
    auto volume_layout(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // Sends one controller VpcConfig frame in chunks, like tunnel_peers,
    // to a network role; fails without sending if it is shorter than
    // oar::min_vpc_config_frame or longer than oar::max_vpc_config_frame.
    auto vpc_config(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    // Block volumes, to a hold role: one controller ReplicaConfig or
    // VolumeOp frame unmodified, and a lease acknowledgement.
    auto replica_config(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    auto volume_op(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    auto lease_grant(const oar::LeaseGrant& grant) -> std::expected<void, LinkError>;
    // Takes up to `max` whole reports the hold role queued (encoded
    // proto::Reports, not yet decoded), oldest first; each is acknowledged
    // with the next request. A chunk that does not continue its report is
    // a bad_response, and the report is read again from the start next
    // time.
    auto hold_reports(std::size_t max)
        -> std::expected<std::vector<std::vector<std::byte>>, LinkError>;
    // Enrollment, to a storage role: its certificate request (empty while
    // it wants none), and the controller's certificate chain for it, sent
    // in chunks; fails without sending if the chain is empty or larger
    // than oar::max_cert_chain.
    struct CertRequest {
        oar::Role role{oar::Role::blk};
        std::vector<std::byte> csr;
    };
    auto cert_request() -> std::expected<CertRequest, LinkError>;
    auto role_certificate(std::span<const std::byte> chain) -> std::expected<void, LinkError>;
    // Cooperative detach, to a storage role (blk): asks the guest to
    // release a function, withdraws that, or looks; the answer is where the
    // function stands.
    auto eject(const oar::Eject& request) -> std::expected<oar::EjectState, LinkError>;
    // Local <-> network conversion, to a storage role (blk): starts a copy
    // with both keys (wiped when this returns, like deliver_key's), or
    // queries or releases one (no keys; `request` carries none either way).
    auto copy_volume(const oar::CopyVolume& request, std::optional<ScopedKey> local_key = {},
                     std::optional<ScopedKey> network_key = {})
        -> std::expected<oar::CopyAnswer, LinkError>;
    // Asks a khold role to run its storage self-test; the results come
    // back as a capacity report through hold_reports.
    auto self_test() -> std::expected<void, LinkError>;

    // Scheduling classes (fleet-scale-networking Requirement 6.4, task 11).
    // Everything above is control or status: one request, answered before
    // the call returns. A controller frame that takes more than one chunk
    // is bulk: send_frame queues it and pump_bulk sends one chunk per call,
    // so the caller can serve control and status work between chunks and a
    // lease or a key never waits behind a whole transfer. A frame that fits
    // one chunk goes at once, unless a transfer of the same type is queued,
    // when it waits its turn behind it so a role sees each type's frames in
    // the order helm sent them. The role's endpoint keeps a transfer in
    // progress across single-chunk frames of any type.
    //
    // `done` runs once with the frame's outcome: before send_frame returns
    // for a frame sent at once or refused (bad_request: a type that is not
    // a controller frame, or a size outside that type's limits), otherwise
    // from the pump_bulk call that ends the transfer. A chunk that fails
    // ends its transfer with that error; the role discards its partial
    // frame when the next transfer starts. Transfers still queued when the
    // link is destroyed never complete and their `done` never runs.
    using FrameDone = std::function<void(const std::expected<void, LinkError>&)>;
    auto send_frame(mctp::VendorType type, std::span<const std::byte> frame, FrameDone done)
        -> void;
    // Sends the next chunk of the oldest queued transfer; true while any
    // transfer is still queued.
    auto pump_bulk() -> bool;
    [[nodiscard]] auto bulk_pending() const noexcept -> bool { return !_bulk.empty(); }
    // Bulk chunks sent, and transfers ended (whatever the outcome).
    [[nodiscard]] auto bulk_chunks() const noexcept -> std::uint64_t { return _bulk_chunks; }

    [[nodiscard]] auto stats() const noexcept -> const LinkStats& { return _stats; }

private:
    struct BulkTransfer {
        mctp::VendorType type{mctp::VendorType::map_update};
        std::vector<std::byte> frame;
        std::size_t offset{0};
        FrameDone done;
    };

    // Sends one request and waits for its response; returns the response
    // body after an ok head. `secret` wipes every buffer that held the body.
    auto transact(mctp::VendorType type, std::vector<std::byte>& body, bool secret = false)
        -> std::expected<std::vector<std::byte>, LinkError>;
    auto send_message(const mctp::Route& route, std::vector<std::byte>& message, bool secret)
        -> std::expected<void, LinkError>;
    auto await_response(mctp::VendorType type, std::uint8_t tag)
        -> std::expected<std::vector<std::byte>, LinkError>;
    // Sends a frame as consecutive chunks of `type` (map_update,
    // tunnel_peers, role_certificate).
    auto send_chunked(mctp::VendorType type, std::span<const std::byte> frame)
        -> std::expected<void, LinkError>;
    // One chunk of `frame` at `offset`, of at most oar::max_map_chunk bytes;
    // returns the chunk's length.
    auto send_chunk(mctp::VendorType type, std::span<const std::byte> frame, std::size_t offset)
        -> std::expected<std::size_t, LinkError>;

    Binding* _binding;
    LinkConfig _config;
    mctp::Assembler _assembler;
    std::uint8_t _next_tag{0};
    LinkStats _stats;
    std::uint64_t _report_ack{0};    // the last hold report read whole
    std::deque<BulkTransfer> _bulk;  // oldest first; the front is in progress
    std::uint64_t _bulk_chunks{0};
};

// What a data-plane role implements to answer OarLink. Each call returns the
// status to send; inventory and health also return their bodies.
class OarHandler {
public:
    OarHandler() = default;
    OarHandler(const OarHandler&) = default;
    auto operator=(const OarHandler&) -> OarHandler& = default;
    OarHandler(OarHandler&&) = default;
    auto operator=(OarHandler&&) -> OarHandler& = default;
    virtual ~OarHandler() = default;

    virtual auto function_inventory() -> std::expected<oar::Inventory, oar::Status> = 0;
    virtual auto prepare_function(const oar::PrepareFunction& request) -> oar::Status = 0;
    virtual auto clean_function(const oar::CleanFunction& request) -> oar::Status = 0;
    // request.key is valid only during the call; copy it into the key slot.
    virtual auto deliver_key(const oar::DeliverKey& request) -> oar::Status = 0;
    virtual auto drop_key(const oar::DropKey& request) -> oar::Status = 0;
    // A whole, reassembled MapUpdate frame, not yet decoded or verified.
    virtual auto map_update(std::span<const std::byte> frame) -> oar::Status = 0;
    virtual auto health() -> std::expected<oar::Health, oar::Status> = 0;
    // The volume store, which only the storage role keeps; every other
    // role answers unsupported. request.wrapped_key is valid only during
    // the call.
    virtual auto create_volume(const oar::CreateVolume& /*request*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto delete_volume(const oar::DeleteVolume& /*request*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto rewrap_volume(const oar::RewrapVolume& /*request*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // The WireGuard keys, which only the network role holds; every other
    // role answers unsupported. The key spans are valid only during the
    // call: copy them.
    virtual auto set_tunnel_key(const oar::SetTunnelKey& /*request*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto set_tunnel_peer(const oar::SetTunnelPeer& /*request*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto remove_tunnel_peer(const oar::RemoveTunnelPeer& /*request*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // Broadcast/multicast policy and meters, which only the network role
    // keeps (oar-net Requirement 10). `frame` is valid only during the call.
    virtual auto group_policy(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // One page of the meter snapshot; network roles answer through an
    // oar::UsagePager.
    virtual auto group_usage(std::uint16_t /*cursor*/)
        -> std::expected<oar::UsagePage, oar::Status> {
        return std::unexpected(oar::Status::unsupported);
    }
    // A whole, reassembled TunnelPeers frame, not yet decoded or verified.
    virtual auto vtep_credential(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto credential_revocations(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto tunnel_peers(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // Snooping, which only the network role does (oar-net Requirement
    // 10.5): a whole, reassembled GroupMembers frame, not yet decoded or
    // verified, and one page of the role's join list (oar::MembershipPager).
    virtual auto group_members(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto group_membership(const oar::MembershipRequest& /*request*/)
        -> std::expected<oar::MembershipPage, oar::Status> {
        return std::unexpected(oar::Status::unsupported);
    }
    // A NIC's instance metadata record, which only the network role keeps
    // (oar-net Requirement 13.4): whole and reassembled, not yet decoded
    // or verified, valid only during the call.
    virtual auto instance_metadata(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // A VPC's gateway configuration, which only the network role keeps
    // (oar-net Requirement 12). `frame` is not yet decoded or verified and
    // is valid only during the call.
    virtual auto vpc_config(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // Block volumes, which only the hold role keeps. The frames are not yet
    // decoded or verified and are valid only during the call; a role
    // answers hold_reports through an oar::ReportQueue.
    virtual auto replica_config(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // A khold volume's layout, which the blk role (kythira
    // khold-block-service Requirement 11.5) and the khold role keep: whole
    // and reassembled, not yet decoded or verified, valid only during the
    // call.
    virtual auto volume_layout(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto volume_op(std::span<const std::byte> /*frame*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto lease_grant(const oar::LeaseGrant& /*grant*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    virtual auto hold_reports(const oar::ReportRequest& /*request*/)
        -> std::expected<oar::ReportChunk, oar::Status> {
        return std::unexpected(oar::Status::unsupported);
    }
    // Enrollment, which only storage roles (blk, hold, khold) take part in. The
    // answer's csr must stay valid until the call returns to the endpoint;
    // `chain` (a whole, reassembled chain, not yet parsed) only during the
    // call.
    virtual auto cert_request() -> std::expected<oar::CertAnswer, oar::Status> {
        return std::unexpected(oar::Status::unsupported);
    }
    virtual auto role_certificate(std::span<const std::byte> /*chain*/) -> oar::Status {
        return oar::Status::unsupported;
    }
    // Starts the storage self-test, which only the khold role runs; its
    // results arrive later as a capacity report.
    virtual auto self_test() -> oar::Status { return oar::Status::unsupported; }
    // Cooperative detach, which only the storage role (blk) implements.
    virtual auto eject(const oar::Eject& /*request*/)
        -> std::expected<oar::EjectState, oar::Status> {
        return std::unexpected(oar::Status::unsupported);
    }
    // Local <-> network conversion, which only the storage role (blk)
    // implements. A start's keys view into the request message, which is
    // wiped after the call: copy them.
    virtual auto copy_volume(const oar::CopyVolume& /*request*/)
        -> std::expected<oar::CopyAnswer, oar::Status> {
        return std::unexpected(oar::Status::unsupported);
    }
};

class OarEndpoint {
public:
    // `binding` must outlive the endpoint. config.address is from the role's
    // side (local = the role); config.timeout is unused.
    OarEndpoint(Binding& binding, const LinkConfig& config);

    // Waits up to `timeout` for one packet and, if it completes a request,
    // answers it through `handler`. Returns true when a request was
    // answered, false when the packet was consumed without one (part of a
    // message, or dropped). Binding errors, timed_out included, are returned
    // as they are.
    auto serve_one(OarHandler& handler, std::chrono::milliseconds timeout)
        -> std::expected<bool, BindingError>;

    [[nodiscard]] auto stats() const noexcept -> const LinkStats& { return _stats; }

private:
    auto dispatch(OarHandler& handler, mctp::VendorType type, std::span<const std::byte> body)
        -> std::vector<std::byte>;
    // One chunk of a map_update, tunnel_peers, group_members,
    // instance_metadata or role_certificate transfer.
    auto frame_chunk(OarHandler& handler, mctp::VendorType type, std::span<const std::byte> body)
        -> oar::Status;
    auto reset_frame() noexcept -> void;
    // Hands a whole frame of `type` to its handler.
    static auto deliver_frame(OarHandler& handler, mctp::VendorType type,
                              std::span<const std::byte> frame) -> oar::Status;

    Binding* _binding;
    LinkConfig _config;
    mctp::Assembler _assembler;
    LinkStats _stats;
    // Chunked transfer in progress: its type, total length, and the bytes
    // so far in _frame.
    mctp::VendorType _frame_type{mctp::VendorType::map_update};
    std::uint32_t _frame_total{0};
    std::vector<std::byte> _frame;
};

}  // namespace ak::helm
