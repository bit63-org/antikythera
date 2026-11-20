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
#include <expected>
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
    // Consumes the key: it is wiped on return whatever the outcome.
    auto deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
        -> std::expected<void, LinkError>;
    auto drop_key(const oar::DropKey& request) -> std::expected<void, LinkError>;
    // The storage role's volume store (oar-blk Requirement 3).
    auto create_volume(const oar::CreateVolume& request) -> std::expected<void, LinkError>;
    auto delete_volume(const oar::DeleteVolume& request) -> std::expected<void, LinkError>;
    auto rewrap_volume(const oar::RewrapVolume& request) -> std::expected<void, LinkError>;
    // The network role's WireGuard keys (oar-net Requirement 5.2). Every
    // buffer that held a key is wiped once sent, success or not; the
    // caller wipes its own copies.
    auto set_tunnel_key(std::span<const std::byte, oar::tunnel_key_size> private_key)
        -> std::expected<void, LinkError>;
    auto set_tunnel_peer(const oar::SetTunnelPeer& request) -> std::expected<void, LinkError>;
    auto remove_tunnel_peer(const oar::RemoveTunnelPeer& request) -> std::expected<void, LinkError>;
    // Sends one controller MapUpdate frame, in chunks. Fails without sending
    // if the frame is empty or larger than oar::max_map_frame. A failure part
    // way leaves the role's partial frame to be discarded by the next
    // transfer, which always starts again at offset 0.
    auto map_update(std::span<const std::byte> frame) -> std::expected<void, LinkError>;
    auto health() -> std::expected<oar::Health, LinkError>;

    [[nodiscard]] auto stats() const noexcept -> const LinkStats& { return _stats; }

private:
    // Sends one request and waits for its response; returns the response
    // body after an ok head. `secret` wipes every buffer that held the body.
    auto transact(mctp::VendorType type, std::vector<std::byte>& body, bool secret = false)
        -> std::expected<std::vector<std::byte>, LinkError>;
    auto send_message(const mctp::Route& route, std::vector<std::byte>& message, bool secret)
        -> std::expected<void, LinkError>;
    auto await_response(mctp::VendorType type, std::uint8_t tag)
        -> std::expected<std::vector<std::byte>, LinkError>;

    Binding* _binding;
    LinkConfig _config;
    mctp::Assembler _assembler;
    std::uint8_t _next_tag{0};
    LinkStats _stats;
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
    auto map_chunk(OarHandler& handler, std::span<const std::byte> body) -> oar::Status;
    auto reset_map() noexcept -> void;

    Binding* _binding;
    LinkConfig _config;
    mctp::Assembler _assembler;
    LinkStats _stats;
    // MapUpdate transfer in progress: total length, bytes so far in _map_frame.
    std::uint32_t _map_total{0};
    std::vector<std::byte> _map_frame;
};

}  // namespace ak::helm
