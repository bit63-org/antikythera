// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/oar_link.hpp"

#include <algorithm>
#include <tuple>
#include <utility>

namespace ak::helm {

namespace {

using Clock = std::chrono::steady_clock;

auto wipe(std::vector<std::byte>& buf) noexcept -> void {
    secure_zero(buf);
}

auto link_error(BindingError e) noexcept -> LinkError {
    return {.code = e == BindingError::disconnected ? LinkErrc::disconnected : LinkErrc::transport};
}

constexpr auto bad_request() noexcept -> LinkError {
    return {.code = LinkErrc::bad_request};
}
constexpr auto bad_response() noexcept -> LinkError {
    return {.code = LinkErrc::bad_response};
}

// The largest whole frame each chunked transfer type may announce.
constexpr auto frame_limit(mctp::VendorType type) noexcept -> std::size_t {
    switch (type) {
        case mctp::VendorType::map_update:
            return oar::max_map_frame;
        case mctp::VendorType::tunnel_peers:
            return oar::max_tunnel_peers_frame;
        case mctp::VendorType::group_members:
            return oar::max_group_members_frame;
        case mctp::VendorType::instance_metadata:
            return oar::max_instance_metadata_frame;
        case mctp::VendorType::volume_layout:
            return oar::max_volume_layout_frame;
        default:
            return oar::max_cert_chain;
    }
}

// Whether a decoded packet travels from `from` to `to` on this segment.
auto addressed(const mctp::Packet& p, std::uint8_t from, std::uint8_t to) noexcept -> bool {
    return p.src_addr == from && p.dest_addr == to;
}

// Fragments `message` along `route` and sends every packet. Wipes the
// packets afterwards when `secret`.
auto send_packets(Binding& binding, const mctp::Route& route, std::span<const std::byte> message,
                  std::size_t mtu, bool secret) -> std::expected<void, LinkError> {
    auto packets = mctp::fragment(route, message, mtu);
    if (!packets) {
        return std::unexpected(bad_request());
    }
    std::expected<void, LinkError> result;
    for (const auto& p : *packets) {
        if (auto sent = binding.send(p); !sent) {
            result = std::unexpected(link_error(sent.error()));
            break;
        }
    }
    if (secret) {
        for (auto& p : *packets) {
            wipe(p);
        }
    }
    return result;
}

}  // namespace

auto to_string(LinkErrc e) noexcept -> const char* {
    switch (e) {
        case LinkErrc::timed_out:
            return "timed_out";
        case LinkErrc::disconnected:
            return "disconnected";
        case LinkErrc::transport:
            return "transport";
        case LinkErrc::bad_request:
            return "bad_request";
        case LinkErrc::bad_response:
            return "bad_response";
        case LinkErrc::refused:
            return "refused";
    }
    return "unknown";
}

// ---- OarLink -----------------------------------------------------------------

namespace {

// A request whose ok answer carries nothing after the head.
auto expect_empty(const std::expected<std::vector<std::byte>, LinkError>& response)
    -> std::expected<void, LinkError> {
    if (!response) {
        return std::unexpected(response.error());
    }
    return response->empty() ? std::expected<void, LinkError>{} : std::unexpected(bad_response());
}

}  // namespace

OarLink::OarLink(Binding& binding, const LinkConfig& config)
    : _binding{&binding}, _config{config}, _assembler{config.address.local_eid} {}

auto OarLink::function_inventory() -> std::expected<oar::Inventory, LinkError> {
    std::vector<std::byte> body;
    auto response = transact(mctp::VendorType::function_inventory, body);
    if (!response) {
        return std::unexpected(response.error());
    }
    auto inv = oar::decode_inventory(*response);
    if (!inv) {
        return std::unexpected(bad_response());
    }
    return std::move(*inv);
}

auto OarLink::prepare_function(const oar::PrepareFunction& request)
    -> std::expected<void, LinkError> {
    auto body = oar::encode_prepare_function(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    auto response = transact(mctp::VendorType::prepare_function, *body);
    if (!response) {
        return std::unexpected(response.error());
    }
    return response->empty() ? std::expected<void, LinkError>{} : std::unexpected(bad_response());
}

auto OarLink::clean_function(const oar::CleanFunction& request) -> std::expected<void, LinkError> {
    auto body = oar::encode_clean_function(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    auto response = transact(mctp::VendorType::clean_function, *body);
    if (!response) {
        return std::unexpected(response.error());
    }
    return response->empty() ? std::expected<void, LinkError>{} : std::unexpected(bad_response());
}

auto OarLink::deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                          std::optional<ScopedKey> image_key) -> std::expected<void, LinkError> {
    // The keys are by-value parameters, so their bytes are wiped when this
    // returns, whichever path returns.
    if (!key.holds_key() || (image_key && !image_key->holds_key())) {
        return std::unexpected(bad_request());
    }
    oar::DeliverKey request{.fn = fn, .volume_id = volume, .key = key.bytes(), .image_key = {}};
    if (image_key) {
        request.image_key = image_key->bytes();
    }
    auto body = oar::encode_deliver_key(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    auto response = transact(mctp::VendorType::deliver_key, *body, true);
    if (!response) {
        return std::unexpected(response.error());
    }
    return response->empty() ? std::expected<void, LinkError>{} : std::unexpected(bad_response());
}

auto OarLink::drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> {
    auto body = oar::encode_drop_key(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    auto response = transact(mctp::VendorType::drop_key, *body);
    if (!response) {
        return std::unexpected(response.error());
    }
    return response->empty() ? std::expected<void, LinkError>{} : std::unexpected(bad_response());
}

auto OarLink::create_volume(const oar::CreateVolume& request) -> std::expected<void, LinkError> {
    auto body = oar::encode_create_volume(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::create_volume, *body));
}

auto OarLink::delete_volume(const oar::DeleteVolume& request) -> std::expected<void, LinkError> {
    auto body = oar::encode_delete_volume(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::delete_volume, *body));
}

auto OarLink::rewrap_volume(const oar::RewrapVolume& request) -> std::expected<void, LinkError> {
    auto body = oar::encode_rewrap_volume(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::rewrap_volume, *body));
}

auto OarLink::set_tunnel_key(std::span<const std::byte, oar::tunnel_key_size> private_key)
    -> std::expected<void, LinkError> {
    auto body = oar::encode_set_tunnel_key({.private_key = private_key});
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::set_tunnel_key, *body, true));
}

auto OarLink::set_tunnel_peer(const oar::SetTunnelPeer& request) -> std::expected<void, LinkError> {
    auto body = oar::encode_set_tunnel_peer(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::set_tunnel_peer, *body, true));
}

auto OarLink::remove_tunnel_peer(const oar::RemoveTunnelPeer& request)
    -> std::expected<void, LinkError> {
    auto body = oar::encode_remove_tunnel_peer(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::remove_tunnel_peer, *body));
}

auto OarLink::map_update(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    if (frame.empty() || frame.size() > oar::max_map_frame) {
        return std::unexpected(bad_request());
    }
    return send_chunked(mctp::VendorType::map_update, frame);
}

auto OarLink::tunnel_peers(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    if (frame.empty() || frame.size() > oar::max_tunnel_peers_frame) {
        return std::unexpected(bad_request());
    }
    return send_chunked(mctp::VendorType::tunnel_peers, frame);
}

auto OarLink::group_members(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    if (frame.empty() || frame.size() > oar::max_group_members_frame) {
        return std::unexpected(bad_request());
    }
    return send_chunked(mctp::VendorType::group_members, frame);
}

auto OarLink::volume_layout(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    if (frame.empty() || frame.size() > oar::max_volume_layout_frame) {
        return std::unexpected(bad_request());
    }
    return send_chunked(mctp::VendorType::volume_layout, frame);
}

auto OarLink::instance_metadata(std::span<const std::byte> frame)
    -> std::expected<void, LinkError> {
    if (frame.empty() || frame.size() > oar::max_instance_metadata_frame) {
        return std::unexpected(bad_request());
    }
    return send_chunked(mctp::VendorType::instance_metadata, frame);
}

auto OarLink::group_membership(std::optional<std::uint32_t> since)
    -> std::expected<std::optional<Memberships>, LinkError> {
    Memberships out;
    std::uint16_t total = 0;
    std::uint16_t cursor = 0;
    do {
        auto body = oar::encode_membership_request({.cursor = cursor, .since = since});
        if (!body) {
            return std::unexpected(bad_request());
        }
        auto response = transact(mctp::VendorType::group_membership, *body);
        if (!response) {
            return std::unexpected(response.error());
        }
        auto page = oar::decode_membership_page(*response, cursor);
        if (!page) {
            return std::unexpected(bad_response());
        }
        if (page->unchanged) {
            if (!since || page->generation != *since) {
                return std::unexpected(bad_response());
            }
            return std::nullopt;
        }
        if (cursor != 0 && (page->total != total || page->generation != out.generation)) {
            return std::unexpected(bad_response());
        }
        total = page->total;
        out.generation = page->generation;
        if (!out.entries.empty() && !page->entries.empty()) {
            const auto& a = out.entries.back();
            const auto& b = page->entries.front();
            if (std::tuple{b.nic_id, b.ipv6, b.group} <= std::tuple{a.nic_id, a.ipv6, a.group}) {
                return std::unexpected(bad_response());
            }
        }
        out.entries.insert(out.entries.end(), page->entries.begin(), page->entries.end());
        cursor = static_cast<std::uint16_t>(out.entries.size());
        // After the first page the role answers from its snapshot, so
        // `since` no longer matters.
    } while (cursor < total);
    return out;
}

auto OarLink::role_certificate(std::span<const std::byte> chain) -> std::expected<void, LinkError> {
    if (chain.empty() || chain.size() > oar::max_cert_chain) {
        return std::unexpected(bad_request());
    }
    return send_chunked(mctp::VendorType::role_certificate, chain);
}

auto OarLink::cert_request() -> std::expected<CertRequest, LinkError> {
    std::vector<std::byte> body;
    auto response = transact(mctp::VendorType::cert_request, body);
    if (!response) {
        return std::unexpected(response.error());
    }
    auto answer = oar::decode_cert_answer(*response);
    if (!answer) {
        return std::unexpected(LinkError{.code = LinkErrc::bad_response});
    }
    return CertRequest{.role = answer->role, .csr = {answer->csr.begin(), answer->csr.end()}};
}

auto OarLink::eject(const oar::Eject& request) -> std::expected<oar::EjectState, LinkError> {
    auto body = oar::encode_eject(request);
    if (!body) {
        return std::unexpected(bad_request());
    }
    auto response = transact(mctp::VendorType::eject, *body);
    if (!response) {
        return std::unexpected(response.error());
    }
    auto state = oar::decode_eject_answer(*response);
    if (!state) {
        return std::unexpected(LinkError{.code = LinkErrc::bad_response});
    }
    return *state;
}

auto OarLink::copy_volume(const oar::CopyVolume& request, std::optional<ScopedKey> local_key,
                          std::optional<ScopedKey> network_key)
    -> std::expected<oar::CopyAnswer, LinkError> {
    // The keys are by-value parameters, so their bytes are wiped when this
    // returns, whichever path returns.
    const bool start = request.op == oar::CopyOp::start;
    if (request.local_key || request.network_key || local_key.has_value() != start ||
        network_key.has_value() != start ||
        (start && (!local_key->holds_key() || !network_key->holds_key()))) {
        return std::unexpected(bad_request());
    }
    oar::CopyVolume r = request;
    if (start) {
        r.local_key = local_key->bytes();
        r.network_key = network_key->bytes();
    }
    auto body = oar::encode_copy_volume(r);
    if (!body) {
        return std::unexpected(bad_request());
    }
    auto response = transact(mctp::VendorType::copy_volume, *body, start);
    if (!response) {
        return std::unexpected(response.error());
    }
    auto answer = oar::decode_copy_answer(*response);
    if (!answer) {
        return std::unexpected(LinkError{.code = LinkErrc::bad_response});
    }
    return *answer;
}

auto OarLink::send_chunked(mctp::VendorType type, std::span<const std::byte> frame)
    -> std::expected<void, LinkError> {
    const auto total = static_cast<std::uint32_t>(frame.size());
    for (std::size_t offset = 0; offset < frame.size();) {
        const auto len = std::min(oar::max_map_chunk, frame.size() - offset);
        auto body = oar::encode_map_chunk({.total = total,
                                           .offset = static_cast<std::uint32_t>(offset),
                                           .chunk = frame.subspan(offset, len)});
        if (!body) {
            return std::unexpected(bad_request());
        }
        auto response = transact(type, *body);
        if (!response) {
            return std::unexpected(response.error());
        }
        if (!response->empty()) {
            return std::unexpected(bad_response());
        }
        offset += len;
    }
    return {};
}

auto OarLink::group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    auto body = oar::encode_group_policy_frame(frame);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::group_policy, *body));
}

auto OarLink::group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> {
    std::vector<oar::UsageEntry> out;
    std::uint16_t total = 0;
    std::uint16_t cursor = 0;
    do {
        auto body = oar::encode_usage_request(cursor);
        if (!body) {
            return std::unexpected(bad_request());
        }
        auto response = transact(mctp::VendorType::group_usage, *body);
        if (!response) {
            return std::unexpected(response.error());
        }
        auto page = oar::decode_usage_page(*response, cursor);
        if (!page || (cursor != 0 && page->total != total)) {
            return std::unexpected(bad_response());
        }
        total = page->total;
        // Each page continues the order of the last.
        if (!out.empty() && !page->entries.empty() &&
            std::pair{page->entries.front().nic_id, page->entries.front().attachment} <=
                std::pair{out.back().nic_id, out.back().attachment}) {
            return std::unexpected(bad_response());
        }
        out.insert(out.end(), page->entries.begin(), page->entries.end());
        cursor = static_cast<std::uint16_t>(out.size());
    } while (cursor < total);
    return out;
}

auto OarLink::vpc_config(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    auto body = oar::encode_vpc_config_frame(frame);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::vpc_config, *body));
}

auto OarLink::replica_config(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    auto body = oar::encode_replica_config_frame(frame);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::replica_config, *body));
}

auto OarLink::volume_op(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    auto body = oar::encode_volume_op_frame(frame);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::volume_op, *body));
}

auto OarLink::lease_grant(const oar::LeaseGrant& grant) -> std::expected<void, LinkError> {
    auto body = oar::encode_lease_grant(grant);
    if (!body) {
        return std::unexpected(bad_request());
    }
    return expect_empty(transact(mctp::VendorType::lease_grant, *body));
}

auto OarLink::hold_reports(std::size_t max)
    -> std::expected<std::vector<std::vector<std::byte>>, LinkError> {
    std::vector<std::vector<std::byte>> out;
    while (out.size() < max) {
        std::vector<std::byte> report;
        std::uint64_t seq = 0;
        std::uint32_t total = 0;
        do {
            auto body = oar::encode_report_request(
                {.ack = _report_ack, .offset = static_cast<std::uint32_t>(report.size())});
            if (!body) {
                return std::unexpected(bad_request());
            }
            auto response = transact(mctp::VendorType::hold_reports, *body);
            if (!response) {
                return std::unexpected(response.error());
            }
            auto chunk = oar::decode_report_chunk(*response);
            if (!chunk) {
                return std::unexpected(bad_response());
            }
            if (chunk->total == 0) {
                if (!report.empty()) {
                    return std::unexpected(bad_response());  // it vanished part way
                }
                return out;
            }
            if (chunk->offset != report.size() ||
                (!report.empty() && (chunk->report_seq != seq || chunk->total != total))) {
                return std::unexpected(bad_response());
            }
            seq = chunk->report_seq;
            total = chunk->total;
            report.insert(report.end(), chunk->chunk.begin(), chunk->chunk.end());
        } while (report.size() < total);
        _report_ack = seq;
        out.push_back(std::move(report));
    }
    return out;
}

auto OarLink::health() -> std::expected<oar::Health, LinkError> {
    std::vector<std::byte> body;
    auto response = transact(mctp::VendorType::health, body);
    if (!response) {
        return std::unexpected(response.error());
    }
    auto h = oar::decode_health(*response);
    if (!h) {
        return std::unexpected(bad_response());
    }
    return *h;
}

auto OarLink::transact(mctp::VendorType type, std::vector<std::byte>& body, bool secret)
    -> std::expected<std::vector<std::byte>, LinkError> {
    const std::uint8_t tag = _next_tag;
    _next_tag = static_cast<std::uint8_t>((tag + 1U) & mctp::max_tag);

    auto message = mctp::encode_vendor({.type = type, .response = false}, body);
    if (secret) {
        wipe(body);
    }
    if (!message) {
        return std::unexpected(bad_request());
    }
    const auto& a = _config.address;
    const mctp::Route route{.dest_addr = a.peer_addr,
                            .src_addr = a.local_addr,
                            .dest_eid = a.peer_eid,
                            .src_eid = a.local_eid,
                            .tag_owner = true,
                            .tag = tag};
    if (auto sent = send_message(route, *message, secret); !sent) {
        return std::unexpected(sent.error());
    }
    return await_response(type, tag);
}

auto OarLink::send_message(const mctp::Route& route, std::vector<std::byte>& message, bool secret)
    -> std::expected<void, LinkError> {
    auto sent = send_packets(*_binding, route, message, _config.mtu, secret);
    if (secret) {
        wipe(message);
    }
    return sent;
}

auto OarLink::await_response(mctp::VendorType type, std::uint8_t tag)
    -> std::expected<std::vector<std::byte>, LinkError> {
    const auto& a = _config.address;
    const auto deadline = Clock::now() + _config.timeout;
    for (;;) {
        const auto left =
            std::max(std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()),
                     std::chrono::milliseconds{0});
        auto raw = _binding->receive(left);
        if (!raw) {
            if (raw.error() == BindingError::timed_out) {
                return std::unexpected(LinkError{.code = LinkErrc::timed_out});
            }
            if (raw.error() == BindingError::oversized) {
                ++_stats.dropped_packets;
                continue;
            }
            return std::unexpected(link_error(raw.error()));
        }
        auto packet = mctp::decode_packet(*raw);
        if (!packet || !addressed(*packet, a.peer_addr, a.local_addr)) {
            ++_stats.dropped_packets;
            continue;
        }
        auto pushed = _assembler.push(*packet);
        if (!pushed) {
            ++_stats.dropped_packets;
            continue;
        }
        if (!pushed->has_value()) {
            continue;
        }
        const auto& msg = **pushed;
        if (msg.route.src_eid != a.peer_eid || msg.route.tag_owner || msg.route.tag != tag) {
            // A late answer to an earlier, timed-out request, or not an answer.
            ++_stats.dropped_messages;
            continue;
        }
        auto vendor = mctp::decode_vendor(msg.bytes);
        if (!vendor || !vendor->header.response || vendor->header.type != type) {
            return std::unexpected(bad_response());
        }
        auto head = oar::decode_response(vendor->body);
        if (!head) {
            return std::unexpected(bad_response());
        }
        if (head->status != oar::Status::ok) {
            return std::unexpected(LinkError{.code = LinkErrc::refused, .status = head->status});
        }
        return std::vector<std::byte>{head->body.begin(), head->body.end()};
    }
}

// ---- OarEndpoint ---------------------------------------------------------------

OarEndpoint::OarEndpoint(Binding& binding, const LinkConfig& config)
    : _binding{&binding}, _config{config}, _assembler{config.address.local_eid} {}

auto OarEndpoint::serve_one(OarHandler& handler, std::chrono::milliseconds timeout)
    -> std::expected<bool, BindingError> {
    const auto& a = _config.address;
    auto raw = _binding->receive(timeout);
    if (!raw) {
        if (raw.error() == BindingError::oversized) {
            ++_stats.dropped_packets;
            return false;
        }
        return std::unexpected(raw.error());
    }
    auto packet = mctp::decode_packet(*raw);
    if (!packet || !addressed(*packet, a.peer_addr, a.local_addr)) {
        ++_stats.dropped_packets;
        return false;
    }
    auto pushed = _assembler.push(*packet);
    if (!pushed) {
        ++_stats.dropped_packets;
        return false;
    }
    if (!pushed->has_value()) {
        return false;
    }
    auto msg = std::move(**pushed);
    auto vendor = mctp::decode_vendor(msg.bytes);
    if (!vendor || vendor->header.response || !msg.route.tag_owner ||
        msg.route.src_eid != a.peer_eid) {
        // Not a request from helm. Without a decodable request there is no
        // operation to answer, so it is dropped rather than refused.
        ++_stats.dropped_messages;
        wipe(msg.bytes);
        return false;
    }

    auto response = dispatch(handler, vendor->header.type, vendor->body);
    // The request may have carried a key (deliver_key); the handler has had
    // its chance to copy it.
    wipe(msg.bytes);

    auto reply = mctp::encode_vendor({.type = vendor->header.type, .response = true}, response);
    if (!reply) {
        return std::unexpected(BindingError::io);
    }
    const mctp::Route route{.dest_addr = a.peer_addr,
                            .src_addr = a.local_addr,
                            .dest_eid = a.peer_eid,
                            .src_eid = a.local_eid,
                            .tag_owner = false,
                            .tag = msg.route.tag};
    auto sent = send_packets(*_binding, route, *reply, _config.mtu, false);
    if (!sent) {
        if (sent.error().code == LinkErrc::disconnected) {
            return std::unexpected(BindingError::disconnected);
        }
        return std::unexpected(BindingError::io);
    }
    return true;
}

auto OarEndpoint::dispatch(OarHandler& handler, mctp::VendorType type,
                           std::span<const std::byte> body) -> std::vector<std::byte> {
    // encode_response cannot fail for a known status with no body, and
    // every status here comes from the oar::Status enum.
    const auto status_only = [](oar::Status s) {
        return oar::encode_response(s).value_or(std::vector<std::byte>{});
    };
    // A handler-supplied body that does not encode is the role's bug; report
    // it as failed rather than send something helm would refuse.
    const auto with_body = [&](auto encoded) {
        if (!encoded) {
            return status_only(oar::Status::failed);
        }
        return oar::encode_response(oar::Status::ok, *encoded)
            .value_or(status_only(oar::Status::failed));
    };

    switch (type) {
        case mctp::VendorType::function_inventory: {
            if (!oar::decode_empty(body)) {
                return status_only(oar::Status::bad_request);
            }
            auto inv = handler.function_inventory();
            if (!inv) {
                return status_only(inv.error() == oar::Status::ok ? oar::Status::failed
                                                                  : inv.error());
            }
            return with_body(oar::encode_inventory(*inv));
        }
        case mctp::VendorType::prepare_function: {
            auto req = oar::decode_prepare_function(body);
            return status_only(req ? handler.prepare_function(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::clean_function: {
            auto req = oar::decode_clean_function(body);
            return status_only(req ? handler.clean_function(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::deliver_key: {
            auto req = oar::decode_deliver_key(body);
            return status_only(req ? handler.deliver_key(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::drop_key: {
            auto req = oar::decode_drop_key(body);
            return status_only(req ? handler.drop_key(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::create_volume: {
            auto req = oar::decode_create_volume(body);
            return status_only(req ? handler.create_volume(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::delete_volume: {
            auto req = oar::decode_delete_volume(body);
            return status_only(req ? handler.delete_volume(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::rewrap_volume: {
            auto req = oar::decode_rewrap_volume(body);
            return status_only(req ? handler.rewrap_volume(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::set_tunnel_key: {
            auto req = oar::decode_set_tunnel_key(body);
            return status_only(req ? handler.set_tunnel_key(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::set_tunnel_peer: {
            auto req = oar::decode_set_tunnel_peer(body);
            return status_only(req ? handler.set_tunnel_peer(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::remove_tunnel_peer: {
            auto req = oar::decode_remove_tunnel_peer(body);
            return status_only(req ? handler.remove_tunnel_peer(*req) : oar::Status::bad_request);
        }
        case mctp::VendorType::map_update:
        case mctp::VendorType::tunnel_peers:
        case mctp::VendorType::group_members:
        case mctp::VendorType::instance_metadata:
        case mctp::VendorType::volume_layout:
        case mctp::VendorType::role_certificate:
            return status_only(frame_chunk(handler, type, body));
        case mctp::VendorType::group_membership: {
            auto req = oar::decode_membership_request(body);
            if (!req) {
                return status_only(oar::Status::bad_request);
            }
            auto page = handler.group_membership(*req);
            if (!page) {
                return status_only(page.error() == oar::Status::ok ? oar::Status::failed
                                                                   : page.error());
            }
            return with_body(oar::encode_membership_page(*page, req->cursor));
        }
        case mctp::VendorType::cert_request: {
            if (!oar::decode_empty(body)) {
                return status_only(oar::Status::bad_request);
            }
            auto answer = handler.cert_request();
            if (!answer) {
                return status_only(answer.error() == oar::Status::ok ? oar::Status::failed
                                                                     : answer.error());
            }
            return with_body(oar::encode_cert_answer(*answer));
        }
        case mctp::VendorType::eject: {
            auto req = oar::decode_eject(body);
            if (!req) {
                return status_only(oar::Status::bad_request);
            }
            auto state = handler.eject(*req);
            if (!state) {
                return status_only(state.error() == oar::Status::ok ? oar::Status::failed
                                                                    : state.error());
            }
            return with_body(oar::encode_eject_answer(*state));
        }
        case mctp::VendorType::copy_volume: {
            auto req = oar::decode_copy_volume(body);
            if (!req) {
                return status_only(oar::Status::bad_request);
            }
            auto answer = handler.copy_volume(*req);
            if (!answer) {
                return status_only(answer.error() == oar::Status::ok ? oar::Status::failed
                                                                     : answer.error());
            }
            return with_body(oar::encode_copy_answer(*answer));
        }
        case mctp::VendorType::group_policy: {
            auto frame = oar::decode_group_policy_frame(body);
            return status_only(frame ? handler.group_policy(*frame) : oar::Status::bad_request);
        }
        case mctp::VendorType::group_usage: {
            auto cursor = oar::decode_usage_request(body);
            if (!cursor) {
                return status_only(oar::Status::bad_request);
            }
            auto page = handler.group_usage(*cursor);
            if (!page) {
                return status_only(page.error() == oar::Status::ok ? oar::Status::failed
                                                                   : page.error());
            }
            return with_body(oar::encode_usage_page(*page, *cursor));
        }
        case mctp::VendorType::vpc_config: {
            auto frame = oar::decode_vpc_config_frame(body);
            return status_only(frame ? handler.vpc_config(*frame) : oar::Status::bad_request);
        }
        case mctp::VendorType::replica_config: {
            auto frame = oar::decode_replica_config_frame(body);
            return status_only(frame ? handler.replica_config(*frame) : oar::Status::bad_request);
        }
        case mctp::VendorType::volume_op: {
            auto frame = oar::decode_volume_op_frame(body);
            return status_only(frame ? handler.volume_op(*frame) : oar::Status::bad_request);
        }
        case mctp::VendorType::lease_grant: {
            auto grant = oar::decode_lease_grant(body);
            return status_only(grant ? handler.lease_grant(*grant) : oar::Status::bad_request);
        }
        case mctp::VendorType::hold_reports: {
            auto req = oar::decode_report_request(body);
            if (!req) {
                return status_only(oar::Status::bad_request);
            }
            auto chunk = handler.hold_reports(*req);
            if (!chunk) {
                return status_only(chunk.error() == oar::Status::ok ? oar::Status::failed
                                                                    : chunk.error());
            }
            return with_body(oar::encode_report_chunk(*chunk));
        }
        case mctp::VendorType::health: {
            if (!oar::decode_empty(body)) {
                return status_only(oar::Status::bad_request);
            }
            auto h = handler.health();
            if (!h) {
                return status_only(h.error() == oar::Status::ok ? oar::Status::failed : h.error());
            }
            return with_body(oar::encode_health(*h));
        }
    }
    return status_only(oar::Status::unsupported);
}

auto OarEndpoint::frame_chunk(OarHandler& handler, mctp::VendorType type,
                              std::span<const std::byte> body) -> oar::Status {
    auto chunk = oar::decode_map_chunk(body);
    if (!chunk) {
        reset_frame();
        return oar::Status::bad_request;
    }
    const std::size_t limit = frame_limit(type);
    if (chunk->offset == 0) {
        // A new transfer; whatever was in progress is abandoned.
        reset_frame();
        if (chunk->total > limit) {
            return oar::Status::bad_request;
        }
        _frame_type = type;
        _frame_total = chunk->total;
        _frame.reserve(chunk->total);
    } else if (_frame_total == 0 || type != _frame_type || chunk->total != _frame_total ||
               chunk->offset != _frame.size()) {
        reset_frame();
        return oar::Status::bad_request;
    }
    _frame.insert(_frame.end(), chunk->chunk.begin(), chunk->chunk.end());
    if (_frame.size() < _frame_total) {
        return oar::Status::ok;
    }
    oar::Status status = oar::Status::bad_request;
    switch (type) {
        case mctp::VendorType::map_update:
            status = handler.map_update(_frame);
            break;
        case mctp::VendorType::tunnel_peers:
            status = handler.tunnel_peers(_frame);
            break;
        case mctp::VendorType::group_members:
            status = handler.group_members(_frame);
            break;
        case mctp::VendorType::instance_metadata:
            status = handler.instance_metadata(_frame);
            break;
        case mctp::VendorType::volume_layout:
            status = handler.volume_layout(_frame);
            break;
        default:
            status = handler.role_certificate(_frame);
            break;
    }
    reset_frame();
    return status;
}

auto OarEndpoint::reset_frame() noexcept -> void {
    _frame_total = 0;
    _frame.clear();
}

}  // namespace ak::helm
