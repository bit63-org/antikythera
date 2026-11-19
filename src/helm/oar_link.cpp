// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/oar_link.hpp"

#include <algorithm>
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

auto OarLink::deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key)
    -> std::expected<void, LinkError> {
    // `key` is a by-value parameter, so its bytes are wiped when this
    // returns, whichever path returns.
    if (!key.holds_key()) {
        return std::unexpected(bad_request());
    }
    auto body = oar::encode_deliver_key({.fn = fn, .volume_id = volume, .key = key.bytes()});
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

auto OarLink::map_update(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    if (frame.empty() || frame.size() > oar::max_map_frame) {
        return std::unexpected(bad_request());
    }
    const auto total = static_cast<std::uint32_t>(frame.size());
    for (std::size_t offset = 0; offset < frame.size();) {
        const auto len = std::min(oar::max_map_chunk, frame.size() - offset);
        auto body = oar::encode_map_chunk({.total = total,
                                           .offset = static_cast<std::uint32_t>(offset),
                                           .chunk = frame.subspan(offset, len)});
        if (!body) {
            return std::unexpected(bad_request());
        }
        auto response = transact(mctp::VendorType::map_update, *body);
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
        case mctp::VendorType::map_update:
            return status_only(map_chunk(handler, body));
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

auto OarEndpoint::map_chunk(OarHandler& handler, std::span<const std::byte> body) -> oar::Status {
    auto chunk = oar::decode_map_chunk(body);
    if (!chunk) {
        reset_map();
        return oar::Status::bad_request;
    }
    if (chunk->offset == 0) {
        // A new transfer; whatever was in progress is abandoned.
        reset_map();
        _map_total = chunk->total;
        _map_frame.reserve(chunk->total);
    } else if (_map_total == 0 || chunk->total != _map_total ||
               chunk->offset != _map_frame.size()) {
        reset_map();
        return oar::Status::bad_request;
    }
    _map_frame.insert(_map_frame.end(), chunk->chunk.begin(), chunk->chunk.end());
    if (_map_frame.size() < _map_total) {
        return oar::Status::ok;
    }
    const auto status = handler.map_update(_map_frame);
    reset_map();
    return status;
}

auto OarEndpoint::reset_map() noexcept -> void {
    _map_total = 0;
    _map_frame.clear();
}

}  // namespace ak::helm
