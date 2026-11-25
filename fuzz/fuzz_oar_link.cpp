// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the OarLink body decoders (helm/oar_protocol.hpp) and the role's
// request path (OarEndpoint): reassembly, dispatch and the map_update chunk
// state machine.
//
// The first input byte picks the mode. Below 0x80, the rest of the input is
// one body handed to every decoder; each body that decodes must re-encode
// to identical bytes. From 0x80, the rest is a stream of packets, each
// prefixed by a one-byte length, delivered to an OarEndpoint through an
// InProcessBinding; every answer it sends must itself be a packet that
// decodes.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "helm/oar_link.hpp"

namespace mctp = ak::helm::mctp;
namespace oar = ak::helm::oar;

namespace {

constexpr std::uint8_t stream_mode = 0x80;
constexpr ak::helm::LinkAddress oar_side{
    .local_addr = 0x10, .peer_addr = 0x08, .local_eid = 0x09, .peer_eid = 0x08};

auto same(std::span<const std::byte> a, const auto& encoded) -> void {
    if (!encoded || !std::ranges::equal(*encoded, a)) {
        std::abort();
    }
}

auto decoders(std::span<const std::byte> body) -> void {
    if (auto p = oar::decode_prepare_function(body)) {
        same(body, oar::encode_prepare_function(*p));
    }
    if (auto c = oar::decode_clean_function(body)) {
        same(body, oar::encode_clean_function(*c));
    }
    if (auto d = oar::decode_deliver_key(body)) {
        same(body, oar::encode_deliver_key(*d));
    }
    if (auto d = oar::decode_drop_key(body)) {
        same(body, oar::encode_drop_key(*d));
    }
    if (auto c = oar::decode_create_volume(body)) {
        same(body, oar::encode_create_volume(*c));
    }
    if (auto d = oar::decode_delete_volume(body)) {
        same(body, oar::encode_delete_volume(*d));
    }
    if (auto r = oar::decode_rewrap_volume(body)) {
        same(body, oar::encode_rewrap_volume(*r));
    }
    if (auto k = oar::decode_set_tunnel_key(body)) {
        same(body, oar::encode_set_tunnel_key(*k));
    }
    if (auto p = oar::decode_set_tunnel_peer(body)) {
        same(body, oar::encode_set_tunnel_peer(*p));
    }
    if (auto r = oar::decode_remove_tunnel_peer(body)) {
        same(body, oar::encode_remove_tunnel_peer(*r));
    }
    if (auto m = oar::decode_map_chunk(body)) {
        same(body, oar::encode_map_chunk(*m));
    }
    if (auto r = oar::decode_response(body)) {
        same(body, oar::encode_response(r->status, r->body));
    }
    if (auto i = oar::decode_inventory(body)) {
        same(body, oar::encode_inventory(*i));
    }
    if (auto h = oar::decode_health(body)) {
        same(body, oar::encode_health(*h));
    }
    if (auto f = oar::decode_group_policy_frame(body)) {
        same(body, oar::encode_group_policy_frame(*f));
    }
    if (auto c = oar::decode_usage_request(body)) {
        same(body, oar::encode_usage_request(*c));
    }
    if (auto f = oar::decode_replica_config_frame(body)) {
        same(body, oar::encode_replica_config_frame(*f));
    }
    if (auto f = oar::decode_volume_op_frame(body)) {
        same(body, oar::encode_volume_op_frame(*f));
    }
    if (auto g = oar::decode_lease_grant(body)) {
        same(body, oar::encode_lease_grant(*g));
    }
    if (auto r = oar::decode_report_request(body)) {
        same(body, oar::encode_report_request(*r));
    }
    if (auto c = oar::decode_report_chunk(body)) {
        same(body, oar::encode_report_chunk(*c));
    }
    if (auto c = oar::decode_cert_answer(body)) {
        same(body, oar::encode_cert_answer(*c));
    }
    if (auto e = oar::decode_eject(body)) {
        same(body, oar::encode_eject(*e));
    }
    if (auto e = oar::decode_eject_answer(body)) {
        same(body, oar::encode_eject_answer(*e));
    }
    // A usage page is checked against the cursor it answers: try the first
    // page and one further in.
    for (const std::uint16_t cursor : {std::uint16_t{0}, std::uint16_t{oar::max_usage_page}}) {
        if (auto u = oar::decode_usage_page(body, cursor)) {
            same(body, oar::encode_usage_page(*u, cursor));
        }
    }
    if (auto m = oar::decode_membership_request(body)) {
        same(body, oar::encode_membership_request(*m));
    }
    for (const std::uint16_t cursor : {std::uint16_t{0}, std::uint16_t{oar::max_membership_page}}) {
        if (auto m = oar::decode_membership_page(body, cursor)) {
            same(body, oar::encode_membership_page(*m, cursor));
        }
    }
}

// Accepts whatever helm asks for; map frames are only counted.
class AcceptAll final : public ak::helm::OarHandler {
public:
    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return oar::Inventory{.role = oar::Role::gpu, .vtep = {}, .functions = {}};
    }
    auto prepare_function(const oar::PrepareFunction&) -> oar::Status override {
        return oar::Status::ok;
    }
    auto clean_function(const oar::CleanFunction&) -> oar::Status override {
        return oar::Status::ok;
    }
    auto deliver_key(const oar::DeliverKey&) -> oar::Status override { return oar::Status::ok; }
    auto drop_key(const oar::DropKey&) -> oar::Status override { return oar::Status::ok; }
    auto map_update(std::span<const std::byte> frame) -> oar::Status override {
        if (frame.empty() || frame.size() > oar::max_map_frame) {
            std::abort();
        }
        return oar::Status::failed;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override {
        return std::unexpected(oar::Status::busy);
    }
    auto create_volume(const oar::CreateVolume& c) -> oar::Status override {
        if (c.wrapped_key.empty() || c.wrapped_key.size() > oar::max_wrapped_volume_key) {
            std::abort();
        }
        return oar::Status::ok;
    }
    auto rewrap_volume(const oar::RewrapVolume& r) -> oar::Status override {
        if (r.wrapped_key.empty() || r.wrapped_key.size() > oar::max_wrapped_volume_key) {
            std::abort();
        }
        return oar::Status::ok;
    }
};

auto stream(std::span<const std::byte> input) -> void {
    auto [helm_b, oar_b] = ak::helm::InProcessBinding::make_pair(input.size() + 1);
    ak::helm::OarEndpoint endpoint{*oar_b, {.address = oar_side}};
    AcceptAll handler;

    std::size_t pos = 0;
    while (pos < input.size()) {
        const auto len = std::to_integer<std::size_t>(input[pos]);
        ++pos;
        const auto chunk = input.subspan(pos, std::min(len, input.size() - pos));
        pos += chunk.size();
        if (!helm_b->send(chunk)) {
            continue;
        }
        (void)endpoint.serve_one(handler, std::chrono::milliseconds{0});
        // Every answer is a well-formed packet addressed back to helm.
        while (auto out = helm_b->receive(std::chrono::milliseconds{0})) {
            auto pkt = mctp::decode_packet(*out);
            if (!pkt || pkt->dest_addr != oar_side.peer_addr || pkt->header.tag_owner) {
                std::abort();
            }
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::span input{reinterpret_cast<const std::byte*>(data), size};
    if (data[0] < stream_mode) {
        decoders(input.subspan(1));
    } else {
        stream(input.subspan(1));
    }
    return 0;
}
