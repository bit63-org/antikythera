// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/standing_frames.hpp"

#include <array>
#include <format>
#include <optional>
#include <utility>

#include "proto/instance_metadata.hpp"
#include "proto/tunnel_peers.hpp"
#include "proto/vpc_config.hpp"

namespace ak::helm {

auto to_string(FrameVerdict v) noexcept -> const char* {
    switch (v) {
        case FrameVerdict::kept:
            return "kept";
        case FrameVerdict::not_standing:
            return "not for a standing NIC";
        case FrameVerdict::stale:
            return "version not newer than the one held";
        case FrameVerdict::wrong_server:
            return "names another server";
        case FrameVerdict::bad_signature:
            return "signature does not verify";
        case FrameVerdict::corrupt:
            return "does not decode";
        case FrameVerdict::store_failed:
            return "sealed store failed";
    }
    return "unknown";
}

namespace {

// The kind's part of an object name, and back.
constexpr std::array<std::pair<std::string_view, proto::RecordType>, 4> kinds{{
    {"peers.", proto::RecordType::tunnel_peers},
    {"vpc.", proto::RecordType::vpc_config},
    {"map.", proto::RecordType::map_update},
    {"meta.", proto::RecordType::instance_metadata},
}};

auto type_of(std::string_view name) -> std::optional<proto::RecordType> {
    if (!name.starts_with(standing_frame_prefix)) {
        return std::nullopt;
    }
    name.remove_prefix(standing_frame_prefix.size());
    for (const auto& [part, type] : kinds) {
        if (name.starts_with(part)) {
            return type;
        }
    }
    return std::nullopt;
}

}  // namespace

StandingFrames::StandingFrames(std::uint64_t server_id, SealedStore* store,
                               const RecordVerifier* verifier) noexcept
    : _server_id{server_id}, _store{store}, _verifier{verifier} {}

auto StandingFrames::object_name(const Key& key) -> std::string {
    const auto part = kinds.at(std::to_underlying(key.kind)).first;
    if (key.kind != Kind::peers) {
        return std::format("{}{}{}", standing_frame_prefix, part, key.id);
    }
    std::string name{standing_frame_prefix};
    name += part;
    for (const auto b : key.vtep) {
        name += std::format("{:02x}", std::to_integer<unsigned>(b));
    }
    return name;
}

auto StandingFrames::parse(proto::RecordType type, std::span<const std::byte> frame) const
    -> std::expected<Parsed, FrameVerdict> {
    // Decodes, checks the server and the signature, and names the frame.
    auto check = [&](const auto& f, std::span<const std::byte> signed_bytes, Key key,
                     std::uint64_t version,
                     std::uint32_t vni) -> std::expected<Parsed, FrameVerdict> {
        if (f.server_id != _server_id) {
            return std::unexpected(FrameVerdict::wrong_server);
        }
        if (_verifier == nullptr || !_verifier->verify(signed_bytes, f.signature, f.key_id)) {
            return std::unexpected(FrameVerdict::bad_signature);
        }
        return Parsed{.key = key,
                      .held = {.type = type,
                               .version = version,
                               .vni = vni,
                               .frame = {frame.begin(), frame.end()}}};
    };
    switch (type) {
        case proto::RecordType::tunnel_peers: {
            auto f = proto::decode_tunnel_peers(frame);
            if (!f) {
                return std::unexpected(FrameVerdict::corrupt);
            }
            return check(*f, proto::tunnel_peers_signed_bytes(frame),
                         {.kind = Kind::peers, .id = 0, .vtep = f->vtep}, f->peers_version, 0);
        }
        case proto::RecordType::vpc_config: {
            auto f = proto::decode_vpc_config(frame);
            if (!f) {
                return std::unexpected(FrameVerdict::corrupt);
            }
            return check(*f, proto::vpc_config_signed_bytes(frame),
                         {.kind = Kind::vpc, .id = f->vni, .vtep = {}}, f->config_version, f->vni);
        }
        case proto::RecordType::map_update: {
            auto f = proto::decode_map_update(frame);
            if (!f) {
                return std::unexpected(FrameVerdict::corrupt);
            }
            return check(*f, proto::map_update_signed_bytes(frame),
                         {.kind = Kind::map, .id = f->vni, .vtep = {}}, f->map_version, f->vni);
        }
        case proto::RecordType::instance_metadata: {
            auto f = proto::decode_instance_metadata(frame);
            if (!f) {
                return std::unexpected(FrameVerdict::corrupt);
            }
            return check(*f, proto::instance_metadata_signed_bytes(frame),
                         {.kind = Kind::metadata, .id = f->nic_id, .vtep = {}}, f->metadata_version,
                         f->vni);
        }
        default:
            return std::unexpected(FrameVerdict::not_standing);
    }
}

auto StandingFrames::wanted(const Key& key, std::uint32_t vni) const -> bool {
    switch (key.kind) {
        case Kind::peers:
            return !_nics.empty();
        case Kind::vpc:
        case Kind::map:
            return _vnis.contains(vni);
        case Kind::metadata: {
            const auto nic = _nics.find(key.id);
            return nic != _nics.end() && nic->second == vni;
        }
    }
    return false;
}

auto StandingFrames::follow(const proto::StandingSet* set) -> void {
    _vnis.clear();
    _nics.clear();
    if (set == nullptr) {
        return;
    }
    for (const auto& in : set->instances) {
        for (const auto& nic : in.nics) {
            _vnis.insert(nic.vni);
            _nics.emplace(nic.nic_id, nic.vni);
        }
    }
}

auto StandingFrames::drop_unwanted() -> void {
    for (auto it = _held.begin(); it != _held.end();) {
        if (wanted(it->first, it->second.vni)) {
            ++it;
            continue;
        }
        if (_store != nullptr) {
            (void)_store->remove(object_name(it->first));
        }
        it = _held.erase(it);
    }
}

auto StandingFrames::load(const proto::StandingSet* set) -> std::size_t {
    follow(set);
    _held.clear();
    if (_store == nullptr) {
        return 0;
    }
    // Requirement 1.5: an older copy of the partition may hold older
    // frames; none is trusted until the controller sends them again.
    const bool trusted = !_store->rolled_back() && !_store->degraded();
    for (const auto& name : _store->names()) {
        const auto type = type_of(name);
        if (!type) {
            continue;
        }
        std::optional<Parsed> parsed;
        if (trusted) {
            if (auto data = _store->get(name); data && *data) {
                if (auto p = parse(*type, **data); p) {
                    parsed = std::move(*p);
                }
            }
        }
        // Removed when untrusted, unreadable, no longer valid (a key retired
        // since), misnamed or no longer for a standing NIC.
        if (!parsed || object_name(parsed->key) != name || !wanted(parsed->key, parsed->held.vni)) {
            (void)_store->remove(name);
            continue;
        }
        auto& held = _held[parsed->key];
        if (held.frame.empty() || parsed->held.version > held.version) {
            held = std::move(parsed->held);
        }
    }
    return _held.size();
}

auto StandingFrames::retain(const proto::StandingSet* set) -> void {
    follow(set);
    drop_unwanted();
}

auto StandingFrames::offer(proto::RecordType type, std::span<const std::byte> frame)
    -> FrameVerdict {
    if (_nics.empty()) {
        return FrameVerdict::not_standing;  // nothing pinned: check nothing
    }
    auto parsed = parse(type, frame);
    if (!parsed) {
        return parsed.error();
    }
    if (!wanted(parsed->key, parsed->held.vni)) {
        return FrameVerdict::not_standing;
    }
    const auto held = _held.find(parsed->key);
    if (held != _held.end() && parsed->held.version <= held->second.version) {
        return FrameVerdict::stale;
    }
    if (_store != nullptr && !_store->put(object_name(parsed->key), parsed->held.frame)) {
        return FrameVerdict::store_failed;
    }
    _held.insert_or_assign(parsed->key, std::move(parsed->held));
    return FrameVerdict::kept;
}

auto StandingFrames::frames() const -> std::vector<StandingFrame> {
    std::vector<StandingFrame> out;
    out.reserve(_held.size());
    for (const auto& [key, held] : _held) {  // Key orders by kind first
        out.push_back({.type = held.type, .frame = held.frame});
    }
    return out;
}

}  // namespace ak::helm
