// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/tunnel_keyring.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <utility>

namespace ak::helm {

namespace {

struct PkeyDeleter {
    auto operator()(EVP_PKEY* p) const noexcept -> void { EVP_PKEY_free(p); }
};
struct PkeyCtxDeleter {
    auto operator()(EVP_PKEY_CTX* p) const noexcept -> void { EVP_PKEY_CTX_free(p); }
};

auto all_zero(std::span<const std::byte> b) -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto valid_vtep(const oar::Vtep& v) -> bool {
    constexpr std::uint8_t multicast = 0xFF;
    return !all_zero(v) && std::to_integer<std::uint8_t>(v[0]) != multicast;
}

// A fresh X25519 key pair from the OpenSSL RNG.
auto generate(std::span<std::byte, oar::tunnel_key_size> private_key,
              std::span<std::byte, oar::tunnel_key_size> public_key) -> bool {
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx{
        EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr)};
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) {
        return false;
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        return false;
    }
    const std::unique_ptr<EVP_PKEY, PkeyDeleter> key{raw};
    std::size_t priv_len = private_key.size();
    std::size_t pub_len = public_key.size();
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL's byte API
    const bool ok =
        EVP_PKEY_get_raw_private_key(
            key.get(), reinterpret_cast<unsigned char*>(private_key.data()), &priv_len) == 1 &&
        EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char*>(public_key.data()),
                                    &pub_len) == 1;
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    if (!ok || priv_len != private_key.size() || pub_len != public_key.size() ||
        all_zero(public_key)) {
        secure_zero(private_key);
        return false;
    }
    return true;
}

}  // namespace

auto to_string(KeyringError e) noexcept -> const char* {
    switch (e) {
        case KeyringError::bad_vtep:
            return "bad_vtep";
        case KeyringError::no_crypto:
            return "no_crypto";
    }
    return "unknown";
}

auto to_string(PeersOutcome o) noexcept -> const char* {
    switch (o) {
        case PeersOutcome::stored:
            return "stored";
        case PeersOutcome::duplicate:
            return "duplicate";
        case PeersOutcome::stale:
            return "stale";
    }
    return "unknown";
}

auto TunnelKeyring::ensure(const oar::Vtep& vtep) -> std::expected<PublicKey, KeyringError> {
    if (!valid_vtep(vtep)) {
        return std::unexpected(KeyringError::bad_vtep);
    }
    if (const auto it = _pairs.find(vtep); it != _pairs.end()) {
        return it->second.public_key;
    }
    Pair pair;
    if (!generate(pair.private_key.span(), pair.public_key)) {
        return std::unexpected(KeyringError::no_crypto);
    }
    const PublicKey pub = pair.public_key;
    _pairs.emplace(vtep, std::move(pair));
    return pub;
}

auto TunnelKeyring::public_key(const oar::Vtep& vtep) const -> std::optional<PublicKey> {
    const auto it = _pairs.find(vtep);
    if (it == _pairs.end()) {
        return std::nullopt;
    }
    return it->second.public_key;
}

auto TunnelKeyring::forget(const oar::Vtep& vtep) -> bool {
    // Erasing destroys the SecretBytes, which wipes the private key.
    const bool had_pair = _pairs.erase(vtep) != 0;
    const bool had_peers = _peers.erase(vtep) != 0;
    return had_pair || had_peers;
}

auto TunnelKeyring::store_peers(const proto::TunnelPeers& peers, std::span<const std::byte> frame)
    -> PeersOutcome {
    Peers& held = _peers[peers.vtep];
    if (peers.peers_version < held.version) {
        return PeersOutcome::stale;
    }
    if (peers.peers_version == held.version && std::ranges::equal(frame, held.frame)) {
        return PeersOutcome::duplicate;
    }
    held.version = peers.peers_version;
    held.frame.assign(frame.begin(), frame.end());
    return PeersOutcome::stored;
}

auto TunnelKeyring::peers_frame(const oar::Vtep& vtep) const -> std::span<const std::byte> {
    const auto it = _peers.find(vtep);
    if (it == _peers.end()) {
        return {};
    }
    return it->second.frame;
}

auto TunnelKeyring::peers_version(const oar::Vtep& vtep) const -> std::uint64_t {
    const auto it = _peers.find(vtep);
    return it == _peers.end() ? 0 : it->second.version;
}

auto TunnelKeyring::provision(OarLink& link, const oar::Vtep& vtep)
    -> std::expected<void, LinkError> {
    const auto it = _pairs.find(vtep);
    if (it == _pairs.end()) {
        return std::unexpected(LinkError{.code = LinkErrc::bad_request});
    }
    if (auto ok = link.set_tunnel_key(it->second.private_key.span()); !ok) {
        return ok;
    }
    if (const auto frame = peers_frame(vtep); !frame.empty()) {
        return link.tunnel_peers(frame);
    }
    return {};
}

auto TunnelKeyring::fill(proto::Inventory& inv) const -> void {
    // Every VTEP's role runs oar-net's WireGuard; none offloads PSP yet.
    constexpr proto::TunnelModes modes = proto::tunnel_mode_bit(proto::TunnelMode::wireguard);
    inv.tunnels.clear();
    inv.tunnels.reserve(inv.vteps.size());
    for (const auto& v : inv.vteps) {
        inv.tunnels.push_back({.modes = modes, .public_key = public_key(v).value_or(PublicKey{})});
    }
}

}  // namespace ak::helm
