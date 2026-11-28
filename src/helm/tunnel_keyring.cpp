// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/tunnel_keyring.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
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

// The public key of an X25519 private key; false if OpenSSL refuses it.
auto public_of(std::span<const std::byte, oar::tunnel_key_size> private_key,
               std::span<std::byte, oar::tunnel_key_size> public_key) -> bool {
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast): OpenSSL's byte API
    const std::unique_ptr<EVP_PKEY, PkeyDeleter> key{EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char*>(private_key.data()),
        private_key.size())};
    std::size_t pub_len = public_key.size();
    const bool ok =
        key && EVP_PKEY_get_raw_public_key(
                   key.get(), reinterpret_cast<unsigned char*>(public_key.data()), &pub_len) == 1;
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    return ok && pub_len == public_key.size() && !all_zero(public_key);
}

constexpr std::string_view epoch_directive = "vtep-key-epoch";

// Parses one decimal number that fills `word`.
template<typename T> auto parse_number(const std::string& word) -> std::optional<T> {
    T v{};
    const auto* end = word.c_str() + word.size();
    const auto [p, ec] = std::from_chars(word.c_str(), end, v);
    if (ec != std::errc{} || p != end) {
        return std::nullopt;
    }
    return v;
}

}  // namespace

auto to_string(KeyringError e) noexcept -> const char* {
    switch (e) {
        case KeyringError::bad_vtep:
            return "bad_vtep";
        case KeyringError::no_crypto:
            return "no_crypto";
        case KeyringError::state_io:
            return "state_io";
    }
    return "unknown";
}

auto to_string(EpochFileError e) noexcept -> const char* {
    switch (e) {
        case EpochFileError::io:
            return "io";
        case EpochFileError::corrupt:
            return "corrupt";
    }
    return "unknown";
}

auto to_string(RotateOutcome o) noexcept -> const char* {
    switch (o) {
        case RotateOutcome::rotated:
            return "rotated";
        case RotateOutcome::raised:
            return "raised";
        case RotateOutcome::stale:
            return "stale";
    }
    return "unknown";
}

// ---- KeyEpochs ------------------------------------------------------------

auto KeyEpochs::open(std::filesystem::path path) -> std::expected<KeyEpochs, EpochFileError> {
    KeyEpochs out;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        if (ec) {
            return std::unexpected(EpochFileError::io);
        }
        out._path = std::move(path);
        return out;
    }
    std::ifstream in{path};
    if (!in) {
        return std::unexpected(EpochFileError::io);
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream words{line};
        std::string directive;
        std::string slot_word;
        std::string epoch_word;
        std::string extra;
        if (!(words >> directive >> slot_word >> epoch_word) || (words >> extra) ||
            directive != epoch_directive) {
            return std::unexpected(EpochFileError::corrupt);
        }
        const auto slot = parse_number<unsigned>(slot_word);
        const auto epoch = parse_number<std::uint32_t>(epoch_word);
        constexpr unsigned max_slot = 0xFF;
        if (!slot || *slot > max_slot || !epoch || *epoch <= first ||
            !out._epochs.emplace(static_cast<std::uint8_t>(*slot), *epoch).second) {
            return std::unexpected(EpochFileError::corrupt);
        }
    }
    if (in.bad()) {
        return std::unexpected(EpochFileError::io);
    }
    out._path = std::move(path);
    return out;
}

auto KeyEpochs::epoch(std::uint8_t slot) const -> std::uint32_t {
    const auto it = _epochs.find(slot);
    return it == _epochs.end() ? first : it->second;
}

auto KeyEpochs::raise(std::uint8_t slot, std::uint32_t epoch)
    -> std::expected<void, EpochFileError> {
    auto next = _epochs;
    next[slot] = epoch;
    if (auto ok = save(next); !ok) {
        return ok;
    }
    _epochs = std::move(next);
    return {};
}

auto KeyEpochs::save(const std::map<std::uint8_t, std::uint32_t>& epochs) const
    -> std::expected<void, EpochFileError> {
    if (!_path) {
        return {};
    }
    std::string text;
    for (const auto& [slot, epoch] : epochs) {
        text += std::string{epoch_directive} + " " + std::to_string(slot) + " " +
                std::to_string(epoch) + "\n";
    }
    auto tmp = *_path;
    tmp += ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return std::unexpected(EpochFileError::io);
    }
    std::string_view rest{text};
    bool ok = true;
    while (ok && !rest.empty()) {
        const auto n = ::write(fd, rest.data(), rest.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        ok = n > 0;
        if (ok) {
            rest.remove_prefix(static_cast<std::size_t>(n));
        }
    }
    ok = ok && ::fsync(fd) == 0;
    ok = (::close(fd) == 0) && ok;
    std::error_code ec;
    if (ok) {
        std::filesystem::rename(tmp, *_path, ec);
    }
    if (!ok || ec) {
        std::filesystem::remove(tmp, ec);
        return std::unexpected(EpochFileError::io);
    }
    return {};
}

// ---- TunnelKeyring ----------------------------------------------------------

TunnelKeyring::TunnelKeyring(Deriver derive, KeyEpochs epochs)
    : _derive{std::move(derive)}, _epochs{std::move(epochs)} {}

auto TunnelKeyring::make_pair(std::uint8_t slot) const -> std::optional<Pair> {
    Pair pair;
    pair.slot = slot;
    pair.epoch = _epochs.epoch(slot);
    if (!_derive) {
        if (!generate(pair.private_key.span(), pair.public_key)) {
            return std::nullopt;
        }
        return pair;
    }
    if (!_derive(slot, pair.epoch, pair.private_key.span()) ||
        !public_of(pair.private_key.span(), pair.public_key)) {
        return std::nullopt;  // the SecretBytes destructor wipes what was written
    }
    return pair;
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

auto TunnelKeyring::ensure(const oar::Vtep& vtep, std::uint8_t slot)
    -> std::expected<PublicKey, KeyringError> {
    if (!valid_vtep(vtep)) {
        return std::unexpected(KeyringError::bad_vtep);
    }
    const auto it = _pairs.find(vtep);
    if (it != _pairs.end() && it->second.slot == slot) {
        return it->second.public_key;
    }
    auto pair = make_pair(slot);
    if (!pair) {
        return std::unexpected(KeyringError::no_crypto);
    }
    const PublicKey pub = pair->public_key;
    _pairs.insert_or_assign(vtep, std::move(*pair));
    return pub;
}

auto TunnelKeyring::rotate(std::uint8_t slot, std::uint32_t epoch, oar::Vtep* rotated_vtep)
    -> std::expected<RotateOutcome, KeyringError> {
    if (epoch <= _epochs.epoch(slot)) {
        return RotateOutcome::stale;
    }
    // The epoch is saved before the key changes: a crash in between comes
    // back with the new key, never with one the controller retired.
    if (!_epochs.raise(slot, epoch)) {
        return std::unexpected(KeyringError::state_io);
    }
    const auto it =
        std::ranges::find_if(_pairs, [&](const auto& p) { return p.second.slot == slot; });
    if (it == _pairs.end()) {
        return RotateOutcome::raised;
    }
    auto pair = make_pair(slot);
    if (!pair) {
        // The old pair goes too: keeping it would advertise a retired key.
        _pairs.erase(it);
        return std::unexpected(KeyringError::no_crypto);
    }
    it->second = std::move(*pair);
    if (rotated_vtep != nullptr) {
        *rotated_vtep = it->first;
    }
    return RotateOutcome::rotated;
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

auto TunnelKeyring::deliver_rotation(OarLink& link, const oar::Vtep& vtep,
                                     std::chrono::seconds grace) -> std::expected<void, LinkError> {
    const auto it = _pairs.find(vtep);
    if (it == _pairs.end()) {
        return std::unexpected(LinkError{.code = LinkErrc::bad_request});
    }
    constexpr auto max_grace = std::chrono::seconds{std::numeric_limits<std::uint32_t>::max()};
    const auto seconds =
        static_cast<std::uint32_t>(std::clamp(grace, std::chrono::seconds{1}, max_grace).count());
    auto done = link.set_tunnel_key(it->second.private_key.span(), seconds);
    if (!done && done.error().code == LinkErrc::refused &&
        done.error().status == oar::Status::bad_request) {
        done = link.set_tunnel_key(it->second.private_key.span());
    }
    return done;
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
