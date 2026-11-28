// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/tunnel.hpp"

#include <algorithm>
#include <cstring>
#include <string_view>
#include <utility>

#include <openssl/rand.h>

#include "common/wire.hpp"
#include "oar/net/credentials.hpp"

namespace ak::oar::net {

namespace {

constexpr std::string_view construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
constexpr std::string_view identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
constexpr std::string_view label_mac1 = "mac1----";

// Offsets inside the handshake messages (wireguard.hpp).
constexpr std::size_t init_ephemeral = 8;
constexpr std::size_t init_static = 40;
constexpr std::size_t init_timestamp = 88;
constexpr std::size_t resp_ephemeral = 12;
constexpr std::size_t resp_empty = 44;
constexpr std::size_t new_index_attempts = 8;

using wg::Hash;
using wg::Key;
using wg::SecretKey;
using Chain = wg::Secret<wg::hash_size>;

auto text(std::string_view s) -> std::span<const std::byte> {
    return std::as_bytes(std::span{s});
}

auto is_zero(std::span<const std::byte> s) -> bool {
    return std::all_of(s.begin(), s.end(), [](std::byte b) { return b == std::byte{0}; });
}

auto mix_hash(Hash& h, std::span<const std::byte> data) -> void {
    h = wg::hash({h, data});
}

// C = KDF1(C, input).
auto mix_key(Chain& c, std::span<const std::byte> input) -> void {
    wg::kdf(c.span(), input, {c.span()});
}

auto put_header(std::span<std::byte> msg, wg::MessageType type) -> void {
    std::fill(msg.begin(), msg.end(), std::byte{0});
    msg[0] = static_cast<std::byte>(type);
}

auto put_le32(std::span<std::byte> at, std::uint32_t v) -> void {
    for (std::size_t i = 0; i < sizeof(v); ++i) {
        at[i] = static_cast<std::byte>((v >> (8U * i)) & 0xFFU);
    }
}

auto put_le64(std::span<std::byte> at, std::uint64_t v) -> void {
    for (std::size_t i = 0; i < sizeof(v); ++i) {
        at[i] = static_cast<std::byte>((v >> (8U * i)) & 0xFFU);
    }
}

}  // namespace

struct Tunnel::Keypair {
    wg::Aead sender;
    wg::Aead receiver;
    std::uint32_t local_index{0};
    std::uint32_t remote_index{0};
    VtepClock::time_point created;
    std::uint64_t send_counter{0};
    wg::ReplayWindow window;
    bool initiator{false};
    std::uint32_t key_generation{0};  // Tunnel::_key_generation it was made under
};

struct Tunnel::Peer {
    Ipv6Address vtep{};
    Key public_key{};
    SecretKey psk;
    Hash mac1_key{};                       // HASH("mac1----" || public_key)
    std::optional<SecretKey> static_dh;    // DH(own private, public_key)
    std::optional<SecretKey> retiring_dh;  // DH(rotated-out private, public_key)
    std::optional<wg::Timestamp> last_timestamp;
    std::optional<VtepClock::time_point> last_initiation_rx;
    std::unique_ptr<Keypair> current;
    std::unique_ptr<Keypair> previous;
    std::unique_ptr<Keypair> next;  // responder side, unconfirmed
    // Our initiation in flight.
    bool handshaking{false};
    SecretKey hs_ephemeral;
    Chain hs_chain;
    Hash hs_hash{};
    std::uint32_t hs_index{0};
    VtepClock::time_point hs_sent;
    VtepClock::time_point hs_started;
    std::optional<VtepClock::time_point> last_handshake;
    std::uint64_t tx_packets{0};
    std::uint64_t rx_packets{0};
    // A certified peer: what its credential said when it was admitted
    // (renewals of the same key update it).
    bool certified{false};
    std::uint32_t cell_id{0};
    std::uint64_t serial{0};
    std::uint64_t not_after{0};
    std::optional<VtepClock::time_point> idle_since;
    std::optional<VtepClock::time_point> refresh_asked;
    // Linux's new-handshake timer: the first send since anything last
    // authenticated from this peer.
    std::optional<VtepClock::time_point> unanswered_since;
};

auto to_string(TunnelConfigError e) noexcept -> const char* {
    switch (e) {
        case TunnelConfigError::bad_port:
            return "bad_port";
        case TunnelConfigError::bad_timers:
            return "bad_timers";
        case TunnelConfigError::bad_limits:
            return "bad_limits";
    }
    return "unknown";
}

auto to_string(TunnelKeyError e) noexcept -> const char* {
    switch (e) {
        case TunnelKeyError::bad_key:
            return "bad_key";
        case TunnelKeyError::own_key:
            return "own_key";
        case TunnelKeyError::duplicate_key:
            return "duplicate_key";
        case TunnelKeyError::no_crypto:
            return "no_crypto";
    }
    return "unknown";
}

auto to_string(TunnelDrop d) noexcept -> const char* {
    switch (d) {
        case TunnelDrop::malformed:
            return "malformed";
        case TunnelDrop::no_private_key:
            return "no_private_key";
        case TunnelDrop::bad_mac1:
            return "bad_mac1";
        case TunnelDrop::unknown_peer:
            return "unknown_peer";
        case TunnelDrop::wrong_source:
            return "wrong_source";
        case TunnelDrop::decrypt_failed:
            return "decrypt_failed";
        case TunnelDrop::stale_timestamp:
            return "stale_timestamp";
        case TunnelDrop::rate_limited:
            return "rate_limited";
        case TunnelDrop::unknown_index:
            return "unknown_index";
        case TunnelDrop::expired_session:
            return "expired_session";
        case TunnelDrop::replay:
            return "replay";
        case TunnelDrop::cookie_reply:
            return "cookie_reply";
        case TunnelDrop::bad_key:
            return "bad_key";
        case TunnelDrop::uncertified:
            return "uncertified";
        case TunnelDrop::credential_refused:
            return "credential_refused";
        case TunnelDrop::credential_rate_limited:
            return "credential_rate_limited";
        case TunnelDrop::credential_conflict:
            return "credential_conflict";
    }
    return "unknown";
}

auto Tunnel::create(DatagramSender& underlay, TunnelConfig config)
    -> std::expected<std::unique_ptr<Tunnel>, TunnelConfigError> {
    using std::chrono::milliseconds;
    if (config.peer_port == 0) {
        return std::unexpected(TunnelConfigError::bad_port);
    }
    for (const auto t :
         {config.rekey_after_time, config.reject_after_time, config.rekey_attempt_time,
          config.rekey_timeout, config.keepalive_timeout, config.initiation_interval}) {
        if (t <= milliseconds::zero()) {
            return std::unexpected(TunnelConfigError::bad_timers);
        }
    }
    if (config.rekey_after_time >= config.reject_after_time) {
        return std::unexpected(TunnelConfigError::bad_timers);
    }
    if (config.rekey_after_messages >= config.reject_after_messages) {
        return std::unexpected(TunnelConfigError::bad_limits);
    }
    if (config.credential_cache_size == 0 || config.max_sources == 0 ||
        !(config.source_verify_rate > 0) || !(config.role_verify_rate > 0)) {
        return std::unexpected(TunnelConfigError::bad_limits);
    }
    if (config.certified_idle <= milliseconds::zero() ||
        config.credential_refresh <= std::chrono::seconds::zero()) {
        return std::unexpected(TunnelConfigError::bad_timers);
    }
    return std::unique_ptr<Tunnel>{new Tunnel(underlay, std::move(config))};
}

Tunnel::Tunnel(DatagramSender& underlay, TunnelConfig config)
    : _underlay{&underlay}, _config{std::move(config)}, _cache{_config.credential_cache_size} {
    _initial_chain = wg::hash({text(construction)});
    _initial_hash = wg::hash({_initial_chain, text(identifier)});
}

Tunnel::~Tunnel() {
    for (auto& [vtep, peer] : _peers) {
        clear_sessions(*peer);
    }
}

auto Tunnel::now() const -> VtepClock::time_point {
    return _config.clock ? _config.clock() : VtepClock::now();
}

auto Tunnel::drop(TunnelDrop reason) -> std::optional<Opened> {
    ++_counters.rx_drop.at(static_cast<std::size_t>(reason));
    return std::nullopt;
}

// ---- Keys -----------------------------------------------------------------

auto Tunnel::set_private_key(std::span<const std::byte, wg::key_size> private_key)
    -> std::expected<void, TunnelKeyError> {
    if (is_zero(private_key)) {
        return std::unexpected(TunnelKeyError::bad_key);
    }
    if (_private && wg::equal(_private->span(), private_key)) {
        return {};  // helm re-delivered the same key: keep the sessions
    }
    const auto pub = wg::public_key(private_key);
    if (!pub) {
        return std::unexpected(TunnelKeyError::bad_key);
    }
    if (_by_key.contains(*pub)) {
        return std::unexpected(TunnelKeyError::own_key);
    }
    retire(false);
    _private.emplace(private_key);
    _public = *pub;
    _mac1_key = wg::hash({text(label_mac1), _public});
    ++_key_generation;
    for (auto& [vtep, peer] : _peers) {
        clear_sessions(*peer);
        refresh_peer_secret(*peer);
        // Initiations made for the old key fail mac1 now, so the replay
        // floor can start again (a peer's clock may have been set back).
        peer->last_timestamp.reset();
    }
    return {};
}

auto Tunnel::rotate_private_key(std::span<const std::byte, wg::key_size> private_key,
                                std::chrono::milliseconds grace)
    -> std::expected<void, TunnelKeyError> {
    if (!_private || grace <= std::chrono::milliseconds::zero()) {
        return set_private_key(private_key);
    }
    if (is_zero(private_key)) {
        return std::unexpected(TunnelKeyError::bad_key);
    }
    if (wg::equal(_private->span(), private_key)) {
        return {};  // already in use: nothing to rotate
    }
    const auto pub = wg::public_key(private_key);
    if (!pub) {
        return std::unexpected(TunnelKeyError::bad_key);
    }
    if (_by_key.contains(*pub)) {
        return std::unexpected(TunnelKeyError::own_key);
    }
    // A rotation during another's grace ends the older one now: only one
    // old key is ever kept.
    retire(true);
    _retiring.emplace(Retiring{.private_key = std::move(*_private),
                               .public_key = _public,
                               .mac1_key = _mac1_key,
                               .generation = _key_generation,
                               .until = now() + grace});
    _private.emplace(private_key);
    _public = *pub;
    _mac1_key = wg::hash({text(label_mac1), _public});
    ++_key_generation;
    for (auto& [vtep, peer] : _peers) {
        cancel_handshake(*peer);
        peer->retiring_dh = std::move(peer->static_dh);
        refresh_peer_secret(*peer);
    }
    ++_counters.key_rotations;
    return {};
}

auto Tunnel::retiring_public_key() const -> std::optional<wg::Key> {
    if (!_retiring) {
        return std::nullopt;
    }
    return _retiring->public_key;
}

auto Tunnel::retire(bool count) -> void {
    if (!_retiring) {
        return;
    }
    for (auto& [vtep, p] : _peers) {
        Peer& peer = *p;
        for (auto* slot : {&peer.current, &peer.previous, &peer.next}) {
            if (*slot && (*slot)->key_generation != _key_generation) {
                release(*slot);
                if (count) {
                    ++_counters.retired_sessions;
                }
            }
        }
        peer.retiring_dh.reset();
    }
    _retiring.reset();  // the Secret destructor wipes the old key
}

auto Tunnel::cancel_handshake(Peer& peer) -> void {
    if (peer.handshaking) {
        release_index(peer.hs_index);
        peer.handshaking = false;
    }
    peer.hs_ephemeral.wipe();
    peer.hs_chain.wipe();
}

auto Tunnel::clear_private_key() -> void {
    retire(false);
    for (auto& [vtep, peer] : _peers) {
        clear_sessions(*peer);
        peer->static_dh.reset();
    }
    _private.reset();
    _public = {};
    _mac1_key = {};
}

auto Tunnel::public_key() const -> std::optional<wg::Key> {
    if (!_private) {
        return std::nullopt;
    }
    return _public;
}

auto Tunnel::set_peer(const Ipv6Address& vtep, std::span<const std::byte, wg::key_size> public_key,
                      std::span<const std::byte, wg::key_size> psk)
    -> std::expected<void, TunnelKeyError> {
    Key pub{};
    std::copy(public_key.begin(), public_key.end(), pub.begin());
    if (is_zero(pub)) {
        return std::unexpected(TunnelKeyError::bad_key);
    }
    if (_private && pub == _public) {
        return std::unexpected(TunnelKeyError::own_key);
    }
    // A peer list wins over a credential: a certified peer holding this key
    // elsewhere makes way.
    if (const auto it = _by_key.find(pub);
        it != _by_key.end() && it->second->vtep != vtep && it->second->certified) {
        drop_peer(_peers.find(it->second->vtep));
    }
    if (const auto it = _by_key.find(pub); it != _by_key.end() && it->second->vtep != vtep) {
        return std::unexpected(TunnelKeyError::duplicate_key);
    }
    std::optional<SecretKey> static_dh;
    std::optional<SecretKey> retiring_dh;
    if (_private) {
        static_dh = wg::dh(_private->span(), pub);
        if (!static_dh) {
            return std::unexpected(TunnelKeyError::bad_key);
        }
    }
    if (_retiring) {
        retiring_dh = wg::dh(_retiring->private_key.span(), pub);
    }
    auto it = _peers.find(vtep);
    if (it != _peers.end()) {
        Peer& p = *it->second;
        if (p.public_key == pub && wg::equal(p.psk.span(), psk)) {
            p.certified = false;  // a peer list now names it
            return {};            // unchanged: keep the sessions
        }
        _by_key.erase(p.public_key);
        clear_sessions(p);
        p.last_timestamp.reset();
        p.last_initiation_rx.reset();
    } else {
        it = _peers.emplace(vtep, std::make_unique<Peer>()).first;
        it->second->vtep = vtep;
    }
    Peer& p = *it->second;
    p.public_key = pub;
    p.psk = SecretKey{psk};
    p.mac1_key = wg::hash({text(label_mac1), pub});
    p.static_dh = std::move(static_dh);
    p.retiring_dh = std::move(retiring_dh);
    p.certified = false;
    _by_key[pub] = &p;
    return {};
}

auto Tunnel::remove_peer(const Ipv6Address& vtep) -> bool {
    const auto it = _peers.find(vtep);
    if (it == _peers.end()) {
        return false;
    }
    clear_sessions(*it->second);
    _by_key.erase(it->second->public_key);
    _peers.erase(it);
    return true;
}

auto Tunnel::refresh_peer_secret(Peer& peer) -> void {
    peer.static_dh.reset();
    if (_private) {
        // A low-order peer key leaves the peer without a secret: it can
        // neither initiate nor answer (counted as bad_key when tried).
        peer.static_dh = wg::dh(_private->span(), peer.public_key);
    }
}

// ---- Indexes and sessions -------------------------------------------------

auto Tunnel::new_index() -> std::optional<std::uint32_t> {
    for (std::size_t i = 0; i < new_index_attempts; ++i) {
        std::array<unsigned char, sizeof(std::uint32_t)> raw{};
        if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
            return std::nullopt;
        }
        std::uint32_t index = 0;
        std::memcpy(&index, raw.data(), raw.size());
        if (!_by_index.contains(index)) {
            return index;
        }
    }
    return std::nullopt;
}

auto Tunnel::release_index(std::uint32_t index) -> void {
    _by_index.erase(index);
}

auto Tunnel::release(std::unique_ptr<Keypair>& kp) -> void {
    if (kp) {
        release_index(kp->local_index);
        kp.reset();  // the Aead destructors cleanse the keys
    }
}

auto Tunnel::clear_sessions(Peer& peer) -> void {
    release(peer.current);
    release(peer.previous);
    release(peer.next);
    if (peer.handshaking) {
        release_index(peer.hs_index);
        peer.handshaking = false;
    }
    peer.hs_ephemeral.wipe();
    peer.hs_chain.wipe();
    peer.last_handshake.reset();
    peer.unanswered_since.reset();
}

auto Tunnel::usable(const Keypair& kp, VtepClock::time_point now) const -> bool {
    return now - kp.created < _config.reject_after_time &&
           kp.send_counter < _config.reject_after_messages;
}

// ---- Handshake ------------------------------------------------------------

auto Tunnel::initiate(Peer& peer, VtepClock::time_point now) -> void {
    if (!_private || !peer.static_dh) {
        return;
    }
    if (peer.handshaking && now - peer.hs_sent < _config.rekey_timeout) {
        return;  // one initiation per rekey_timeout
    }
    auto ephemeral = wg::generate_private_key();
    const auto ephemeral_pub = ephemeral ? wg::public_key(ephemeral->span()) : std::nullopt;
    const auto index = new_index();
    if (!ephemeral_pub || !index) {
        return;
    }
    std::array<std::byte, wg::initiation_size> msg{};
    const std::span<std::byte> m{msg};
    put_header(m, wg::MessageType::initiation);
    put_le32(m.subspan(4), *index);

    Chain c{_initial_chain};
    Hash h = wg::hash({_initial_hash, peer.public_key});
    mix_key(c, *ephemeral_pub);
    std::copy(ephemeral_pub->begin(), ephemeral_pub->end(), m.begin() + init_ephemeral);
    mix_hash(h, *ephemeral_pub);

    const auto es = wg::dh(ephemeral->span(), peer.public_key);
    if (!es) {
        ++_counters.rx_drop.at(static_cast<std::size_t>(TunnelDrop::bad_key));
        return;
    }
    SecretKey k;
    wg::kdf(c.span(), es->span(), {c.span(), k.span()});
    const auto enc_static = m.subspan(init_static, wg::key_size + wg::tag_size);
    if (!wg::seal(k.span(), 0, _public, h, enc_static)) {
        return;
    }
    mix_hash(h, enc_static);

    wg::kdf(c.span(), peer.static_dh->span(), {c.span(), k.span()});
    const auto stamp =
        wg::tai64n(_config.wall_clock ? _config.wall_clock() : std::chrono::system_clock::now());
    const auto enc_stamp = m.subspan(init_timestamp, wg::timestamp_size + wg::tag_size);
    if (!wg::seal(k.span(), 0, stamp, h, enc_stamp)) {
        return;
    }
    mix_hash(h, enc_stamp);

    const auto mac1 = wg::mac(peer.mac1_key, m.first(wg::initiation_mac1_offset));
    std::copy(mac1.begin(), mac1.end(), m.begin() + wg::initiation_mac1_offset);
    // mac2 stays zero: no cookie.

    if (peer.handshaking) {
        release_index(peer.hs_index);  // a retry: the old index is dead
        // An unanswered certified handshake: the responder may have dropped
        // us (revoked, expired, reclaimed), so present the credential again.
        if (peer.certified && send_credential(peer.vtep, wg::credential_flag_send_yours)) {
            ++_counters.credentials_tx;
        }
    } else {
        peer.hs_started = now;
    }
    peer.handshaking = true;
    peer.hs_ephemeral = std::move(*ephemeral);
    peer.hs_chain = std::move(c);
    peer.hs_hash = h;
    peer.hs_index = *index;
    peer.hs_sent = now;
    _by_index[*index] = &peer;
    if (send_raw(peer, flow_port_base, m)) {
        ++_counters.initiations_tx;
    }
}

auto Tunnel::handle_initiation(const wg::Initiation& m, const Ipv6Address& outer_src)
    -> std::optional<Opened> {
    if (!_private) {
        return drop(TunnelDrop::no_private_key);
    }
    // mac1 names the static key the initiator believes we have: the
    // current one, or during a rotation's grace the old one.
    const SecretKey* own_private = &*_private;
    const Key* own_public = &_public;
    std::uint32_t generation = _key_generation;
    bool retiring = false;
    if (!wg::equal(wg::mac(_mac1_key, m.before_mac1), m.mac1)) {
        if (!_retiring || !wg::equal(wg::mac(_retiring->mac1_key, m.before_mac1), m.mac1)) {
            return drop(TunnelDrop::bad_mac1);
        }
        own_private = &_retiring->private_key;
        own_public = &_retiring->public_key;
        generation = _retiring->generation;
        retiring = true;
    }
    Chain c{_initial_chain};
    Hash h = wg::hash({_initial_hash, *own_public});
    mix_key(c, m.ephemeral);
    mix_hash(h, m.ephemeral);

    const auto es = wg::dh(own_private->span(), m.ephemeral);
    if (!es) {
        return drop(TunnelDrop::bad_key);
    }
    SecretKey k;
    wg::kdf(c.span(), es->span(), {c.span(), k.span()});
    Key static_pub{};
    if (!wg::open(k.span(), 0, m.encrypted_static, h, static_pub)) {
        return drop(TunnelDrop::decrypt_failed);
    }
    mix_hash(h, m.encrypted_static);

    Peer* known = nullptr;
    if (const auto found = _by_key.find(static_pub); found != _by_key.end()) {
        known = found->second;
    }
    // A key in no peer list may still be a certified peer: its credential
    // must be cached, valid, name this source, and the VTEP must not be a
    // list peer's.
    std::optional<proto::VtepCredential> certificate;
    std::optional<SecretKey> fresh_dh;
    if (known == nullptr) {
        if (_store == nullptr) {
            return drop(TunnelDrop::unknown_peer);
        }
        const auto* cached = _cache.find(static_pub);
        if (cached == nullptr) {
            return drop(TunnelDrop::uncertified);
        }
        if (cached->credential.vtep != outer_src) {
            return drop(TunnelDrop::wrong_source);
        }
        if (const auto at = _peers.find(outer_src); at != _peers.end() && !at->second->certified) {
            return drop(TunnelDrop::uncertified);
        }
        if (!_store->still_valid(cached->credential)) {
            _cache.erase(static_pub);
            return drop(TunnelDrop::uncertified);
        }
        certificate = cached->credential;
        fresh_dh = wg::dh(own_private->span(), static_pub);
        if (!fresh_dh) {
            return drop(TunnelDrop::bad_key);
        }
    } else if (known->vtep != outer_src) {
        return drop(TunnelDrop::wrong_source);
    }
    const std::optional<SecretKey>& static_dh =
        known == nullptr ? fresh_dh : (retiring ? known->retiring_dh : known->static_dh);
    if (!static_dh) {
        return drop(TunnelDrop::bad_key);
    }
    wg::kdf(c.span(), static_dh->span(), {c.span(), k.span()});
    wg::Timestamp stamp{};
    if (!wg::open(k.span(), 0, m.encrypted_timestamp, h, stamp)) {
        return drop(TunnelDrop::decrypt_failed);
    }
    mix_hash(h, m.encrypted_timestamp);
    if (known == nullptr) {
        // The initiator proved it holds the certified key: admit it.
        known = install_certified(outer_src, static_pub, *certificate);
        if (known == nullptr) {
            return drop(TunnelDrop::bad_key);
        }
    }
    Peer& peer = *known;

    const auto t = now();
    if (peer.last_timestamp && stamp <= *peer.last_timestamp) {
        return drop(TunnelDrop::stale_timestamp);
    }
    if (peer.last_initiation_rx && t - *peer.last_initiation_rx < _config.initiation_interval) {
        return drop(TunnelDrop::rate_limited);
    }
    peer.last_timestamp = stamp;
    peer.last_initiation_rx = t;
    ++_counters.initiations_rx;
    if (retiring) {
        ++_counters.retiring_handshakes;
    }

    // The response.
    auto ephemeral = wg::generate_private_key();
    const auto ephemeral_pub = ephemeral ? wg::public_key(ephemeral->span()) : std::nullopt;
    const auto index = new_index();
    if (!ephemeral_pub || !index) {
        return std::nullopt;
    }
    std::array<std::byte, wg::response_size> msg{};
    const std::span<std::byte> r{msg};
    put_header(r, wg::MessageType::response);
    put_le32(r.subspan(4), *index);
    put_le32(r.subspan(8), m.sender);

    mix_key(c, *ephemeral_pub);
    std::copy(ephemeral_pub->begin(), ephemeral_pub->end(), r.begin() + resp_ephemeral);
    mix_hash(h, *ephemeral_pub);
    const auto ee = wg::dh(ephemeral->span(), m.ephemeral);
    const auto se = wg::dh(ephemeral->span(), peer.public_key);
    if (!ee || !se) {
        return drop(TunnelDrop::bad_key);
    }
    mix_key(c, ee->span());
    mix_key(c, se->span());
    SecretKey tau;
    wg::kdf(c.span(), peer.psk.span(), {c.span(), tau.span(), k.span()});
    mix_hash(h, tau.span());
    const auto enc_empty = r.subspan(resp_empty, wg::tag_size);
    if (!wg::seal(k.span(), 0, {}, h, enc_empty)) {
        return std::nullopt;
    }
    const auto mac1 = wg::mac(peer.mac1_key, r.first(wg::response_mac1_offset));
    std::copy(mac1.begin(), mac1.end(), r.begin() + wg::response_mac1_offset);

    // Responder: the first key receives, the second sends.
    SecretKey recv_key;
    SecretKey send_key;
    wg::kdf(c.span(), {}, {recv_key.span(), send_key.span()});
    auto sender = wg::Aead::create(send_key.span(), true);
    auto receiver = wg::Aead::create(recv_key.span(), false);
    if (!sender || !receiver) {
        return std::nullopt;
    }
    auto kp = std::make_unique<Keypair>(Keypair{.sender = std::move(*sender),
                                                .receiver = std::move(*receiver),
                                                .local_index = *index,
                                                .remote_index = m.sender,
                                                .created = t,
                                                .send_counter = 0,
                                                .window = {},
                                                .initiator = false,
                                                .key_generation = generation});
    // Linux: the new session waits in `next` until the initiator uses it;
    // `previous` goes, `current` stays usable meanwhile.
    release(peer.next);
    release(peer.previous);
    peer.next = std::move(kp);
    _by_index[*index] = &peer;
    ++_counters.sessions_established;
    if (send_raw(peer, flow_port_base, r)) {
        ++_counters.responses_tx;
    }
    return std::nullopt;
}

auto Tunnel::handle_response(const wg::Response& m, const Ipv6Address& outer_src)
    -> std::optional<Opened> {
    if (!_private) {
        return drop(TunnelDrop::no_private_key);
    }
    if (!wg::equal(wg::mac(_mac1_key, m.before_mac1), m.mac1)) {
        return drop(TunnelDrop::bad_mac1);
    }
    const auto found = _by_index.find(m.receiver);
    if (found == _by_index.end() || !found->second->handshaking ||
        found->second->hs_index != m.receiver) {
        return drop(TunnelDrop::unknown_index);
    }
    Peer& peer = *found->second;
    if (peer.vtep != outer_src) {
        return drop(TunnelDrop::wrong_source);
    }
    Chain c{peer.hs_chain.span()};
    Hash h = peer.hs_hash;
    mix_key(c, m.ephemeral);
    mix_hash(h, m.ephemeral);
    const auto ee = wg::dh(peer.hs_ephemeral.span(), m.ephemeral);
    const auto se = wg::dh(_private->span(), m.ephemeral);
    if (!ee || !se) {
        return drop(TunnelDrop::bad_key);
    }
    mix_key(c, ee->span());
    mix_key(c, se->span());
    SecretKey tau;
    SecretKey k;
    wg::kdf(c.span(), peer.psk.span(), {c.span(), tau.span(), k.span()});
    mix_hash(h, tau.span());
    if (!wg::open(k.span(), 0, m.encrypted_empty, h, {})) {
        return drop(TunnelDrop::decrypt_failed);
    }

    // Initiator: the first key sends, the second receives.
    SecretKey send_key;
    SecretKey recv_key;
    wg::kdf(c.span(), {}, {send_key.span(), recv_key.span()});
    auto sender = wg::Aead::create(send_key.span(), true);
    auto receiver = wg::Aead::create(recv_key.span(), false);
    if (!sender || !receiver) {
        return std::nullopt;
    }
    const auto t = now();
    auto kp = std::make_unique<Keypair>(Keypair{.sender = std::move(*sender),
                                                .receiver = std::move(*receiver),
                                                .local_index = peer.hs_index,
                                                .remote_index = m.sender,
                                                .created = t,
                                                .send_counter = 0,
                                                .window = {},
                                                .initiator = true,
                                                .key_generation = _key_generation});
    // The handshake's index now names the session.
    peer.handshaking = false;
    peer.hs_ephemeral.wipe();
    peer.hs_chain.wipe();
    // Linux's begin_session for the initiator.
    if (peer.next) {
        release(peer.previous);
        peer.previous = std::move(peer.next);
        release(peer.current);
    } else {
        release(peer.previous);
        peer.previous = std::move(peer.current);
    }
    peer.current = std::move(kp);
    peer.last_handshake = t;
    peer.unanswered_since.reset();
    ++_counters.responses_rx;
    ++_counters.sessions_established;
    // Confirm the session to the responder at once with a keepalive.
    static_cast<void>(send_transport(peer, *peer.current, _config.peer_port, flow_port_base, {}));
    return std::nullopt;
}

// ---- Transport ------------------------------------------------------------

auto Tunnel::handle_transport(const wg::Transport& m, const Ipv6Address& outer_src)
    -> std::optional<Opened> {
    const auto found = _by_index.find(m.receiver);
    if (found == _by_index.end()) {
        return drop(TunnelDrop::unknown_index);
    }
    Peer& peer = *found->second;
    Keypair* kp = nullptr;
    for (auto* slot : {&peer.current, &peer.previous, &peer.next}) {
        if (*slot && (*slot)->local_index == m.receiver) {
            kp = slot->get();
        }
    }
    if (kp == nullptr) {
        return drop(TunnelDrop::unknown_index);  // a handshake's index
    }
    if (peer.vtep != outer_src) {
        return drop(TunnelDrop::wrong_source);
    }
    const auto t = now();
    if (t - kp->created >= _config.reject_after_time ||
        m.counter >= _config.reject_after_messages) {
        return drop(TunnelDrop::expired_session);
    }
    if (!kp->window.may_accept(m.counter)) {
        return drop(TunnelDrop::replay);
    }
    _rx.resize(m.ciphertext.size() - wg::tag_size);
    if (!kp->receiver.open(m.counter, m.ciphertext, _rx)) {
        return drop(TunnelDrop::decrypt_failed);
    }
    if (!kp->window.accept(m.counter)) {
        return drop(TunnelDrop::replay);
    }
    peer.unanswered_since.reset();
    if (kp == peer.next.get()) {
        // The initiator used the new session: it is confirmed.
        release(peer.previous);
        peer.previous = std::move(peer.current);
        peer.current = std::move(peer.next);
        peer.last_handshake = t;
    }
    // Linux's keep_key_fresh on receive: an initiator whose session is
    // nearly too old to receive on starts the next handshake.
    if (peer.current && peer.current->initiator && !peer.handshaking &&
        t - peer.current->created >=
            _config.reject_after_time - _config.keepalive_timeout - _config.rekey_timeout) {
        initiate(peer, t);
    }
    if (_rx.empty()) {
        ++_counters.rx_keepalives;
        return std::nullopt;
    }
    ++peer.rx_packets;
    ++_counters.rx_packets;
    return Opened{.payload = _rx, .peer = peer.vtep};
}

auto Tunnel::send_to(const Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                     std::span<const std::byte> payload) -> bool {
    if (!_private) {
        ++_counters.tx_no_key;
        return false;
    }
    auto it = _peers.find(dst);
    const auto t = now();
    if (it == _peers.end() && _store != nullptr) {
        // No list peer: a cached, still valid credential admits it now;
        // otherwise ask for one, at most once per rekey_timeout.
        if (const auto* cached = _cache.find_vtep(dst); cached != nullptr) {
            if (_store->still_valid(cached->credential)) {
                if (auto* p =
                        install_certified(dst, cached->credential.public_key, cached->credential);
                    p != nullptr) {
                    it = _peers.find(dst);
                }
            } else {
                _cache.erase_vtep(dst);
            }
        }
        if (it == _peers.end() && !_store->own(_public)) {
            ++_counters.tx_no_peer;  // nothing to offer: only list peers reach us
            return false;
        }
        if (it == _peers.end()) {
            const auto asked = _wanted.find(dst);
            if (asked == _wanted.end() || t - asked->second >= _config.rekey_timeout) {
                if (_wanted.size() < _config.max_sources || asked != _wanted.end()) {
                    if (send_credential(dst, wg::credential_flag_send_yours)) {
                        _wanted[dst] = t;
                        ++_counters.credentials_tx;
                    }
                }
            }
            ++_counters.tx_no_session;
            return false;
        }
    }
    if (it == _peers.end()) {
        ++_counters.tx_no_peer;
        return false;
    }
    Peer& peer = *it->second;
    if (!peer.current || !usable(*peer.current, t)) {
        ++_counters.tx_no_session;
        initiate(peer, t);
        return false;
    }
    Keypair& kp = *peer.current;
    const bool sent = send_transport(peer, kp, dst_port, flow_port, payload);
    // Linux's keep_key_fresh on send.
    if (kp.initiator && (kp.send_counter > _config.rekey_after_messages ||
                         t - kp.created >= _config.rekey_after_time)) {
        initiate(peer, t);
    }
    // Linux's new-handshake timer: sending for keepalive_timeout +
    // rekey_timeout with nothing authenticated back means the other end
    // lost the session (restarted, or dropped us); handshake again.
    if (!peer.unanswered_since) {
        peer.unanswered_since = t;
    } else if (t - *peer.unanswered_since >= _config.keepalive_timeout + _config.rekey_timeout) {
        peer.unanswered_since = t;
        initiate(peer, t);
    }
    return sent;
}

auto Tunnel::send_transport(Peer& peer, Keypair& kp, std::uint16_t dst_port,
                            std::uint16_t flow_port, std::span<const std::byte> payload) -> bool {
    _tx.resize(wg::transport_overhead + payload.size());
    const std::span<std::byte> m{_tx};
    put_header(m.first(wg::transport_header_size), wg::MessageType::transport);
    put_le32(m.subspan(4), kp.remote_index);
    put_le64(m.subspan(8), kp.send_counter);
    if (!kp.sender.seal(kp.send_counter, payload, m.subspan(wg::transport_header_size))) {
        ++_counters.tx_crypto_failed;
        return false;
    }
    ++kp.send_counter;  // a counter is never reused, sent or not
    if (!_underlay->send_to(peer.vtep, dst_port, flow_port, m)) {
        ++_counters.tx_send_failed;
        return false;
    }
    if (!payload.empty()) {
        ++_counters.tx_packets;
        _counters.tx_bytes += payload.size();
        ++peer.tx_packets;
    }
    return true;
}

auto Tunnel::send_raw(const Peer& peer, std::uint16_t flow_port,
                      std::span<const std::byte> datagram) -> bool {
    if (!_underlay->send_to(peer.vtep, _config.peer_port, flow_port, datagram)) {
        ++_counters.tx_send_failed;
        return false;
    }
    return true;
}

auto Tunnel::receive(std::span<const std::byte> datagram, const Ipv6Address& outer_src)
    -> std::optional<Opened> {
    ++_counters.rx_datagrams;
    const auto message = wg::parse(datagram);
    if (!message) {
        ++_counters.rx_drop_parse.at(static_cast<std::size_t>(message.error()));
        return drop(TunnelDrop::malformed);
    }
    if (const auto* m = std::get_if<wg::Initiation>(&*message)) {
        return handle_initiation(*m, outer_src);
    }
    if (const auto* m = std::get_if<wg::Response>(&*message)) {
        return handle_response(*m, outer_src);
    }
    if (const auto* m = std::get_if<wg::Transport>(&*message)) {
        return handle_transport(*m, outer_src);
    }
    if (const auto* m = std::get_if<wg::Credential>(&*message)) {
        return handle_credential(*m, outer_src);
    }
    return drop(TunnelDrop::cookie_reply);
}

auto Tunnel::tick() -> VtepClock::time_point {
    const auto t = now();
    auto next = VtepClock::time_point::max();
    if (_retiring) {
        if (t >= _retiring->until) {
            retire(true);
        } else {
            next = _retiring->until;
        }
    }
    if (_store != nullptr) {
        next = std::min(next, tick_certified(t));
    }
    for (auto& [vtep, p] : _peers) {
        Peer& peer = *p;
        if (peer.handshaking) {
            if (t - peer.hs_started >= _config.rekey_attempt_time) {
                release_index(peer.hs_index);
                peer.handshaking = false;
                peer.hs_ephemeral.wipe();
                peer.hs_chain.wipe();
                ++_counters.handshake_timeouts;
            } else if (t - peer.hs_sent >= _config.rekey_timeout) {
                initiate(peer, t);
            }
        }
        if (peer.handshaking) {
            next = std::min(next, peer.hs_sent + _config.rekey_timeout);
        }
        for (auto* slot : {&peer.current, &peer.previous, &peer.next}) {
            if (!*slot) {
                continue;
            }
            const auto expiry = (*slot)->created + _config.reject_after_time;
            if (t >= expiry) {
                release(*slot);
            } else {
                next = std::min(next, expiry);
            }
        }
    }
    return next;
}

auto Tunnel::peers() const -> std::vector<TunnelPeerStatus> {
    std::vector<TunnelPeerStatus> out;
    out.reserve(_peers.size());
    const auto t = now();
    for (const auto& [vtep, p] : _peers) {
        out.push_back({.vtep = vtep,
                       .public_key = p->public_key,
                       .session = p->current && usable(*p->current, t),
                       .handshaking = p->handshaking,
                       .certified = p->certified,
                       .last_handshake = p->last_handshake,
                       .tx_packets = p->tx_packets,
                       .rx_packets = p->rx_packets});
    }
    return out;
}

// ---- Certified peers --------------------------------------------------------

auto Tunnel::Bucket::take(double rate, VtepClock::time_point now) -> bool {
    if (!at) {
        tokens = rate;
    } else {
        const std::chrono::duration<double> elapsed = now - *at;
        tokens = std::min(rate, tokens + (std::max(0.0, elapsed.count()) * rate));
    }
    at = now;
    if (tokens < 1.0) {
        return false;
    }
    tokens -= 1.0;
    return true;
}

auto Tunnel::set_credentials(CredentialStore* store) -> void {
    if (store == _store) {
        return;
    }
    for (auto it = _peers.begin(); it != _peers.end();) {
        it = it->second->certified ? drop_peer(it) : std::next(it);
    }
    _store = store;
    _cache = CredentialCache{_config.credential_cache_size};
    _sources.clear();
    _wanted.clear();
    _announced.reset();
    _role_bucket = {};
}

auto Tunnel::drop_peer(std::map<Ipv6Address, std::unique_ptr<Peer>>::iterator it)
    -> std::map<Ipv6Address, std::unique_ptr<Peer>>::iterator {
    if (it == _peers.end()) {
        return it;
    }
    clear_sessions(*it->second);
    _by_key.erase(it->second->public_key);
    return _peers.erase(it);
}

auto Tunnel::has_session(const Peer& peer) const -> bool {
    return peer.current || peer.previous || peer.next || peer.handshaking;
}

auto Tunnel::install_certified(const Ipv6Address& vtep, const Key& key,
                               const proto::VtepCredential& credential) -> Peer* {
    if (!_private || key == _public || (_retiring && key == _retiring->public_key)) {
        return nullptr;
    }
    if (const auto held = _by_key.find(key); held != _by_key.end() && held->second->vtep != vtep) {
        if (!held->second->certified) {
            return nullptr;  // a list peer's key
        }
        drop_peer(_peers.find(held->second->vtep));
    }
    auto it = _peers.find(vtep);
    if (it != _peers.end() && !it->second->certified) {
        return nullptr;  // a list peer's VTEP: the list decides its key
    }
    auto static_dh = wg::dh(_private->span(), key);
    if (!static_dh) {
        return nullptr;
    }
    if (it == _peers.end()) {
        it = _peers.emplace(vtep, std::make_unique<Peer>()).first;
        it->second->vtep = vtep;
        ++_counters.certified_peers_added;
    } else if (it->second->public_key != key) {
        // The peer rotated its key: its sessions were under the old one.
        _by_key.erase(it->second->public_key);
        clear_sessions(*it->second);
        it->second->last_timestamp.reset();
        it->second->last_initiation_rx.reset();
    }
    Peer& p = *it->second;
    p.public_key = key;
    p.psk = SecretKey{};
    p.mac1_key = wg::hash({text(label_mac1), key});
    p.static_dh = std::move(static_dh);
    p.retiring_dh.reset();
    if (_retiring) {
        p.retiring_dh = wg::dh(_retiring->private_key.span(), key);
    }
    p.certified = true;
    p.cell_id = credential.cell_id;
    p.serial = credential.serial;
    p.not_after = credential.not_after;
    p.idle_since.reset();
    p.refresh_asked.reset();
    _by_key[key] = &p;
    return &p;
}

auto Tunnel::source(const Ipv6Address& addr, VtepClock::time_point now) -> Source* {
    auto it = _sources.find(addr);
    if (it == _sources.end()) {
        if (_sources.size() >= _config.max_sources) {
            // Make room from sources quiet for a second; a flood of new
            // sources finds the table full and is refused.
            for (auto s = _sources.begin(); s != _sources.end();) {
                s = now - s->second.last_used >= std::chrono::seconds{1} ? _sources.erase(s)
                                                                         : std::next(s);
            }
            if (_sources.size() >= _config.max_sources) {
                return nullptr;
            }
        }
        it = _sources.emplace(addr, Source{}).first;
    }
    it->second.last_used = now;
    return &it->second;
}

auto Tunnel::send_credential(const Ipv6Address& dst, std::uint8_t flags) -> bool {
    if (_store == nullptr || !_private) {
        return false;
    }
    const auto own = _store->own(_public);
    if (!own || own->size() != wg::credential_body_size) {
        return false;
    }
    std::array<std::byte, wg::credential_message_size> msg{};
    const std::span<std::byte> m{msg};
    put_header(m, wg::MessageType::credential);
    m[4] = std::byte{flags};
    std::copy(own->begin(), own->end(), m.begin() + 8);
    if (!_underlay->send_to(dst, _config.peer_port, flow_port_base, m)) {
        ++_counters.tx_send_failed;
        return false;
    }
    return true;
}

auto Tunnel::handle_credential(const wg::Credential& m, const Ipv6Address& outer_src)
    -> std::optional<Opened> {
    if (_store == nullptr) {
        return drop(TunnelDrop::uncertified);
    }
    if (!_private) {
        return drop(TunnelDrop::no_private_key);
    }
    const auto t = now();
    auto* src = source(outer_src, t);
    if (src == nullptr) {
        return drop(TunnelDrop::credential_rate_limited);
    }
    const auto* cached = _cache.find_vtep(outer_src);
    std::optional<proto::VtepCredential> credential;
    if (cached != nullptr && std::ranges::equal(cached->frame, m.credential)) {
        if (!_store->still_valid(cached->credential)) {
            _cache.erase_vtep(outer_src);
            return drop(TunnelDrop::credential_refused);
        }
        credential = cached->credential;
        ++_counters.credentials_cached;
    } else {
        const auto at = _peers.find(outer_src);
        const bool in_session = at != _peers.end() && has_session(*at->second);
        if (!src->verifies.take(_config.source_verify_rate, t)) {
            return drop(TunnelDrop::credential_rate_limited);
        }
        // Past the role's limit only sources with a session are verified.
        if (!_role_bucket.take(_config.role_verify_rate, t) && !in_session) {
            return drop(TunnelDrop::credential_rate_limited);
        }
        auto verified = _store->verify_peer(m.credential, outer_src);
        if (!verified) {
            return drop(TunnelDrop::credential_refused);
        }
        const auto& key = verified->public_key;
        if (key == _public || (_retiring && key == _retiring->public_key)) {
            return drop(TunnelDrop::credential_conflict);
        }
        if (const auto held = _by_key.find(key);
            held != _by_key.end() && !held->second->certified && held->second->vtep != outer_src) {
            return drop(TunnelDrop::credential_conflict);
        }
        _cache.insert(*verified, m.credential);
        ++_counters.credentials_verified;
        credential = *verified;
    }
    // A certified peer at this address follows its newest credential: a
    // renewal of the same key keeps the sessions, a new key replaces them.
    const auto at = _peers.find(outer_src);
    if (at != _peers.end() && at->second->certified) {
        static_cast<void>(install_certified(outer_src, credential->public_key, *credential));
    }
    if ((m.flags & wg::credential_flag_send_yours) != 0 &&
        (!src->last_reply || t - *src->last_reply >= _config.initiation_interval)) {
        if (send_credential(outer_src, 0)) {
            src->last_reply = t;
            ++_counters.credential_replies_tx;
        }
    }
    // We asked for this one: start the handshake.
    if (const auto asked = _wanted.find(outer_src); asked != _wanted.end()) {
        _wanted.erase(asked);
        if (_peers.find(outer_src) == _peers.end()) {
            if (auto* p = install_certified(outer_src, credential->public_key, *credential);
                p != nullptr) {
                initiate(*p, t);
            }
        }
    }
    return std::nullopt;
}

auto Tunnel::tick_certified(VtepClock::time_point now) -> VtepClock::time_point {
    const auto t = now;
    auto next = VtepClock::time_point::max();
    const auto unix_now = _store->now_unix();
    const auto skew = static_cast<std::uint64_t>(_store->skew().count());
    const auto refresh = static_cast<std::uint64_t>(_config.credential_refresh.count());
    bool any = false;
    // A credential for a new key of ours goes to the peers we talk to.
    const bool announce =
        _private && (!_announced || *_announced != _public) && _store->own(_public).has_value();
    if (announce) {
        _announced = _public;
    }
    for (auto it = _peers.begin(); it != _peers.end();) {
        Peer& peer = *it->second;
        if (announce && peer.certified && has_session(peer) && send_credential(peer.vtep, 0)) {
            ++_counters.credentials_tx;
        }
        if (!peer.certified) {
            ++it;
            continue;
        }
        any = true;
        if (peer.not_after + skew <= unix_now) {
            _cache.erase(peer.public_key);
            ++_counters.certified_expired;
            it = drop_peer(it);
            continue;
        }
        if (_store->revoked(peer.cell_id, peer.serial)) {
            _cache.erase(peer.public_key);
            ++_counters.certified_revoked;
            it = drop_peer(it);
            continue;
        }
        if (has_session(peer)) {
            peer.idle_since.reset();
            // Near expiry, ask a peer we talk to for its renewed credential.
            if (unix_now + refresh >= peer.not_after &&
                (!peer.refresh_asked || t - *peer.refresh_asked >= _config.rekey_timeout) &&
                send_credential(peer.vtep, wg::credential_flag_send_yours)) {
                peer.refresh_asked = t;
                ++_counters.credentials_tx;
            }
        } else if (!peer.idle_since) {
            peer.idle_since = t;
        } else if (t - *peer.idle_since >= _config.certified_idle) {
            ++_counters.certified_peers_reclaimed;
            it = drop_peer(it);
            continue;
        }
        if (peer.idle_since) {
            next = std::min(next, *peer.idle_since + _config.certified_idle);
        }
        ++it;
    }
    // Requests nobody answered are forgotten after a handshake's lifetime.
    for (auto it = _wanted.begin(); it != _wanted.end();) {
        it = t - it->second >= _config.rekey_attempt_time ? _wanted.erase(it) : std::next(it);
    }
    if (!_wanted.empty()) {
        any = true;
    }
    // Wall-clock deadlines (expiry, revocation) are checked once a second.
    if (any) {
        next = std::min(next, t + std::chrono::seconds{1});
    }
    return next;
}

auto pump(UdpEndpoint& endpoint, Tunnel& tunnel, Vtep& vtep, VSwitch& vswitch,
          std::span<std::byte> buffer, std::size_t budget, VtepClock::time_point now)
    -> std::size_t {
    std::size_t read = 0;
    while (read < budget) {
        auto d = endpoint.receive(buffer);
        if (!d) {
            break;
        }
        ++read;
        if (d->truncated) {
            continue;
        }
        const auto opened = tunnel.receive(buffer.first(d->size), d->source);
        if (!opened) {
            continue;
        }
        // From here on the peer's configured address stands in for the
        // outer source: it is the one the payload authenticated as.
        if (auto packet = vtep.receive(opened->payload, opened->peer, now)) {
            static_cast<void>(vswitch.receive(*packet, opened->peer));
        }
    }
    return read;
}

}  // namespace ak::oar::net
