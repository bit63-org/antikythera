// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Tunnel: the WireGuard layer between the Vtep and the IPv6/UDP underlay
// (.kiro/specs/oar-net-data-plane/ Requirement 5, design "Tunnel", task 10).
//
//   VSwitch -> Vtep --send_to--> Tunnel --send_to--> UdpEndpoint -> underlay
//   underlay -> UdpEndpoint -> Tunnel::receive -> Vtep::receive -> VSwitch
//
// The Tunnel is a DatagramSender, so the Vtep sends through it unchanged:
// each Geneve payload for a peer VTEP goes out as one WireGuard transport
// message to that peer's address and port (the flow source port is kept,
// so ECMP still spreads flows). Tunnel::receive takes every datagram the
// endpoint reads, consumes handshake messages and returns only payloads
// that authenticated under a live session, with the configured address of
// the peer they authenticated as. That address, not the datagram's outer
// source, is what the Vtep and the VSwitch's ingress policy then check, so
// a forged or replayed packet is dropped here, before Geneve decode
// (Requirement 5.3), and spoofing a VTEP's address gains nothing.
//
// Keys (Requirement 5.2). helm delivers them over the sideband: the role's
// own static private key (set_private_key) and, per peer VTEP, its public
// key and a pre-shared key for the pair (set_peer). The role holds no other
// private key. Peers are VTEPs, the same set as MappingSnapshot::peer_vteps()
// once helm has delivered their keys; a Vtep send to a VTEP without keys is
// refused and counted (tx_no_peer). Changing the private key or a peer's
// keys drops every session it affects; new ones are negotiated on demand.
//
// Key rotation (.kiro/specs/fleet-scale-networking/ Requirement 1.3).
// rotate_private_key() replaces the static key without dropping sessions:
// the old key is kept for a grace period, during which sessions made under
// it keep sending and receiving, and an initiation whose mac1 names the old
// public key (a peer that has not yet been told the new one) is still
// answered under the old key. In-flight initiations of our own are
// abandoned, since their responses would be keyed to the old static key;
// the next send starts one under the new key. When the grace ends, every
// session made under the old key is dropped and the old key wiped.
//
// Certified peers (.kiro/specs/fleet-scale-networking/ Requirement 3,
// design "Certified handshake", task 3). With a CredentialStore attached
// (set_credentials), a VTEP that is in no peer list can still be a peer if
// it holds a controller credential for its key. Before a handshake the two
// ends exchange credentials in `credential` messages (wireguard.hpp): an
// initiator with no credential of the destination cached sends its own
// with "send me yours", the responder verifies it and answers with its
// own, and the initiator, having verified that, starts WireGuard's
// handshake. The responder accepts an initiation whose static key is in
// neither a peer list nor the cache as `uncertified`.
//
//   - Verification (CredentialStore::verify_peer) checks the signature,
//     the validity window with the skew allowance, the revocation list and
//     that the credential names the outer source address it came from.
//     Verified credentials go into a CredentialCache (LRU, by key and by
//     VTEP), and an identical credential sent again is not verified again.
//   - Cost bounds: verifies of credentials not already cached are limited
//     per source address (source_verify_rate) and per role
//     (role_verify_rate); past the role limit only sources that already
//     have a session are verified. Replies are limited to one per source
//     per initiation_interval.
//   - Peer state is created at the first accepted handshake (or when the
//     initiator has the responder's credential) and reclaimed
//     certified_idle after the peer's last session ends.
//   - Peer lists win: a VTEP or key in a TunnelPeers set or set_peer is a
//     list peer and needs no credential, as before; Linux peers in lists
//     see nothing new.
//   - Rotation: once the role holds a credential for a new key of its
//     own, tick() sends it to every certified peer with a session, which
//     replaces the key and handshakes again (the old sessions go: a peer
//     record holds one key).
//   - Expiry and revocation: tick() drops a certified peer whose
//     credential expired or was revoked, with its cache entry and sessions;
//     it must present a new credential. Within credential_refresh of its
//     expiry a peer with a session is asked for its current one, and a
//     renewal of the same key keeps the sessions.
//
// Protocol: WireGuard's handshake and timers (wireguard.hpp for formats),
// with these simplifications, none of which changes what goes on the wire:
//
//   - No packet queue: a send with no usable session starts a handshake and
//     is dropped (tx_no_session). The Vtep's keepalives (one per peer per
//     second) bring sessions up and keep them busy, so this costs at most
//     the first second of traffic to a new peer.
//   - No cookie replies. mac1 is checked before any public-key work, so
//     only someone who knows the role's public key can make it compute;
//     mac2 is sent as zeros and a received cookie reply is dropped and
//     counted. Load-based cookies (and the XChaCha20 they need, which
//     OpenSSL 3.0 lacks) are a follow-up if handshake floods matter.
//   - Endpoints are fixed. A peer's address comes from helm and never roams;
//     anything for a session that arrives from another address is dropped
//     (wrong_source). Handshake messages always go to the peer's address
//     and peer_port, since the endpoint's flow-port sockets do not receive.
//   - No passive keepalives: the Vtep's OAM keepalives already flow both
//     ways every second.
//   - Linux's new-handshake timer is kept: a peer we have sent to for
//     keepalive_timeout + rekey_timeout without anything authenticated
//     coming back gets a new handshake, so an end that lost the session
//     (restarted, or dropped a certified peer) is recovered from.
//
// Time comes from config.clock (steady) for every timer and config.wall_clock
// for the TAI64N handshake timestamp, so tests can drive both. tick() must
// be called at or before the time it returns: it retransmits handshakes,
// gives up on unanswered ones and destroys expired sessions.
//
// Threading: like the Vtep, one data-plane thread owns a Tunnel.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "oar/net/credential_cache.hpp"
#include "oar/net/udp_endpoint.hpp"
#include "oar/net/vtep.hpp"
#include "oar/net/vtep_policy.hpp"
#include "oar/net/wireguard.hpp"

namespace ak::oar::net {

struct TunnelConfig {
    std::uint16_t peer_port{geneve::udp_port};
    // WireGuard's timers (Linux messages.h); tests shorten them.
    std::chrono::milliseconds rekey_after_time{std::chrono::seconds{120}};
    std::chrono::milliseconds reject_after_time{std::chrono::seconds{180}};
    std::chrono::milliseconds rekey_attempt_time{std::chrono::seconds{90}};
    std::chrono::milliseconds rekey_timeout{std::chrono::seconds{5}};
    std::chrono::milliseconds keepalive_timeout{std::chrono::seconds{10}};
    // Fewest milliseconds between two initiations accepted from one peer
    // (Linux: 1 s / INITIATIONS_PER_SECOND).
    std::chrono::milliseconds initiation_interval{20};
    // Certified peers (used only with set_credentials).
    std::size_t credential_cache_size{65'536};
    double source_verify_rate{16.0};   // verifies per second per source address
    double role_verify_rate{2'000.0};  // verifies per second for the role
    std::size_t max_sources{4'096};    // sources tracked for the per-source limit
    std::chrono::milliseconds certified_idle{std::chrono::minutes{5}};
    std::chrono::seconds credential_refresh{std::chrono::hours{1}};
    std::uint64_t rekey_after_messages{std::uint64_t{1} << 60U};
    std::uint64_t reject_after_messages{~std::uint64_t{0} - (std::uint64_t{1} << 13U)};
    // Empty: steady_clock::now and system_clock::now.
    std::function<VtepClock::time_point()> clock;
    std::function<std::chrono::system_clock::time_point()> wall_clock;
};

enum class TunnelConfigError : std::uint8_t {
    bad_port,    // peer_port is zero
    bad_timers,  // a timer is not positive, or rekey_after_time >= reject_after_time
    bad_limits,  // rekey_after_messages >= reject_after_messages
};

[[nodiscard]] auto to_string(TunnelConfigError e) noexcept -> const char*;

enum class TunnelKeyError : std::uint8_t {
    bad_key,        // all zero, or not a usable X25519 key (low order, or OpenSSL refused it)
    own_key,        // a peer with the role's own public key
    duplicate_key,  // another peer already has this public key
    no_crypto,      // OpenSSL failed (RNG, BLAKE2s missing)
};

[[nodiscard]] auto to_string(TunnelKeyError e) noexcept -> const char*;

// Why a received datagram was dropped. Counted per reason.
enum class TunnelDrop : std::uint8_t {
    malformed,        // wg::parse refused it (also counted per ParseError)
    no_private_key,   // helm has not delivered the role's key yet
    bad_mac1,         // handshake message not addressed to this role's key
    unknown_peer,     // initiation from a static key that is not a peer
    wrong_source,     // authenticated as a peer, but from another address
    decrypt_failed,   // AEAD authentication failed
    stale_timestamp,  // initiation timestamp not newer than the last one (replay)
    rate_limited,     // initiation sooner than initiation_interval after the last
    unknown_index,    // receiver index matches no handshake or session
    expired_session,  // session past reject_after_time or reject_after_messages
    replay,           // transport counter already seen or too old
    cookie_reply,     // cookie replies are not supported
    bad_key,          // the handshake produced an all-zero DH result
    // Certified peers (task 3).
    uncertified,              // static key in no peer list and no valid cached credential
    credential_refused,       // a credential failed verification (CredentialStore counts why)
    credential_rate_limited,  // a credential past the per-source or role verify limit
    credential_conflict,      // a credential for our own key, or a key a list peer holds
};

inline constexpr std::size_t tunnel_drop_count =
    static_cast<std::size_t>(TunnelDrop::credential_conflict) + 1;

[[nodiscard]] auto to_string(TunnelDrop d) noexcept -> const char*;

struct TunnelCounters {
    std::uint64_t tx_packets{0};        // transport messages sent with a payload
    std::uint64_t tx_bytes{0};          // their payload bytes
    std::uint64_t tx_no_peer{0};        // send to an address with no peer keys
    std::uint64_t tx_no_key{0};         // send before the private key arrived
    std::uint64_t tx_no_session{0};     // send with no usable session (handshake started)
    std::uint64_t tx_send_failed{0};    // the underlay refused a datagram
    std::uint64_t tx_crypto_failed{0};  // encryption failed
    std::uint64_t rx_datagrams{0};      // datagrams handed to receive()
    std::uint64_t rx_packets{0};        // authenticated payloads returned
    std::uint64_t rx_keepalives{0};     // authenticated empty transport messages
    std::array<std::uint64_t, tunnel_drop_count> rx_drop{};            // by TunnelDrop
    std::array<std::uint64_t, wg::parse_error_count> rx_drop_parse{};  // by wg::ParseError
    std::uint64_t initiations_tx{0};
    std::uint64_t initiations_rx{0};  // accepted
    std::uint64_t responses_tx{0};
    std::uint64_t responses_rx{0};        // accepted
    std::uint64_t handshake_timeouts{0};  // gave up after rekey_attempt_time
    std::uint64_t sessions_established{0};
    std::uint64_t key_rotations{0};        // rotate_private_key with a new key
    std::uint64_t retiring_handshakes{0};  // initiations answered under the old key
    std::uint64_t retired_sessions{0};     // old-key sessions dropped when the grace ended
    // Certified peers (task 3).
    std::uint64_t credentials_tx{0};         // our credential sent, asking for theirs
    std::uint64_t credential_replies_tx{0};  // our credential sent in answer
    std::uint64_t credentials_verified{0};   // peers' credentials verified and cached
    std::uint64_t credentials_cached{0};     // an identical cached credential: not verified again
    std::uint64_t certified_peers_added{0};
    std::uint64_t certified_peers_reclaimed{0};  // idle certified_idle after the last session
    std::uint64_t certified_expired{0};          // dropped: credential expired
    std::uint64_t certified_revoked{0};          // dropped: credential revoked
};

struct TunnelPeerStatus {
    Ipv6Address vtep{};
    wg::Key public_key{};
    bool session{false};  // a current session can send
    bool handshaking{false};
    bool certified{false};  // admitted by credential, not by a peer list
    std::optional<VtepClock::time_point> last_handshake;  // when the current session started
    std::uint64_t tx_packets{0};
    std::uint64_t rx_packets{0};
};

class CredentialStore;

class Tunnel final : public DatagramSender {
public:
    // A payload that authenticated: `payload` aliases the Tunnel's buffer
    // and is valid until the next receive().
    struct Opened {
        std::span<const std::byte> payload;
        Ipv6Address peer{};
    };

    // `underlay` must outlive the Tunnel.
    static auto create(DatagramSender& underlay, TunnelConfig config)
        -> std::expected<std::unique_ptr<Tunnel>, TunnelConfigError>;

    Tunnel(const Tunnel&) = delete;
    auto operator=(const Tunnel&) -> Tunnel& = delete;
    Tunnel(Tunnel&&) = delete;
    auto operator=(Tunnel&&) -> Tunnel& = delete;
    ~Tunnel() override;

    // The role's static private key; copied, and the caller wipes its own
    // copy. Drops every session.
    auto set_private_key(std::span<const std::byte, wg::key_size> private_key)
        -> std::expected<void, TunnelKeyError>;
    auto clear_private_key() -> void;
    // Replaces the private key, keeping the old one for `grace` (above
    // zero) as described above. Without a key yet it is set_private_key().
    auto rotate_private_key(std::span<const std::byte, wg::key_size> private_key,
                            std::chrono::milliseconds grace) -> std::expected<void, TunnelKeyError>;
    [[nodiscard]] auto public_key() const -> std::optional<wg::Key>;
    // The old public key while a rotation's grace runs.
    [[nodiscard]] auto retiring_public_key() const -> std::optional<wg::Key>;

    // Adds the peer VTEP at `vtep`, or replaces its keys (dropping its
    // sessions if they changed). An all-zero `psk` means none, as in
    // WireGuard.
    auto set_peer(const Ipv6Address& vtep, std::span<const std::byte, wg::key_size> public_key,
                  std::span<const std::byte, wg::key_size> psk)
        -> std::expected<void, TunnelKeyError>;
    // False if there was no such peer.
    auto remove_peer(const Ipv6Address& vtep) -> bool;

    // Admits certified peers through `store` (the role's own credential,
    // revocation lists and verification); it must outlive the Tunnel or be
    // detached with nullptr, which drops every certified peer.
    auto set_credentials(CredentialStore* store) -> void;
    [[nodiscard]] auto credential_cache() const noexcept -> const CredentialCache& {
        return _cache;
    }

    // DatagramSender: sends `payload` to the peer at `dst` as a transport
    // message. False (and counted) if it could not.
    auto send_to(const Ipv6Address& dst, std::uint16_t dst_port, std::uint16_t flow_port,
                 std::span<const std::byte> payload) -> bool override;

    // One datagram from the underlay. Returns the authenticated payload, or
    // nothing if it was a handshake message, a keepalive or dropped.
    auto receive(std::span<const std::byte> datagram, const Ipv6Address& outer_src)
        -> std::optional<Opened>;

    // Runs the timers. Returns when it next needs to run (time_point::max()
    // if nothing is pending).
    auto tick() -> VtepClock::time_point;

    [[nodiscard]] auto peers() const -> std::vector<TunnelPeerStatus>;
    [[nodiscard]] auto counters() const noexcept -> const TunnelCounters& { return _counters; }

private:
    struct Keypair;
    struct Peer;

    Tunnel(DatagramSender& underlay, TunnelConfig config);

    [[nodiscard]] auto now() const -> VtepClock::time_point;
    auto drop(TunnelDrop reason) -> std::optional<Opened>;
    auto initiate(Peer& peer, VtepClock::time_point now) -> void;
    auto handle_initiation(const wg::Initiation& m, const Ipv6Address& outer_src)
        -> std::optional<Opened>;
    auto handle_response(const wg::Response& m, const Ipv6Address& outer_src)
        -> std::optional<Opened>;
    auto handle_transport(const wg::Transport& m, const Ipv6Address& outer_src)
        -> std::optional<Opened>;
    auto send_transport(Peer& peer, Keypair& kp, std::uint16_t dst_port, std::uint16_t flow_port,
                        std::span<const std::byte> payload) -> bool;
    auto send_raw(const Peer& peer, std::uint16_t flow_port, std::span<const std::byte> datagram)
        -> bool;
    [[nodiscard]] auto new_index() -> std::optional<std::uint32_t>;
    auto release_index(std::uint32_t index) -> void;
    auto release(std::unique_ptr<Keypair>& kp) -> void;
    auto clear_sessions(Peer& peer) -> void;
    auto refresh_peer_secret(Peer& peer) -> void;
    [[nodiscard]] auto usable(const Keypair& kp, VtepClock::time_point now) const -> bool;
    // Forgets the rotated-out key and every session made under it.
    auto retire(bool count) -> void;
    auto cancel_handshake(Peer& peer) -> void;

    // Certified peers.
    struct Bucket {
        double tokens{0};
        std::optional<VtepClock::time_point> at;
        // Takes a token from a bucket that refills at `rate` per second up
        // to `rate` tokens.
        auto take(double rate, VtepClock::time_point now) -> bool;
    };
    struct Source {
        Bucket verifies;
        std::optional<VtepClock::time_point> last_reply;
        VtepClock::time_point last_used;
    };
    auto handle_credential(const wg::Credential& m, const Ipv6Address& outer_src)
        -> std::optional<Opened>;
    auto send_credential(const Ipv6Address& dst, std::uint8_t flags) -> bool;
    auto source(const Ipv6Address& addr, VtepClock::time_point now) -> Source*;
    auto install_certified(const Ipv6Address& vtep, const wg::Key& key,
                           const proto::VtepCredential& credential) -> Peer*;
    auto drop_peer(std::map<Ipv6Address, std::unique_ptr<Peer>>::iterator it)
        -> std::map<Ipv6Address, std::unique_ptr<Peer>>::iterator;
    [[nodiscard]] auto has_session(const Peer& peer) const -> bool;
    auto tick_certified(VtepClock::time_point now) -> VtepClock::time_point;

    DatagramSender* _underlay;
    TunnelConfig _config;
    std::optional<wg::SecretKey> _private;
    wg::Key _public{};
    wg::Hash _initial_chain{};  // HASH(CONSTRUCTION)
    wg::Hash _initial_hash{};   // HASH(_initial_chain || IDENTIFIER)
    wg::Hash _mac1_key{};       // HASH("mac1----" || _public): checks incoming mac1
    // Raised on every key change; each session records the one it was
    // made under.
    std::uint32_t _key_generation{0};
    struct Retiring {
        wg::SecretKey private_key;
        wg::Key public_key{};
        wg::Hash mac1_key{};
        std::uint32_t generation{0};
        VtepClock::time_point until;
    };
    std::optional<Retiring> _retiring;  // the old key during a rotation's grace
    std::map<Ipv6Address, std::unique_ptr<Peer>> _peers;
    std::map<wg::Key, Peer*> _by_key;
    std::unordered_map<std::uint32_t, Peer*> _by_index;
    CredentialStore* _store{nullptr};
    CredentialCache _cache;
    Bucket _role_bucket;
    std::map<Ipv6Address, Source> _sources;
    // Destinations we sent our credential to, asking for theirs, and when.
    std::map<Ipv6Address, VtepClock::time_point> _wanted;
    // The key whose credential certified peers were last sent unasked: a
    // new one (after a rotation) is pushed to every peer with a session.
    std::optional<wg::Key> _announced;
    std::vector<std::byte> _rx;  // the last decrypted payload (Opened::payload)
    std::vector<std::byte> _tx;  // the message being sent
    TunnelCounters _counters;
};

// As pump() in udp_endpoint.hpp, with every datagram authenticated by
// `tunnel` before the Vtep sees it.
auto pump(UdpEndpoint& endpoint, Tunnel& tunnel, Vtep& vtep, VSwitch& vswitch,
          std::span<std::byte> buffer, std::size_t budget, VtepClock::time_point now)
    -> std::size_t;

}  // namespace ak::oar::net
