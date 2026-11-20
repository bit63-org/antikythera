// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// WireGuard message formats and primitives (.kiro/specs/oar-net-data-plane/
// Requirement 5, design "Tunnel", task 10).
//
// The underlay between VTEPs is authenticated with the WireGuard protocol
// (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, as in the WireGuard paper and the
// Linux implementation), run inside oar-net rather than through a kernel
// wg device: the data-plane role needs no CAP_NET_ADMIN, keeps the keys
// helm gives it in its own memory, and drops forged packets before the
// Geneve decoder sees them (Requirement 5.3). tunnel.hpp holds the state
// machine; this header holds what it is built from:
//
//   - the four message formats and a strict structural parser for them
//     (untrusted input: std::expected, ak::wire, fuzzed by fuzz_wireguard);
//   - the primitives: HASH (BLAKE2s-256), MAC (keyed BLAKE2s-128), HMAC and
//     the KDF built on it, X25519, ChaCha20-Poly1305 and TAI64N, all from
//     OpenSSL 3 except the little glue around them.
//
// Message layouts (integers little-endian, WireGuard's own byte order):
//
//   initiation   0 type u8 = 1 | 1 reserved [3] | 4 sender u32 | 8 ephemeral [32]
//                40 static [32 + 16] | 88 timestamp [12 + 16] | 116 mac1 [16]
//                132 mac2 [16]                                       (148 bytes)
//   response     0 type u8 = 2 | 1 reserved [3] | 4 sender u32 | 8 receiver u32
//                12 ephemeral [32] | 44 empty [0 + 16] | 60 mac1 [16]
//                76 mac2 [16]                                        (92 bytes)
//   cookie reply 0 type u8 = 3 | 1 reserved [3] | 4 receiver u32 | 8 nonce [24]
//                32 cookie [16 + 16]                                 (64 bytes)
//   transport    0 type u8 = 4 | 1 reserved [3] | 4 receiver u32 | 8 counter u64
//                16 packet [n + 16]                               (32 + n bytes)
//
// One deliberate difference from WireGuard over IP: a transport message
// carries one Geneve UDP payload, not an IP packet, and so is not padded
// to a multiple of 16 bytes (the receiver could not tell padding from
// payload without an IP header to give the length). The handshake is
// unchanged and interoperates with a kernel peer (tests/wireguard_interop.sh),
// as does a transport message whose plaintext is an IP packet.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <initializer_list>
#include <optional>
#include <span>
#include <variant>

namespace ak::oar::net::wg {

inline constexpr std::size_t key_size = 32;
inline constexpr std::size_t hash_size = 32;
inline constexpr std::size_t mac_size = 16;
inline constexpr std::size_t tag_size = 16;  // Poly1305
inline constexpr std::size_t timestamp_size = 12;
inline constexpr std::size_t cookie_nonce_size = 24;

inline constexpr std::size_t initiation_size = 148;
inline constexpr std::size_t response_size = 92;
inline constexpr std::size_t cookie_reply_size = 64;
inline constexpr std::size_t transport_header_size = 16;
// What a transport message adds to its payload: header plus tag. The guest
// MTU (task 11) subtracts this on top of Geneve's overhead.
inline constexpr std::size_t transport_overhead = transport_header_size + tag_size;

// Where mac1 and mac2 sit: each covers every byte before it.
inline constexpr std::size_t initiation_mac1_offset = 116;
inline constexpr std::size_t response_mac1_offset = 60;

using Key = std::array<std::byte, key_size>;
using Hash = std::array<std::byte, hash_size>;
using Mac = std::array<std::byte, mac_size>;
using Timestamp = std::array<std::byte, timestamp_size>;

// Values are wire protocol.
enum class MessageType : std::uint8_t {
    initiation = 1,
    response = 2,
    cookie_reply = 3,
    transport = 4,
};

enum class ParseError : std::uint8_t {
    empty,              // no bytes at all
    unknown_type,       // first byte is not 1-4
    reserved_not_zero,  // bytes 1-3 are not zero
    bad_length,         // wrong size for the type (transport: shorter than 32)
};

inline constexpr std::size_t parse_error_count =
    static_cast<std::size_t>(ParseError::bad_length) + 1;

[[nodiscard]] auto to_string(ParseError e) noexcept -> const char*;

// Parsed messages are views into the bytes they came from.
struct Initiation {
    std::uint32_t sender{0};
    std::span<const std::byte, key_size> ephemeral;
    std::span<const std::byte, key_size + tag_size> encrypted_static;
    std::span<const std::byte, timestamp_size + tag_size> encrypted_timestamp;
    std::span<const std::byte, mac_size> mac1;
    std::span<const std::byte, mac_size> mac2;
    std::span<const std::byte> before_mac1;  // what mac1 covers
};

struct Response {
    std::uint32_t sender{0};
    std::uint32_t receiver{0};
    std::span<const std::byte, key_size> ephemeral;
    std::span<const std::byte, tag_size> encrypted_empty;
    std::span<const std::byte, mac_size> mac1;
    std::span<const std::byte, mac_size> mac2;
    std::span<const std::byte> before_mac1;
};

struct CookieReply {
    std::uint32_t receiver{0};
    std::span<const std::byte, cookie_nonce_size> nonce;
    std::span<const std::byte, mac_size + tag_size> encrypted_cookie;
};

struct Transport {
    std::uint32_t receiver{0};
    std::uint64_t counter{0};
    std::span<const std::byte> ciphertext;  // payload and tag, at least tag_size
};

using Message = std::variant<Initiation, Response, CookieReply, Transport>;

// Structural parse only: type, reserved bytes and length. Nothing is
// authenticated yet; the Tunnel checks mac1 before any public-key work.
[[nodiscard]] auto parse(std::span<const std::byte> datagram) noexcept
    -> std::expected<Message, ParseError>;

// ---- Primitives -----------------------------------------------------------

// Wipes `bytes` in a way the compiler cannot optimize away.
auto wipe(std::span<std::byte> bytes) noexcept -> void;

// A fixed-size secret wiped with OPENSSL_cleanse on destruction and when
// moved from.
template<std::size_t N> class Secret {
public:
    Secret() noexcept = default;
    explicit Secret(std::span<const std::byte, N> bytes) noexcept {
        std::copy(bytes.begin(), bytes.end(), _bytes.begin());
    }
    ~Secret() { wipe(); }
    Secret(const Secret&) = delete;
    auto operator=(const Secret&) -> Secret& = delete;
    Secret(Secret&& other) noexcept : _bytes{other._bytes} { other.wipe(); }
    auto operator=(Secret&& other) noexcept -> Secret& {
        if (this != &other) {
            _bytes = other._bytes;
            other.wipe();
        }
        return *this;
    }

    [[nodiscard]] auto span() noexcept -> std::span<std::byte, N> { return _bytes; }
    [[nodiscard]] auto span() const noexcept -> std::span<const std::byte, N> { return _bytes; }
    auto wipe() noexcept -> void { wg::wipe(_bytes); }

private:
    std::array<std::byte, N> _bytes{};
};

using SecretKey = Secret<key_size>;

// Constant-time comparison of equal-length spans.
[[nodiscard]] auto equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept
    -> bool;

// HASH(a || b || ...), BLAKE2s-256.
[[nodiscard]] auto hash(std::initializer_list<std::span<const std::byte>> parts) -> Hash;

// MAC(key, data): BLAKE2s keyed with `key`, 16-byte output.
[[nodiscard]] auto mac(std::span<const std::byte> key, std::span<const std::byte> data) -> Mac;

// KDF_n(key, input) from the WireGuard paper (HKDF over HMAC-BLAKE2s):
// fills each output in turn. 1 to 3 outputs.
auto kdf(std::span<const std::byte, hash_size> key, std::span<const std::byte> input,
         std::initializer_list<std::span<std::byte, hash_size>> outputs) -> void;

// A fresh X25519 private key from the OpenSSL RNG; nothing on RNG failure.
[[nodiscard]] auto generate_private_key() -> std::optional<SecretKey>;
// The public key of a private key; nothing if OpenSSL refuses it.
[[nodiscard]] auto public_key(std::span<const std::byte, key_size> private_key)
    -> std::optional<Key>;
// X25519(private, public). Nothing if the result is all zero (a low-order
// public key) or OpenSSL refuses the keys.
[[nodiscard]] auto dh(std::span<const std::byte, key_size> private_key,
                      std::span<const std::byte, key_size> public_key) -> std::optional<SecretKey>;

// One-shot ChaCha20-Poly1305 with the nonce 0^32 || le64(counter).
// `out` is plaintext.size() + tag_size bytes for seal, ciphertext.size() -
// tag_size for open. open returns false if authentication fails (and then
// leaves `out` zeroed).
auto seal(std::span<const std::byte, key_size> key, std::uint64_t counter,
          std::span<const std::byte> plaintext, std::span<const std::byte> ad,
          std::span<std::byte> out) -> bool;
[[nodiscard]] auto open(std::span<const std::byte, key_size> key, std::uint64_t counter,
                        std::span<const std::byte> ciphertext, std::span<const std::byte> ad,
                        std::span<std::byte> out) -> bool;

// TAI64N for `t`, with the nanoseconds rounded down to 1/64 s as Linux does
// (so the timestamp does not leak the clock's fine grain).
[[nodiscard]] auto tai64n(std::chrono::system_clock::time_point t) -> Timestamp;

// A keyed ChaCha20-Poly1305 context for one direction of a session, so the
// data path does not rebuild the key schedule for every packet.
class Aead {
public:
    // Nothing if OpenSSL fails to set the key up.
    [[nodiscard]] static auto create(std::span<const std::byte, key_size> key, bool encrypt)
        -> std::optional<Aead>;

    Aead(const Aead&) = delete;
    auto operator=(const Aead&) -> Aead& = delete;
    Aead(Aead&& other) noexcept;
    auto operator=(Aead&& other) noexcept -> Aead&;
    ~Aead();

    // As seal()/open() above, with no additional data.
    auto seal(std::uint64_t counter, std::span<const std::byte> plaintext, std::span<std::byte> out)
        -> bool;
    [[nodiscard]] auto open(std::uint64_t counter, std::span<const std::byte> ciphertext,
                            std::span<std::byte> out) -> bool;

private:
    explicit Aead(void* ctx) noexcept : _ctx{ctx} {}
    void* _ctx{nullptr};  // EVP_CIPHER_CTX*
};

// The sliding anti-replay window of RFC 6479, sized as in Linux (8192 bits,
// of which 8128 are usable). Accepts each counter at most once and anything
// up to 8128 behind the highest seen.
class ReplayWindow {
public:
    // True if `counter` has not been seen and is not too old. Does not
    // record it: call only before authentication, as a cheap pre-check.
    [[nodiscard]] auto may_accept(std::uint64_t counter) const noexcept -> bool;
    // Records `counter` after authentication; false if it was a replay.
    auto accept(std::uint64_t counter) noexcept -> bool;

    static constexpr std::uint64_t bits_total = 8192;
    static constexpr std::uint64_t word_bits = 64;
    static constexpr std::uint64_t window = bits_total - word_bits;

private:
    std::uint64_t _highest{0};  // highest accepted counter + 1, 0 if none yet
    std::array<std::uint64_t, bits_total / word_bits> _bits{};
};

}  // namespace ak::oar::net::wg
