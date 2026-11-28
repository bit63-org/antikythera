// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/fleet-scale-networking/ Requirements 2.3, 2.4 and 3, design
// "VTEP credentials": the network role's CredentialStore takes its own
// credential only for its server, VTEP and current key, keeps the newest,
// keeps each cell's highest revocation list, and verifies peers'
// credentials against the clock, the source address and the lists.

#define BOOST_TEST_MODULE credentials_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "oar/net/credentials.hpp"
#include "proto/vtep_credential.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace proto = ak::proto;
namespace wg = ak::oar::net::wg;
using net::CredentialResult;
using net::PeerCredentialError;

namespace {

constexpr std::uint64_t server = 0x0102'0304'0506'0708;
constexpr std::uint16_t good_key = 3;
constexpr std::byte good_mark{0x5A};
constexpr std::uint64_t t0 = 1'800'000'000;
constexpr std::uint64_t day = 86'400;
constexpr std::uint64_t skew = 300;

auto vtep(std::uint8_t tail) -> net::Ipv6Address {
    net::Ipv6Address a{};
    a[0] = std::byte{0xFD};
    a.back() = std::byte{tail};
    return a;
}

auto key(std::uint8_t fill) -> wg::Key {
    wg::Key k{};
    k.fill(std::byte{fill});
    return k;
}

// Stands in for Ed25519: a signature verifies when it is filled with
// good_mark under good_key, and the signed bytes are the frame less its
// last 64. The real verifier is exercised in helm_daemon_test.
auto fake_verifier(int& calls) -> net::FrameVerifier {
    return
        [&calls](std::span<const std::byte> signed_bytes,
                 std::span<const std::byte, net::frame_signature_size> sig, std::uint16_t key_id) {
            ++calls;
            return key_id == good_key && !signed_bytes.empty() &&
                   std::ranges::all_of(sig, [](std::byte b) { return b == good_mark; });
        };
}

struct Cred {
    std::uint64_t server_id{server};
    std::uint8_t tail{1};
    std::uint8_t key_fill{0x11};
    std::uint64_t not_before{t0};
    std::uint64_t not_after{t0 + day};
    std::uint64_t serial{1};
    std::uint32_t cell{7};
    proto::TunnelModes modes{proto::tunnel_mode_bit(proto::TunnelMode::wireguard)};
    std::byte mark{good_mark};

    [[nodiscard]] auto bytes() const -> std::vector<std::byte> {
        proto::VtepCredential c{.key_id = good_key,
                                .server_id = server_id,
                                .cell_id = cell,
                                .modes = modes,
                                .slot = 0,
                                .key_epoch = 1,
                                .vtep = vtep(tail),
                                .public_key = key(key_fill),
                                .not_before = not_before,
                                .not_after = not_after,
                                .serial = serial,
                                .signature = {}};
        c.signature.fill(mark);
        return proto::encode_vtep_credential(c).value();
    }
};

auto revocations(std::uint64_t version, std::vector<proto::Revocation> entries,
                 std::uint32_t cell = 7, std::byte mark = good_mark) -> std::vector<std::byte> {
    proto::CredentialRevocations l{.key_id = good_key,
                                   .cell_id = cell,
                                   .list_version = version,
                                   .entries = std::move(entries),
                                   .signature = {}};
    l.signature.fill(mark);
    return proto::encode_credential_revocations(l).value();
}

struct Rig {
    int calls{0};
    std::uint64_t now{t0 + 60};
    net::CredentialStore store{
        net::CredentialConfig{.server_id = server,
                              .vtep = vtep(1),
                              .skew = std::chrono::seconds{skew},
                              .wall_clock =
                                  [this] {
                                      return std::chrono::system_clock::time_point{
                                          std::chrono::seconds{static_cast<std::int64_t>(now)}};
                                  }},
        fake_verifier(calls)};
};

}  // namespace

BOOST_AUTO_TEST_CASE(own_credential_installs_and_is_presented,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    const auto f = Cred{}.bytes();
    BOOST_TEST(!r.store.own(key(0x11)).has_value());
    BOOST_TEST((r.store.install_own(f, key(0x11)) == CredentialResult::installed));
    auto own = r.store.own(key(0x11));
    BOOST_REQUIRE(own.has_value());
    BOOST_TEST(std::ranges::equal(*own, f));
    BOOST_TEST(r.store.own_credential()->serial == 1U);
    // The same bytes again change nothing.
    BOOST_TEST((r.store.install_own(f, key(0x11)) == CredentialResult::redelivered));
    BOOST_TEST(r.store.counters().own_installed == 1U);
    BOOST_TEST(net::accepted(CredentialResult::redelivered));
    BOOST_TEST(!net::accepted(CredentialResult::stale));
}

BOOST_AUTO_TEST_CASE(own_credential_refusals,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    BOOST_TEST((r.store.install_own(std::vector<std::byte>(10), key(0x11)) ==
                CredentialResult::undecodable));
    BOOST_TEST((r.store.install_own(Cred{.server_id = server + 1}.bytes(), key(0x11)) ==
                CredentialResult::wrong_target));
    BOOST_TEST((r.store.install_own(Cred{.tail = 2}.bytes(), key(0x11)) ==
                CredentialResult::wrong_target));
    // A credential for an old key (Requirement 2.4).
    BOOST_TEST((r.store.install_own(Cred{}.bytes(), key(0x12)) == CredentialResult::wrong_key));
    BOOST_TEST((r.store.install_own(Cred{.mark = std::byte{1}}.bytes(), key(0x11)) ==
                CredentialResult::bad_signature));
    // Expired, beyond the skew allowance.
    r.now = t0 + day + skew;
    BOOST_TEST((r.store.install_own(Cred{}.bytes(), key(0x11)) == CredentialResult::expired));
    BOOST_TEST(r.store.counters().own_refused == 6U);
    BOOST_TEST(!r.store.own_credential().has_value());
    // Within the skew allowance it is still taken.
    r.now = t0 + day + skew - 1;
    BOOST_TEST((r.store.install_own(Cred{}.bytes(), key(0x11)) == CredentialResult::installed));
}

BOOST_AUTO_TEST_CASE(own_credential_keeps_the_newest,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    BOOST_TEST((r.store.install_own(Cred{.not_after = t0 + day, .serial = 5}.bytes(), key(0x11)) ==
                CredentialResult::installed));
    // Older window, then the same window with a lower serial.
    BOOST_TEST((r.store.install_own(Cred{.not_after = t0 + day - 1, .serial = 9}.bytes(),
                                    key(0x11)) == CredentialResult::stale));
    BOOST_TEST((r.store.install_own(Cred{.not_after = t0 + day, .serial = 4}.bytes(), key(0x11)) ==
                CredentialResult::stale));
    // Same window, higher serial; then a renewal.
    BOOST_TEST((r.store.install_own(Cred{.not_after = t0 + day, .serial = 6}.bytes(), key(0x11)) ==
                CredentialResult::installed));
    BOOST_TEST((r.store.install_own(Cred{.not_after = t0 + (2 * day), .serial = 7}.bytes(),
                                    key(0x11)) == CredentialResult::installed));
    BOOST_TEST(r.store.own_credential()->serial == 7U);
}

BOOST_AUTO_TEST_CASE(rotation_drops_the_old_credential,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    BOOST_TEST(
        (r.store.install_own(Cred{.serial = 5}.bytes(), key(0x11)) == CredentialResult::installed));
    // The role rotated to key 0x12: the held credential is no longer
    // presented, and one for the new key replaces it even with an earlier
    // window.
    BOOST_TEST(!r.store.own(key(0x12)).has_value());
    BOOST_TEST(
        (r.store.install_own(Cred{.key_fill = 0x12, .not_after = t0 + 100, .serial = 2}.bytes(),
                             key(0x12)) == CredentialResult::installed));
    BOOST_TEST(r.store.own(key(0x12)).has_value());
    BOOST_TEST(!r.store.own(key(0x11)).has_value());
}

BOOST_AUTO_TEST_CASE(own_credential_is_presented_only_inside_its_window,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    // Issued by a controller whose clock runs ahead: kept, held back.
    r.now = t0 - skew - 10;
    BOOST_TEST((r.store.install_own(Cred{}.bytes(), key(0x11)) == CredentialResult::installed));
    BOOST_TEST(!r.store.own(key(0x11)).has_value());
    r.now = t0 - skew;
    BOOST_TEST(r.store.own(key(0x11)).has_value());
    r.now = t0 + day + skew - 1;
    BOOST_TEST(r.store.own(key(0x11)).has_value());
    r.now = t0 + day + skew;
    BOOST_TEST(!r.store.own(key(0x11)).has_value());
}

BOOST_AUTO_TEST_CASE(revocation_lists_keep_the_highest_version_per_cell,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    BOOST_TEST(r.store.revocations_version(7) == 0U);
    const auto v2 = revocations(2, {{.serial = 4, .not_after = t0 + day}});
    BOOST_TEST((r.store.install_revocations(v2) == CredentialResult::installed));
    BOOST_TEST((r.store.install_revocations(v2) == CredentialResult::redelivered));
    BOOST_TEST((r.store.install_revocations(revocations(1, {})) == CredentialResult::stale));
    // A different list under a version already held: the first stands.
    BOOST_TEST((r.store.install_revocations(revocations(2, {})) == CredentialResult::stale));
    BOOST_TEST(r.store.revoked(7, 4));
    BOOST_TEST(!r.store.revoked(7, 5));
    BOOST_TEST(!r.store.revoked(8, 4));
    // Cells are independent.
    BOOST_TEST((r.store.install_revocations(revocations(1, {}, 8)) == CredentialResult::installed));
    BOOST_TEST(r.store.revocations_version(7) == 2U);
    BOOST_TEST(r.store.revocations_version(8) == 1U);
    // A full snapshot replaces, it does not add.
    BOOST_TEST((r.store.install_revocations(revocations(
                    3, {{.serial = 9, .not_after = t0 + day}})) == CredentialResult::installed));
    BOOST_TEST(!r.store.revoked(7, 4));
    BOOST_TEST(r.store.revoked(7, 9));
    BOOST_TEST(
        (r.store.install_revocations(std::vector<std::byte>(4)) == CredentialResult::undecodable));
    BOOST_TEST((r.store.install_revocations(revocations(4, {}, 7, std::byte{1})) ==
                CredentialResult::bad_signature));
    BOOST_TEST(r.store.counters().revocations_installed == 3U);
    BOOST_TEST(r.store.counters().revocations_refused == 4U);
}

BOOST_AUTO_TEST_CASE(a_revocation_entry_lapses_after_its_credential,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    BOOST_TEST((r.store.install_revocations(revocations(
                    1, {{.serial = 4, .not_after = t0 + 100}})) == CredentialResult::installed));
    r.now = t0 + 100 + skew - 1;
    BOOST_TEST(r.store.revoked(7, 4));
    r.now = t0 + 100 + skew;
    BOOST_TEST(!r.store.revoked(7, 4));
}

BOOST_AUTO_TEST_CASE(peer_credentials_verify,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    Rig r;
    const auto peer = Cred{.server_id = 9, .tail = 2, .key_fill = 0x22, .serial = 4};
    auto c = r.store.verify_peer(peer.bytes(), vtep(2));
    BOOST_REQUIRE(c.has_value());
    BOOST_TEST(c->server_id == 9U);
    BOOST_TEST(r.store.counters().peer_verified == 1U);

    const auto refused = [&r](const std::vector<std::byte>& f, const net::Ipv6Address& from) {
        auto v = r.store.verify_peer(f, from);
        BOOST_REQUIRE(!v.has_value());
        return v.error();
    };
    BOOST_TEST((refused(std::vector<std::byte>(3), vtep(2)) == PeerCredentialError::undecodable));
    BOOST_TEST((refused(peer.bytes(), vtep(3)) == PeerCredentialError::wrong_source));
    auto psp_only = peer;
    psp_only.modes = proto::tunnel_mode_bit(proto::TunnelMode::psp);
    BOOST_TEST((refused(psp_only.bytes(), vtep(2)) == PeerCredentialError::no_mode));
    auto forged = peer;
    forged.mark = std::byte{2};
    BOOST_TEST((refused(forged.bytes(), vtep(2)) == PeerCredentialError::bad_signature));

    // Validity with the skew allowance on both ends.
    r.now = t0 - skew - 1;
    BOOST_TEST((refused(peer.bytes(), vtep(2)) == PeerCredentialError::not_yet_valid));
    r.now = t0 - skew;
    BOOST_TEST(r.store.verify_peer(peer.bytes(), vtep(2)).has_value());
    r.now = t0 + day + skew;
    BOOST_TEST((refused(peer.bytes(), vtep(2)) == PeerCredentialError::expired));

    // Revoked in its own cell only.
    r.now = t0 + 60;
    BOOST_TEST((r.store.install_revocations(revocations(
                    1, {{.serial = 4, .not_after = t0 + day}})) == CredentialResult::installed));
    BOOST_TEST((refused(peer.bytes(), vtep(2)) == PeerCredentialError::revoked));
    auto other_cell = peer;
    other_cell.cell = 8;
    BOOST_TEST(r.store.verify_peer(other_cell.bytes(), vtep(2)).has_value());

    const auto& counts = r.store.counters().peer_refused;
    for (auto e : {PeerCredentialError::undecodable, PeerCredentialError::wrong_source,
                   PeerCredentialError::no_mode, PeerCredentialError::bad_signature,
                   PeerCredentialError::not_yet_valid, PeerCredentialError::expired,
                   PeerCredentialError::revoked}) {
        BOOST_TEST(counts.at(static_cast<std::size_t>(e)) == 1U);
    }
}

BOOST_AUTO_TEST_CASE(no_verifier_trusts_nothing,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    net::CredentialStore store{net::CredentialConfig{.server_id = server,
                                                     .vtep = vtep(1),
                                                     .skew = std::chrono::seconds{skew},
                                                     .wall_clock = {}},
                               net::FrameVerifier{}};
    BOOST_TEST((store.install_own(Cred{.not_before = 1, .not_after = 0xFFFF'FFFF'FFFF}.bytes(),
                                  key(0x11)) == CredentialResult::bad_signature));
    BOOST_TEST((store.install_revocations(revocations(1, {})) == CredentialResult::bad_signature));
}

BOOST_AUTO_TEST_CASE(results_and_errors_have_names,
                     *boost::unit_test::timeout(ak::test::unit_timeout_seconds)) {
    for (auto res :
         {CredentialResult::installed, CredentialResult::redelivered, CredentialResult::undecodable,
          CredentialResult::wrong_target, CredentialResult::wrong_key,
          CredentialResult::bad_signature, CredentialResult::expired, CredentialResult::stale}) {
        BOOST_TEST(std::string_view{net::to_string(res)} != "unknown");
    }
    for (std::size_t i = 0; i < net::peer_credential_error_count; ++i) {
        BOOST_TEST(std::string_view{net::to_string(static_cast<PeerCredentialError>(i))} !=
                   "unknown");
    }
}
