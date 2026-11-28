// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ design "Tunnel keys" and oar-net
// Requirement 5.2: helm's TunnelKeyring generates one WireGuard key pair
// per VTEP, reports the public keys, keeps the newest controller peer set
// per VTEP, and provisions a network role with both.
//
// fleet-scale-networking task 1: keys derived from the secure element
// survive a helm restart, epochs are kept in a state file, and a rotation
// gives a new key delivered with a grace period.

#define BOOST_TEST_MODULE tunnel_keyring_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string_view>
#include <thread>
#include <vector>

#include <stdlib.h>  // NOLINT(modernize-deprecated-headers): mkdtemp is POSIX

#include <openssl/evp.h>

#include "helm/oar_link.hpp"
#include "helm/secure_element.hpp"
#include "helm/sideband_binding.hpp"
#include "helm/tunnel_keyring.hpp"
#include "proto/report.hpp"
#include "proto/tunnel_peers.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace oar = ak::helm::oar;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::PeersOutcome;
using namespace std::chrono_literals;

namespace {

constexpr helm::LinkAddress helm_side{
    .local_addr = 0x10, .peer_addr = 0x20, .local_eid = 8, .peer_eid = 9};

auto vtep(std::uint8_t tail) -> oar::Vtep {
    oar::Vtep a{};
    a[0] = std::byte{0xfd};
    a.back() = std::byte{tail};
    return a;
}

auto peers_frame(const oar::Vtep& to, std::uint64_t version)
    -> std::pair<proto::TunnelPeers, std::vector<std::byte>> {
    proto::TunnelPeers t{
        .server_id = 1,
        .key_id = 1,
        .vtep = to,
        .peers_version = version,
        .peers = {{.vtep = vtep(0x77), .mode = proto::TunnelMode::wireguard, .spi = 0, .key = {}}},
        .signature = {}};
    t.peers[0].key.fill(std::byte{static_cast<std::uint8_t>(version)});
    auto b = proto::encode_tunnel_peers(t);
    BOOST_REQUIRE(b.has_value());
    return {t, *b};
}

// Records what a network role is sent.
class RecordingRole final : public helm::OarHandler {
public:
    std::vector<std::byte> private_key;
    std::vector<std::vector<std::byte>> frames;
    int key_calls = 0;
    std::uint32_t grace = 0;    // the last key's grace_seconds
    bool refuse_grace = false;  // answer a rotation as a role built before them

    auto function_inventory() -> std::expected<oar::Inventory, oar::Status> override {
        return std::unexpected(oar::Status::unsupported);
    }
    auto prepare_function(const oar::PrepareFunction& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto clean_function(const oar::CleanFunction& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto deliver_key(const oar::DeliverKey& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto drop_key(const oar::DropKey& /*r*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto map_update(std::span<const std::byte> /*frame*/) -> oar::Status override {
        return oar::Status::unsupported;
    }
    auto health() -> std::expected<oar::Health, oar::Status> override { return oar::Health{}; }
    auto set_tunnel_key(const oar::SetTunnelKey& r) -> oar::Status override {
        if (refuse_grace && r.grace_seconds != 0) {
            return oar::Status::bad_request;
        }
        ++key_calls;
        grace = r.grace_seconds;
        private_key.assign(r.private_key.begin(), r.private_key.end());
        return oar::Status::ok;
    }
    auto tunnel_peers(std::span<const std::byte> frame) -> oar::Status override {
        frames.emplace_back(frame.begin(), frame.end());
        return oar::Status::ok;
    }
};

// X25519 public key of `priv`, through OpenSSL, independently of the keyring.
auto x25519_public(std::span<const std::byte> priv) -> proto::TunnelPublicKey {
    proto::TunnelPublicKey out{};
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char*>(priv.data()), priv.size());
    BOOST_REQUIRE(k != nullptr);
    std::size_t len = out.size();
    BOOST_REQUIRE(
        EVP_PKEY_get_raw_public_key(k, reinterpret_cast<unsigned char*>(out.data()), &len) == 1);
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    EVP_PKEY_free(k);
    return out;
}

// A private temporary directory, removed with everything in it.
struct TempDir {
    std::filesystem::path path;
    TempDir() {
        auto pattern = (std::filesystem::temp_directory_path() / "ak-keyring-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(pattern.data()) != nullptr);
        path = pattern;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

constexpr std::uint64_t server = 0x5E'0001;

auto deriver(helm::SecureElement& se) -> helm::TunnelKeyring::Deriver {
    return [&se](std::uint8_t slot, std::uint32_t epoch,
                 std::span<std::byte, oar::tunnel_key_size> out) {
        return se.derive_vtep_key(server, slot, epoch, out).has_value();
    };
}

auto derive(helm::SecureElement& se, std::uint64_t id, std::uint8_t slot, std::uint32_t epoch)
    -> std::array<std::byte, helm::vtep_key_size> {
    std::array<std::byte, helm::vtep_key_size> out{};
    BOOST_REQUIRE(se.derive_vtep_key(id, slot, epoch, out).has_value());
    return out;
}

// Serves `role` on the far end of `link` while it is alive.
struct ServedRole {
    RecordingRole role;
    std::unique_ptr<helm::Binding> helm_b;
    std::unique_ptr<helm::Binding> oar_b;
    std::unique_ptr<helm::OarEndpoint> endpoint;
    std::unique_ptr<helm::OarLink> link;
    std::jthread server;

    ServedRole() : ServedRole(helm::InProcessBinding::make_pair()) {}
    explicit ServedRole(
        std::pair<std::unique_ptr<helm::InProcessBinding>, std::unique_ptr<helm::InProcessBinding>>
            bindings)
        : helm_b{std::move(bindings.first)}, oar_b{std::move(bindings.second)} {
        endpoint = std::make_unique<helm::OarEndpoint>(
            *oar_b, helm::LinkConfig{.address = helm_side.reversed(), .mtu = 64, .timeout = 5s});
        link = std::make_unique<helm::OarLink>(
            *helm_b, helm::LinkConfig{.address = helm_side, .mtu = 64, .timeout = 5s});
        server = std::jthread{[this](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint->serve_one(role, 10ms);
                if (!r && r.error() != helm::BindingError::timed_out) {
                    return;
                }
            }
        }};
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(tunnel_keyring, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(one_key_pair_per_vtep) {
    helm::TunnelKeyring ring;
    BOOST_TEST(!ring.public_key(vtep(1)).has_value());
    const auto a = ring.ensure(vtep(1), 0);
    const auto b = ring.ensure(vtep(2), 0);
    BOOST_REQUIRE(a.has_value());
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST((*a != *b));
    BOOST_TEST(!std::ranges::all_of(*a, [](std::byte x) { return x == std::byte{0}; }));
    // Asking again returns the same pair.
    BOOST_TEST((ring.ensure(vtep(1), 0).value() == *a));
    BOOST_TEST((ring.public_key(vtep(1)) == *a));
    BOOST_TEST(ring.size() == 2U);

    // Another helm boot (another keyring) gets new keys.
    helm::TunnelKeyring next_boot;
    BOOST_TEST((next_boot.ensure(vtep(1), 0).value() != *a));

    BOOST_TEST(ring.forget(vtep(1)));
    BOOST_TEST(!ring.forget(vtep(1)));
    BOOST_TEST(!ring.public_key(vtep(1)).has_value());
    BOOST_TEST((ring.ensure(vtep(1), 0).value() != *a));
}

BOOST_AUTO_TEST_CASE(bad_vteps_get_no_key) {
    helm::TunnelKeyring ring;
    BOOST_TEST((ring.ensure(oar::Vtep{}, 0).error() == helm::KeyringError::bad_vtep));
    auto multicast = vtep(1);
    multicast[0] = std::byte{0xFF};
    BOOST_TEST((ring.ensure(multicast, 0).error() == helm::KeyringError::bad_vtep));
    BOOST_TEST(ring.size() == 0U);
    BOOST_TEST(std::string_view{helm::to_string(helm::KeyringError::no_crypto)} != "unknown");
}

BOOST_AUTO_TEST_CASE(fill_reports_public_keys_in_vtep_order) {
    helm::TunnelKeyring ring;
    proto::Inventory inv;
    inv.boot_id = 1;
    inv.vteps = {vtep(1), vtep(2), vtep(3)};
    constexpr auto wg = proto::tunnel_mode_bit(proto::TunnelMode::wireguard);
    ring.fill(inv);
    // Every VTEP supports WireGuard (and only WireGuard), keyed or not.
    BOOST_REQUIRE(inv.tunnels.size() == 3U);
    BOOST_TEST(std::ranges::all_of(inv.tunnels, [](const proto::VtepTunnel& t) {
        return t.modes == wg && t.public_key == proto::TunnelPublicKey{};
    }));

    const auto k1 = ring.ensure(vtep(1), 0).value();
    const auto k3 = ring.ensure(vtep(3), 0).value();
    ring.fill(inv);
    BOOST_REQUIRE(inv.tunnels.size() == 3U);
    BOOST_TEST((inv.tunnels[0].public_key == k1));
    BOOST_TEST((inv.tunnels[1].public_key == proto::TunnelPublicKey{}));
    BOOST_TEST((inv.tunnels[2].public_key == k3));
    BOOST_TEST(inv.tunnels[2].modes == wg);

    // The controller reads them back from the encoded report.
    auto bytes =
        proto::encode_report({.server_id = 1, .report_seq = 1, .body = proto::ReportBody{inv}});
    BOOST_REQUIRE(bytes.has_value());
    auto back = proto::decode_report(*bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((std::get<proto::Inventory>(back->body).tunnels == inv.tunnels));
}

BOOST_AUTO_TEST_CASE(keeps_the_newest_peer_set_per_vtep) {
    helm::TunnelKeyring ring;
    BOOST_TEST(ring.peers_frame(vtep(1)).empty());
    BOOST_TEST(ring.peers_version(vtep(1)) == 0U);
    const auto [p2, f2] = peers_frame(vtep(1), 2);
    const auto [p1, f1] = peers_frame(vtep(1), 1);
    const auto [p3, f3] = peers_frame(vtep(1), 3);
    const auto [q1, g1] = peers_frame(vtep(2), 1);

    BOOST_TEST((ring.store_peers(p2, f2) == PeersOutcome::stored));
    BOOST_TEST((ring.store_peers(p2, f2) == PeersOutcome::duplicate));
    // The same version with other bytes (a forged or re-signed frame helm
    // cannot judge) replaces it, so it never shadows the real one.
    auto f2b = f2;
    f2b.back() = std::byte{0x01};
    BOOST_TEST((ring.store_peers(p2, f2b) == PeersOutcome::stored));
    BOOST_TEST((ring.store_peers(p2, f2) == PeersOutcome::stored));
    BOOST_TEST((ring.store_peers(p1, f1) == PeersOutcome::stale));
    BOOST_TEST(std::ranges::equal(ring.peers_frame(vtep(1)), f2));
    BOOST_TEST((ring.store_peers(p3, f3) == PeersOutcome::stored));
    BOOST_TEST((ring.store_peers(q1, g1) == PeersOutcome::stored));  // per VTEP
    BOOST_TEST(std::ranges::equal(ring.peers_frame(vtep(1)), f3));
    BOOST_TEST(std::ranges::equal(ring.peers_frame(vtep(2)), g1));
    BOOST_TEST(ring.peers_version(vtep(1)) == 3U);
    BOOST_TEST(std::string_view{helm::to_string(PeersOutcome::stale)} != "unknown");
}

BOOST_AUTO_TEST_CASE(provision_sends_the_key_then_the_peer_set) {
    helm::TunnelKeyring ring;
    RecordingRole role;
    auto [helm_b, oar_b] = helm::InProcessBinding::make_pair();
    helm::OarEndpoint endpoint{
        *oar_b, helm::LinkConfig{.address = helm_side.reversed(), .mtu = 64, .timeout = 5s}};
    helm::OarLink link{*helm_b, helm::LinkConfig{.address = helm_side, .mtu = 64, .timeout = 5s}};

    // No key pair yet: nothing is sent.
    BOOST_TEST((ring.provision(link, vtep(1)).error().code == helm::LinkErrc::bad_request));

    const auto pub = ring.ensure(vtep(1), 0).value();
    const auto [p, f] = peers_frame(vtep(1), 4);
    {
        const std::jthread server{[&](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint.serve_one(role, 10ms);
                if (!r && r.error() != helm::BindingError::timed_out) {
                    return;
                }
            }
        }};
        // Before the controller's peer set arrives: the key alone.
        BOOST_TEST(ring.provision(link, vtep(1)).has_value());
        BOOST_TEST((ring.store_peers(p, f) == PeersOutcome::stored));
        // A restarted role: the same key, then the peer set.
        BOOST_TEST(ring.provision(link, vtep(1)).has_value());
    }
    BOOST_TEST(role.key_calls == 2);
    BOOST_TEST((x25519_public(role.private_key) == pub));
    BOOST_REQUIRE(role.frames.size() == 1U);
    BOOST_TEST(std::ranges::equal(role.frames[0], f));
}

// ---- fleet-scale-networking task 1: stable keys ---------------------------

BOOST_AUTO_TEST_CASE(secure_element_derives_one_key_per_server_slot_and_epoch) {
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se.has_value());
    const auto k = derive(*se, server, 2, 1);
    BOOST_TEST((derive(*se, server, 2, 1) == k));  // deterministic
    BOOST_TEST((derive(*se, server, 3, 1) != k));
    BOOST_TEST((derive(*se, server, 2, 2) != k));
    BOOST_TEST((derive(*se, server + 1, 2, 1) != k));
    // Clamped as an X25519 private key (RFC 7748).
    BOOST_TEST((std::to_integer<unsigned>(k[0]) & 0x07U) == 0U);
    BOOST_TEST((std::to_integer<unsigned>(k[31]) & 0xC0U) == 0x40U);
    // Another master key (a re-provisioned server) derives other keys.
    auto other = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(other.has_value());
    BOOST_TEST((derive(*other, server, 2, 1) != k));
}

BOOST_AUTO_TEST_CASE(secure_element_derivation_survives_reopening_the_master_key) {
    const TempDir dir;
    const auto path = dir.path / "master.key";
    std::array<std::byte, helm::vtep_key_size> first{};
    {
        auto se = helm::SoftwareSecureElement::open(path);
        BOOST_REQUIRE(se.has_value());
        first = derive(*se, server, 1, 1);
    }
    auto se = helm::SoftwareSecureElement::open(path);
    BOOST_REQUIRE(se.has_value());
    BOOST_TEST((derive(*se, server, 1, 1) == first));
}

BOOST_AUTO_TEST_CASE(a_helm_restart_keeps_every_vtep_key) {
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se.has_value());
    helm::TunnelKeyring ring{deriver(*se), {}};
    const auto a = ring.ensure(vtep(1), 1).value();
    const auto b = ring.ensure(vtep(2), 2).value();
    BOOST_TEST((a != b));
    BOOST_TEST((a == x25519_public(derive(*se, server, 1, 1))));
    // The next helm boot: a new keyring over the same secure element.
    helm::TunnelKeyring next_boot{deriver(*se), {}};
    BOOST_TEST((next_boot.ensure(vtep(1), 1).value() == a));
    BOOST_TEST((next_boot.ensure(vtep(2), 2).value() == b));
    // A VTEP that moved to another slot gets that slot's key.
    BOOST_TEST((next_boot.ensure(vtep(1), 3).value() == x25519_public(derive(*se, server, 3, 1))));
}

BOOST_AUTO_TEST_CASE(a_rotation_changes_the_key_and_survives_a_restart) {
    const TempDir dir;
    const auto state = dir.path / "key-epochs";
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se.has_value());
    auto epochs = helm::KeyEpochs::open(state);
    BOOST_REQUIRE(epochs.has_value());
    BOOST_TEST(epochs->epoch(1) == helm::KeyEpochs::first);
    helm::TunnelKeyring ring{deriver(*se), std::move(*epochs)};
    const auto old_key = ring.ensure(vtep(1), 1).value();

    oar::Vtep rotated{};
    auto r = ring.rotate(1, 5, &rotated);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((*r == helm::RotateOutcome::rotated));
    BOOST_TEST((rotated == vtep(1)));
    BOOST_TEST(ring.key_epoch(1) == 5U);
    const auto new_key = ring.public_key(vtep(1)).value();
    BOOST_TEST((new_key != old_key));
    BOOST_TEST((new_key == x25519_public(derive(*se, server, 1, 5))));
    // Repeats and older epochs change nothing.
    BOOST_TEST((ring.rotate(1, 5).value() == helm::RotateOutcome::stale));
    BOOST_TEST((ring.rotate(1, 2).value() == helm::RotateOutcome::stale));
    BOOST_TEST((ring.public_key(vtep(1)).value() == new_key));
    // A slot with no VTEP key yet only moves its epoch.
    BOOST_TEST((ring.rotate(4, 2).value() == helm::RotateOutcome::raised));
    BOOST_TEST((ring.ensure(vtep(4), 4).value() == x25519_public(derive(*se, server, 4, 2))));

    // The next boot reads the epochs back and derives the rotated keys.
    auto reread = helm::KeyEpochs::open(state);
    BOOST_REQUIRE(reread.has_value());
    BOOST_TEST(reread->epoch(1) == 5U);
    BOOST_TEST(reread->epoch(4) == 2U);
    BOOST_TEST(reread->epoch(9) == helm::KeyEpochs::first);
    helm::TunnelKeyring next_boot{deriver(*se), std::move(*reread)};
    BOOST_TEST((next_boot.ensure(vtep(1), 1).value() == new_key));
    BOOST_TEST(std::string_view{helm::to_string(helm::RotateOutcome::raised)} == "raised");
}

BOOST_AUTO_TEST_CASE(an_unsaved_rotation_changes_nothing) {
    const TempDir dir;
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se.has_value());
    // A state file in a directory that does not exist cannot be written.
    auto epochs = helm::KeyEpochs::open(dir.path / "missing" / "key-epochs");
    BOOST_REQUIRE(epochs.has_value());
    helm::TunnelKeyring ring{deriver(*se), std::move(*epochs)};
    const auto key = ring.ensure(vtep(1), 1).value();
    auto r = ring.rotate(1, 2);
    BOOST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error() == helm::KeyringError::state_io));
    BOOST_TEST(ring.key_epoch(1) == 1U);
    BOOST_TEST((ring.public_key(vtep(1)).value() == key));
}

BOOST_AUTO_TEST_CASE(a_corrupt_epoch_file_is_refused) {
    const TempDir dir;
    const auto state = dir.path / "key-epochs";
    for (const std::string_view text :
         {"vtep-key-epoch 1\n", "vtep-key-epoch 1 2 3\n", "epoch 1 2\n", "vtep-key-epoch 256 2\n",
          "vtep-key-epoch 1 1\n", "vtep-key-epoch 1 x\n",
          "vtep-key-epoch 1 2\nvtep-key-epoch 1 3\n", "vtep-key-epoch 1 99999999999\n"}) {
        {
            std::ofstream out{state, std::ios::trunc};
            out << text;
        }
        auto e = helm::KeyEpochs::open(state);
        BOOST_TEST_CONTEXT(text) {
            BOOST_REQUIRE(!e.has_value());
            BOOST_TEST((e.error() == helm::EpochFileError::corrupt));
        }
    }
    {
        std::ofstream out{state, std::ios::trunc};
        out << "vtep-key-epoch 1 2\nvtep-key-epoch 7 9\n";
    }
    auto e = helm::KeyEpochs::open(state);
    BOOST_REQUIRE(e.has_value());
    BOOST_TEST(e->epoch(7) == 9U);
    BOOST_TEST(std::string_view{helm::to_string(helm::EpochFileError::corrupt)} == "corrupt");
}

BOOST_AUTO_TEST_CASE(a_rotation_is_delivered_with_its_grace) {
    auto se = helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se.has_value());
    helm::TunnelKeyring ring{deriver(*se), {}};
    ServedRole served;
    BOOST_TEST((ring.deliver_rotation(*served.link, vtep(1), 600s).error().code ==
                helm::LinkErrc::bad_request));  // no key pair yet
    static_cast<void>(ring.ensure(vtep(1), 1).value());
    BOOST_REQUIRE(ring.provision(*served.link, vtep(1)).has_value());
    BOOST_TEST(served.role.grace == 0U);
    BOOST_REQUIRE(ring.rotate(1, 2).has_value());
    BOOST_REQUIRE(ring.deliver_rotation(*served.link, vtep(1), 600s).has_value());
    BOOST_TEST(served.role.grace == 600U);
    BOOST_TEST((x25519_public(served.role.private_key) == ring.public_key(vtep(1)).value()));
    // A role that predates rotations gets the key without the grace.
    served.role.refuse_grace = true;
    BOOST_REQUIRE(ring.rotate(1, 3).has_value());
    BOOST_REQUIRE(ring.deliver_rotation(*served.link, vtep(1), 600s).has_value());
    BOOST_TEST(served.role.grace == 0U);
    BOOST_TEST((x25519_public(served.role.private_key) == ring.public_key(vtep(1)).value()));
}

BOOST_AUTO_TEST_SUITE_END()
