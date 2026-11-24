// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 12 (enrollment): a storage role's
// own key, certificate request and certificate, against a throwaway CA
// standing in for the controller's.

#define BOOST_TEST_MODULE role_identity_test
#include <boost/test/unit_test.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "proto/server_identity.hpp"
#include "test_support.hpp"
#include "tls/role_identity.hpp"
#include "tls/tls.hpp"
#include "tls_test_support.hpp"

namespace {

namespace fs = std::filesystem;
namespace tls = ak::tls;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using Bytes = std::vector<std::byte>;

constexpr std::uint64_t server = 42;

auto server_san(std::uint64_t id) -> std::string {
    return "URI:" + ak::proto::server_uri(id);
}

struct Dir {
    fs::path path;
    Dir() {
        std::string tmpl = (fs::temp_directory_path() / "ak-role-identity-XXXXXX").string();
        path = ::mkdtemp(tmpl.data());
    }
    Dir(const Dir&) = delete;
    auto operator=(const Dir&) -> Dir& = delete;
    Dir(Dir&&) = delete;
    auto operator=(Dir&&) -> Dir& = delete;
    ~Dir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

struct Rig {
    Dir dir;
    ak::test::TestCa ca{"storage CA"};

    [[nodiscard]] auto config(std::vector<std::string> addresses = {}) const
        -> tls::IdentityConfig {
        return {.key_path = dir.path / "storage.key",
                .cert_path = dir.path / "storage.crt",
                .ca_pem = ca.cert_pem(),
                .server_id = server,
                .common_name = "hold",
                .addresses = std::move(addresses)};
    }
};

auto open(const tls::IdentityConfig& c) -> tls::RoleIdentity {
    auto id = tls::RoleIdentity::open(c);
    BOOST_TEST_REQUIRE(id.has_value());
    return std::move(*id);
}

// The SANs of a DER request.
auto request_sans(std::span<const std::byte> der) -> std::pair<std::vector<std::string>, int> {
    const auto* p = reinterpret_cast<const unsigned char*>(der.data());
    std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req{
        d2i_X509_REQ(nullptr, &p, static_cast<long>(der.size())), &X509_REQ_free};
    BOOST_TEST_REQUIRE(req != nullptr);
    BOOST_TEST(X509_REQ_verify(req.get(), X509_REQ_get0_pubkey(req.get())) == 1);
    std::unique_ptr<STACK_OF(X509_EXTENSION), void (*)(STACK_OF(X509_EXTENSION)*)> exts{
        X509_REQ_get_extensions(req.get()),
        [](STACK_OF(X509_EXTENSION) * s) { sk_X509_EXTENSION_pop_free(s, X509_EXTENSION_free); }};
    BOOST_TEST_REQUIRE(exts != nullptr);
    auto* names = static_cast<GENERAL_NAMES*>(
        X509V3_get_d2i(exts.get(), NID_subject_alt_name, nullptr, nullptr));
    BOOST_TEST_REQUIRE(names != nullptr);
    std::vector<std::string> uris;
    int ips = 0;
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME* n = sk_GENERAL_NAME_value(names, i);
        if (n->type == GEN_URI) {
            const auto* s = n->d.uniformResourceIdentifier;
            uris.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                              static_cast<std::size_t>(ASN1_STRING_length(s)));
        } else if (n->type == GEN_IPADD) {
            ++ips;
        }
    }
    GENERAL_NAMES_free(names);
    return {uris, ips};
}

auto file_mode(const fs::path& p) -> mode_t {
    struct stat st{};
    BOOST_TEST_REQUIRE(::stat(p.c_str(), &st) == 0);
    return st.st_mode & 0777U;
}

}  // namespace

BOOST_AUTO_TEST_CASE(creates_a_private_key_and_a_request_naming_the_server,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto id = open(rig.config({"127.0.0.1", "::1"}));
    BOOST_TEST(!id.ready());
    BOOST_TEST(!id.config(tls::Role::server).has_value());
    BOOST_TEST(file_mode(rig.dir.path / "storage.key") == 0600U);
    const auto req = id.request();
    BOOST_TEST_REQUIRE(!req.empty());
    BOOST_TEST(std::to_integer<int>(req[0]) == 0x30);
    const auto [uris, ips] = request_sans(req);
    BOOST_TEST_REQUIRE(uris.size() == 1U);
    BOOST_TEST(uris[0] == ak::proto::server_uri(server));
    BOOST_TEST(ips == 2);
    // The same bytes every time, so helm can tell a repeat from a new one.
    BOOST_TEST(std::ranges::equal(id.request(), req));

    // A restart keeps the key: the new process's request has the same key.
    auto again = open(rig.config({"127.0.0.1", "::1"}));
    const auto cert =
        rig.ca.sign_request(again.request(), server_san(server) + ",IP:127.0.0.1,IP:::1");
    BOOST_TEST(id.install(cert).has_value());
}

BOOST_AUTO_TEST_CASE(installs_a_good_chain_and_keeps_it,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto id = open(rig.config({"127.0.0.1"}));
    auto chain = rig.ca.sign_request(id.request(), server_san(server) + ",IP:127.0.0.1");
    const auto ca = rig.ca.cert_der();
    chain.insert(chain.end(), ca.begin(), ca.end());  // a chain may carry its issuer
    BOOST_TEST_REQUIRE(id.install(chain).has_value());
    BOOST_TEST(id.ready());
    BOOST_TEST(id.request().empty());  // fresh: nothing to ask for
    BOOST_TEST(id.not_after().has_value());
    BOOST_TEST(file_mode(rig.dir.path / "storage.crt") == 0644U);

    // The configuration it hands out is one TLS accepts.
    const auto cfg = id.config(tls::Role::server);
    BOOST_TEST_REQUIRE(cfg.has_value());
    BOOST_TEST(tls::Context::create(*cfg).has_value());

    // A restart picks the certificate up from disk.
    const auto reopened = open(rig.config({"127.0.0.1"}));
    BOOST_TEST(reopened.ready());
    BOOST_TEST(reopened.request().empty());
}

BOOST_AUTO_TEST_CASE(refuses_chains_that_do_not_fit,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto id = open(rig.config({"127.0.0.1"}));
    const auto req = id.request();
    const auto good_san = server_san(server) + ",IP:127.0.0.1";

    BOOST_TEST((id.install({}).error() == tls::IdentityError::bad_certificate));
    BOOST_TEST((id.install(ak::test::bytes_of(0x30, 0x03, 1, 2, 3)).error() ==
                tls::IdentityError::bad_certificate));
    auto trailing = rig.ca.sign_request(req, good_san);
    trailing.push_back(std::byte{0});
    BOOST_TEST((id.install(trailing).error() == tls::IdentityError::bad_certificate));

    // Another key: a certificate the CA issued for someone else.
    const auto other = rig.ca.issue("other", good_san);
    {
        Rig other_rig;
        auto stranger = open(other_rig.config({"127.0.0.1"}));
        BOOST_TEST((id.install(rig.ca.sign_request(stranger.request(), good_san)).error() ==
                    tls::IdentityError::wrong_key));
    }
    BOOST_TEST((id.install(rig.ca.sign_request(req, server_san(7) + ",IP:127.0.0.1")).error() ==
                tls::IdentityError::wrong_server));
    BOOST_TEST((id.install(rig.ca.sign_request(req, "IP:127.0.0.1")).error() ==
                tls::IdentityError::wrong_server));
    BOOST_TEST((id.install(rig.ca.sign_request(
                               req, server_san(server) + "," + server_san(7) + ",IP:127.0.0.1"))
                    .error() == tls::IdentityError::wrong_server));
    BOOST_TEST((id.install(rig.ca.sign_request(req, server_san(server) + ",IP:10.0.0.1")).error() ==
                tls::IdentityError::missing_address));
    ak::test::TestCa rogue{"rogue CA"};
    BOOST_TEST(
        (id.install(rogue.sign_request(req, good_san)).error() == tls::IdentityError::untrusted));
    BOOST_TEST((id.install(rig.ca.sign_request(req, good_san, -7200, -3600)).error() ==
                tls::IdentityError::untrusted));  // expired
    BOOST_TEST(!id.ready());
    BOOST_TEST(!fs::exists(rig.dir.path / "storage.crt"));
    static_cast<void>(other);
}

BOOST_AUTO_TEST_CASE(asks_again_when_a_third_of_the_lifetime_is_left,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    auto id = open(rig.config());
    // Valid from 60 s ago for 3660 s: renewal opens 1220 s before the end.
    BOOST_TEST_REQUIRE(
        id.install(rig.ca.sign_request(id.request(), server_san(server))).has_value());
    const auto now = std::chrono::system_clock::now();
    BOOST_TEST(id.request(now).empty());
    BOOST_TEST(id.request(now + 2300s).empty());
    BOOST_TEST(!id.request(now + 2500s).empty());
    // The renewal replaces it.
    BOOST_TEST_REQUIRE(
        id.install(rig.ca.sign_request(id.request(now + 2500s), server_san(server), -60, 36000))
            .has_value());
    BOOST_TEST(id.request(now + 2500s).empty());
}

BOOST_AUTO_TEST_CASE(a_stale_certificate_on_disk_is_ignored,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    {
        auto id = open(rig.config());
        // Install a good one, then replace the file with someone else's.
        BOOST_TEST_REQUIRE(
            id.install(rig.ca.sign_request(id.request(), server_san(server))).has_value());
    }
    const auto foreign = rig.ca.issue("other", server_san(server));
    std::ofstream{rig.dir.path / "storage.crt"} << foreign.cert;
    const auto id = open(rig.config());
    BOOST_TEST(!id.ready());
    BOOST_TEST(!id.request().empty());
}

BOOST_AUTO_TEST_CASE(refuses_a_key_others_can_read_and_bad_configs,
                     *utf::timeout(ak::test::unit_timeout_seconds)) {
    Rig rig;
    static_cast<void>(open(rig.config()));
    ::chmod((rig.dir.path / "storage.key").c_str(), 0644);
    BOOST_TEST((tls::RoleIdentity::open(rig.config()).error() == tls::IdentityError::bad_key));
    ::chmod((rig.dir.path / "storage.key").c_str(), 0600);
    std::ofstream{rig.dir.path / "storage.key"} << "not a key";
    BOOST_TEST((tls::RoleIdentity::open(rig.config()).error() == tls::IdentityError::bad_key));

    Rig fresh;
    auto c = fresh.config();
    c.server_id = 0;
    BOOST_TEST((tls::RoleIdentity::open(c).error() == tls::IdentityError::bad_config));
    c = fresh.config();
    c.ca_pem = "nonsense";
    BOOST_TEST((tls::RoleIdentity::open(c).error() == tls::IdentityError::bad_config));
    c = fresh.config({"not an address"});
    BOOST_TEST((tls::RoleIdentity::open(c).error() == tls::IdentityError::bad_config));
    c = fresh.config();
    c.key_path = fresh.dir.path / "missing" / "storage.key";
    BOOST_TEST((tls::RoleIdentity::open(c).error() == tls::IdentityError::io));
    BOOST_TEST(std::string_view{tls::to_string(tls::IdentityError::untrusted)} == "untrusted");
}
