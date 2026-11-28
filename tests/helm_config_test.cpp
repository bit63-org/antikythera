// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-helm's configuration file (src/helm/helm_config.hpp): every directive
// parses to its field, and mistakes are refused with the line they are on.

#define BOOST_TEST_MODULE helm_config_test
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <string>
#include <string_view>

#include "helm/helm_config.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
using ak::test::unit_timeout_seconds;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t server_id = 7;
constexpr std::uint16_t controller_port = 7443;
constexpr std::uint8_t helm_addr = 0x08;
constexpr std::uint8_t board_addr = 0x10;
constexpr std::uint8_t helm_eid = 8;
constexpr std::uint8_t board_eid = 9;

const std::string base = R"(# harbor server 7
server-id 7
controller 10.0.0.1:7443
ca /etc/ak/ca.pem
cert /etc/ak/helm.pem
key /etc/ak/helm-key.pem      # PEM
audit-log /var/lib/helm/audit.log
master-key ephemeral
slot 1 /run/harbor/slot1.sock 0x08 0x10 8 9 /usr/bin/ak-board --slot 1
)";

auto error_of(std::string_view text) -> std::string {
    auto c = helm::parse_helm_config(text);
    BOOST_REQUIRE_MESSAGE(!c.has_value(), "parsed: " + std::string{text});
    return c.error();
}

auto contains(const std::string& s, std::string_view what) -> bool {
    return s.find(what) != std::string::npos;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(helm_config, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(minimal_file_parses) {
    auto c = helm::parse_helm_config(base);
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error()));
    BOOST_TEST(c->server_id == server_id);
    BOOST_TEST(c->controller_host == "10.0.0.1");
    BOOST_TEST(c->controller_port == controller_port);
    BOOST_TEST(c->controller_name == "10.0.0.1");  // defaults to the host
    BOOST_TEST(c->key.string() == "/etc/ak/helm-key.pem");
    BOOST_TEST(!c->master_key.has_value());
    BOOST_TEST(c->host_argv.empty());
    BOOST_REQUIRE(c->slots.size() == 1U);
    const auto& slot = c->slots.at(1);
    BOOST_TEST(slot.address.local_addr == helm_addr);
    BOOST_TEST(slot.address.peer_addr == board_addr);
    BOOST_TEST(slot.address.local_eid == helm_eid);
    BOOST_TEST(slot.address.peer_eid == board_eid);
    BOOST_TEST(slot.process.ready_path.string() == "/run/harbor/slot1.sock");
    BOOST_TEST((slot.process.argv == std::vector<std::string>{"/usr/bin/ak-board", "--slot", "1"}));
    BOOST_TEST(!c->command_timeout.has_value());
}

BOOST_AUTO_TEST_CASE(optional_directives_parse) {
    std::string text = base;
    text.erase(text.find("master-key ephemeral\n"),
               std::string_view{"master-key ephemeral\n"}.size());
    auto c = helm::parse_helm_config(text + R"(
controller-name controller.example
master-key /var/lib/helm/master.key
host /usr/bin/qemu-system-x86_64 -m 4096
slot 2 /run/harbor/slot2.sock 0x08 0x11 8 10 /usr/bin/ak-board --slot 2
command-timeout-ms 5000
release-timeout-ms 6000
clean-timeout-ms 7000
link-timeout-ms 8000
sideband-timeout-ms 900
check-interval-ms 250
)");
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error()));
    BOOST_TEST(c->controller_name == "controller.example");
    BOOST_REQUIRE(c->master_key.has_value());
    BOOST_TEST(c->master_key->string() == "/var/lib/helm/master.key");
    BOOST_TEST(c->host_argv.size() == 3U);
    BOOST_TEST(c->slots.size() == 2U);
    BOOST_TEST((c->command_timeout == 5000ms));
    BOOST_TEST((c->release_timeout == 6000ms));
    BOOST_TEST((c->clean_timeout == 7000ms));
    BOOST_TEST((c->link_timeout == 8000ms));
    BOOST_TEST((c->sideband_timeout == 900ms));
    BOOST_TEST((c->check_interval == 250ms));
}

// cold-start Requirements 1 and 6.3: the optional sealed store.
BOOST_AUTO_TEST_CASE(store_directives_parse_and_go_together) {
    auto plain = helm::parse_helm_config(base);
    BOOST_REQUIRE(plain.has_value());
    BOOST_TEST(!plain->store.has_value());

    auto c = helm::parse_helm_config(base +
                                     "store /var/lib/helm/store\nstore-size 0x20000\n"
                                     "store-anchor /var/lib/helm/anchor\n");
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error()));
    BOOST_TEST(c->store->string() == "/var/lib/helm/store");
    BOOST_TEST(c->store_size == 0x20000U);
    BOOST_TEST(c->store_anchor->string() == "/var/lib/helm/anchor");

    auto e = helm::parse_helm_config(base + "store /s\nstore-anchor ephemeral\n");
    BOOST_REQUIRE(e.has_value());
    BOOST_TEST(!e->store_anchor.has_value());
    BOOST_TEST(e->store_size == std::uint64_t{1} << 20);

    BOOST_TEST(contains(error_of(base + "store /s\n"), "store and store-anchor go together"));
    BOOST_TEST(contains(error_of(base + "store-anchor /a\n"), "go together"));
    BOOST_TEST(contains(error_of(base + "store-size 65536\n"), "store-size without store"));
    BOOST_TEST(contains(error_of(base + "store /s\nstore-anchor /a\nstore-size 4096\n"),
                        "store-size must be"));
    BOOST_TEST(contains(error_of(base + "store /s\nstore-anchor /a\nstore-size 20000\n"),
                        "store-size must be"));
}

BOOST_AUTO_TEST_CASE(ipv6_controllers_use_brackets) {
    std::string text = base;
    text.replace(text.find("10.0.0.1:7443"), std::string_view{"10.0.0.1:7443"}.size(),
                 "[fd00::1]:7443");
    auto c = helm::parse_helm_config(text);
    BOOST_REQUIRE_MESSAGE(c.has_value(), (c ? std::string{} : c.error()));
    BOOST_TEST(c->controller_host == "fd00::1");
    BOOST_TEST(c->controller_port == controller_port);
}

BOOST_AUTO_TEST_CASE(missing_directives_are_named) {
    BOOST_TEST(contains(error_of(""), "missing server-id"));
    std::string no_slot = base.substr(0, base.find("slot 1"));
    BOOST_TEST(contains(error_of(no_slot), "missing slot"));
    std::string no_audit = base;
    no_audit.erase(no_audit.find("audit-log"), no_audit.find('\n', no_audit.find("audit-log")) -
                                                   no_audit.find("audit-log") + 1);
    BOOST_TEST(contains(error_of(no_audit), "missing audit-log"));
}

BOOST_AUTO_TEST_CASE(mistakes_name_their_line) {
    const auto at_end = [](std::string_view line) { return base + std::string{line} + "\n"; };
    const std::string end_line = "line 10: ";  // base has 9 lines and ends in a newline
    BOOST_TEST(contains(error_of(at_end("bogus 1")), end_line + "unknown directive"));
    BOOST_TEST(contains(error_of(at_end("server-id 8")), "duplicate server-id"));
    BOOST_TEST(contains(error_of(at_end("ca a b")), "takes one value"));
    BOOST_TEST(contains(error_of(at_end("command-timeout-ms 0")), "bad milliseconds"));
    BOOST_TEST(contains(error_of(at_end("command-timeout-ms 5s")), "bad milliseconds"));
    BOOST_TEST(contains(error_of(at_end("host")), "host needs ARGV"));
    BOOST_TEST(contains(error_of(at_end("slot 1 /s 0x08 0x12 8 11 /bin/b")), "duplicate slot 1"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x08 0x12 8 11")), "slot needs"));
    BOOST_TEST(contains(error_of(at_end("slot 256 /s 0x08 0x12 8 11 /bin/b")), "bad slot number"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x80 0x12 8 11 /bin/b")), "bus addresses"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x08 0x08 8 11 /bin/b")), "bus addresses"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x08 0x12 7 11 /bin/b")), "EIDs"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x08 0x12 8 255 /bin/b")), "EIDs"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x08 0x12 9 9 /bin/b")), "EIDs"));
    BOOST_TEST(contains(error_of(at_end("slot 2 /s 0x08 0x12 8 11 bin/b")), "absolute path"));

    std::string bad = base;
    bad.replace(bad.find("server-id 7"), std::string_view{"server-id 7"}.size(), "server-id 0");
    BOOST_TEST(contains(error_of(bad), "line 2: bad server-id"));
    for (const auto* endpoint :
         {"10.0.0.1", "10.0.0.1:0", "10.0.0.1:65536", ":7443", "fd00::1:7443", "[fd00::1]7443"}) {
        std::string e = base;
        e.replace(e.find("10.0.0.1:7443"), std::string_view{"10.0.0.1:7443"}.size(), endpoint);
        BOOST_TEST_CONTEXT(endpoint) {
            BOOST_TEST(contains(error_of(e), "line 3: controller must be HOST:PORT"));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
