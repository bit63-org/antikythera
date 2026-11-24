// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 8: the strict JSON reader, the HTTP
// reply parser and vm.info extraction the agent applies to its VMMs'
// answers, the vm.create body, and ChApiClient against an in-process
// server on a UNIX socket.

#define BOOST_TEST_MODULE vmm_api_test
#include <boost/test/unit_test.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#include "hull/ch_config.hpp"
#include "hull/json.hpp"
#include "hull/vmm_api.hpp"
#include "test_support.hpp"

namespace json = ak::hull::json;
using ak::hull::ChApiClient;
using ak::hull::HttpReply;
using ak::hull::ReplyParse;
using ak::hull::VmmApiError;
using ak::hull::VmmState;
using ak::test::unit_timeout_seconds;
using json::JsonError;

BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<std::uint64_t>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<bool>)
BOOST_TEST_DONT_PRINT_LOG_VALUE(std::optional<ak::hull::json::JsonError>)

namespace ak::hull::json {
auto boost_test_print_type(std::ostream& os, JsonError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::hull::json

namespace {

auto bytes(std::string_view s) -> std::span<const std::byte> {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

auto parse_error(std::string_view text) -> std::optional<JsonError> {
    const auto r = json::parse(text);
    if (r) {
        return std::nullopt;
    }
    return r.error();
}

auto reply_of(std::string_view raw, bool closed = true)
    -> std::expected<std::pair<ReplyParse, HttpReply>, ak::hull::VmmApiFailure> {
    HttpReply out;
    auto r = ak::hull::parse_reply(bytes(raw), closed, out);
    if (!r) {
        return std::unexpected(r.error());
    }
    return std::pair{*r, out};
}

}  // namespace

// --- JSON ------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(json_reads_every_value_kind,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto v =
        json::parse(R"( {"a":[1,-2.5e3,true,false,null],"b":{"c":"d\u00e9\ud83d\ude00\n"}} )");
    BOOST_TEST_REQUIRE(v.has_value());
    const auto* a = v->find("a")->as_array();
    BOOST_TEST_REQUIRE(a != nullptr);
    BOOST_TEST(a->size() == 5U);
    BOOST_TEST((*a)[0].as_u64() == std::optional<std::uint64_t>{1});
    BOOST_TEST(!(*a)[1].as_u64().has_value());  // negative, fraction, exponent
    BOOST_TEST((*a)[2].as_bool() == std::optional<bool>{true});
    BOOST_TEST((*a)[4].is_null());
    BOOST_TEST(*v->find("b")->find("c")->as_string() == "d\xC3\xA9\xF0\x9F\x98\x80\n");
    BOOST_TEST(v->find("missing") == nullptr);
}

BOOST_AUTO_TEST_CASE(json_refuses_what_the_grammar_does_not_allow,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(parse_error("") == JsonError::syntax);
    BOOST_TEST(parse_error("[1,]") == JsonError::syntax);
    BOOST_TEST(parse_error("{\"a\":1,}") == JsonError::syntax);
    BOOST_TEST(parse_error("{a:1}") == JsonError::syntax);
    BOOST_TEST(parse_error("// c\n1") == JsonError::syntax);
    BOOST_TEST(parse_error("NaN") == JsonError::syntax);
    BOOST_TEST(parse_error("01") == JsonError::bad_number);
    BOOST_TEST(parse_error("1.") == JsonError::bad_number);
    BOOST_TEST(parse_error("-") == JsonError::bad_number);
    BOOST_TEST(parse_error("1e") == JsonError::bad_number);
    BOOST_TEST(parse_error("\"a\tb\"") == JsonError::bad_string);          // raw control char
    BOOST_TEST(parse_error("\"\\x\"") == JsonError::bad_string);           // unknown escape
    BOOST_TEST(parse_error("\"\\ud800\"") == JsonError::bad_string);       // lone high surrogate
    BOOST_TEST(parse_error("\"\\udc00\"") == JsonError::bad_string);       // lone low surrogate
    BOOST_TEST(parse_error("\"\xC0\xAF\"") == JsonError::bad_string);      // overlong
    BOOST_TEST(parse_error("\"\xED\xA0\x80\"") == JsonError::bad_string);  // UTF-8 surrogate
    BOOST_TEST(parse_error("\"abc") == JsonError::bad_string);
    BOOST_TEST(parse_error("{\"a\":1,\"a\":2}") == JsonError::duplicate_key);
    BOOST_TEST(parse_error("1 2") == JsonError::trailing_data);
    BOOST_TEST(parse_error("{} x") == JsonError::trailing_data);
}

BOOST_AUTO_TEST_CASE(json_bounds_size_and_depth, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::string deep(json::max_depth + 1, '[');
    deep += std::string(json::max_depth + 1, ']');
    BOOST_TEST(parse_error(deep) == JsonError::too_deep);
    std::string ok(json::max_depth, '[');
    ok += std::string(json::max_depth, ']');
    BOOST_TEST(json::parse(ok).has_value());
    std::string big = "\"" + std::string(json::max_document, 'x') + "\"";
    BOOST_TEST(parse_error(big) == JsonError::too_large);
}

BOOST_AUTO_TEST_CASE(json_as_u64_takes_only_plain_integers_that_fit,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(json::parse("18446744073709551615")->as_u64() ==
               std::optional<std::uint64_t>{18446744073709551615ULL});
    BOOST_TEST(!json::parse("18446744073709551616")->as_u64().has_value());
    BOOST_TEST(!json::parse("1e3")->as_u64().has_value());
    BOOST_TEST(!json::parse("\"7\"")->as_u64().has_value());
}

BOOST_AUTO_TEST_CASE(json_quote_round_trips, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::string nasty = "a\"b\\c\n\x01/d";
    const auto q = json::quote(nasty);
    BOOST_TEST(q == "\"a\\\"b\\\\c\\u000a\\u0001/d\"");
    BOOST_TEST(*json::parse(q)->as_string() == nasty);
}

// --- HTTP replies -------------------------------------------------------------

BOOST_AUTO_TEST_CASE(reply_with_and_without_body,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto r = reply_of(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->first == ReplyParse::complete));
    BOOST_TEST(r->second.status == 200U);
    BOOST_TEST(r->second.body == "{}");

    r = reply_of("HTTP/1.1 204 No Content\r\n\r\n");
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->second.status == 204U);
    BOOST_TEST(r->second.body.empty());

    r = reply_of("HTTP/1.0 404 Not Found\r\ncontent-length: 0\r\n\r\n");
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST(r->second.status == 404U);
}

BOOST_AUTO_TEST_CASE(reply_waits_for_the_rest, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto r = reply_of("HTTP/1.1 200 OK\r\nContent-Len", false);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->first == ReplyParse::incomplete));
    r = reply_of("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}", false);
    BOOST_TEST_REQUIRE(r.has_value());
    BOOST_TEST((r->first == ReplyParse::incomplete));
    // The same bytes with the peer gone are a short reply.
    r = reply_of("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}", true);
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error().error == VmmApiError::bad_reply));
}

BOOST_AUTO_TEST_CASE(reply_refuses_malformed_heads,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::array<std::string_view, 13> bad{
        "HTTP/2 200 OK\r\n\r\n",
        "HTTP/1.1 2x0 OK\r\n\r\n",
        "HTTP/1.1 099 Low\r\n\r\n",
        "HTTP/1.1 200OK\r\n\r\n",
        "HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: a\nb\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra",
        "HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\n{}",
    };
    for (const auto raw : bad) {
        const auto r = reply_of(raw);
        BOOST_TEST(!r.has_value(), raw);
    }
    // Over the size limits.
    const auto huge =
        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(ak::hull::max_reply_body + 1) +
        "\r\n\r\n";
    BOOST_TEST(!reply_of(huge).has_value());
    const auto long_head = "HTTP/1.1 200 OK\r\nX: " + std::string(ak::hull::max_reply_head, 'a');
    BOOST_TEST(!reply_of(long_head, false).has_value());
}

BOOST_AUTO_TEST_CASE(request_bytes_match_what_cloud_hypervisor_expects,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(
        ak::hull::format_request("GET", "vm.info", "") ==
        "GET /api/v1/vm.info HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n");
    BOOST_TEST(ak::hull::format_request("PUT", "vm.remove-device", "{\"id\":\"x\"}") ==
               "PUT /api/v1/vm.remove-device HTTP/1.1\r\nHost: localhost\r\nAccept: "
               "application/json\r\nContent-Type: application/json\r\nContent-Length: "
               "10\r\n\r\n{\"id\":\"x\"}");
}

// --- vm.info -------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(vm_info_reads_state_and_device_ids,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto info = ak::hull::parse_vm_info(
        R"({"config":{"cpus":{"boot_vcpus":2},"devices":[{"path":"/sys/x","id":"ak-s1-nic-f3"},)"
        R"({"path":"/sys/y","id":"ak-s2-blk-f0"}]},"state":"Running","memory_actual_size":1})");
    BOOST_TEST_REQUIRE(info.has_value());
    BOOST_TEST((info->state == VmmState::running));
    BOOST_TEST((info->device_ids == std::vector<std::string>{"ak-s1-nic-f3", "ak-s2-blk-f0"}));

    const auto none = ak::hull::parse_vm_info(R"({"config":{"devices":null},"state":"Created"})");
    BOOST_TEST_REQUIRE(none.has_value());
    BOOST_TEST((none->state == VmmState::created));
    BOOST_TEST(none->device_ids.empty());
    BOOST_TEST((ak::hull::parse_vm_info(R"({"config":{},"state":"BreakPoint"})")->state ==
                VmmState::other));
}

BOOST_AUTO_TEST_CASE(vm_info_refuses_what_it_cannot_trust,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::array<std::string_view, 7> bad{
        R"({"config":{}})",
        R"({"state":"Running"})",
        R"({"state":1,"config":{}})",
        R"({"state":"Running","config":{"devices":{}}})",
        R"({"state":"Running","config":{"devices":[{"path":"/x"}]}})",
        R"({"state":"Running","config":{"devices":[{"id":"a"},{"id":"a"}]}})",
        R"({"state":"Running","config":{"devices":[]}} trailing)",
    };
    for (const auto body : bad) {
        const auto r = ak::hull::parse_vm_info(body);
        BOOST_TEST_REQUIRE(!r.has_value(), body);
        BOOST_TEST((r.error().error == VmmApiError::bad_body));
    }
}

// --- vm.create body ----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(vm_config_pins_vcpus_and_uses_huge_pages,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const ak::hull::Allocation a{.vm_id = 7, .vcpus = 3, .cpus = {4, 5, 6, 7}, .hugepages = 2};
    const auto j = ak::hull::vm_config_json(
        a, {.firmware = "/usr/share/hypervisor-fw", .kernel = {}, .cmdline = {}, .initramfs = {}});
    BOOST_TEST(j ==
               R"({"cpus":{"boot_vcpus":3,"max_vcpus":3,"affinity":[{"vcpu":0,"host_cpus":[4]},)"
               R"({"vcpu":1,"host_cpus":[5]},{"vcpu":2,"host_cpus":[6]}]},)"
               R"("memory":{"size":2147483648,"hugepages":true,"hugepage_size":1073741824,)"
               R"("shared":false},"payload":{"firmware":"/usr/share/hypervisor-fw"},)"
               R"("serial":{"mode":"Off"},"console":{"mode":"Off"}})");
    BOOST_TEST(json::parse(j).has_value());

    const auto k = ak::hull::vm_config_json(a, {.firmware = {},
                                                .kernel = "/boot/vmlinux",
                                                .cmdline = "console=hvc0 \"q\"",
                                                .initramfs = "/boot/i"});
    const auto doc = json::parse(k);
    BOOST_TEST_REQUIRE(doc.has_value());
    const auto* payload = doc->find("payload");
    BOOST_TEST(*payload->find("kernel")->as_string() == "/boot/vmlinux");
    BOOST_TEST(*payload->find("cmdline")->as_string() == "console=hvc0 \"q\"");
    BOOST_TEST(*payload->find("initramfs")->as_string() == "/boot/i");
    BOOST_TEST(payload->find("firmware") == nullptr);
}

BOOST_AUTO_TEST_CASE(argv_and_device_ids, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((ak::hull::ch_argv("/usr/bin/cloud-hypervisor", "/run/hull/vm-1/api.sock") ==
                std::vector<std::string>{"/usr/bin/cloud-hypervisor", "--api-socket",
                                         "path=/run/hull/vm-1/api.sock", "--seccomp", "true"}));
    using ak::helm::mailbox::DeviceType;
    BOOST_TEST(ak::hull::device_id({.slot = 3, .type = DeviceType::nic_vf, .function = 17}) ==
               "ak-s3-nic-f17");
    BOOST_TEST(ak::hull::device_id({.slot = 0, .type = DeviceType::blk_fn, .function = 0}) ==
               "ak-s0-blk-f0");
}

// --- ChApiClient against a socket ------------------------------------------------------

namespace {

// Serves one connection per expected request with `answer(request) -> raw reply`.
class OneShotServer {
public:
    OneShotServer(std::filesystem::path path, int connections,
                  std::function<std::string(const std::string&)> answer)
        : _path{std::move(path)}, _fd{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)} {
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, _path.c_str(), _path.native().size() + 1);
        BOOST_TEST_REQUIRE(::bind(_fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) ==
                           0);
        BOOST_TEST_REQUIRE(::listen(_fd, 4) == 0);
        _thread = std::thread{[this, connections, answer = std::move(answer)] {
            for (int i = 0; i < connections; ++i) {
                const int c = ::accept(_fd, nullptr, nullptr);
                if (c < 0) {
                    return;
                }
                std::string req;
                std::array<char, 4096> buf{};
                // Read the head and any body the request announces.
                for (;;) {
                    const auto n = ::recv(c, buf.data(), buf.size(), 0);
                    if (n <= 0) {
                        break;
                    }
                    req.append(buf.data(), static_cast<std::size_t>(n));
                    const auto end = req.find("\r\n\r\n");
                    if (end == std::string::npos) {
                        continue;
                    }
                    const auto cl = req.find("Content-Length: ");
                    const std::size_t len =
                        cl == std::string::npos ? 0 : std::stoul(req.substr(cl + 16));
                    if (req.size() >= end + 4 + len) {
                        break;
                    }
                }
                {
                    const std::scoped_lock lock{_mutex};
                    _requests.push_back(req);
                }
                const auto raw = answer(req);
                if (!raw.empty()) {
                    (void)::send(c, raw.data(), raw.size(), MSG_NOSIGNAL);
                    ::close(c);
                } else {
                    stalled.push_back(c);  // never answer
                }
            }
        }};
    }
    OneShotServer(const OneShotServer&) = delete;
    auto operator=(const OneShotServer&) -> OneShotServer& = delete;
    OneShotServer(OneShotServer&&) = delete;
    auto operator=(OneShotServer&&) -> OneShotServer& = delete;
    ~OneShotServer() {
        ::shutdown(_fd, SHUT_RDWR);
        _thread.join();
        for (const int c : stalled) {
            ::close(c);
        }
        ::close(_fd);
        std::filesystem::remove(_path);
    }

    // The requests received so far.
    [[nodiscard]] auto requests() -> std::vector<std::string> {
        const std::scoped_lock lock{_mutex};
        return _requests;
    }

    std::vector<int> stalled;  // server thread only, until the join

private:
    std::mutex _mutex;
    std::vector<std::string> _requests;
    std::filesystem::path _path;
    int _fd{-1};
    std::thread _thread;
};

auto socket_path(const char* tag) -> std::filesystem::path {
    return std::filesystem::temp_directory_path() /
           ("ak-vmm-api-" + std::string{tag} + "-" + std::to_string(::getpid()) + ".sock");
}

}  // namespace

BOOST_AUTO_TEST_CASE(client_talks_to_a_vmm, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto path = socket_path("ok");
    {
        OneShotServer server{
            path, 4, [](const std::string& req) -> std::string {
                if (req.starts_with("GET /api/v1/vm.info ")) {
                    const std::string body =
                        R"({"config":{"devices":[{"id":"ak-s1-nic-f0"}]},"state":"Running"})";
                    return "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                           "\r\n\r\n" + body;
                }
                if (req.starts_with("PUT /api/v1/vm.add-device ")) {
                    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
                }
                return "HTTP/1.1 204 No Content\r\n\r\n";
            }};
        ChApiClient client{path, std::chrono::seconds{5}};
        BOOST_TEST(client.create(R"({"payload":{}})").has_value());
        BOOST_TEST(
            client.add_device("ak-s1-nic-f0", "/sys/bus/pci/devices/0000:01:00.0").has_value());
        BOOST_TEST(client.remove_device("ak-s1-nic-f0").has_value());
        const auto info = client.info();
        BOOST_TEST_REQUIRE(info.has_value());
        BOOST_TEST((info->state == VmmState::running));
        BOOST_TEST(info->device_ids.size() == 1U);
        // Wait for the server thread to record the last request.
        // Every request was recorded before its reply was sent.
        const auto requests = server.requests();
        BOOST_TEST_REQUIRE(requests.size() == 4U);
        BOOST_TEST(requests[0].starts_with("PUT /api/v1/vm.create HTTP/1.1\r\n"));
        BOOST_TEST(requests[1].ends_with(
            R"({"id":"ak-s1-nic-f0","path":"/sys/bus/pci/devices/0000:01:00.0"})"));
        BOOST_TEST(requests[2].ends_with(R"({"id":"ak-s1-nic-f0"})"));
    }
}

BOOST_AUTO_TEST_CASE(client_reports_refusals_and_garbage,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto path = socket_path("bad");
    OneShotServer server{
        path, 2, [n = 0](const std::string&) mutable -> std::string {
            return n++ == 0 ? "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
                            : "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{\"a\":";
        }};
    ChApiClient client{path, std::chrono::seconds{5}};
    const auto refused = client.boot();
    BOOST_TEST_REQUIRE(!refused.has_value());
    BOOST_TEST((refused.error().error == VmmApiError::refused));
    BOOST_TEST(refused.error().http_status == 500U);
    const auto garbage = client.info();
    BOOST_TEST_REQUIRE(!garbage.has_value());
    BOOST_TEST((garbage.error().error == VmmApiError::bad_body));
}

BOOST_AUTO_TEST_CASE(client_gives_up_on_a_silent_vmm,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto path = socket_path("silent");
    OneShotServer server{path, 1, [](const std::string&) { return std::string{}; }};
    ChApiClient client{path, std::chrono::milliseconds{200}};
    const auto start = std::chrono::steady_clock::now();
    const auto r = client.boot();
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error().error == VmmApiError::timed_out));
    BOOST_TEST((std::chrono::steady_clock::now() - start < std::chrono::seconds{3}));
}

BOOST_AUTO_TEST_CASE(client_without_a_socket, *boost::unit_test::timeout(unit_timeout_seconds)) {
    ChApiClient client{socket_path("absent"), std::chrono::milliseconds{200}};
    const auto r = client.ping();
    BOOST_TEST_REQUIRE(!r.has_value());
    BOOST_TEST((r.error().error == VmmApiError::connect_failed));
}
