// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-net-data-plane/ Requirements 13.4 to 13.8 (task 21.4):
// the metadata service's request parser, IMDSv2 tokens, path table and
// connection server, the last over socket pairs.

#define BOOST_TEST_MODULE metadata_http_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "oar/net/metadata_http.hpp"
#include "oar/net/metadata_server.hpp"
#include "test_support.hpp"

namespace net = ak::oar::net;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using net::HttpMethod;
using net::RequestError;
using net::TokenError;
using namespace std::chrono_literals;

namespace {

constexpr std::uint64_t nic = 0x5001;
constexpr std::uint64_t other_nic = 0x5002;

auto parse(std::string_view text) -> std::expected<net::HttpRequest, RequestError> {
    return net::parse_request(std::as_bytes(std::span{text}));
}

auto key_bytes(std::byte fill) -> std::array<std::byte, net::token_key_size> {
    std::array<std::byte, net::token_key_size> k{};
    k.fill(fill);
    return k;
}

auto test_key() -> net::TokenKey {
    return net::TokenKey{key_bytes(std::byte{0x42})};
}

auto record() -> proto::InstanceMetadata {
    proto::InstanceMetadata m;
    m.server_id = 7;
    m.key_id = 1;
    m.nic_id = nic;
    m.metadata_version = 1;
    m.vni = 0x1234;
    m.put_hop_limit = 2;
    m.device_index = 0;
    m.launch_index = 3;
    m.pending_time = 1764086400;  // 2025-11-25T16:00:00Z
    m.instance_id = "i-0123456789abcdef0";
    m.image_id = "ami-0fedcba987654321";
    m.instance_type = "m1.small";
    m.account_id = "123456789012";
    m.local_hostname = "ip-10-0-0-5.internal";
    m.availability_zone = "zone-a";
    m.region = "region-1";
    m.interface_id = "eni-0123456789abcdef0";
    m.vpc_id = "vpc-0123456789abcdef0";
    return m;
}

auto network() -> net::NicNetwork {
    net::NicNetwork n;
    n.mac = {std::byte{0x02}, std::byte{0x00}, std::byte{0x00},
             std::byte{0x0a}, std::byte{0xbc}, std::byte{0xde}};
    n.ipv4 = {{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{5}},
              {std::byte{10}, std::byte{0}, std::byte{0}, std::byte{6}}};
    net::Ipv6Address v6{};
    v6[0] = std::byte{0xfd};
    v6[15] = std::byte{0x05};
    n.ipv6 = {v6};
    n.subnet4 = net::neighbor::Ipv4Address{std::byte{10}, std::byte{0}, std::byte{0}, std::byte{0}};
    n.subnet4_length = 24;
    return n;
}

auto get(std::string_view path, std::string_view extra = {}) -> net::HttpRequest {
    const auto text =
        "GET " + std::string{path} + " HTTP/1.1\r\nHost: x\r\n" + std::string{extra} + "\r\n";
    auto r = parse(text);
    BOOST_REQUIRE(r.has_value());
    return *r;
}

auto put_token(std::string_view ttl, std::string_view extra = {}) -> net::HttpRequest {
    const auto text = "PUT /latest/api/token HTTP/1.1\r\nX-aws-ec2-metadata-token-ttl-seconds: " +
                      std::string{ttl} + "\r\n" + std::string{extra} + "\r\n";
    auto r = parse(text);
    BOOST_REQUIRE(r.has_value());
    return *r;
}

struct Answers {
    proto::InstanceMetadata m = record();
    net::TokenKey key = test_key();
    std::uint64_t now = 1000;

    auto operator()(const net::HttpRequest& r) -> net::HttpResponse {
        return net::answer(r, net::MetadataView{.record = &m, .network = network()}, key, now);
    }
    auto body(std::string_view path) -> std::string {
        const auto r = (*this)(get(path));
        BOOST_TEST_INFO(path);
        BOOST_TEST(r.status == 200U);
        return r.body;
    }
    auto status(std::string_view path) -> unsigned { return (*this)(get(path)).status; }
};

// ---- sockets ----

struct Pair {
    int client{-1};
    int server{-1};
    Pair() {
        std::array<int, 2> fds{};
        BOOST_REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
        client = fds[0];
        server = fds[1];
    }
    Pair(const Pair&) = delete;
    auto operator=(const Pair&) -> Pair& = delete;
    Pair(Pair&&) = delete;
    auto operator=(Pair&&) -> Pair& = delete;
    ~Pair() { ::close(client); }  // the server owns its end
};

auto send_text(int fd, std::string_view text) -> void {
    BOOST_REQUIRE(::send(fd, text.data(), text.size(), MSG_NOSIGNAL) ==
                  static_cast<ssize_t>(text.size()));
}

// Everything readable now; `closed` says whether the peer has closed.
auto drain(int fd, bool* closed = nullptr) -> std::string {
    std::string out;
    std::array<char, 4096> buf{};
    for (;;) {
        const auto n = ::recv(fd, buf.data(), buf.size(), MSG_DONTWAIT);
        if (n > 0) {
            out.append(buf.data(), static_cast<std::size_t>(n));
            continue;
        }
        if (closed != nullptr) {
            *closed = n == 0 || (n < 0 && errno == ECONNRESET);
        }
        return out;
    }
}

auto count(std::string_view hay, std::string_view needle) -> std::size_t {
    std::size_t n = 0;
    for (auto pos = hay.find(needle); pos != std::string_view::npos;
         pos = hay.find(needle, pos + 1)) {
        ++n;
    }
    return n;
}

struct Server {
    proto::InstanceMetadata m = record();
    bool has_record = true;
    std::vector<std::pair<int, std::uint8_t>> hops;
    bool hops_ok = true;
    net::MetadataServer server;
    net::MetadataClock::time_point t0 = net::MetadataClock::now();

    explicit Server(net::MetadataLimits limits = {})
        : server{test_key(),
                 [this](std::uint64_t id) {
                     return net::MetadataView{.record = (has_record && id == nic) ? &m : nullptr,
                                              .network = network()};
                 },
                 limits} {
        server.set_hop_limit_setter([this](int fd, std::uint8_t h) {
            hops.emplace_back(fd, h);
            return hops_ok;
        });
    }
    auto run(std::chrono::milliseconds at = 0ms) -> void { server.run_once(t0 + at, 0ms); }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(metadata_http, *boost::unit_test::timeout(unit_timeout_seconds))

// ---- the parser ----

BOOST_AUTO_TEST_CASE(parses_a_request_head) {
    const std::string text =
        "GET /latest/meta-data/?x=1 HTTP/1.1\r\nHost: 169.254.169.254\r\n"
        "x-aws-ec2-metadata-token:  abc \r\nX-Forwarded-For: 1.2.3.4\r\n\r\nGET / HTTP/1.1\r\n";
    const auto r = parse(text);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((r->method == HttpMethod::get));
    BOOST_TEST(r->path == "/latest/meta-data/");
    BOOST_TEST(r->minor == 1U);
    BOOST_TEST(r->keep_alive);
    BOOST_TEST(r->token.value() == "abc");
    BOOST_TEST(!r->token_ttl.has_value());
    BOOST_TEST(r->forwarded_for);
    BOOST_TEST(r->head_bytes == text.find("GET /", 1));  // the next request is left

    BOOST_TEST(!parse("GET / HTTP/1.0\r\n\r\n")->keep_alive);
    BOOST_TEST(parse("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n")->keep_alive);
    BOOST_TEST(!parse("GET / HTTP/1.1\r\nConnection: foo, close\r\n\r\n")->keep_alive);
    BOOST_TEST((parse("HEAD / HTTP/1.1\r\n\r\n")->method == HttpMethod::head));
    BOOST_TEST((parse("DELETE / HTTP/1.1\r\n\r\n")->method == HttpMethod::other));
    BOOST_TEST(parse("PUT /latest/api/token HTTP/1.1\r\nContent-Length: 0\r\n\r\n").has_value());

    // Every proper prefix is incomplete.
    for (std::size_t n = 0; n < r->head_bytes; ++n) {
        BOOST_TEST_INFO(n);
        BOOST_TEST(
            (parse(std::string_view{text}.substr(0, n)).error() == RequestError::incomplete));
    }
}

BOOST_AUTO_TEST_CASE(refuses_malformed_and_oversized_heads) {
    const auto error = [](std::string_view text) { return parse(text).error(); };
    BOOST_TEST((error("GET / HTTP/1.1\n\n") == RequestError::bad_request_line));
    BOOST_TEST((error("GET / HTTP/1.1\r\nHost: x\n\r\n") == RequestError::bad_header));
    BOOST_TEST((error("GET / HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n") == RequestError::bad_header));
    BOOST_TEST((error("GET / HTTP/1.1\r\nBad Name: x\r\n\r\n") == RequestError::bad_header));
    BOOST_TEST((error("GET / HTTP/1.1\r\nX: a\x01"
                      "b\r\n\r\n") == RequestError::bad_header));
    BOOST_TEST((error("GET / HTTP/2.0\r\n\r\n") == RequestError::bad_version));
    BOOST_TEST((error("GET http://x/ HTTP/1.1\r\n\r\n") == RequestError::bad_request_line));
    BOOST_TEST((error("GET  / HTTP/1.1\r\n\r\n") == RequestError::bad_request_line));
    BOOST_TEST(
        (error("PUT / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello") == RequestError::has_body));
    BOOST_TEST(
        (error("PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n") == RequestError::has_body));
    BOOST_TEST((error("PUT / HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n") ==
                RequestError::duplicate_field));
    BOOST_TEST((error("GET / HTTP/1.1\r\nX-aws-ec2-metadata-token: a\r\n"
                      "X-AWS-EC2-METADATA-TOKEN: b\r\n\r\n") == RequestError::duplicate_field));

    // The request line: 2,048 bytes fit, one more does not.
    const auto line = [](std::size_t length) {
        return "GET /" + std::string(length - 14, 'a') + " HTTP/1.1";
    };
    BOOST_REQUIRE(line(net::max_request_line).size() == net::max_request_line);
    BOOST_TEST(parse(line(net::max_request_line) + "\r\n\r\n").has_value());
    BOOST_TEST(
        (error(line(net::max_request_line + 1) + "\r\n\r\n") == RequestError::line_too_long));
    BOOST_TEST((error(std::string(net::max_request_line + 2, 'G')) == RequestError::line_too_long));

    // Fields: 32 fit, 33 do not; 8 KiB of fields fits, more does not.
    std::string fields;
    for (int i = 0; i < 32; ++i) {
        fields += "X-" + std::to_string(i) + ": v\r\n";
    }
    BOOST_TEST(parse("GET / HTTP/1.1\r\n" + fields + "\r\n").has_value());
    BOOST_TEST((error("GET / HTTP/1.1\r\n" + fields + "X-32: v\r\n\r\n") ==
                RequestError::too_many_fields));
    const std::string big = "X: " + std::string(net::max_request_headers - 7, 'v') + "\r\n";
    BOOST_TEST(parse("GET / HTTP/1.1\r\n" + big + "\r\n").has_value());
    BOOST_TEST((error("GET / HTTP/1.1\r\nX: " + std::string(net::max_request_headers, 'v')) ==
                RequestError::headers_too_large));

    BOOST_TEST(net::status_for(RequestError::line_too_long) == 414U);
    BOOST_TEST(net::status_for(RequestError::too_many_fields) == 431U);
    BOOST_TEST(net::status_for(RequestError::bad_header) == 400U);
}

// ---- tokens ----

BOOST_AUTO_TEST_CASE(tokens_are_bound_to_nic_instance_key_and_time) {
    const auto key = test_key();
    const auto token = key.issue(nic, "i-0123456789abcdef0", 60, 1000);
    BOOST_REQUIRE(token.has_value());
    BOOST_TEST(token->size() == net::token_chars);
    BOOST_TEST(token->find_first_of("+/=") == std::string::npos);  // base64url, unpadded

    const auto fields = net::decode_token(*token);
    BOOST_REQUIRE(fields.has_value());
    BOOST_TEST(fields->version == net::token_version);
    BOOST_TEST(fields->nic_id == nic);
    BOOST_TEST(fields->expiry == 1060U);

    BOOST_TEST(key.check(*token, nic, "i-0123456789abcdef0", 1059).value() == 1060U);
    BOOST_TEST(
        (key.check(*token, nic, "i-0123456789abcdef0", 1060).error() == TokenError::expired));
    BOOST_TEST((key.check(*token, other_nic, "i-0123456789abcdef0", 1000).error() ==
                TokenError::wrong_nic));
    // The interface moved to another instance.
    BOOST_TEST(
        (key.check(*token, nic, "i-00000000000000001", 1000).error() == TokenError::bad_mac));
    // Another role's key (or this role after a restart).
    const net::TokenKey other{key_bytes(std::byte{0x43})};
    BOOST_TEST(
        (other.check(*token, nic, "i-0123456789abcdef0", 1000).error() == TokenError::bad_mac));
    // Two tokens differ by their nonce.
    BOOST_TEST(*key.issue(nic, "i-0123456789abcdef0", 60, 1000) != *token);

    // A changed MAC byte, a bad character, stray bits, a wrong length.
    auto forged = *token;
    forged[60] = forged[60] == 'A' ? 'B' : 'A';
    BOOST_TEST(
        (key.check(forged, nic, "i-0123456789abcdef0", 1000).error() == TokenError::bad_mac));
    forged = *token;
    forged[3] = '+';
    BOOST_TEST((net::decode_token(forged).error() == TokenError::bad_encoding));
    forged = *token;
    forged.back() = 'B';  // the last character carries 4 bits: 'B' sets a stray one
    BOOST_TEST((net::decode_token(forged).error() == TokenError::bad_encoding));
    BOOST_TEST((net::decode_token(token->substr(1)).error() == TokenError::bad_length));
    forged = *token;
    forged[0] = 'B';  // another version
    BOOST_TEST((net::decode_token(forged).error() == TokenError::bad_version));

    BOOST_TEST(net::TokenKey::generate().has_value());
}

// ---- answers ----

BOOST_AUTO_TEST_CASE(the_path_table) {
    Answers a;
    BOOST_TEST(a.body("/") == "latest");
    BOOST_TEST(a.body("/latest") == "dynamic\nmeta-data");  // no user data
    BOOST_TEST(a.body("/latest/meta-data") ==
               "ami-id\nami-launch-index\nhostname\ninstance-id\ninstance-type\n"
               "local-hostname\nlocal-ipv4\nmac\nnetwork/\nplacement/");
    BOOST_TEST(a.body("/2007-01-19/meta-data/instance-id") == "i-0123456789abcdef0");
    BOOST_TEST(a.body("/2021-07-15/meta-data/ami-id") == "ami-0fedcba987654321");
    BOOST_TEST(a.status("/2007-01-18/meta-data/instance-id") == 404U);
    BOOST_TEST(a.status("/1.0/meta-data/instance-id") == 404U);
    BOOST_TEST(a.body("/latest/meta-data/ami-launch-index") == "3");
    BOOST_TEST(a.body("/latest/meta-data/hostname") == "ip-10-0-0-5.internal");
    BOOST_TEST(a.body("/latest/meta-data/local-hostname") == "ip-10-0-0-5.internal");
    BOOST_TEST(a.body("/latest/meta-data/instance-type") == "m1.small");
    BOOST_TEST(a.body("/latest/meta-data/local-ipv4") == "10.0.0.5");
    BOOST_TEST(a.body("/latest/meta-data/mac") == "02:00:00:0a:bc:de");
    BOOST_TEST(a.body("/latest/meta-data/placement/") == "availability-zone\nregion");
    BOOST_TEST(a.body("/latest/meta-data/placement/availability-zone") == "zone-a");
    BOOST_TEST(a.body("/latest/meta-data/placement/region") == "region-1");
    BOOST_TEST(a.body("/latest/meta-data/network/interfaces/macs/") == "02:00:00:0a:bc:de/");
    const std::string mac = "/latest/meta-data/network/interfaces/macs/02:00:00:0a:bc:de/";
    BOOST_TEST(a.body(mac) ==
               "device-number\ninterface-id\nipv6s\nlocal-ipv4s\nmac\n"
               "subnet-ipv4-cidr-block\nvpc-id");
    BOOST_TEST(a.body(mac + "device-number") == "0");
    BOOST_TEST(a.body(mac + "interface-id") == "eni-0123456789abcdef0");
    BOOST_TEST(a.body(mac + "ipv6s") == "fd00::5");
    BOOST_TEST(a.body(mac + "local-ipv4s") == "10.0.0.5\n10.0.0.6");
    BOOST_TEST(a.body(mac + "subnet-ipv4-cidr-block") == "10.0.0.0/24");
    BOOST_TEST(a.body(mac + "vpc-id") == "vpc-0123456789abcdef0");
    BOOST_TEST(a.status("/latest/meta-data/network/interfaces/macs/02:00:00:00:00:01/mac") == 404U);
    BOOST_TEST(a.status("/latest/meta-data/iam/") == 404U);
    BOOST_TEST(a.status("/latest/meta-data/nothing") == 404U);
    BOOST_TEST(a.status("/latest/dynamic/instance-identity/signature") == 404U);

    BOOST_TEST(a.status("/latest/user-data") == 404U);
    const std::string_view script = "#!/bin/sh\necho hi\n";
    for (const char c : script) {
        a.m.user_data.push_back(static_cast<std::byte>(c));
    }
    BOOST_TEST(a.body("/latest") == "dynamic\nmeta-data\nuser-data");
    const auto user = a(get("/latest/user-data"));
    BOOST_TEST(user.body == script);
    BOOST_TEST(user.content_type == "application/octet-stream");

    const auto doc = a.body("/latest/dynamic/instance-identity/document");
    BOOST_TEST(doc.find("\"instanceId\" : \"i-0123456789abcdef0\"") != std::string::npos);
    BOOST_TEST(doc.find("\"privateIp\" : \"10.0.0.5\"") != std::string::npos);
    BOOST_TEST(doc.find("\"pendingTime\" : \"2025-11-25T16:00:00Z\"") != std::string::npos);
    BOOST_TEST(doc.find("\"region\" : \"region-1\"") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(imdsv2_rules) {
    Answers a;
    const auto issued = a(put_token("21600"));
    BOOST_TEST(issued.status == 200U);
    BOOST_TEST(issued.body.size() == net::token_chars);
    BOOST_TEST(issued.token_ttl.value() == 21600U);
    BOOST_TEST(issued.hop_limit.value() == 2U);  // the record's
    BOOST_TEST(a(put_token("0")).status == 400U);
    BOOST_TEST(a(put_token("21601")).status == 400U);
    BOOST_TEST(a(put_token("1e3")).status == 400U);
    BOOST_TEST(a(put_token("60", "X-Forwarded-For: 10.0.0.9\r\n")).status == 403U);
    BOOST_TEST(a(*parse("PUT /latest/api/token HTTP/1.1\r\n\r\n")).status == 400U);

    // Optional: no token is served, a valid one too, a bad one is not.
    const auto with = [&](std::string_view token) {
        return a(get("/latest/meta-data/instance-id",
                     "X-aws-ec2-metadata-token: " + std::string{token} + "\r\n"));
    };
    BOOST_TEST(a.status("/latest/meta-data/instance-id") == 200U);
    a.now += 100;
    const auto served = with(issued.body);
    BOOST_TEST(served.status == 200U);
    BOOST_TEST(served.token_ttl.value() == 21500U);  // what is left
    BOOST_TEST(with("bogus").status == 401U);
    a.now += 21500;
    BOOST_TEST(with(issued.body).status == 401U);  // expired

    // Required: no token is refused.
    a.m.http_tokens = proto::MetadataTokens::required;
    BOOST_TEST(a.status("/latest/meta-data/instance-id") == 401U);
    const auto fresh = a(put_token("60"));
    BOOST_TEST(with(fresh.body).status == 200U);
    BOOST_TEST(with(fresh.body).token_ttl.value() == 60U);
    BOOST_TEST(a(get("/nothing", "X-aws-ec2-metadata-token: " + fresh.body + "\r\n")).status ==
               404U);

    // Methods.
    BOOST_TEST(a(get("/latest/api/token")).status == 405U);
    BOOST_TEST(a(*parse("PUT /latest/meta-data/ HTTP/1.1\r\n\r\n")).status == 405U);
    BOOST_TEST(a(*parse("POST /latest/meta-data/ HTTP/1.1\r\n\r\n")).status == 405U);

    // Disabled, or no record: reset, never answered.
    a.m.http_endpoint = proto::MetadataEndpoint::disabled;
    BOOST_TEST(a(put_token("60")).reset);
    BOOST_TEST(net::answer(get("/"), net::MetadataView{}, a.key, a.now).reset);
}

BOOST_AUTO_TEST_CASE(renders_responses) {
    net::HttpResponse r;
    r.body = "abc";
    r.token_ttl = 60;
    BOOST_TEST(net::render(r, false) ==
               "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n"
               "X-Aws-Ec2-Metadata-Token-Ttl-Seconds: 60\r\nConnection: keep-alive\r\n\r\nabc");
    BOOST_TEST(net::render(r, true).ends_with("keep-alive\r\n\r\n"));  // HEAD: no body
    const auto e = net::render(net::error_response(RequestError::line_too_long), false);
    BOOST_TEST(e == "HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

// ---- the server ----

BOOST_AUTO_TEST_CASE(serves_keep_alive_requests_one_at_a_time) {
    Server s;
    Pair p;
    BOOST_REQUIRE(s.server.adopt(p.server, nic, s.t0));
    send_text(p.client,
              "GET /latest/meta-data/instance-id HTTP/1.1\r\n\r\n"
              "HEAD /latest/meta-data/mac HTTP/1.1\r\n\r\n"
              "PUT /latest/api/token HTTP/1.1\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\n\r\n");
    s.run();
    const auto got = drain(p.client);
    BOOST_TEST(count(got, "HTTP/1.1 200 OK") == 3U);
    BOOST_TEST(got.find("i-0123456789abcdef0") != std::string::npos);
    BOOST_TEST(got.find("02:00:00:0a:bc:de") == std::string::npos);  // HEAD
    BOOST_REQUIRE(s.hops.size() == 1U);                              // set before the token answer
    BOOST_TEST(s.hops[0].second == 2U);
    BOOST_TEST(s.server.counters().requests == 3U);
    BOOST_TEST(s.server.counters().tokens == 1U);
    BOOST_TEST(s.server.connections(nic) == 1U);

    // The hop limit cannot be set: no token is sent.
    s.hops_ok = false;
    send_text(p.client,
              "PUT /latest/api/token HTTP/1.1\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\n\r\n");
    s.run();
    bool closed = false;
    const auto refused = drain(p.client, &closed);
    BOOST_TEST(refused.starts_with("HTTP/1.1 500"));
    BOOST_TEST(closed);
    BOOST_TEST(s.server.counters().hop_limit_failures == 1U);
    BOOST_TEST(s.server.connections() == 0U);
}

BOOST_AUTO_TEST_CASE(closes_on_bad_requests_and_deadlines) {
    Server s;
    Pair bad;
    Pair slow;
    Pair idle;
    Pair closing;
    BOOST_REQUIRE(s.server.adopt(bad.server, nic, s.t0));
    BOOST_REQUIRE(s.server.adopt(slow.server, nic, s.t0));
    BOOST_REQUIRE(s.server.adopt(idle.server, nic, s.t0));
    BOOST_REQUIRE(s.server.adopt(closing.server, nic, s.t0));
    send_text(bad.client, "GET / HTTP/1.1\nHost: x\n\n");
    send_text(slow.client, "GET /latest/meta-data/ HTT");
    send_text(closing.client, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
    s.run();
    bool closed = false;
    BOOST_TEST(drain(bad.client, &closed).starts_with("HTTP/1.1 400"));
    BOOST_TEST(closed);
    BOOST_TEST(drain(closing.client, &closed).ends_with("\r\n\r\nlatest"));
    BOOST_TEST(closed);
    BOOST_TEST(s.server.connections() == 2U);

    s.run(1900ms);  // within both deadlines
    BOOST_TEST(s.server.connections() == 2U);
    s.run(2100ms);  // the partial request is too slow
    BOOST_TEST(s.server.connections() == 1U);
    (void)drain(slow.client, &closed);
    BOOST_TEST(closed);
    s.run(5100ms);  // idle too long
    BOOST_TEST(s.server.connections() == 0U);
    BOOST_TEST(s.server.counters().timeouts == 2U);
    BOOST_TEST(s.server.counters().bad_requests == 1U);
}

BOOST_AUTO_TEST_CASE(limits_connections_per_nic_and_in_all) {
    Server s{
        net::MetadataLimits{.read_deadline = 2s, .idle_deadline = 5s, .per_nic = 2, .total = 3}};
    std::vector<std::unique_ptr<Pair>> pairs;
    for (int i = 0; i < 5; ++i) {
        pairs.push_back(std::make_unique<Pair>());
    }
    BOOST_TEST(s.server.adopt(pairs[0]->server, nic, s.t0));
    BOOST_TEST(s.server.adopt(pairs[1]->server, nic, s.t0));
    BOOST_TEST(!s.server.adopt(pairs[2]->server, nic, s.t0));  // the NIC's limit
    BOOST_TEST(s.server.adopt(pairs[3]->server, other_nic, s.t0));
    BOOST_TEST(!s.server.adopt(pairs[4]->server, 0x5003, s.t0));  // the role's limit
    BOOST_TEST(s.server.counters().refused_limit == 2U);
    bool closed = false;
    (void)drain(pairs[2]->client, &closed);
    BOOST_TEST(closed);
    BOOST_TEST(s.server.connections() == 3U);
}

BOOST_AUTO_TEST_CASE(resets_disabled_endpoints_and_unknown_peers) {
    Server s;
    Pair p;
    Pair q;
    BOOST_REQUIRE(s.server.adopt(p.server, nic, s.t0));
    BOOST_REQUIRE(s.server.adopt(q.server, other_nic, s.t0));
    s.m.http_endpoint = proto::MetadataEndpoint::disabled;
    send_text(p.client, "GET / HTTP/1.1\r\n\r\n");
    send_text(q.client, "GET / HTTP/1.1\r\n\r\n");  // no record for this NIC
    s.run();
    bool closed = false;
    BOOST_TEST(drain(p.client, &closed).empty());
    BOOST_TEST(closed);
    BOOST_TEST(drain(q.client, &closed).empty());
    BOOST_TEST(closed);
    BOOST_TEST(s.server.counters().resets == 2U);

    Pair r;
    BOOST_REQUIRE(s.server.adopt(r.server, nic, s.t0));
    s.server.reset_nic(nic);
    BOOST_TEST(s.server.connections() == 0U);
    (void)drain(r.client, &closed);
    BOOST_TEST(closed);

    // Accepting: a listening socket whose peers the resolver maps.
    const int listener = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    BOOST_REQUIRE(listener >= 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const std::string name = "ak-metadata-test-" + std::to_string(::getpid());
    std::ranges::copy(name, addr.sun_path + 1);  // abstract
    const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + name.size());
    BOOST_REQUIRE(::bind(listener, reinterpret_cast<const sockaddr*>(&addr), length) == 0);
    BOOST_REQUIRE(::listen(listener, 8) == 0);
    int resolved = 0;
    s.server.listen(listener,
                    [&](const sockaddr_storage&, socklen_t) -> std::optional<std::uint64_t> {
                        return ++resolved == 1 ? std::optional{nic} : std::nullopt;
                    });
    s.m.http_endpoint = proto::MetadataEndpoint::enabled;
    const auto connect = [&] {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            throw std::system_error{errno, std::generic_category(), "socket"};
        }
        BOOST_REQUIRE(::connect(fd, reinterpret_cast<const sockaddr*>(&addr), length) == 0);
        return fd;
    };
    const int known = connect();
    const int unknown = connect();
    s.run();
    BOOST_TEST(s.server.connections(nic) == 1U);
    BOOST_TEST(s.server.counters().refused_unknown == 1U);
    send_text(known, "GET /latest/meta-data/instance-id HTTP/1.1\r\n\r\n");
    s.run();
    BOOST_TEST(drain(known).ends_with("i-0123456789abcdef0"));
    (void)drain(unknown, &closed);
    BOOST_TEST(closed);
    ::close(known);
    ::close(unknown);
}

BOOST_AUTO_TEST_CASE(sets_the_ttl_on_ip_sockets) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    BOOST_REQUIRE(fd >= 0);
    BOOST_TEST(net::set_hop_limit(fd, 1));
    int ttl = 0;
    socklen_t length = sizeof ttl;
    BOOST_REQUIRE(::getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &length) == 0);
    BOOST_TEST(ttl == 1);
    ::close(fd);
    const int v6 = ::socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (v6 >= 0) {  // a sandbox may have no IPv6
        BOOST_TEST(net::set_hop_limit(v6, 3));
        int hops = 0;
        length = sizeof hops;
        BOOST_REQUIRE(::getsockopt(v6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, &length) == 0);
        BOOST_TEST(hops == 3);
        ::close(v6);
    }
    Pair p;
    BOOST_TEST(net::set_hop_limit(p.server, 1));  // not IP: nothing to set
    ::close(p.server);
}

BOOST_AUTO_TEST_SUITE_END()
