// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/metadata_http.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <ctime>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "common/wire.hpp"

namespace ak::oar::net {

namespace {

// The token's fields before its MAC.
constexpr std::size_t token_fields_size = token_bytes - token_mac_size;  // 33

auto as_text(std::span<const std::byte> b) -> std::string_view {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

auto lower(char c) -> char {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() &&
           std::ranges::equal(a, b, [](char x, char y) { return lower(x) == lower(y); });
}

auto is_tchar(char c) -> bool {
    static constexpr std::string_view extra = "!#$%&'*+-.^_`|~";
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           extra.find(c) != std::string_view::npos;
}

auto is_token(std::string_view s) -> bool {
    return !s.empty() && std::ranges::all_of(s, is_tchar);
}

// A field value character: visible ASCII, space, tab or obs-text.
auto is_field_char(char c) -> bool {
    const auto u = static_cast<unsigned char>(c);
    return u == '\t' || (u >= 0x20 && u != 0x7F);
}

auto is_digit(char c) -> bool {
    return c >= '0' && c <= '9';
}

auto trim(std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

// The connection options a Connection field names.
auto read_connection(std::string_view value, bool& close, bool& keep_alive) -> void {
    while (!value.empty()) {
        const auto comma = value.find(',');
        const auto option = trim(value.substr(0, comma));
        if (iequals(option, "close")) {
            close = true;
        } else if (iequals(option, "keep-alive")) {
            keep_alive = true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
}

auto parse_request_line(std::string_view line, HttpRequest& out)
    -> std::expected<void, RequestError> {
    if (line.find_first_of("\r\n") != std::string_view::npos) {
        return std::unexpected{RequestError::bad_request_line};
    }
    const auto sp1 = line.find(' ');
    if (sp1 == std::string_view::npos) {
        return std::unexpected{RequestError::bad_request_line};
    }
    const auto method = line.substr(0, sp1);
    const auto rest = line.substr(sp1 + 1);
    const auto sp2 = rest.find(' ');
    if (!is_token(method) || sp2 == std::string_view::npos) {
        return std::unexpected{RequestError::bad_request_line};
    }
    const auto target = rest.substr(0, sp2);
    const auto version = rest.substr(sp2 + 1);
    const auto visible = [](char c) { return c > 0x20 && c < 0x7F; };
    if (target.empty() || target.front() != '/' || !std::ranges::all_of(target, visible)) {
        return std::unexpected{RequestError::bad_request_line};
    }
    if (version == "HTTP/1.1") {
        out.minor = 1;
    } else if (version == "HTTP/1.0") {
        out.minor = 0;
    } else if (version.starts_with("HTTP/")) {
        return std::unexpected{RequestError::bad_version};
    } else {
        return std::unexpected{RequestError::bad_request_line};
    }
    if (method == "GET") {
        out.method = HttpMethod::get;
    } else if (method == "HEAD") {
        out.method = HttpMethod::head;
    } else if (method == "PUT") {
        out.method = HttpMethod::put;
    } else {
        out.method = HttpMethod::other;
    }
    out.path = std::string{target.substr(0, target.find_first_of("?#"))};
    return {};
}

auto keep_once(std::optional<std::string>& slot, std::string_view value)
    -> std::expected<void, RequestError> {
    if (slot) {
        return std::unexpected{RequestError::duplicate_field};
    }
    slot = std::string{value};
    return {};
}

// ---- base64url ------------------------------------------------------------------

constexpr std::string_view base64url_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

auto base64url_value(char c) -> int {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
        return 63;
    }
    return -1;
}

auto base64url_encode(std::span<const std::byte> in) -> std::string {
    std::string out;
    out.reserve(((in.size() * 8) + 5) / 6);
    std::uint32_t acc = 0;
    int bits = 0;
    for (const auto b : in) {
        acc = (acc << 8U) | std::to_integer<std::uint32_t>(b);
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(base64url_alphabet[(acc >> static_cast<unsigned>(bits)) & 0x3FU]);
        }
    }
    if (bits > 0) {
        out.push_back(base64url_alphabet[(acc << static_cast<unsigned>(6 - bits)) & 0x3FU]);
    }
    return out;
}

// Exactly token_chars characters to token_bytes bytes; the last
// character's unused low bits must be zero, so each token has one spelling.
auto decode_raw(std::string_view token)
    -> std::expected<std::array<std::byte, token_bytes>, TokenError> {
    if (token.size() != token_chars) {
        return std::unexpected{TokenError::bad_length};
    }
    std::array<std::byte, token_bytes> out{};
    std::size_t n = 0;
    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : token) {
        const int v = base64url_value(c);
        if (v < 0) {
            return std::unexpected{TokenError::bad_encoding};
        }
        acc = ((acc << 6U) | static_cast<std::uint32_t>(v)) & 0xFFFFU;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n < out.size()) {
                out[n] = static_cast<std::byte>((acc >> static_cast<unsigned>(bits)) & 0xFFU);
            }
            ++n;
        }
    }
    const auto stray = acc & ((1U << static_cast<unsigned>(bits)) - 1U);
    if (n != token_bytes || stray != 0) {
        return std::unexpected{TokenError::bad_encoding};
    }
    return out;
}

auto fields_of(std::span<const std::byte, token_bytes> raw)
    -> std::expected<TokenFields, TokenError> {
    wire::Reader r{raw};
    auto version = r.u8();
    auto nic = r.be64();
    auto expiry = r.be64();
    auto nonce = r.bytes(token_nonce_size);
    auto mac = r.bytes(token_mac_size);
    if (!version || !nic || !expiry || !nonce || !mac || r.remaining() != 0) {
        return std::unexpected{TokenError::bad_length};
    }
    TokenFields out{.version = *version, .nic_id = *nic, .expiry = *expiry, .nonce = {}, .mac = {}};
    std::ranges::copy(*nonce, out.nonce.begin());
    std::ranges::copy(*mac, out.mac.begin());
    if (out.version != token_version) {
        return std::unexpected{TokenError::bad_version};
    }
    return out;
}

// ---- answers --------------------------------------------------------------------

auto reason(unsigned status) -> std::string_view {
    switch (status) {
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 414:
            return "URI Too Long";
        case 431:
            return "Request Header Fields Too Large";
        default:
            return "Internal Server Error";
    }
}

auto ipv4_text(const neighbor::Ipv4Address& a) -> std::string {
    std::array<char, INET_ADDRSTRLEN> buf{};
    ::inet_ntop(AF_INET, a.data(), buf.data(), buf.size());
    return buf.data();
}

auto ipv6_text(const Ipv6Address& a) -> std::string {
    std::array<char, INET6_ADDRSTRLEN> buf{};
    ::inet_ntop(AF_INET6, a.data(), buf.data(), buf.size());  // RFC 5952 form
    return buf.data();
}

auto mac_text(const MacAddress& m) -> std::string {
    std::string out;
    static constexpr std::string_view hex = "0123456789abcdef";
    for (std::size_t i = 0; i < m.size(); ++i) {
        if (i != 0) {
            out.push_back(':');
        }
        const auto v = std::to_integer<unsigned>(m[i]);
        out.push_back(hex[v >> 4U]);
        out.push_back(hex[v & 0xFU]);
    }
    return out;
}

auto lines(std::initializer_list<std::string_view> items) -> std::string {
    std::string out;
    for (const auto item : items) {
        if (item.empty()) {
            continue;  // an entry left out
        }
        if (!out.empty()) {
            out.push_back('\n');
        }
        out.append(item);
    }
    return out;
}

template<typename T, typename F> auto lines_of(const std::vector<T>& items, F text) -> std::string {
    std::string out;
    for (const auto& item : items) {
        if (!out.empty()) {
            out.push_back('\n');
        }
        out.append(text(item));
    }
    return out;
}

auto json_string(std::string_view s) -> std::string {
    std::string out{"\""};
    for (const char c : s) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

auto iso8601(std::uint64_t unix_seconds) -> std::string {
    // Year 9999 at most: a later time is clamped rather than misprinted.
    constexpr std::uint64_t last = 253402300799;
    const auto t = static_cast<std::time_t>(std::min(unix_seconds, last));
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    std::array<char, 32> buf{};
    const auto n = std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return {buf.data(), n};
}

// The unsigned instance identity document, in EC2's field names.
auto identity_document(const MetadataView& view) -> std::string {
    const auto& m = *view.record;
    const auto ip = view.network.ipv4.empty() ? std::string{"null"}
                                              : json_string(ipv4_text(view.network.ipv4.front()));
    std::string out = "{\n";
    out += "  \"accountId\" : " + json_string(m.account_id) + ",\n";
    out += "  \"availabilityZone\" : " + json_string(m.availability_zone) + ",\n";
    out += "  \"imageId\" : " + json_string(m.image_id) + ",\n";
    out += "  \"instanceId\" : " + json_string(m.instance_id) + ",\n";
    out += "  \"instanceType\" : " + json_string(m.instance_type) + ",\n";
    out += "  \"pendingTime\" : " + json_string(iso8601(m.pending_time)) + ",\n";
    out += "  \"privateIp\" : " + ip + ",\n";
    out += "  \"region\" : " + json_string(m.region) + ",\n";
    out += "  \"version\" : \"2017-09-30\"\n}";
    return out;
}

// "latest", or a dated version from 2007-01-19 on.
auto known_version(std::string_view v) -> bool {
    if (v == "latest") {
        return true;
    }
    if (v.size() != 10 || v[4] != '-' || v[7] != '-') {
        return false;
    }
    for (const std::size_t i : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
        if (!is_digit(v[i])) {
            return false;
        }
    }
    return v >= "2007-01-19";
}

// `path` names directory `dir` (with or without its trailing slash).
auto is_dir(std::string_view path, std::string_view dir) -> bool {
    return path == dir ||
           (path.size() == dir.size() + 1 && path.starts_with(dir) && path.back() == '/');
}

// The body for a GET of `rest` (the path after "/<version>"), or nullopt
// for 404.
auto lookup(std::string_view rest, const MetadataView& view)
    -> std::optional<std::pair<std::string, std::string_view>> {
    constexpr std::string_view text = "text/plain";
    const auto& m = *view.record;
    const auto& net = view.network;
    const auto ok = [&](std::string body) {
        return std::optional{std::pair{std::move(body), text}};
    };
    if (rest.empty() || rest == "/") {
        return ok(lines({"dynamic", "meta-data", m.user_data.empty() ? "" : "user-data"}));
    }
    if (rest == "/user-data") {
        if (m.user_data.empty()) {
            return std::nullopt;
        }
        return std::optional{std::pair{std::string{as_text(m.user_data)},
                                       std::string_view{"application/octet-stream"}}};
    }
    if (is_dir(rest, "/dynamic")) {
        return ok("instance-identity/");
    }
    if (is_dir(rest, "/dynamic/instance-identity")) {
        return ok("document");
    }
    if (rest == "/dynamic/instance-identity/document") {
        return ok(identity_document(view));
    }
    constexpr std::string_view meta = "/meta-data";
    if (!rest.starts_with(meta)) {
        return std::nullopt;
    }
    const auto key = rest.substr(meta.size());
    if (key.empty() || key == "/") {
        return ok(lines({"ami-id", "ami-launch-index", "hostname", "instance-id", "instance-type",
                         "local-hostname", net.ipv4.empty() ? "" : "local-ipv4", "mac", "network/",
                         "placement/"}));
    }
    if (key == "/ami-id") {
        return ok(m.image_id);
    }
    if (key == "/ami-launch-index") {
        return ok(std::to_string(m.launch_index));
    }
    if (key == "/hostname" || key == "/local-hostname") {
        return ok(m.local_hostname);
    }
    if (key == "/instance-id") {
        return ok(m.instance_id);
    }
    if (key == "/instance-type") {
        return ok(m.instance_type);
    }
    if (key == "/local-ipv4") {
        if (net.ipv4.empty()) {
            return std::nullopt;
        }
        return ok(ipv4_text(net.ipv4.front()));
    }
    if (key == "/mac") {
        return ok(mac_text(net.mac));
    }
    if (is_dir(key, "/placement")) {
        return ok("availability-zone\nregion");
    }
    if (key == "/placement/availability-zone") {
        return ok(m.availability_zone);
    }
    if (key == "/placement/region") {
        return ok(m.region);
    }
    if (is_dir(key, "/network")) {
        return ok("interfaces/");
    }
    if (is_dir(key, "/network/interfaces")) {
        return ok("macs/");
    }
    const auto mac = mac_text(net.mac);
    if (is_dir(key, "/network/interfaces/macs")) {
        return ok(mac + "/");
    }
    const auto prefix = "/network/interfaces/macs/" + mac;
    if (!key.starts_with(prefix)) {
        return std::nullopt;
    }
    const auto leaf = key.substr(prefix.size());
    if (leaf.empty() || leaf == "/") {
        return ok(
            lines({"device-number", "interface-id", net.ipv6.empty() ? "" : "ipv6s", "local-ipv4s",
                   "mac", net.subnet4 ? "subnet-ipv4-cidr-block" : "", "vpc-id"}));
    }
    if (leaf == "/device-number") {
        return ok(std::to_string(m.device_index));
    }
    if (leaf == "/interface-id") {
        return ok(m.interface_id);
    }
    if (leaf == "/ipv6s" && !net.ipv6.empty()) {
        return ok(lines_of(net.ipv6, ipv6_text));
    }
    if (leaf == "/local-ipv4s") {
        return ok(lines_of(net.ipv4, ipv4_text));
    }
    if (leaf == "/mac") {
        return ok(mac);
    }
    if (leaf == "/subnet-ipv4-cidr-block" && net.subnet4) {
        return ok(ipv4_text(*net.subnet4) + "/" + std::to_string(net.subnet4_length));
    }
    if (leaf == "/vpc-id") {
        return ok(m.vpc_id);
    }
    return std::nullopt;
}

auto status_only(unsigned status, bool close) -> HttpResponse {
    HttpResponse r;
    r.status = status;
    r.close = close;
    return r;
}

auto parse_ttl(const std::optional<std::string>& value) -> std::optional<std::uint32_t> {
    if (!value || value->empty() || value->size() > 5 || !std::ranges::all_of(*value, is_digit)) {
        return std::nullopt;
    }
    std::uint32_t ttl = 0;
    std::from_chars(value->data(), value->data() + value->size(), ttl);
    if (ttl < min_token_ttl || ttl > max_token_ttl) {
        return std::nullopt;
    }
    return ttl;
}

}  // namespace

// ---- requests -------------------------------------------------------------------

auto to_string(RequestError e) noexcept -> const char* {
    switch (e) {
        case RequestError::incomplete:
            return "incomplete";
        case RequestError::line_too_long:
            return "line_too_long";
        case RequestError::headers_too_large:
            return "headers_too_large";
        case RequestError::too_many_fields:
            return "too_many_fields";
        case RequestError::bad_request_line:
            return "bad_request_line";
        case RequestError::bad_version:
            return "bad_version";
        case RequestError::bad_header:
            return "bad_header";
        case RequestError::duplicate_field:
            return "duplicate_field";
        case RequestError::has_body:
            return "has_body";
    }
    return "unknown";
}

auto status_for(RequestError e) noexcept -> unsigned {
    switch (e) {
        case RequestError::incomplete:
            return 0;
        case RequestError::line_too_long:
            return 414;
        case RequestError::headers_too_large:
        case RequestError::too_many_fields:
            return 431;
        default:
            return 400;
    }
}

auto parse_request(std::span<const std::byte> bytes) -> std::expected<HttpRequest, RequestError> {
    const auto text = as_text(bytes);
    HttpRequest out;

    // The request line.
    const auto line_window = text.substr(0, max_request_line + 2);
    const auto line_end = line_window.find("\r\n");
    if (line_end == std::string_view::npos) {
        if (line_window.find('\n') != std::string_view::npos) {
            return std::unexpected{RequestError::bad_request_line};  // a bare LF
        }
        if (text.size() >= max_request_line + 2) {
            return std::unexpected{RequestError::line_too_long};
        }
        return std::unexpected{RequestError::incomplete};
    }
    if (line_end > max_request_line) {
        return std::unexpected{RequestError::line_too_long};
    }
    if (auto r = parse_request_line(text.substr(0, line_end), out); !r) {
        return std::unexpected{r.error()};
    }

    // The fields, up to the blank line.
    const std::size_t fields_start = line_end + 2;
    std::size_t pos = fields_start;
    std::size_t fields = 0;
    bool close = false;
    bool keep_alive = false;
    bool content_length = false;
    for (;;) {
        const auto end = text.find("\r\n", pos);
        const auto limit = fields_start + max_request_headers;
        if (end == std::string_view::npos) {
            if (text.substr(pos).find('\n') != std::string_view::npos) {
                return std::unexpected{RequestError::bad_header};  // a bare LF
            }
            if (text.size() >= limit) {
                return std::unexpected{RequestError::headers_too_large};
            }
            return std::unexpected{RequestError::incomplete};
        }
        if (end + 2 > limit) {
            return std::unexpected{RequestError::headers_too_large};
        }
        const auto line = text.substr(pos, end - pos);
        pos = end + 2;
        if (line.empty()) {
            break;
        }
        if (++fields > max_request_fields) {
            return std::unexpected{RequestError::too_many_fields};
        }
        const auto colon = line.find(':');
        if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) {
            return std::unexpected{RequestError::bad_header};  // folding starts with a space
        }
        const auto name = line.substr(0, colon);
        const auto raw_value = line.substr(colon + 1);
        if (!std::ranges::all_of(raw_value, is_field_char)) {
            return std::unexpected{RequestError::bad_header};
        }
        const auto value = trim(raw_value);
        if (iequals(name, "X-aws-ec2-metadata-token")) {
            if (auto r = keep_once(out.token, value); !r) {
                return std::unexpected{r.error()};
            }
        } else if (iequals(name, "X-aws-ec2-metadata-token-ttl-seconds")) {
            if (auto r = keep_once(out.token_ttl, value); !r) {
                return std::unexpected{r.error()};
            }
        } else if (iequals(name, "X-Forwarded-For")) {
            out.forwarded_for = true;
        } else if (iequals(name, "Content-Length")) {
            if (content_length) {
                return std::unexpected{RequestError::duplicate_field};
            }
            content_length = true;
            if (value.empty() || !std::ranges::all_of(value, is_digit)) {
                return std::unexpected{RequestError::bad_header};
            }
            if (!std::ranges::all_of(value, [](char c) { return c == '0'; })) {
                return std::unexpected{RequestError::has_body};
            }
        } else if (iequals(name, "Transfer-Encoding")) {
            return std::unexpected{RequestError::has_body};
        } else if (iequals(name, "Connection")) {
            read_connection(value, close, keep_alive);
        }
    }
    out.keep_alive = out.minor == 1 ? !close : (keep_alive && !close);
    out.head_bytes = pos;
    return out;
}

// ---- tokens ---------------------------------------------------------------------

auto to_string(TokenError e) noexcept -> const char* {
    switch (e) {
        case TokenError::bad_length:
            return "bad_length";
        case TokenError::bad_encoding:
            return "bad_encoding";
        case TokenError::bad_version:
            return "bad_version";
        case TokenError::wrong_nic:
            return "wrong_nic";
        case TokenError::expired:
            return "expired";
        case TokenError::bad_mac:
            return "bad_mac";
        case TokenError::rng_failed:
            return "rng_failed";
    }
    return "unknown";
}

auto decode_token(std::string_view token) -> std::expected<TokenFields, TokenError> {
    auto raw = decode_raw(token);
    if (!raw) {
        return std::unexpected{raw.error()};
    }
    return fields_of(*raw);
}

TokenKey::TokenKey(std::span<const std::byte, token_key_size> key) noexcept {
    std::ranges::copy(key, _key.begin());
}

TokenKey::TokenKey(TokenKey&& other) noexcept : _key{other._key} {
    OPENSSL_cleanse(other._key.data(), other._key.size());
}

auto TokenKey::operator=(TokenKey&& other) noexcept -> TokenKey& {
    if (this != &other) {
        _key = other._key;
        OPENSSL_cleanse(other._key.data(), other._key.size());
    }
    return *this;
}

TokenKey::~TokenKey() {
    OPENSSL_cleanse(_key.data(), _key.size());
}

auto TokenKey::generate() -> std::expected<TokenKey, TokenError> {
    TokenKey key;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(key._key.data()),
                   static_cast<int>(key._key.size())) != 1) {
        return std::unexpected{TokenError::rng_failed};
    }
    return key;
}

auto TokenKey::mac(std::span<const std::byte> fields, std::string_view instance_id,
                   std::span<std::byte, token_mac_size> out) const -> bool {
    std::vector<unsigned char> message;
    message.reserve(fields.size() + instance_id.size());
    for (const auto b : fields) {
        message.push_back(std::to_integer<unsigned char>(b));
    }
    message.insert(message.end(), instance_id.begin(), instance_id.end());
    unsigned int length = 0;
    const auto* ok = HMAC(EVP_sha256(), _key.data(), static_cast<int>(_key.size()), message.data(),
                          message.size(), reinterpret_cast<unsigned char*>(out.data()), &length);
    return ok != nullptr && length == token_mac_size;
}

auto TokenKey::issue(std::uint64_t nic_id, std::string_view instance_id, std::uint32_t ttl,
                     std::uint64_t now) const -> std::expected<std::string, TokenError> {
    std::array<std::byte, token_bytes> raw{};
    wire::SpanWriter w{raw};
    std::array<std::byte, token_nonce_size> nonce{};
    if (RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()),
                   static_cast<int>(nonce.size())) != 1) {
        return std::unexpected{TokenError::rng_failed};
    }
    if (!w.write(token_version, wire::Order::big) || !w.write(nic_id, wire::Order::big) ||
        !w.write(now + ttl, wire::Order::big) || !w.bytes(nonce)) {
        return std::unexpected{TokenError::bad_length};
    }
    const auto fields = std::span{raw}.first<token_fields_size>();
    if (!mac(fields, instance_id, std::span{raw}.last<token_mac_size>())) {
        return std::unexpected{TokenError::bad_mac};
    }
    return base64url_encode(raw);
}

auto TokenKey::check(std::string_view token, std::uint64_t nic_id, std::string_view instance_id,
                     std::uint64_t now) const -> std::expected<std::uint64_t, TokenError> {
    auto raw = decode_raw(token);
    if (!raw) {
        return std::unexpected{raw.error()};
    }
    auto fields = fields_of(*raw);
    if (!fields) {
        return std::unexpected{fields.error()};
    }
    if (fields->nic_id != nic_id) {
        return std::unexpected{TokenError::wrong_nic};
    }
    if (now >= fields->expiry) {
        return std::unexpected{TokenError::expired};
    }
    std::array<std::byte, token_mac_size> expected{};
    if (!mac(std::span{*raw}.first<token_fields_size>(), instance_id, expected) ||
        CRYPTO_memcmp(expected.data(), fields->mac.data(), expected.size()) != 0) {
        return std::unexpected{TokenError::bad_mac};
    }
    return fields->expiry;
}

// ---- answers --------------------------------------------------------------------

auto error_response(RequestError e) -> HttpResponse {
    const auto status = status_for(e);
    return status_only(status == 0 ? 400 : status, true);
}

auto answer(const HttpRequest& request, const MetadataView& view, const TokenKey& key,
            std::uint64_t now) -> HttpResponse {
    if (view.record == nullptr || view.record->http_endpoint != proto::MetadataEndpoint::enabled) {
        HttpResponse r;
        r.reset = true;
        return r;
    }
    const auto& m = *view.record;
    const bool close = !request.keep_alive;

    // "/<version><rest>"
    const std::string_view path = request.path;
    const auto slash = path.find('/', 1);
    const auto version =
        path.substr(1, slash == std::string_view::npos ? std::string_view::npos : slash - 1);
    const auto rest = slash == std::string_view::npos ? std::string_view{} : path.substr(slash);
    const bool versioned = known_version(version);
    const bool token_path = versioned && rest == "/api/token";

    if (request.method == HttpMethod::other || (request.method == HttpMethod::put) != token_path) {
        return status_only(405, close);
    }

    if (request.method == HttpMethod::put) {
        if (request.forwarded_for) {
            return status_only(403, close);  // through a proxy on the guest (Requirement 13.6)
        }
        const auto ttl = parse_ttl(request.token_ttl);
        if (!ttl) {
            return status_only(400, close);
        }
        auto token = key.issue(m.nic_id, m.instance_id, *ttl, now);
        if (!token) {
            return status_only(500, close);
        }
        HttpResponse r;
        r.body = std::move(*token);
        r.token_ttl = ttl;
        r.hop_limit = m.put_hop_limit;
        r.close = close;
        return r;
    }

    std::optional<std::uint32_t> remaining;
    if (request.token) {
        const auto expiry = key.check(*request.token, m.nic_id, m.instance_id, now);
        if (!expiry) {
            return status_only(401, close);  // even when tokens are optional (13.7)
        }
        remaining =
            static_cast<std::uint32_t>(std::min<std::uint64_t>(*expiry - now, max_token_ttl));
    } else if (m.http_tokens == proto::MetadataTokens::required) {
        return status_only(401, close);
    }

    std::optional<std::pair<std::string, std::string_view>> found;
    if (path == "/") {
        found = std::pair{std::string{"latest"}, std::string_view{"text/plain"}};
    } else if (versioned) {
        found = lookup(rest, view);
    }
    if (!found) {
        auto r = status_only(404, close);
        r.token_ttl = remaining;
        return r;
    }
    HttpResponse r;
    r.body = std::move(found->first);
    r.content_type = std::string{found->second};
    r.token_ttl = remaining;
    r.close = close;
    return r;
}

auto render(const HttpResponse& response, bool head_only) -> std::string {
    std::string out = "HTTP/1.1 " + std::to_string(response.status) + " ";
    out += reason(response.status);
    out += "\r\n";
    if (!response.body.empty()) {
        out += "Content-Type: " + response.content_type + "\r\n";
    }
    out += "Content-Length: " + std::to_string(response.body.size()) + "\r\n";
    if (response.token_ttl) {
        out +=
            "X-Aws-Ec2-Metadata-Token-Ttl-Seconds: " + std::to_string(*response.token_ttl) + "\r\n";
    }
    if (response.status == 405) {
        out += "Allow: GET, HEAD, PUT\r\n";
    }
    out += response.close ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
    out += "\r\n";
    if (!head_only) {
        out += response.body;
    }
    return out;
}

}  // namespace ak::oar::net
