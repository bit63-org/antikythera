// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/helm_config.hpp"

#include <charconv>
#include <cstddef>
#include <limits>
#include <set>
#include <system_error>

#include "helm/mctp.hpp"
#include "helm/sealed_store.hpp"

namespace ak::helm {

namespace {

constexpr int hex_base = 16;
constexpr int dec_base = 10;
constexpr std::size_t slot_fixed_words = 7;  // slot N SOCKET ADDR PEER EID PEER_EID

auto split(std::string_view line) -> std::vector<std::string_view> {
    if (const auto hash = line.find('#'); hash != std::string_view::npos) {
        line = line.substr(0, hash);
    }
    std::vector<std::string_view> words;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t' || line[i] == '\r')) {
            ++i;
        }
        const auto start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t' && line[i] != '\r') {
            ++i;
        }
        if (i > start) {
            words.push_back(line.substr(start, i - start));
        }
    }
    return words;
}

auto parse_u64(std::string_view s) -> std::optional<std::uint64_t> {
    int base = dec_base;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
        base = hex_base;
    }
    if (s.empty()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v, base);
    if (ec != std::errc{} || end != s.data() + s.size()) {
        return std::nullopt;
    }
    return v;
}

template<typename T> auto parse_uint(std::string_view s, T max) -> std::optional<T> {
    const auto v = parse_u64(s);
    if (!v || *v > max) {
        return std::nullopt;
    }
    return static_cast<T>(*v);
}

auto parse_endpoint(std::string_view s) -> std::optional<std::pair<std::string, std::uint16_t>> {
    std::string_view host;
    std::string_view port;
    if (s.starts_with('[')) {
        const auto close = s.find("]:");
        if (close == std::string_view::npos) {
            return std::nullopt;
        }
        host = s.substr(1, close - 1);
        port = s.substr(close + 2);
    } else {
        const auto colon = s.find(':');
        if (colon == std::string_view::npos || s.find(':', colon + 1) != std::string_view::npos) {
            return std::nullopt;
        }
        host = s.substr(0, colon);
        port = s.substr(colon + 1);
    }
    const auto p = parse_uint<std::uint16_t>(port, std::numeric_limits<std::uint16_t>::max());
    if (host.empty() || !p || *p == 0) {
        return std::nullopt;
    }
    return std::pair{std::string{host}, *p};
}

auto valid_eid(std::uint8_t eid) -> bool {
    return eid >= mctp::first_assignable_eid && eid != mctp::broadcast_eid;
}

class Parser {
public:
    auto line(std::size_t number, std::string_view text) -> std::expected<void, std::string> {
        _number = number;
        const auto w = split(text);
        if (w.empty()) {
            return {};
        }
        const auto name = w[0];
        if (name == "slot") {
            return slot(w);
        }
        if (name == "host") {
            if (w.size() < 2) {
                return fail("host needs ARGV");
            }
            if (!once(name)) {
                return fail("duplicate host");
            }
            for (std::size_t i = 1; i < w.size(); ++i) {
                _config.host_argv.emplace_back(w[i]);
            }
            return {};
        }
        if (w.size() != 2) {
            return fail(std::string{name} + " takes one value");
        }
        if (!once(name)) {
            return fail("duplicate " + std::string{name});
        }
        return single(name, w[1]);
    }

    auto finish() -> std::expected<HelmConfig, std::string> {
        for (const auto* required :
             {"server-id", "controller", "ca", "cert", "key", "audit-log", "master-key"}) {
            if (!_seen.contains(required)) {
                return std::unexpected(std::string{"missing "} + required);
            }
        }
        if (_config.slots.empty()) {
            return std::unexpected("missing slot");
        }
        if (_config.store.has_value() != _seen.contains("store-anchor")) {
            return std::unexpected("store and store-anchor go together");
        }
        if (!_config.store && _seen.contains("store-size")) {
            return std::unexpected("store-size without store");
        }
        if (_config.controller_name.empty()) {
            _config.controller_name = _config.controller_host;
        }
        return std::move(_config);
    }

private:
    [[nodiscard]] auto fail(const std::string& what) const -> std::unexpected<std::string> {
        return std::unexpected("line " + std::to_string(_number) + ": " + what);
    }

    auto once(std::string_view name) -> bool { return _seen.emplace(name).second; }

    auto millis(std::string_view value, std::optional<std::chrono::milliseconds>& out)
        -> std::expected<void, std::string> {
        const auto v = parse_uint<std::uint32_t>(value, std::numeric_limits<std::uint32_t>::max());
        if (!v || *v == 0) {
            return fail("bad milliseconds '" + std::string{value} + "'");
        }
        out = std::chrono::milliseconds{*v};
        return {};
    }

    auto single(std::string_view name, std::string_view value) -> std::expected<void, std::string> {
        if (name == "server-id") {
            const auto v = parse_u64(value);
            if (!v || *v == 0) {
                return fail("bad server-id '" + std::string{value} + "'");
            }
            _config.server_id = *v;
        } else if (name == "controller") {
            auto ep = parse_endpoint(value);
            if (!ep) {
                return fail("controller must be HOST:PORT, got '" + std::string{value} + "'");
            }
            _config.controller_host = std::move(ep->first);
            _config.controller_port = ep->second;
        } else if (name == "controller-name") {
            _config.controller_name = value;
        } else if (name == "ca") {
            _config.ca = value;
        } else if (name == "cert") {
            _config.cert = value;
        } else if (name == "key") {
            _config.key = value;
        } else if (name == "audit-log") {
            _config.audit_log = value;
        } else if (name == "master-key") {
            if (value != "ephemeral") {
                _config.master_key = std::filesystem::path{value};
            }
        } else if (name == "store") {
            _config.store = std::filesystem::path{value};
        } else if (name == "store-size") {
            const auto v = parse_u64(value);
            if (!v || *v < min_store_size || *v % store_page_size != 0) {
                return fail("store-size must be a multiple of 4096, at least " +
                            std::to_string(min_store_size));
            }
            _config.store_size = *v;
        } else if (name == "store-anchor") {
            if (value != "ephemeral") {
                _config.store_anchor = std::filesystem::path{value};
            }
        } else if (name == "controller-keys") {
            _config.controller_keys = value;
        } else if (name == "power-on-policy") {
            if (value != "apply" && value != "skip") {
                return fail("power-on-policy must be apply or skip");
            }
            _config.apply_power_policy = value == "apply";
        } else if (name == "power-marker") {
            if (!value.starts_with('/')) {
                return fail("power-marker must be an absolute path");
            }
            _config.power_marker = value;
        } else if (name == "key-epochs") {
            _config.key_epochs = std::filesystem::path{value};
        } else if (name == "command-timeout-ms") {
            return millis(value, _config.command_timeout);
        } else if (name == "release-timeout-ms") {
            return millis(value, _config.release_timeout);
        } else if (name == "clean-timeout-ms") {
            return millis(value, _config.clean_timeout);
        } else if (name == "link-timeout-ms") {
            return millis(value, _config.link_timeout);
        } else if (name == "sideband-timeout-ms") {
            return millis(value, _config.sideband_timeout);
        } else if (name == "check-interval-ms") {
            return millis(value, _config.check_interval);
        } else {
            _seen.erase(std::string{name});
            return fail("unknown directive '" + std::string{name} + "'");
        }
        return {};
    }

    auto slot(const std::vector<std::string_view>& w) -> std::expected<void, std::string> {
        if (w.size() <= slot_fixed_words) {
            return fail("slot needs N SOCKET ADDR PEER_ADDR EID PEER_EID ARGV...");
        }
        const auto n = parse_uint<SlotNumber>(w[1], std::numeric_limits<SlotNumber>::max());
        if (!n) {
            return fail("bad slot number '" + std::string{w[1]} + "'");
        }
        if (_config.slots.contains(*n)) {
            return fail("duplicate slot " + std::to_string(*n));
        }
        const auto addr = parse_uint<std::uint8_t>(w[3], mctp::max_smbus_address);
        const auto peer_addr = parse_uint<std::uint8_t>(w[4], mctp::max_smbus_address);
        if (!addr || !peer_addr || *addr == *peer_addr) {
            return fail("slot bus addresses must be distinct 7-bit numbers");
        }
        const auto eid = parse_uint<std::uint8_t>(w[5], std::numeric_limits<std::uint8_t>::max());
        const auto peer_eid =
            parse_uint<std::uint8_t>(w[6], std::numeric_limits<std::uint8_t>::max());
        if (!eid || !peer_eid || !valid_eid(*eid) || !valid_eid(*peer_eid) || *eid == *peer_eid) {
            return fail("slot EIDs must be distinct, assignable (8-254)");
        }
        if (!w[slot_fixed_words].starts_with('/')) {
            return fail("slot ARGV[0] must be an absolute path");
        }
        SlotEntry entry{.address = {.local_addr = *addr,
                                    .peer_addr = *peer_addr,
                                    .local_eid = *eid,
                                    .peer_eid = *peer_eid},
                        .process = {.argv = {}, .ready_path = std::filesystem::path{w[2]}}};
        for (std::size_t i = slot_fixed_words; i < w.size(); ++i) {
            entry.process.argv.emplace_back(w[i]);
        }
        _config.slots.emplace(*n, std::move(entry));
        return {};
    }

    HelmConfig _config;
    std::set<std::string, std::less<>> _seen;
    std::size_t _number{0};
};

}  // namespace

auto parse_helm_config(std::string_view text) -> std::expected<HelmConfig, std::string> {
    Parser parser;
    std::size_t number = 0;
    while (!text.empty()) {
        ++number;
        const auto nl = text.find('\n');
        const auto line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        if (auto ok = parser.line(number, line); !ok) {
            return std::unexpected(ok.error());
        }
    }
    return parser.finish();
}

}  // namespace ak::helm
