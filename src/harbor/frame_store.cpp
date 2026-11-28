// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "harbor/frame_store.hpp"

#include <poll.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <format>
#include <utility>

namespace ak::harbor {

namespace {

constexpr auto request_timeout = std::chrono::seconds{5};
constexpr auto accept_slice = std::chrono::milliseconds{100};
constexpr std::string_view frames_prefix = "/v1/frames/";

auto is_lower_hex(char c) noexcept -> bool {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

auto sha256_hex(std::span<const std::byte> bytes) -> std::string {
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
    unsigned len = 0;
    static_cast<void>(
        EVP_Digest(bytes.data(), bytes.size(), md.data(), &len, EVP_sha256(), nullptr));
    std::string out;
    out.reserve(2U * len);
    for (unsigned i = 0; i < len; ++i) {
        out += std::format("{:02x}", md.at(i));
    }
    return out;
}

auto reason(unsigned status) -> std::string_view {
    switch (status) {
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 404:
            return "Not Found";
        case 503:
            return "Service Unavailable";
        default:
            return "Status";
    }
}

}  // namespace

auto parse_frame_request(std::span<const std::byte> head)
    -> std::expected<std::string, FrameRequestError> {
    const std::string_view text{reinterpret_cast<const char*>(head.data()), head.size()};
    const auto end = text.find("\r\n\r\n");
    if (end == std::string_view::npos) {
        return std::unexpected(text.size() >= max_frame_request_head
                                   ? FrameRequestError::too_large
                                   : FrameRequestError::incomplete);
    }
    if (end + 4 > max_frame_request_head) {
        return std::unexpected(FrameRequestError::too_large);
    }
    std::string_view rest = text.substr(0, end + 2);  // every line ends in CRLF
    const auto line_end = rest.find("\r\n");
    const auto request_line = rest.substr(0, line_end);
    rest.remove_prefix(line_end + 2);
    while (!rest.empty()) {
        const auto e = rest.find("\r\n");
        const auto line = rest.substr(0, e);
        if (line.find(':') == std::string_view::npos ||
            std::ranges::any_of(line, [](char c) { return c == '\0' || c == '\r' || c == '\n'; })) {
            return std::unexpected(FrameRequestError::bad_request);
        }
        rest.remove_prefix(e + 2);
    }

    // "GET <path> HTTP/1.1", single spaces.
    constexpr std::string_view method = "GET ";
    constexpr std::string_view version = " HTTP/1.1";
    if (!request_line.starts_with(method) || !request_line.ends_with(version)) {
        return std::unexpected(FrameRequestError::bad_request);
    }
    const auto path =
        request_line.substr(method.size(), request_line.size() - method.size() - version.size());
    if (path.empty() || path.front() != '/' ||
        std::ranges::any_of(path, [](char c) { return c <= ' ' || c > '~'; })) {
        return std::unexpected(FrameRequestError::bad_request);
    }
    if (!path.starts_with(frames_prefix)) {
        return std::unexpected(FrameRequestError::not_found);
    }
    const auto digest = path.substr(frames_prefix.size());
    if (digest.size() != frame_digest_hex_size || !std::ranges::all_of(digest, is_lower_hex)) {
        return std::unexpected(FrameRequestError::not_found);
    }
    return std::string{digest};
}

auto FrameStore::create(const tls::Config& config, const std::string& host, std::uint16_t port)
    -> std::expected<std::unique_ptr<FrameStore>, std::string> {
    if (config.role != tls::Role::server) {
        return std::unexpected("the frame store needs a server TLS configuration");
    }
    auto ctx = tls::Context::create(config);
    if (!ctx) {
        return std::unexpected(std::format("frame store TLS: {}", tls::to_string(ctx.error())));
    }
    auto listener = tls::Listener::bind(host, port);
    if (!listener) {
        return std::unexpected(std::format("frame store cannot listen on {}:{}: {}", host, port,
                                           tls::to_string(listener.error())));
    }
    return std::unique_ptr<FrameStore>{new FrameStore{std::move(*ctx), std::move(*listener)}};
}

FrameStore::FrameStore(tls::Context ctx, tls::Listener listener)
    : _ctx{std::move(ctx)},
      _listener{std::move(listener)},
      _port{_listener.port()},
      _thread{[this](const std::stop_token& stop) { run(stop); }} {}

FrameStore::~FrameStore() {
    _thread.request_stop();
    if (_thread.joinable()) {
        _thread.join();
    }
}

auto FrameStore::put(std::vector<std::byte> frame) -> std::string {
    auto hex = sha256_hex(frame);
    const std::scoped_lock lock{_mutex};
    _frames.insert_or_assign(hex, std::move(frame));
    return hex;
}

auto FrameStore::remove(std::string_view digest_hex) -> void {
    const std::scoped_lock lock{_mutex};
    if (auto it = _frames.find(digest_hex); it != _frames.end()) {
        _frames.erase(it);
    }
}

auto FrameStore::set_fault(const FrameStoreFault& fault, std::size_t count) -> void {
    const std::scoped_lock lock{_mutex};
    _fault = fault;
    _fault_count = count;
}

auto FrameStore::next_fault() -> std::optional<FrameStoreFault> {
    const std::scoped_lock lock{_mutex};
    if (_fault_count == 0) {
        return std::nullopt;
    }
    --_fault_count;
    return _fault;
}

auto FrameStore::run(const std::stop_token& stop) -> void {
    while (!stop.stop_requested()) {
        auto fd = _listener.accept_fd(tls::Clock::now() + accept_slice);
        if (fd) {
            serve(*fd);
        }
    }
}

auto FrameStore::serve(int fd) -> void {
    ++_connections;
    const auto fault = next_fault();
    if (fault && fault->drop) {
        ::close(fd);
        return;
    }
    const auto deadline = tls::Clock::now() + request_timeout;
    auto stream = tls::Stream::accept(_ctx, fd, deadline);
    if (!stream) {
        return;
    }

    std::vector<std::byte> head;
    std::array<std::byte, 1024> buf{};
    std::expected<std::string, FrameRequestError> request =
        std::unexpected(FrameRequestError::incomplete);
    while (!request && request.error() == FrameRequestError::incomplete) {
        const auto n = stream->read_some(buf);
        if (!n) {
            return;
        }
        if (*n == 0) {
            if (stream->pending()) {
                continue;
            }
            const auto left =
                std::chrono::ceil<std::chrono::milliseconds>(deadline - tls::Clock::now());
            if (left.count() <= 0) {
                return;
            }
            pollfd p{.fd = stream->fd(), .events = POLLIN, .revents = 0};
            static_cast<void>(::poll(&p, 1, static_cast<int>(left.count())));
            continue;
        }
        head.insert(head.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n));
        request = parse_frame_request(head);
    }

    unsigned status = 200;
    std::vector<std::byte> body;
    if (!request) {
        status = request.error() == FrameRequestError::not_found ? 404 : 400;
    } else {
        const std::scoped_lock lock{_mutex};
        if (auto it = _frames.find(*request); it != _frames.end()) {
            body = it->second;
        } else {
            status = 404;
        }
    }
    if (fault && fault->status != 0) {
        status = fault->status;
    }
    if (status != 200) {
        body.clear();
    }
    const auto declared = body.size();
    if (fault && fault->corrupt && !body.empty()) {
        body.back() ^= std::byte{0x01};
    }
    bool cut = false;
    if (fault && fault->cut_after && *fault->cut_after < body.size()) {
        body.resize(*fault->cut_after);
        cut = true;
    }
    const auto response_head =
        std::format("HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", status,
                    reason(status), declared);
    if (!stream->write_all(std::as_bytes(std::span{response_head}), deadline) ||
        !stream->write_all(body, deadline)) {
        return;
    }
    if (status == 200 && !cut) {
        ++_served;
    }
    stream->close();
}

}  // namespace ak::harbor
