// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// harbor's frame store (.kiro/specs/fleet-scale-networking/ task 12): the
// read-only, content-addressed endpoint a network role's bulk channel
// fetches announced frames from. It answers
//
//   GET /v1/frames/<64 lowercase hex digits> HTTP/1.1
//
// over mutually authenticated TLS 1.3 (ak::tls, server side) with 200 and
// the frame (Content-Length, no transfer coding), 404 for a digest it
// does not hold, and 400 for anything else, then closes the connection.
// Frames are named by their own SHA-256, so the store needs no index the
// role has to trust.
//
// Faults let a test break the channel on purpose: cut the body after N
// bytes, serve one byte flipped, answer another status, or drop the
// connection before the handshake. Each applies to the next `count`
// requests, then the store serves normally again.
//
// It serves one connection at a time on a thread of its own, which is
// all a test needs; kythira's frame store is the production one.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "tls/tls.hpp"

namespace ak::harbor {

// What the request head said, or why it was refused.
enum class FrameRequestError : std::uint8_t {
    incomplete,   // no blank line yet
    too_large,    // the head passed max_frame_request_head
    bad_request,  // not "GET /v1/frames/<hex> HTTP/1.1"
    not_found,    // a well-formed path outside /v1/frames/
};
inline constexpr std::size_t max_frame_request_head = 8U * 1024U;
inline constexpr std::size_t frame_digest_hex_size = 64;

// The digest a request head names: 64 lowercase hex digits. Header lines
// are skipped (each must hold a colon); the head ends at the first blank
// line, and bytes after it are ignored.
[[nodiscard]] auto parse_frame_request(std::span<const std::byte> head)
    -> std::expected<std::string, FrameRequestError>;

struct FrameStoreFault {
    std::optional<std::size_t> cut_after;  // close after this many body bytes
    bool corrupt{false};                   // flip the body's last byte
    unsigned status{0};                    // answer this status instead (0: no)
    bool drop{false};                      // close before the TLS handshake
};

class FrameStore {
public:
    // Listens on host:port (0 picks a port) with a server configuration.
    [[nodiscard]] static auto create(const tls::Config& config, const std::string& host,
                                     std::uint16_t port)
        -> std::expected<std::unique_ptr<FrameStore>, std::string>;
    FrameStore(const FrameStore&) = delete;
    auto operator=(const FrameStore&) -> FrameStore& = delete;
    FrameStore(FrameStore&&) = delete;
    auto operator=(FrameStore&&) -> FrameStore& = delete;
    ~FrameStore();

    // Holds `frame`; returns its digest as lowercase hex.
    auto put(std::vector<std::byte> frame) -> std::string;
    auto remove(std::string_view digest_hex) -> void;
    // Applies `fault` to the next `count` requests (0 clears it).
    auto set_fault(const FrameStoreFault& fault, std::size_t count) -> void;

    [[nodiscard]] auto port() const noexcept -> std::uint16_t { return _port; }
    // Connections accepted, and frames served whole.
    [[nodiscard]] auto connections() const noexcept -> std::uint64_t { return _connections; }
    [[nodiscard]] auto served() const noexcept -> std::uint64_t { return _served; }

private:
    FrameStore(tls::Context ctx, tls::Listener listener);
    auto run(const std::stop_token& stop) -> void;
    auto serve(int fd) -> void;
    // The fault for this connection, if one is still armed.
    auto next_fault() -> std::optional<FrameStoreFault>;

    tls::Context _ctx;
    tls::Listener _listener;
    std::uint16_t _port{0};
    std::mutex _mutex;
    std::map<std::string, std::vector<std::byte>, std::less<>> _frames;  // guarded by _mutex
    FrameStoreFault _fault;                                              // guarded by _mutex
    std::size_t _fault_count{0};                                         // guarded by _mutex
    std::atomic<std::uint64_t> _connections{0};
    std::atomic<std::uint64_t> _served{0};
    std::jthread _thread;  // last: started once the rest exists
};

}  // namespace ak::harbor
