// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The agent's client for Cloud Hypervisor's REST API
// (.kiro/specs/hull-host-agent/ tasks 8 and 9, Requirements 6 and 7;
// design.md "VmSupervisor").
//
// Each VMM listens on a UNIX socket inside its jail's run directory. The
// agent sends one HTTP/1.1 request per connection, the way ch-remote does,
// and reads one reply. The VMM is the agent's least trusted peer -- it
// runs guest code and may be compromised by it -- so its replies go
// through a strict parser (parse_reply) and a strict JSON reader
// (json.hpp), both fuzzed (fuzz/fuzz_vmm_reply.cpp), and every exchange
// has a deadline so a VMM that stops answering cannot stall the agent's
// mailbox loop.
//
// Only the calls the agent needs exist:
//   vm.create        PUT the VM's configuration (no devices, not booted)
//   vm.boot          PUT
//   vm.add-device    PUT {"id","path"}: cold-plug before boot, hot-plug after
//   vm.remove-device PUT {"id"}: before boot drops it from the configuration;
//                    after boot asks the guest to eject (ACPI) and returns
//   vm.info          GET: the state and the devices still configured
//   vmm.shutdown     PUT: the VMM exits

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ak::hull {

enum class VmmApiError : std::uint8_t {
    connect_failed,  // no socket, or nothing listening yet
    io_failed,       // send or receive failed
    timed_out,       // the deadline passed
    bad_reply,       // the reply is not well-formed HTTP/1.1 (see parse_reply)
    refused,         // a well-formed reply with a status other than 200/204
    bad_body,        // the reply's JSON is malformed or lacks what was asked for
};

[[nodiscard]] auto to_string(VmmApiError e) noexcept -> const char*;

struct VmmApiFailure {
    VmmApiError error{VmmApiError::io_failed};
    unsigned http_status{0};  // for refused
    int sys_errno{0};         // for connect_failed and io_failed
};

// What vm.info says, reduced to what the agent acts on.
enum class VmmState : std::uint8_t {
    created,  // configured, not booted
    running,
    paused,
    shutdown,  // the guest powered off, or vm.shutdown
    other,     // any state this agent does not know
};

struct VmmInfo {
    VmmState state{VmmState::other};
    std::vector<std::string> device_ids;  // config.devices[].id, in order
    friend auto operator==(const VmmInfo&, const VmmInfo&) -> bool = default;
};

class VmmApi {
public:
    VmmApi() = default;
    VmmApi(const VmmApi&) = delete;
    auto operator=(const VmmApi&) -> VmmApi& = delete;
    VmmApi(VmmApi&&) = delete;
    auto operator=(VmmApi&&) -> VmmApi& = delete;
    virtual ~VmmApi() = default;

    using Result = std::expected<void, VmmApiFailure>;

    [[nodiscard]] virtual auto create(std::string_view config_json) -> Result = 0;
    [[nodiscard]] virtual auto boot() -> Result = 0;
    [[nodiscard]] virtual auto add_device(std::string_view id, const std::filesystem::path& path)
        -> Result = 0;
    [[nodiscard]] virtual auto remove_device(std::string_view id) -> Result = 0;
    [[nodiscard]] virtual auto info() -> std::expected<VmmInfo, VmmApiFailure> = 0;
    [[nodiscard]] virtual auto shutdown_vmm() -> Result = 0;
};

// --- Wire helpers, public for tests and the fuzzer ---------------------------

inline constexpr std::size_t max_reply_head = 8U * 1024U;
inline constexpr std::size_t max_reply_body = 256U * 1024U;

struct HttpReply {
    unsigned status{0};
    std::string body;
};

enum class ReplyParse : std::uint8_t {
    complete,
    incomplete,  // read more
};

// Parses a complete reply held in `bytes`:
//   - "HTTP/1.1 NNN reason" or "HTTP/1.0 NNN reason", CRLF line endings,
//     no bare LF, no obsolete folding, header names are tokens;
//   - Content-Length is decimal digits, at most once, at most
//     max_reply_body; without one the reply has no body (as ch-remote
//     reads it); Transfer-Encoding of any kind is refused;
//   - nothing may follow the body.
// Returns incomplete while the head or body is still short and
// `peer_closed` is false; with `peer_closed` true a short reply is
// bad_reply.
[[nodiscard]] auto parse_reply(std::span<const std::byte> bytes, bool peer_closed, HttpReply& out)
    -> std::expected<ReplyParse, VmmApiFailure>;

// The request bytes for `method` on /api/v1/<endpoint>, with `body` as
// application/json when non-empty.
[[nodiscard]] auto format_request(std::string_view method, std::string_view endpoint,
                                  std::string_view body) -> std::string;

// vm.info's reply body: "state" and "config.devices[].id". A missing or
// null devices list is an empty one; a device without a string id, or two
// with the same id, is bad_body.
[[nodiscard]] auto parse_vm_info(std::string_view body) -> std::expected<VmmInfo, VmmApiFailure>;

// --- The real client -----------------------------------------------------------

class ChApiClient final : public VmmApi {
public:
    ChApiClient(std::filesystem::path socket, std::chrono::milliseconds timeout)
        : _socket{std::move(socket)}, _timeout{timeout} {}

    [[nodiscard]] auto create(std::string_view config_json) -> Result override;
    [[nodiscard]] auto boot() -> Result override;
    [[nodiscard]] auto add_device(std::string_view id, const std::filesystem::path& path)
        -> Result override;
    [[nodiscard]] auto remove_device(std::string_view id) -> Result override;
    [[nodiscard]] auto info() -> std::expected<VmmInfo, VmmApiFailure> override;
    [[nodiscard]] auto shutdown_vmm() -> Result override;
    // vmm.ping: the VMM's API is up (a VM need not exist yet).
    [[nodiscard]] auto ping() -> Result;

    // One request and its reply; any 2xx other than 200/204 counts as refused.
    [[nodiscard]] auto call(std::string_view method, std::string_view endpoint,
                            std::string_view body) -> std::expected<HttpReply, VmmApiFailure>;

private:
    std::filesystem::path _socket;
    std::chrono::milliseconds _timeout;
};

}  // namespace ak::hull
