// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// A storage role's media sanitize at decommission
// (.kiro/specs/server-provisioning/ Requirement 5.3, task 5): every drive
// the role serves is sanitized with NVMe Sanitize, crypto erase where the
// controller supports it and block erase otherwise, and each drive's
// result is reported by serial, drives that could not be sanitized
// included.
//
//   nvme_sanitize    the NVMe admin sequence over any command transport:
//                    Identify Controller for SANICAP, Sanitize with the
//                    strongest action supported (a refused or failed
//                    crypto erase falls back to block erase), then the
//                    Sanitize Status log page until the operation ends
//   sanitize_device  nvme_sanitize on a device node through
//                    NVME_IOCTL_ADMIN_CMD (/dev/nvmeN or a namespace of it)
//   MediaSanitizer   one worker thread per drive, started once; answers
//                    the oar sanitize request (OarHandler::set_sanitizer)
//
// A drive the role names by serial (--drive-serial) but gives no device
// for (--drive-device) cannot be sanitized and is reported failed, so the
// controller knows to destroy it.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string_view>
#include <thread>
#include <vector>

#include <linux/nvme_ioctl.h>

#include "helm/oar_protocol.hpp"
#include "proto/report.hpp"

namespace ak::helm {

// NVMe constants (NVM Express Base Specification 2.0).
namespace nvme {
inline constexpr std::uint8_t opcode_get_log_page = 0x02;
inline constexpr std::uint8_t opcode_identify = 0x06;
inline constexpr std::uint8_t opcode_sanitize = 0x84;
inline constexpr std::uint32_t identify_controller = 1;  // CNS
inline constexpr std::size_t identify_size = 4096;
inline constexpr std::size_t sanicap_offset = 328;
inline constexpr std::uint32_t sanicap_crypto = 1U << 0;  // CES
inline constexpr std::uint32_t sanicap_block = 1U << 1;   // BES
inline constexpr std::uint32_t sanact_block = 2;
inline constexpr std::uint32_t sanact_crypto = 4;
inline constexpr std::uint8_t log_sanitize_status = 0x81;
inline constexpr std::size_t sanitize_log_size = 512;
inline constexpr std::uint16_t sstat_mask = 0x7;
inline constexpr std::uint16_t sstat_never = 0;
inline constexpr std::uint16_t sstat_done = 1;
inline constexpr std::uint16_t sstat_running = 2;
inline constexpr std::uint16_t sstat_failed = 3;
inline constexpr std::uint16_t sstat_done_no_deallocate = 4;
}  // namespace nvme

// Runs one admin command: the NVMe status (0 for success), or -1 when the
// command could not be submitted.
using NvmeAdmin = std::function<int(nvme_passthru_cmd& cmd)>;

struct NvmeSanitizeTiming {
    std::chrono::milliseconds poll{std::chrono::seconds{1}};
    // A sanitize still running after this is given up as failed.
    std::chrono::milliseconds limit{std::chrono::hours{12}};
    // Empty: std::this_thread::sleep_for.
    std::function<void(std::chrono::milliseconds)> sleep;
};

[[nodiscard]] auto nvme_sanitize(const NvmeAdmin& admin, const std::stop_token& stop,
                                 const NvmeSanitizeTiming& timing = {}) -> proto::SanitizeResult;

// Opens `device` and sanitizes it through NVME_IOCTL_ADMIN_CMD; failed if
// it does not open or is not an NVMe device.
[[nodiscard]] auto sanitize_device(const std::filesystem::path& device, const std::stop_token& stop)
    -> proto::SanitizeResult;

struct SanitizeTarget {
    proto::IdentityText serial{};
    std::filesystem::path device;  // empty: cannot be sanitized (reported failed)
    friend auto operator==(const SanitizeTarget&, const SanitizeTarget&) -> bool = default;
};

// --drive-device SERIAL:PATH (PATH absolute; SERIAL may hold colons):
// empty when `flag` is another option, false when the value is bad or
// names a serial twice, true when taken (kept in serial order).
[[nodiscard]] auto parse_sanitize_option(std::string_view flag, std::string_view value,
                                         std::vector<SanitizeTarget>& out) -> std::optional<bool>;

// The drives to sanitize: every device given, and every drive the
// identity names without one (which can only be reported failed).
[[nodiscard]] auto sanitize_targets(const oar::RoleIdentity& identity,
                                    std::vector<SanitizeTarget> devices)
    -> std::vector<SanitizeTarget>;

class MediaSanitizer {
public:
    using Run = std::function<proto::SanitizeResult(const std::filesystem::path& device,
                                                    const std::stop_token& stop)>;

    // `targets` strictly increasing by serial. An empty `run` uses
    // sanitize_device.
    explicit MediaSanitizer(std::vector<SanitizeTarget> targets, Run run = {});
    MediaSanitizer(const MediaSanitizer&) = delete;
    auto operator=(const MediaSanitizer&) -> MediaSanitizer& = delete;
    MediaSanitizer(MediaSanitizer&&) = delete;
    auto operator=(MediaSanitizer&&) -> MediaSanitizer& = delete;
    ~MediaSanitizer();

    // Starts every drive's sanitize, once; later calls change nothing.
    // Thread-safe, as is status().
    auto start() -> oar::SanitizeStatus;
    // Running until every drive has a result, then done with them all.
    [[nodiscard]] auto status() const -> oar::SanitizeStatus;

private:
    std::vector<SanitizeTarget> _targets;
    Run _run;
    mutable std::mutex _mutex;
    std::vector<std::optional<proto::SanitizeResult>> _results;
    bool _started{false};
    std::vector<std::jthread> _workers;  // last: joined before the rest goes
};

}  // namespace ak::helm
