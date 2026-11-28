// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/media_sanitize.hpp"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>

namespace ak::helm {

namespace {

auto le16_at(std::span<const std::byte> b, std::size_t at) -> std::uint16_t {
    return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(b[at]) |
                                      (std::to_integer<std::uint16_t>(b[at + 1]) << 8U));
}

auto le32_at(std::span<const std::byte> b, std::size_t at) -> std::uint32_t {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        v |= std::to_integer<std::uint32_t>(b[at + i]) << (8U * i);
    }
    return v;
}

auto data_command(std::uint8_t opcode, std::span<std::byte> buffer) -> nvme_passthru_cmd {
    nvme_passthru_cmd cmd{};
    cmd.opcode = opcode;
    cmd.addr = reinterpret_cast<std::uintptr_t>(buffer.data());
    cmd.data_len = static_cast<std::uint32_t>(buffer.size());
    return cmd;
}

auto sanicap(const NvmeAdmin& admin) -> std::optional<std::uint32_t> {
    std::array<std::byte, nvme::identify_size> id{};
    auto cmd = data_command(nvme::opcode_identify, id);
    cmd.cdw10 = nvme::identify_controller;
    if (admin(cmd) != 0) {
        return std::nullopt;
    }
    return le32_at(id, nvme::sanicap_offset);
}

auto sanitize_status(const NvmeAdmin& admin) -> std::optional<std::uint16_t> {
    std::array<std::byte, nvme::sanitize_log_size> log{};
    auto cmd = data_command(nvme::opcode_get_log_page, log);
    cmd.nsid = 0xFFFF'FFFFU;
    constexpr std::uint32_t numd = (nvme::sanitize_log_size / 4) - 1;
    cmd.cdw10 = nvme::log_sanitize_status | (numd << 16U);
    if (admin(cmd) != 0) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(le16_at(log, 2) & nvme::sstat_mask);
}

// One sanitize action, issued and waited for; true if it completed.
auto run_action(const NvmeAdmin& admin, std::uint32_t sanact, const std::stop_token& stop,
                const NvmeSanitizeTiming& timing) -> bool {
    nvme_passthru_cmd cmd{};
    cmd.opcode = nvme::opcode_sanitize;
    cmd.cdw10 = sanact;
    if (admin(cmd) != 0) {
        return false;
    }
    const auto sleep = timing.sleep ? timing.sleep : [](std::chrono::milliseconds d) {
        std::this_thread::sleep_for(d);
    };
    // A controller may not show the new operation at once: "never
    // sanitized" right after the command is waited out like "running".
    for (std::chrono::milliseconds waited{0}; waited < timing.limit && !stop.stop_requested();
         waited += timing.poll) {
        const auto st = sanitize_status(admin);
        if (!st) {
            return false;
        }
        if (*st == nvme::sstat_done || *st == nvme::sstat_done_no_deallocate) {
            return true;
        }
        if (*st == nvme::sstat_failed) {
            return false;
        }
        sleep(timing.poll);
    }
    return false;
}

}  // namespace

auto nvme_sanitize(const NvmeAdmin& admin, const std::stop_token& stop,
                   const NvmeSanitizeTiming& timing) -> proto::SanitizeResult {
    const auto caps = sanicap(admin);
    if (!caps) {
        return proto::SanitizeResult::failed;
    }
    if ((*caps & nvme::sanicap_crypto) != 0 &&
        run_action(admin, nvme::sanact_crypto, stop, timing)) {
        return proto::SanitizeResult::sanitized_crypto;
    }
    if ((*caps & nvme::sanicap_block) != 0 && !stop.stop_requested() &&
        run_action(admin, nvme::sanact_block, stop, timing)) {
        return proto::SanitizeResult::sanitized_block;
    }
    return proto::SanitizeResult::failed;
}

auto sanitize_device(const std::filesystem::path& device, const std::stop_token& stop)
    -> proto::SanitizeResult {
    const int fd = ::open(device.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return proto::SanitizeResult::failed;
    }
    const auto result = nvme_sanitize(
        [fd](nvme_passthru_cmd& cmd) {
            // The ioctl returns the NVMe status, or -1 with errno set.
            const int r = ::ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
            return r < 0 ? -1 : r;
        },
        stop);
    (void)::close(fd);
    return result;
}

auto parse_sanitize_option(std::string_view flag, std::string_view value,
                           std::vector<SanitizeTarget>& out) -> std::optional<bool> {
    if (flag != "--drive-device") {
        return std::nullopt;
    }
    const auto split = value.find(":/");
    if (split == std::string_view::npos || split == 0 || split > proto::identity_text_size) {
        return false;
    }
    SanitizeTarget t{.serial = proto::identity_text(value.substr(0, split)),
                     .device = std::filesystem::path{value.substr(split + 1)}};
    if (!proto::detail::valid_text(t.serial)) {
        return false;
    }
    const auto at = std::ranges::lower_bound(out, t.serial, {}, &SanitizeTarget::serial);
    if ((at != out.end() && at->serial == t.serial) || out.size() >= oar::max_role_drives) {
        return false;
    }
    out.insert(at, std::move(t));
    return true;
}

auto sanitize_targets(const oar::RoleIdentity& identity, std::vector<SanitizeTarget> devices)
    -> std::vector<SanitizeTarget> {
    for (const auto& d : identity.drives) {
        const auto at = std::ranges::lower_bound(devices, d.serial, {}, &SanitizeTarget::serial);
        if ((at == devices.end() || at->serial != d.serial) &&
            devices.size() < oar::max_role_drives) {
            devices.insert(at, SanitizeTarget{.serial = d.serial, .device = {}});
        }
    }
    return devices;
}

MediaSanitizer::MediaSanitizer(std::vector<SanitizeTarget> targets, Run run)
    : _targets{std::move(targets)},
      _run{run ? std::move(run) : Run{sanitize_device}},
      _results(_targets.size()) {}

MediaSanitizer::~MediaSanitizer() {
    for (auto& w : _workers) {
        w.request_stop();
    }
}

auto MediaSanitizer::start() -> oar::SanitizeStatus {
    {
        const std::scoped_lock lock{_mutex};
        if (!_started) {
            _started = true;
            for (std::size_t i = 0; i < _targets.size(); ++i) {
                if (_targets[i].device.empty()) {
                    _results[i] = proto::SanitizeResult::failed;
                    continue;
                }
                _workers.emplace_back([this, i](const std::stop_token& stop) {
                    const auto r = _run(_targets[i].device, stop);
                    const std::scoped_lock done{_mutex};
                    _results[i] = r;
                });
            }
        }
    }
    return status();
}

auto MediaSanitizer::status() const -> oar::SanitizeStatus {
    const std::scoped_lock lock{_mutex};
    oar::SanitizeStatus st{.state = oar::SanitizeState::running, .drives = {}};
    if (!_started || std::ranges::any_of(_results, [](const auto& r) { return !r.has_value(); })) {
        return st;
    }
    st.state = oar::SanitizeState::done;
    for (std::size_t i = 0; i < _targets.size(); ++i) {
        st.drives.push_back({.serial = _targets[i].serial, .result = *_results[i]});
    }
    return st;
}

}  // namespace ak::helm
