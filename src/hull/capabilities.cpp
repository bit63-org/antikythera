// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/capabilities.hpp"

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>

namespace ak::hull {

namespace {

constexpr std::array<int, 7> agent_caps{CAP_SYS_ADMIN, CAP_SETUID,       CAP_SETGID, CAP_CHOWN,
                                        CAP_FOWNER,    CAP_SYS_RESOURCE, CAP_KILL};

}  // namespace

auto agent_capabilities() -> std::span<const int> {
    return agent_caps;
}

auto drop_capabilities_except(std::span<const int> keep) -> std::expected<void, int> {
    auto kept = [&](int cap) { return std::ranges::find(keep, cap) != keep.end(); };

    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    std::array<__user_cap_data_struct, 2> data{};
    if (::syscall(SYS_capget, &header, data.data()) != 0) {
        return std::unexpected(errno);
    }

    if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) {
        return std::unexpected(errno);
    }
    // Dropping from the bounding set needs CAP_SETPCAP in the effective
    // set, which capset clears last. Without it (an unprivileged test run)
    // the bounding set stays, which no_new_privs below makes harmless.
    const bool can_drop_bounding = (data[0].effective & (1U << CAP_SETPCAP)) != 0;
    for (int cap = 0; can_drop_bounding && cap < 64; ++cap) {
        if (kept(cap)) {
            continue;
        }
        if (::prctl(PR_CAPBSET_READ, cap, 0, 0, 0) < 0) {
            break;  // past the kernel's last capability
        }
        if (::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
            return std::unexpected(errno);
        }
    }

    std::array<std::uint32_t, 2> mask{};
    for (const int cap : keep) {
        if (cap >= 0 && cap < 64) {
            mask[static_cast<std::size_t>(cap) / 32] |= 1U << (static_cast<unsigned>(cap) % 32);
        }
    }
    for (std::size_t i = 0; i < 2; ++i) {
        data[i].permitted &= mask[i];
        data[i].effective &= mask[i];
        data[i].inheritable = 0;
    }
    if (::syscall(SYS_capset, &header, data.data()) != 0) {
        return std::unexpected(errno);
    }
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return std::unexpected(errno);
    }
    return {};
}

}  // namespace ak::hull
