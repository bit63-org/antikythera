// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/device_inventory.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <string_view>

namespace ak::hull {

namespace {

// Writes `value` to an existing sysfs attribute in one write(2).
auto write_attr(const std::filesystem::path& file, std::string_view value) -> bool {
    const int fd = ::open(file.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    ssize_t n = -1;
    do {
        n = ::write(fd, value.data(), value.size());
    } while (n < 0 && errno == EINTR);
    ::close(fd);
    return n == static_cast<ssize_t>(value.size());
}

}  // namespace

DeviceInventory::DeviceInventory(std::vector<InventoryEntry> entries) {
    for (auto& e : entries) {
        if (find(e.ref) == nullptr) {
            _entries.push_back(std::move(e));
        }
    }
}

auto DeviceInventory::find(const helm::mailbox::DeviceRef& ref) const noexcept
    -> const InventoryEntry* {
    const auto it = std::ranges::find(_entries, ref, &InventoryEntry::ref);
    return it == _entries.end() ? nullptr : &*it;
}

auto pci_device_path(const std::filesystem::path& sysfs, const std::string& bdf)
    -> std::filesystem::path {
    return sysfs / "bus" / "pci" / "devices" / bdf;
}

auto SysfsFunctionResetter::reset(const InventoryEntry& function) -> bool {
    if (function.bdf.empty() || function.bdf.find('/') != std::string::npos ||
        function.bdf.starts_with('.')) {
        return false;
    }
    const auto dir = pci_device_path(_sysfs, function.bdf);
    const std::string_view method = function.reset == ResetMethod::flr ? "flr" : "bus";
    // Selecting the method first means the kernel never falls back to a
    // weaker one (a PM reset that leaves state behind) when the chosen one
    // fails: the write to reset fails instead, and the release says so.
    return write_attr(dir / "reset_method", method) && write_attr(dir / "reset", "1");
}

}  // namespace ak::hull
