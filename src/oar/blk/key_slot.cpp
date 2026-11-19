// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/key_slot.hpp"

#include <algorithm>
#include <utility>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <openssl/crypto.h>

namespace ak::oar::blk {

namespace {

// mlock and munlock through the raw system call, not libc. The sanitizer
// runtimes intercept mlock and turn it into a silent no-op that reports
// success, so an ASan build would hold the key in pageable memory. The
// syscall cannot be interposed, by a sanitizer or by LD_PRELOAD.
auto lock_page(void* addr, std::size_t len) noexcept -> bool {
    return ::syscall(SYS_mlock, addr, len) == 0;
}

auto unlock_page(void* addr, std::size_t len) noexcept -> void {
    static_cast<void>(::syscall(SYS_munlock, addr, len));
}

}  // namespace

auto to_string(KeySlotError e) noexcept -> const char* {
    switch (e) {
        case KeySlotError::map_failed:
            return "map_failed";
        case KeySlotError::lock_failed:
            return "lock_failed";
        case KeySlotError::advise_failed:
            return "advise_failed";
        case KeySlotError::occupied:
            return "occupied";
        case KeySlotError::empty:
            return "empty";
        case KeySlotError::rlimit_failed:
            return "rlimit_failed";
        case KeySlotError::prctl_failed:
            return "prctl_failed";
    }
    return "unknown";
}

auto KeySlot::create() -> std::expected<KeySlot, KeySlotError> {
    const long sc_page = ::sysconf(_SC_PAGESIZE);
    if (sc_page <= 0) {
        return std::unexpected{KeySlotError::map_failed};
    }
    const auto page_size = static_cast<std::size_t>(sc_page);

    void* addr =
        ::mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        return std::unexpected{KeySlotError::map_failed};
    }
    // From here the slot owns the page, so every failure path unmaps it.
    KeySlot slot{static_cast<std::byte*>(addr), page_size};

    // Advise before locking: MADV_WIPEONFORK and MADV_DONTDUMP need no
    // privilege, and a refused advice should fail before mlock charges
    // RLIMIT_MEMLOCK.
    if (::madvise(addr, page_size, MADV_DONTDUMP) != 0 ||
        ::madvise(addr, page_size, MADV_WIPEONFORK) != 0) {
        return std::unexpected{KeySlotError::advise_failed};
    }
    if (!lock_page(addr, page_size)) {
        return std::unexpected{KeySlotError::lock_failed};
    }
    return slot;
}

KeySlot::KeySlot(KeySlot&& other) noexcept
    : _page{std::exchange(other._page, nullptr)},
      _page_size{std::exchange(other._page_size, 0)},
      _holds_key{std::exchange(other._holds_key, false)} {}

auto KeySlot::operator=(KeySlot&& other) noexcept -> KeySlot& {
    if (this != &other) {
        release();
        _page = std::exchange(other._page, nullptr);
        _page_size = std::exchange(other._page_size, 0);
        _holds_key = std::exchange(other._holds_key, false);
    }
    return *this;
}

KeySlot::~KeySlot() {
    release();
}

auto KeySlot::release() noexcept -> void {
    if (_page == nullptr) {
        return;
    }
    // Wipe the whole page, not just the key bytes: cheap, and it does not
    // depend on load() having written only the first xts_key_size bytes.
    OPENSSL_cleanse(_page, _page_size);
    _holds_key = false;
    // munlock fails harmlessly if create() bailed out before mlock.
    unlock_page(_page, _page_size);
    static_cast<void>(::munmap(_page, _page_size));
    _page = nullptr;
    _page_size = 0;
}

auto KeySlot::load(XtsKey key) -> std::expected<void, KeySlotError> {
    if (_page == nullptr) {
        return std::unexpected{KeySlotError::map_failed};
    }
    if (_holds_key) {
        return std::unexpected{KeySlotError::occupied};
    }
    std::ranges::copy(key, _page);
    _holds_key = true;
    return {};
}

auto KeySlot::drop() noexcept -> void {
    if (_page != nullptr) {
        OPENSSL_cleanse(_page, xts_key_size);
    }
    _holds_key = false;
}

auto KeySlot::key() const -> std::expected<XtsKey, KeySlotError> {
    if (!_holds_key) {
        return std::unexpected{KeySlotError::empty};
    }
    return XtsKey{_page, xts_key_size};
}

auto harden_process() -> std::expected<void, KeySlotError> {
    const rlimit no_core{.rlim_cur = 0, .rlim_max = 0};
    if (::setrlimit(RLIMIT_CORE, &no_core) != 0) {
        return std::unexpected{KeySlotError::rlimit_failed};
    }
    if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return std::unexpected{KeySlotError::prctl_failed};
    }
    return {};
}

}  // namespace ak::oar::blk
