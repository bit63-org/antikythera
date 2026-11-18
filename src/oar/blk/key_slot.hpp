// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The volume key holder (.kiro/specs/oar-blk-data-plane/ Requirements 2.2
// and 2.3, design "KeySlot").
//
// A KeySlot holds at most one AES-256-XTS volume key, in a page of its own
// that is:
//   - locked in RAM (mlock), so the key never reaches swap;
//   - excluded from core dumps (MADV_DONTDUMP);
//   - wiped in a forked child (MADV_WIPEONFORK), so a helper process the
//     data plane forks never inherits the key.
// drop() wipes the key with OPENSSL_cleanse, which the optimizer may not
// elide. The data plane calls it on helm's drop_key, on function reset
// (FLR) and on detach; the destructor calls it too, so a slot that goes
// out of scope, including during process exit, leaves nothing behind.
// If the process dies without unwinding, the kernel frees the page and
// MADV_DONTDUMP keeps it out of any core file. harden_process() turns off
// core dumps for the whole process as a second line of defence.
//
// The raw key leaves the slot only as a span for XtsCipher::create, which
// copies it into OpenSSL's key schedule and keeps no copy of its own.
//
// A KeySlot is not thread-safe. Its owner, the virtio-blk function, must
// not drop the key while an I/O queue is building a cipher from it.

#include <cstddef>
#include <cstdint>
#include <expected>

#include "oar/blk/xts_cipher.hpp"

namespace ak::oar::blk {

enum class KeySlotError : std::uint8_t {
    map_failed,     // mmap of the key page failed
    lock_failed,    // mlock failed, e.g. RLIMIT_MEMLOCK too low
    advise_failed,  // MADV_DONTDUMP or MADV_WIPEONFORK was refused
    occupied,       // load() on a slot that already holds a key
    empty,          // key() on a slot that holds no key
    rlimit_failed,  // harden_process: setrlimit(RLIMIT_CORE) failed
    prctl_failed,   // harden_process: prctl(PR_SET_DUMPABLE) failed
};

[[nodiscard]] auto to_string(KeySlotError e) noexcept -> const char*;

struct KeySlotTestAccess;

class KeySlot {
public:
    // Maps, locks and advises the key page. Fails rather than holding a key
    // in memory that could be swapped or dumped.
    [[nodiscard]] static auto create() -> std::expected<KeySlot, KeySlotError>;

    KeySlot(const KeySlot&) = delete;
    auto operator=(const KeySlot&) -> KeySlot& = delete;
    // A moved-from slot owns no page: it is empty, and load() on it fails
    // with map_failed.
    KeySlot(KeySlot&& other) noexcept;
    auto operator=(KeySlot&& other) noexcept -> KeySlot&;
    // Wipes the key, then unlocks and unmaps the page.
    ~KeySlot();

    // Copies `key` into the slot. A slot holds one key: helm drops the
    // old key before it delivers a new one, so a second load is a
    // protocol error and leaves the held key untouched. The caller should
    // wipe its own copy afterwards.
    [[nodiscard]] auto load(XtsKey key) -> std::expected<void, KeySlotError>;

    // Wipes the key. Safe to call on an empty or moved-from slot.
    auto drop() noexcept -> void;

    [[nodiscard]] auto holds_key() const noexcept -> bool { return _holds_key; }

    // The held key, valid until the next drop() or load(). Hand it straight
    // to XtsCipher::create; do not copy it.
    [[nodiscard]] auto key() const -> std::expected<XtsKey, KeySlotError>;

private:
    // Unit tests read the page after drop() to check it was wiped.
    friend struct KeySlotTestAccess;

    KeySlot(std::byte* page, std::size_t page_size) noexcept : _page{page}, _page_size{page_size} {}

    auto release() noexcept -> void;

    std::byte* _page{nullptr};
    std::size_t _page_size{0};
    bool _holds_key{false};
};

// Process-wide hardening for the storage data plane: RLIMIT_CORE = 0 and
// PR_SET_DUMPABLE = 0, so no core file is written and other processes of
// the same user cannot ptrace it or read its /proc/<pid>/mem. Call once at
// start-up, before any key arrives.
[[nodiscard]] auto harden_process() -> std::expected<void, KeySlotError>;

}  // namespace ak::oar::blk
