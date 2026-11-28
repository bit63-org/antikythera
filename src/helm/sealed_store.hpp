// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// helm's sealed store (.kiro/specs/cold-start/ Requirement 1, design
// "Sealed store layout"): the few named objects a server must remember
// across power loss (LKG images, the standing set, the power-on policy, the
// time floor, the last command sequence), kept in a flash partition,
// encrypted and authenticated under a key only the secure element can
// derive, and protected against rollback by its monotonic counter.
//
// Partition layout:
//   [0, 4 KiB)      superblock slot 0
//   [4 KiB, 8 KiB)  superblock slot 1
//   [8 KiB, end)    two equal halves of 4 KiB pages; one is active
//
// Superblock (little-endian, 96 bytes at the start of its slot):
//   magic u32 'AKSB' | format u16 (1) | active_half u8 | reserved u8
//   store_version u64 | half_generation u64 | tail u64
//   chain [32] | mac [32] HMAC-SHA256(superblock key, every byte before it)
//
// Records, appended back to back in the active half from its start to
// `tail`:
//   magic u32 'AKSO' | name_len u8 | reserved u8 | flags u16 (bit 0: removed)
//   version u64 | ciphertext_len u32 | reserved u32 | nonce [12] | reserved u32
//   name [name_len] | ciphertext [ciphertext_len] | tag [16]
//
// Each record is AES-256-GCM under the object key with AAD = the record's
// header and name, the half generation and the record's offset, so the
// name and version are authenticated (Requirement 1.2) and a record moved
// to another place or half fails. `chain` is SHA-256 chained over every
// record up to `tail` from a seed of the half generation, so the
// superblock also pins exactly which records exist: one cannot be dropped,
// reordered or replaced by an older genuine record.
//
// Writes are atomic (Requirement 1.4): commit() appends its records past
// `tail`, syncs, then writes the next superblock (store_version + 1) into
// the other slot and syncs. Until that superblock lands, open() finds the
// previous one and sees none of the new records. Only after it does the
// store advance the secure element's store_version counter.
//
// Rollback (Requirement 1.5): open() takes the valid superblock with the
// highest version. A version below the counter means the partition was
// restored from an older copy (or its superblocks destroyed): the store
// still opens, reports rolled_back(), and helm discards the standing set
// and power-on policy and waits for the controller. A version one above
// the counter is a commit whose counter update the power cut; open()
// finishes it.
//
// Faults (Requirement 1.6): if the chain does not match, the store falls
// back to checking each object's newest record alone, discards the ones
// that fail, reports them in faults(), and sets degraded(), which helm
// treats like a rollback for its signed records. A record that fails to
// open on get() is discarded and counted the same way.
//
// Garbage collection: when a commit does not fit, every live object is
// re-sealed into the other half (half_generation + 1) together with the
// commit's writes, and one superblock switches halves. Power lost during
// the copy leaves the old half and superblock in force.
//
// Erase (Requirement 1.7): erase() destroys the store key in the secure
// element and overwrites both superblocks.
//
// Not thread-safe: helm's daemon owns it on one thread.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "helm/flash.hpp"
#include "helm/scoped_key.hpp"
#include "helm/store_anchor.hpp"

namespace ak::helm {

inline constexpr std::size_t store_page_size = 4096;
inline constexpr std::size_t store_superblock_size = 96;
inline constexpr std::size_t store_record_header_size = 40;
inline constexpr std::size_t store_tag_size = 16;
inline constexpr std::size_t max_store_name_size = 64;
// The smallest partition: two superblock slots and two one-page halves.
inline constexpr std::uint64_t min_store_size = 4 * store_page_size;

enum class StoreError : std::uint8_t {
    flash,                  // the partition failed (flash_error() says how)
    anchor,                 // the secure element failed (anchor_error() says how)
    too_small,              // the partition is below min_store_size
    bad_name,               // an object name is empty, too long, or not [a-z0-9._-]
    no_space,               // the live objects and the write do not fit in one half
    authentication_failed,  // a record failed to open; it was discarded
    crypto,                 // OpenSSL failed outside authentication
    closed,                 // erase() ran, or an earlier commit lost the flash
};

[[nodiscard]] auto to_string(StoreError e) noexcept -> const char*;

// One write of a commit: `data` replaces the object, nullopt removes it.
struct StoreWrite {
    std::string name;
    std::optional<std::vector<std::byte>> data;
};

class SealedStore {
public:
    // Opens the store on `flash`, formatting an empty one if the partition
    // holds no valid superblock. Neither `flash` nor `anchor` is owned;
    // both must outlive the store.
    [[nodiscard]] static auto open(Flash& flash, StoreAnchor& anchor)
        -> std::expected<SealedStore, StoreError>;

    // The newest contents of `name`, or nullopt if it does not exist.
    [[nodiscard]] auto get(std::string_view name)
        -> std::expected<std::optional<std::vector<std::byte>>, StoreError>;
    [[nodiscard]] auto contains(std::string_view name) const -> bool;
    [[nodiscard]] auto names() const -> std::vector<std::string>;

    // Applies every write, or none of them if power is lost.
    auto commit(std::span<const StoreWrite> writes) -> std::expected<void, StoreError>;
    auto put(std::string_view name, std::span<const std::byte> data)
        -> std::expected<void, StoreError>;
    auto remove(std::string_view name) -> std::expected<void, StoreError>;

    // Destroys the store key and the superblocks (decommission).
    auto erase() -> std::expected<void, StoreError>;

    [[nodiscard]] auto rolled_back() const noexcept -> bool { return _rolled_back; }
    [[nodiscard]] auto degraded() const noexcept -> bool { return _degraded; }
    [[nodiscard]] auto faults() const noexcept -> std::uint32_t { return _faults; }
    [[nodiscard]] auto version() const noexcept -> std::uint64_t { return _version; }
    [[nodiscard]] auto half_size() const noexcept -> std::uint64_t { return _half_size; }
    [[nodiscard]] auto free_bytes() const noexcept -> std::uint64_t { return _half_size - _tail; }
    [[nodiscard]] auto flash_error() const noexcept -> FlashError { return _flash_error; }
    [[nodiscard]] auto anchor_error() const noexcept -> AnchorError { return _anchor_error; }

    // The bytes a record of `name` with `data_size` bytes takes.
    [[nodiscard]] static auto record_size(std::size_t name_size, std::size_t data_size) noexcept
        -> std::uint64_t;

    struct Entry {
        std::uint64_t offset{0};  // within the active half
        std::uint64_t version{0};
        std::uint32_t ciphertext_len{0};
        bool removed{false};
    };

    SealedStore(SealedStore&&) noexcept = default;
    auto operator=(SealedStore&&) noexcept -> SealedStore& = default;
    SealedStore(const SealedStore&) = delete;
    auto operator=(const SealedStore&) -> SealedStore& = delete;
    ~SealedStore() = default;

private:
    SealedStore(Flash& flash, StoreAnchor& anchor) noexcept : _flash{&flash}, _anchor{&anchor} {}

    using Digest = std::array<std::byte, 32>;
    struct Superblock {
        std::uint8_t active_half{0};
        std::uint64_t version{0};
        std::uint64_t generation{0};
        std::uint64_t tail{0};
        Digest chain{};
    };

    [[nodiscard]] auto load() -> std::expected<void, StoreError>;
    [[nodiscard]] auto format(std::uint64_t version) -> std::expected<void, StoreError>;
    [[nodiscard]] auto half_base(std::uint8_t half) const noexcept -> std::uint64_t;
    [[nodiscard]] auto read_superblock(std::size_t slot) -> std::optional<Superblock>;
    [[nodiscard]] auto write_superblock(const Superblock& sb) -> std::expected<void, StoreError>;
    [[nodiscard]] auto scan(const Superblock& sb) -> std::expected<void, StoreError>;
    [[nodiscard]] auto open_record(std::uint8_t half, std::uint64_t generation,
                                   std::uint64_t offset, std::string_view name, const Entry& entry)
        -> std::expected<std::vector<std::byte>, StoreError>;
    [[nodiscard]] auto seal_record(std::uint64_t generation, std::uint64_t offset,
                                   std::string_view name, std::uint64_t version, bool removed,
                                   std::span<const std::byte> data)
        -> std::expected<std::vector<std::byte>, StoreError>;
    [[nodiscard]] auto append(std::span<const StoreWrite> writes)
        -> std::expected<void, StoreError>;
    [[nodiscard]] auto compact(std::span<const StoreWrite> writes)
        -> std::expected<void, StoreError>;
    [[nodiscard]] auto finish_commit(std::uint8_t half, std::uint64_t generation,
                                     std::uint64_t tail, const Digest& chain)
        -> std::expected<void, StoreError>;
    auto flash_failed(FlashError e) -> StoreError;
    auto anchor_failed(AnchorError e) -> StoreError;

    Flash* _flash;
    StoreAnchor* _anchor;
    SecretBytes<store_key_size> _object_key;
    SecretBytes<store_key_size> _superblock_key;
    std::uint64_t _half_size{0};
    std::uint8_t _active_half{0};
    std::uint64_t _half_generation{0};
    std::uint64_t _version{0};
    std::uint64_t _tail{0};
    Digest _chain{};
    std::map<std::string, Entry, std::less<>> _index;
    bool _rolled_back{false};
    bool _degraded{false};
    bool _closed{false};
    std::uint32_t _faults{0};
    FlashError _flash_error{FlashError::io};
    AnchorError _anchor_error{AnchorError::io};
};

}  // namespace ak::helm
