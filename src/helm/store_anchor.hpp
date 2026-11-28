// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// What the sealed store needs from helm's secure element
// (.kiro/specs/cold-start/ Requirements 1.2, 1.5, 1.7, 4.2, 6.1; design
// "helm boots from flash and owns the only persistent state"):
//
//   - a 256-bit store key the secure element derives and can destroy, so
//     decommission erases the store by destroying one key;
//   - three monotonic counters that only move forward and survive power
//     loss: the store version (rollback detection), the standing
//     generation (an older standing set is refused even from a restored
//     copy of the store) and the boot epoch (command sequence numbers are
//     scoped to one host boot).
//
// The store key leaves the secure element into helm's memory (as
// SecretBytes, wiped on release): sealing two hull images of a hundred
// megabytes or more inside an I2C-attached element is not practical. What
// the element guarantees is that nothing outside it can derive the key or
// move a counter back.
//
// SoftwareStoreAnchor is the harbor and QEMU stand-in: a 0600 file holding
// a random store key and the counters, rewritten whole by write, fsync and
// rename, so a power cut leaves either the old or the new contents. It
// keeps the counters only as well as its file is kept; a real secure
// element keeps them in hardware.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <utility>

#include "helm/scoped_key.hpp"

namespace ak::helm {

inline constexpr std::size_t store_key_size = 32;

// Values are stored in the software anchor's file: never renumber.
enum class Counter : std::uint8_t {
    store_version = 0,
    standing_generation = 1,
    boot_epoch = 2,
};
inline constexpr std::size_t counter_count = 3;

enum class AnchorError : std::uint8_t {
    io,              // the anchor (or its file) could not be read or written
    insecure,        // the anchor file is not a 0600-or-tighter regular file
    corrupt,         // the anchor file is the wrong size or has a bad magic
    not_monotonic,   // a counter was asked to stay or move backwards
    random_failure,  // the RNG failed
};

[[nodiscard]] auto to_string(AnchorError e) noexcept -> const char*;

class StoreAnchor {
public:
    StoreAnchor() = default;
    StoreAnchor(const StoreAnchor&) = delete;
    auto operator=(const StoreAnchor&) -> StoreAnchor& = delete;
    StoreAnchor(StoreAnchor&&) = delete;
    auto operator=(StoreAnchor&&) -> StoreAnchor& = delete;
    virtual ~StoreAnchor() = default;

    [[nodiscard]] virtual auto store_key()
        -> std::expected<SecretBytes<store_key_size>, AnchorError> = 0;
    [[nodiscard]] virtual auto counter(Counter c) -> std::expected<std::uint64_t, AnchorError> = 0;
    // Moves `c` to `value`, which must be greater than its current value.
    virtual auto advance(Counter c, std::uint64_t value) -> std::expected<void, AnchorError> = 0;
    // Replaces the store key with a fresh random one: everything sealed
    // under the old key is unreadable from then on. Counters are kept, so
    // a store sealed before the erase still reads as rolled back.
    virtual auto destroy_store_key() -> std::expected<void, AnchorError> = 0;
};

class SoftwareStoreAnchor final : public StoreAnchor {
public:
    // Opens the anchor file at `path`, creating it (0600, a random key,
    // counters at zero) if it does not exist. Refuses symlinks and files
    // anyone else can read or write.
    [[nodiscard]] static auto open(const std::filesystem::path& path)
        -> std::expected<std::unique_ptr<SoftwareStoreAnchor>, AnchorError>;
    // A random key and zero counters held only in memory.
    [[nodiscard]] static auto ephemeral()
        -> std::expected<std::unique_ptr<SoftwareStoreAnchor>, AnchorError>;

    [[nodiscard]] auto store_key()
        -> std::expected<SecretBytes<store_key_size>, AnchorError> override;
    [[nodiscard]] auto counter(Counter c) -> std::expected<std::uint64_t, AnchorError> override;
    auto advance(Counter c, std::uint64_t value) -> std::expected<void, AnchorError> override;
    auto destroy_store_key() -> std::expected<void, AnchorError> override;

    struct State {
        SecretBytes<store_key_size> key;
        std::array<std::uint64_t, counter_count> counters{};
    };

    SoftwareStoreAnchor(std::optional<std::filesystem::path> path, State state) noexcept
        : _path{std::move(path)}, _state{std::move(state)} {}

private:
    [[nodiscard]] auto persist(const State& next) -> std::expected<void, AnchorError>;

    std::optional<std::filesystem::path> _path;  // nullopt: in memory only
    State _state;
};

}  // namespace ak::helm
