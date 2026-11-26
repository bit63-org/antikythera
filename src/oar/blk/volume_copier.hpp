// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Local <-> network conversion (.kiro/specs/block-volume-service/
// Requirement 8.6, design "Local ↔ network conversion", task 23.2): a
// keyed copy of one detached volume into another on the same server.
//
// Both volumes hold ciphertext under their own AES-256-XTS key, each block
// encrypted at its own number (the tweak VirtioBlkFunction uses), so a
// copy cannot move bytes: every block is decrypted with the source's key
// and encrypted with the target's at the same number. The copier does
// that region by region through two BlockBackends, which is all it knows
// of either side: a local volume is a FileBackend, a network volume a
// NetworkVolumeBackend opened for a utility attachment (no VM), and a
// khold volume will be whatever backend its initiator provides.
//
//   read     a region (region_bytes, cut at the source's end) from the
//            source;
//   skip     every block whose ciphertext is all zeros: a block that was
//            never written (a sparse file's hole, a hold block with no
//            checksum). Written ciphertext is never all zeros in
//            practice (a 2^-4096 chance for a 512-byte block), so the
//            target stays as thin as the source;
//   rewrap   the other blocks, decrypted and encrypted in place, in runs
//            of consecutive written blocks;
//   write    each run to the target; the region is done when every run
//            is.
//
// When every region is done the target is flushed, and only then is the
// copy `completed`: a completed copy is durable on the target. The copier
// never writes the source.
//
// Pace and retries: at most max_in_flight regions at once, paced at
// mib_per_s (0: as fast as the backends go) with at most one region of
// burst. A region whose read or write fails with `io` is tried again after
// retry_backoff, max_tries times in all, then the copy fails. A source
// answering `not_hydrated` (a network volume still being restored from an
// image under another key: its unhydrated blocks need oar-blk's
// HydratingBackend and an image) or `out_of_range` fails at once: the
// controller hydrates the volume first (replica_status hydrated_bytes ==
// total_bytes) and converts it afterwards.
//
// Keys: load_keys() builds both ciphers (copies of keys helm delivered,
// which the caller wipes) and starts the copy; the copier wipes every
// buffer that held plaintext once a region is written or abandoned, and
// its ciphers go with it. The target must be new (never written): blocks
// skipped as unwritten in the source are left as the target holds them.
//
// Threads: the role thread owns it. poll() runs what is ready, starting at
// most max_in_flight regions per call so a backend that completes inside
// its submits (a FileBackend) cannot hold the role thread for the whole
// volume; it is true while there is more to start at once. wake_fd() is
// one epoll descriptor over the pace timer and both backends' wake fds.
// Destroying the copier (a cancel) drops the backends' pending
// completions without running them.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "common/token_bucket.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "oar/blk/xts_cipher.hpp"

namespace ak::oar::blk {

struct CopyParams {
    using Clock = std::chrono::steady_clock;

    std::unique_ptr<BlockBackend> source;
    std::unique_ptr<BlockBackend> target;
    // Both volumes' block size (the XTS data unit): 512 or 4096.
    std::uint32_t logical_block_size{512};
    std::uint64_t region_bytes{1U << 20U};  // a whole number of blocks
    std::size_t max_in_flight{2};
    std::uint32_t mib_per_s{0};  // 0: unpaced
    unsigned max_tries{3};       // per region: the first try and the retries
    std::chrono::milliseconds retry_backoff{1000};
    std::function<Clock::time_point()> clock;  // empty: steady_clock::now
};

enum class CopyError : std::uint8_t {
    no_backend,      // a backend is missing
    bad_block_size,  // not 512 or 4096
    bad_region,      // zero, or not a whole number of blocks
    bad_capacity,    // the source is empty or not whole blocks, or larger than the target
    wake,            // a timerfd or epoll descriptor failed
};

enum class CopyKeyError : std::uint8_t {
    occupied,  // keys are already loaded
    rejected,  // XtsCipher refused a key (equal halves)
};

enum class CopyState : std::uint8_t {
    waiting_for_keys,
    copying,
    flushing,
    completed,  // every region written and the target flushed
    failed,
};

enum class CopyFailure : std::uint8_t {
    none,
    source_io,     // the source failed a read max_tries times
    target_io,     // the target failed a write max_tries times, or the flush
    not_hydrated,  // the source still awaits hydration
    out_of_range,  // a backend refused a range inside the volume
    crypto,        // a cipher failed
};

[[nodiscard]] auto to_string(CopyError e) noexcept -> const char*;
[[nodiscard]] auto to_string(CopyState s) noexcept -> const char*;
[[nodiscard]] auto to_string(CopyFailure f) noexcept -> const char*;

struct CopyProgress {
    std::uint64_t total_bytes{0};    // the source's size
    std::uint64_t done_bytes{0};     // regions finished (written or skipped whole)
    std::uint64_t written_bytes{0};  // blocks written to the target
    std::uint64_t retries{0};        // region attempts after a failure
};

class VolumeCopier {
public:
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] static auto create(CopyParams params)
        -> std::expected<std::unique_ptr<VolumeCopier>, CopyError>;

    VolumeCopier(const VolumeCopier&) = delete;
    auto operator=(const VolumeCopier&) -> VolumeCopier& = delete;
    VolumeCopier(VolumeCopier&&) = delete;
    auto operator=(VolumeCopier&&) -> VolumeCopier& = delete;
    ~VolumeCopier();

    // Builds both ciphers and starts copying.
    [[nodiscard]] auto load_keys(XtsKey source_key, XtsKey target_key)
        -> std::expected<void, CopyKeyError>;

    [[nodiscard]] auto state() const noexcept -> CopyState { return _state; }
    [[nodiscard]] auto failure() const noexcept -> CopyFailure { return _failure; }
    [[nodiscard]] auto progress() const noexcept -> const CopyProgress& { return _progress; }
    [[nodiscard]] auto source() noexcept -> BlockBackend& { return *_source; }
    [[nodiscard]] auto target() noexcept -> BlockBackend& { return *_target; }

    [[nodiscard]] auto poll() -> bool;
    [[nodiscard]] auto wake_fd() const noexcept -> int { return _epoll; }

private:
    struct Region {
        std::vector<std::byte> data;  // ciphertext, plaintext, ciphertext
        std::size_t pending{0};       // writes outstanding, plus a guard while submitting
        std::uint64_t written{0};     // bytes of written blocks sent to the target
        bool failed{false};
        BackendError error{BackendError::io};
    };

    VolumeCopier(CopyParams params, int timer, int epoll) noexcept;

    [[nodiscard]] auto now() const -> Clock::time_point;
    [[nodiscard]] auto regions() const noexcept -> std::uint64_t;
    [[nodiscard]] auto region_length(std::uint64_t region) const noexcept -> std::uint64_t;
    auto pump(std::size_t& budget) -> void;
    auto start(std::uint64_t region) -> void;
    auto on_read(std::uint64_t region, BackendResult r) -> void;
    auto on_write(std::uint64_t region, BackendResult r) -> void;
    auto settle(std::uint64_t region) -> void;
    auto retry_or_fail(std::uint64_t region, BackendError e, CopyFailure side) -> void;
    auto fail(CopyFailure f) -> void;
    auto maybe_flush() -> void;
    auto arm() -> void;

    CopyParams _params;
    std::unique_ptr<BlockBackend> _source;
    std::unique_ptr<BlockBackend> _target;
    int _timer{-1};
    int _epoll{-1};
    std::optional<XtsCipher> _from;
    std::optional<XtsCipher> _to;
    CopyState _state{CopyState::waiting_for_keys};
    CopyFailure _failure{CopyFailure::none};
    CopyProgress _progress;
    std::map<std::uint64_t, Region> _active;   // regions in flight
    std::map<std::uint64_t, unsigned> _tries;  // attempts so far, by region
    std::vector<std::uint64_t> _retry;         // regions to try again
    std::uint64_t _cursor{0};                  // the next region to start
    Clock::time_point _resume{};               // after a failure: not before
    TokenBucket _pace;
};

}  // namespace ak::oar::blk
