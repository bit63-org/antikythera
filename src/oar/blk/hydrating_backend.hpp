// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Foreign-key restore (.kiro/specs/block-volume-service/ task 23, design
// "Restore, hydration and clones", Requirements 11.7 and 12.5): the
// BlockBackend of a network volume made from a public (plaintext) image,
// or from an encrypted image under another key. hold cannot fill such a
// volume itself, since its blocks must be encrypted under the volume's key
// K_vol, which no hold role ever sees. So every block the image covers
// starts unhydrated on every replica, and hold answers a read touching one
// with not_hydrated; this backend, in oar-blk, fills them in.
//
// It sits between VirtioBlkFunction (which encrypts writes and decrypts
// reads with K_vol, so both sides here are ciphertext under K_vol) and the
// volume's NetworkVolumeBackend (a HydrationTarget):
//
//   writes, flushes  passed through: a guest write hydrates the blocks it
//                    covers on the hold side, as an ordinary write does;
//   reads            passed through; one the hold answers with
//                    not_hydrated hydrates every region it touches, then
//                    goes again (at most max_read_tries times in all);
//   hydrating        a region (one image chunk: 1 << chunk_shift bytes,
//                    cut at the volume's end) is fetched through the shared
//                    chunk cache and Fetcher, decrypted with K_img for an
//                    encrypted image, encrypted with K_vol at each block's
//                    own number (the same XTS tweak VirtioBlkFunction uses),
//                    and sent as a hydrate write: the hold stores only the
//                    blocks still unhydrated, so whatever the guest wrote
//                    meanwhile stays. Holes and the part of the volume past
//                    the image are zeros under K_vol.
//
// Background hydration: a walker hydrates the volume region by region
// from block 0 (boot regions first), paced at hydrate_mib_per_s (the
// volume's provisioned initialization rate from its ReplicaConfig source;
// 0: on demand only), at most max_background regions at a time. It first
// reads each region: one already whole (hydrated earlier, or written) is
// skipped without touching the object store, which is how a detached,
// partly hydrated volume resumes on its next attach; the hold's bits are
// the only record. A region whose fetch or write fails is tried again
// after retry_backoff. done() reports a finished walk; counters() the
// progress.
//
// Keys. load_keys() builds the K_vol cipher (and K_img's for an encrypted
// image), copies of the key VirtioBlkFunction holds, in the same process;
// drop_keys() frees them, after which a read that needs hydration fails
// with io and the walker waits for the next key. Image plaintext exists
// only in buffers this backend wipes once the region is encrypted.
//
// Threads: the role thread owns it. Fetches complete on Fetcher workers,
// which post to an inbox; wake_fd() is one epoll descriptor over that
// inbox, the inner backend's wake_fd() and a timer for the walker's pace,
// and poll() runs them all. poll() is true while a guest read waits here
// (background work alone sleeps on wake_fd()). Destroying the backend
// drops its pending completions without running them.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include "common/token_bucket.hpp"
#include "objstore/chunk_cache.hpp"
#include "objstore/fetcher.hpp"
#include "oar/blk/hydration_target.hpp"
#include "oar/blk/virtio_blk_function.hpp"
#include "oar/blk/xts_cipher.hpp"

namespace ak::oar::blk {

struct HydratingParams {
    using Clock = std::chrono::steady_clock;

    std::unique_ptr<HydrationTarget> volume;
    std::shared_ptr<objstore::CachedImage> image;
    objstore::Fetcher* fetcher{nullptr};  // must outlive the backend
    // The volume's block size (the XTS data unit): the image's for an
    // encrypted image; any block size that divides the image otherwise.
    std::uint32_t logical_block_size{512};
    std::uint32_t hydrate_mib_per_s{0};  // background pace; 0: on demand only
    std::size_t max_background{2};       // regions the walker has in flight
    unsigned max_read_tries{3};          // a guest read: first try and retries
    std::chrono::milliseconds retry_backoff{1000};
    std::function<Clock::time_point()> clock;  // empty: steady_clock::now
};

enum class HydratingError : std::uint8_t {
    no_image,        // no volume, image or fetcher
    bad_block_size,  // not 512/4096, or does not fit the image
    bad_capacity,    // the volume is smaller than the image, or not whole blocks
    snapshot,        // a chunked (snapshot) manifest: hold hydrates those
    wake,            // an eventfd, timerfd or epoll descriptor failed
};

enum class HydratingKeyError : std::uint8_t {
    occupied,              // keys are already loaded: drop_keys first
    rejected,              // XtsCipher refused a key (equal halves)
    missing_image_key,     // the image is encrypted and no K_img came
    unexpected_image_key,  // the image is plaintext and a K_img came
};

[[nodiscard]] auto to_string(HydratingError e) noexcept -> const char*;
[[nodiscard]] auto to_string(HydratingKeyError e) noexcept -> const char*;

struct HydratingCounters {
    std::uint64_t not_hydrated{0};        // guest reads the hold sent back
    std::uint64_t demand_regions{0};      // regions hydrated for a guest read
    std::uint64_t background_regions{0};  // regions the walker hydrated
    std::uint64_t skipped_regions{0};     // regions the walker found whole
    std::uint64_t hydrated_bytes{0};      // sent as hydrate writes
    std::uint64_t fetches{0};             // image chunks fetched (cache misses)
    std::uint64_t failures{0};            // regions whose fetch or write failed
};

class HydratingBackend final : public BlockBackend {
public:
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] static auto create(HydratingParams params)
        -> std::expected<std::unique_ptr<HydratingBackend>, HydratingError>;

    HydratingBackend(const HydratingBackend&) = delete;
    auto operator=(const HydratingBackend&) -> HydratingBackend& = delete;
    HydratingBackend(HydratingBackend&&) = delete;
    auto operator=(HydratingBackend&&) -> HydratingBackend& = delete;
    ~HydratingBackend() override;

    [[nodiscard]] auto load_keys(XtsKey volume_key, std::optional<XtsKey> image_key)
        -> std::expected<void, HydratingKeyError>;
    auto drop_keys() noexcept -> void;
    [[nodiscard]] auto holds_keys() const noexcept -> bool { return _vol.has_value(); }

    [[nodiscard]] auto volume() noexcept -> HydrationTarget& { return *_inner; }
    [[nodiscard]] auto counters() const noexcept -> const HydratingCounters& { return _counters; }
    // The walker has been over every region of the volume.
    [[nodiscard]] auto done() const noexcept -> bool;
    // The next region the walker starts, and how many the volume has.
    [[nodiscard]] auto cursor() const noexcept -> std::uint64_t { return _cursor; }
    [[nodiscard]] auto regions() const noexcept -> std::uint64_t;

    // BlockBackend
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override {
        return _inner->size_bytes();
    }
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, BackendCompletion done)
        -> void override;
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in, BackendCompletion done)
        -> void override {
        _inner->submit_write(offset, in, std::move(done));
    }
    auto submit_flush(BackendCompletion done) -> void override {
        _inner->submit_flush(std::move(done));
    }
    [[nodiscard]] auto poll() -> bool override;
    [[nodiscard]] auto wake_fd() const noexcept -> int override { return _fds->epoll; }

private:
    struct Arrival {
        std::uint64_t region{0};
        objstore::FetchResult result;
    };
    // The inbox and the descriptors, shared with fetch callbacks so one
    // finishing after the backend is gone is safe.
    struct Fds {
        Fds() = default;
        Fds(const Fds&) = delete;
        auto operator=(const Fds&) -> Fds& = delete;
        Fds(Fds&&) = delete;
        auto operator=(Fds&&) -> Fds& = delete;
        ~Fds();
        auto post(Arrival a) -> void;
        [[nodiscard]] auto take() -> std::vector<Arrival>;

        int inbox{-1};  // eventfd
        int timer{-1};  // timerfd: the walker's next step
        int epoll{-1};  // wake_fd(): both, and the inner backend's
        std::mutex mutex;
        std::vector<Arrival> arrivals;
    };
    using Waiter = std::move_only_function<void(bool)>;
    struct Region {
        std::vector<std::byte> data;  // plaintext, then ciphertext under K_vol
        std::vector<Waiter> waiters;
        bool writing{false};
    };
    struct Read {
        std::uint64_t offset{0};
        std::span<std::byte> out;
        BackendCompletion done;
        unsigned tries{0};
        std::size_t waiting{0};
        bool failed{false};
    };
    struct Probe {
        std::vector<std::byte> buffer;
    };

    HydratingBackend(HydratingParams params, std::shared_ptr<Fds> fds) noexcept;

    [[nodiscard]] auto now() const -> Clock::time_point;
    [[nodiscard]] auto region_bytes() const noexcept -> std::uint64_t;
    auto send_read(std::uint64_t id) -> void;
    auto on_read(std::uint64_t id, BackendResult r) -> void;
    // Hydrates `region` (or joins its hydration); `w` runs once with the
    // outcome.
    auto hydrate(std::uint64_t region, bool background, Waiter w) -> void;
    auto fill(std::uint64_t region) -> void;
    auto finish(std::uint64_t region, bool ok) -> void;
    auto pump() -> void;
    auto probe(std::uint64_t region) -> void;
    auto background_done(std::uint64_t region, bool ok) -> void;
    auto read_region_done(std::uint64_t id, bool ok) -> void;
    auto arm() -> void;

    HydratingParams _params;
    std::shared_ptr<Fds> _fds;
    std::optional<XtsCipher> _vol;
    std::optional<XtsCipher> _img;
    HydratingCounters _counters;
    std::map<std::uint64_t, Region> _regions;  // hydrating, by region
    std::map<std::uint64_t, Read> _reads;      // guest reads waiting here, by id
    std::uint64_t _next_read{1};
    std::map<std::uint64_t, Probe> _probes;  // the walker's reads, by region
    std::size_t _background{0};              // walker regions in flight
    std::uint64_t _cursor{0};
    std::vector<std::uint64_t> _retry;  // walker regions to try again
    Clock::time_point _resume{};        // after a failure: not before
    TokenBucket _pace;
    // Last: destroyed first, dropping its completions (which name this).
    std::unique_ptr<HydrationTarget> _inner;
};

}  // namespace ak::oar::blk
