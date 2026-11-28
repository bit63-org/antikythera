// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Choosing and writing the hull image a host boots
// (.kiro/specs/cold-start/ Requirement 2, task 4;
// .kiro/specs/server-provisioning/ Requirement 4, task 4).
//
//   BootImageKeeper  keeps the newest boot_image record (link type 25,
//                    proto/boot_image.hpp): the image the controller
//                    assigned this server. It checks the controller's
//                    signature and the image key's inside the descriptor
//                    and stores the frame in the sealed store. A store that
//                    opened rolled back or degraded loses it, as it loses
//                    the power policy (Requirement 1.5): an older copy may
//                    name a release the controller has moved off.
//
//   HostBooter       fills the boot function before helm releases the host
//                    (Requirement 2.1). It tries, in order:
//
//                      1. the assigned image: from the ImageCache if a slot
//                         holds it, else fetched from the metal boot layer
//                         within fetch_limit (30 s, Requirement 2.2) and
//                         staged, so the next boot needs no fetch;
//                      2. the LKG;
//                      3. the previous image;
//
//                    skipping an image the caller says failed to start
//                    (Requirement 2.4: the daemon passes the image that did
//                    not bring hull's agent up, once). Each candidate is
//                    read back from the store and checked again before it
//                    is booted (2.5); one that fails is skipped. A staged
//                    image with no assignment naming it is never booted:
//                    nothing vouches for it once its assignment is gone.
//
//                    Then begin_host_boot() advances the boot epoch and
//                    the disk is written with that provisioning frame.
//                    The epoch is taken after the image is chosen, so a
//                    server with no image to boot burns no epoch.
//
// The boot layer is reached through ImageFetch, which the daemon builds
// on an objstore::ObjectStore (object_store_fetch()). The image is
// fetched by its digest (host_image_data_key()) and checked by
// ImageCache::stage, so the boot layer is trusted with nothing.
//
// Not thread-safe: helm's loop thread owns both.

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "helm/boot_function.hpp"
#include "helm/boot_state.hpp"
#include "helm/image_cache.hpp"
#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "objstore/object_store.hpp"
#include "proto/boot_image.hpp"
#include "proto/provisioning.hpp"
#include "proto/report.hpp"

namespace ak::helm {

inline constexpr std::string_view boot_image_object = "helm.boot-image";
inline constexpr std::chrono::milliseconds default_image_fetch_limit{std::chrono::seconds{30}};

class BootImageKeeper {
public:
    // `store` may be null (the assignment then lives in memory only). A
    // null verifier refuses every record. None is owned.
    BootImageKeeper(std::uint64_t server_id, SealedStore* store,
                    const RecordVerifier* controller_keys,
                    const RecordVerifier* image_keys) noexcept
        : _server_id{server_id}, _store{store}, _controller{controller_keys}, _images{image_keys} {}

    // Loads the stored assignment, if any. Call once at start.
    auto load() -> PolicyVerdict;
    // A boot_image record from the controller and its exact encoding.
    auto offer(const proto::BootImage& assignment, std::span<const std::byte> frame)
        -> PolicyVerdict;

    [[nodiscard]] auto current() const noexcept -> const std::optional<proto::BootImage>& {
        return _current;
    }
    // The assigned image's descriptor frame, as the image key signed it;
    // empty with no assignment.
    [[nodiscard]] auto descriptor() const noexcept -> std::span<const std::byte> {
        return proto::boot_image_descriptor(_frame);
    }

private:
    [[nodiscard]] auto verified(const proto::BootImage& b, std::span<const std::byte> frame) const
        -> bool;

    std::uint64_t _server_id;
    SealedStore* _store;
    const RecordVerifier* _controller;
    const RecordVerifier* _images;
    std::optional<proto::BootImage> _current;
    std::vector<std::byte> _frame;
};

// The image bytes for `image` from the metal boot layer, by `deadline`.
using ImageFetch = std::function<std::expected<std::vector<std::byte>, objstore::FetchError>(
    const proto::HostImage& image, objstore::ObjectStore::Clock::time_point deadline)>;

// Fetches host_image_data_key(image.digest) from `store`, refusing an
// object that is not exactly image.size bytes. `store` must outlive the
// returned function.
[[nodiscard]] auto object_store_fetch(objstore::ObjectStore& store) -> ImageFetch;

// Writes the boot disk for `uki` with `provisioning` (write_boot_disk_file
// on the boot function's backing file in production).
using BootDiskWriter = std::function<std::expected<void, BootDiskError>(
    std::span<const std::byte> uki, const proto::Provisioning& provisioning)>;

enum class HostBootError : std::uint8_t {
    no_image,    // no slot holds an image that may be booted and passes its check
    boot_state,  // the boot epoch could not be advanced (boot_state says how)
    boot_disk,   // the boot function could not be written (boot_disk says how)
};

[[nodiscard]] auto to_string(HostBootError e) noexcept -> const char*;

struct HostBootFailure {
    HostBootError error{HostBootError::no_image};
    BootStateFailure boot_state{};
    BootDiskError boot_disk{BootDiskError::flash};
};

struct HostBoot {
    proto::BootSource source{proto::BootSource::lkg};
    ImageSlot slot{ImageSlot::lkg};
    proto::ImageDigest digest{};
    std::uint64_t image_version{0};
    proto::Provisioning provisioning{};
    // An image was assigned but not booted: it could not be fetched in
    // time, did not pass its checks, or the store could not keep it
    // (Requirement 2.2: reported).
    bool assigned_unavailable{false};
    std::optional<objstore::FetchError> fetch_error;
    std::optional<ImageError> image_error;  // the last check or store failure seen
};

struct HostBootConfig {
    std::uint64_t server_id{0};
    BootArch arch{BootArch::x86_64};
    std::chrono::milliseconds fetch_limit{default_image_fetch_limit};
};

class HostBooter {
public:
    using Clock = objstore::ObjectStore::Clock;

    // Every reference must outlive the booter. An empty `fetch` means no
    // boot layer: an assigned image not in the cache is unavailable.
    HostBooter(HostBootConfig config, ImageCache& images, const BootImageKeeper& assignment,
               SealedStore& store, StoreAnchor& anchor, ImageFetch fetch, BootDiskWriter write,
               std::function<Clock::time_point()> clock = {});

    // Chooses an image, advances the boot epoch and writes the boot
    // function. `failed`: an image that just failed to start, skipped
    // wherever it appears.
    auto prepare(const std::optional<proto::ImageDigest>& failed = std::nullopt)
        -> std::expected<HostBoot, HostBootFailure>;

private:
    struct Choice {
        ImageSlot slot{ImageSlot::lkg};
        proto::BootSource source{proto::BootSource::lkg};
        std::vector<std::byte> uki;
    };
    // The assigned image's slot, fetching and staging it if no slot holds
    // it; empty (with `out` noting why) if it cannot be had.
    auto assigned_slot(HostBoot& out) -> std::optional<ImageSlot>;
    auto choose(const std::optional<proto::ImageDigest>& failed, HostBoot& out)
        -> std::optional<Choice>;

    HostBootConfig _config;
    ImageCache* _images;
    const BootImageKeeper* _assignment;
    SealedStore* _store;
    StoreAnchor* _anchor;
    ImageFetch _fetch;
    BootDiskWriter _write;
    std::function<Clock::time_point()> _clock;
};

}  // namespace ak::helm
