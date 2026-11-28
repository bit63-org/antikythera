// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ImageCache: the hull images helm keeps in its sealed store so a server
// boots after an outage without the metal boot layer
// (.kiro/specs/cold-start/ Requirement 2, task 4;
// .kiro/specs/server-provisioning/ Requirement 4.4, task 4).
//
// Three slots, each a signed HostImage descriptor plus the image's bytes:
//
//   staged    an image the controller assigned and helm fetched, booted
//             but not yet trusted to come back after an outage
//   lkg       the last-known-good image, booted when nothing else is
//             assigned or the boot layer cannot be reached
//   previous  the LKG before it, booted once if the LKG fails to start
//
// An image becomes LKG only through promote(), on a signed keep_image in
// the power-on policy (Requirement 2.3), which the controller sends after
// the server booted it, renewed its certificate with a fresh attestation
// and passed its checks. The old LKG becomes previous and the old previous
// is dropped. promote() of the LKG's own digest changes nothing.
//
// Images are kept as 1 MiB chunks named by their SHA-256
// (`helm.chunk.<first 16 bytes in hex>`), so the slots share every chunk
// two releases have in common and a promotion writes no image bytes. Each
// slot's object (`helm.image.<slot>`) is the descriptor frame followed by
// its chunk list:
//
//   descriptor [0x80] | chunk_count u32 | chunk digests [32] x chunk_count
//
// A slot and its chunks are written in one sealed-store commit, so a power
// cut leaves either the old slot or the new one. A chunk no slot names is
// removed in the same commit that drops its last reference.
//
// Every image is checked when it is stored (stage) and again, from the
// chunks read back, before it is booted (read): the descriptor's
// signature under an image key, kind hull, the exact size, and the SHA-256
// of the whole image (Requirement 2.5). A slot that fails its check on
// read is reported, not repaired; helm then boots another slot.
//
// Not thread-safe: helm's daemon owns it on one thread.

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "helm/power_on.hpp"
#include "helm/sealed_store.hpp"
#include "proto/host_image.hpp"

namespace ak::helm {

inline constexpr std::size_t image_chunk_size = std::size_t{1} << 20;

enum class ImageSlot : std::uint8_t {
    staged,
    lkg,
    previous,
};

[[nodiscard]] auto to_string(ImageSlot s) noexcept -> const char*;
[[nodiscard]] auto image_slot_object(ImageSlot s) noexcept -> std::string_view;

enum class ImageError : std::uint8_t {
    bad_descriptor,   // the descriptor frame does not decode
    bad_signature,    // it does not verify under an image key (or there is none)
    wrong_kind,       // not a hull image
    size_mismatch,    // the image is not the descriptor's size
    digest_mismatch,  // the image's SHA-256 is not the descriptor's digest
    empty,            // read() or promote() of a slot that holds nothing
    corrupt,          // a slot object or chunk in the store is malformed or missing
    store,            // the sealed store failed (store_error() says how)
    crypto,           // OpenSSL failed
};

[[nodiscard]] auto to_string(ImageError e) noexcept -> const char*;

struct CachedImage {
    proto::HostImage descriptor;
    std::vector<std::byte> frame;  // the descriptor's exact encoding
    std::vector<proto::ImageDigest> chunks;
};

class ImageCache {
public:
    // Neither is owned; both must outlive the cache. `image_keys` verifies
    // descriptors; null refuses every image.
    ImageCache(SealedStore& store, const RecordVerifier* image_keys) noexcept
        : _store{&store}, _keys{image_keys} {}

    // Reads the slots' descriptors and chunk lists. A slot whose object is
    // malformed is dropped from memory (not from the store) and counted in
    // faults().
    auto load() -> std::expected<void, ImageError>;

    // Checks `frame` and `image` and stores them as the staged image,
    // replacing any staged one. An image already in a slot is not
    // stored twice: staging the LKG's digest only points staged at it.
    auto stage(std::span<const std::byte> frame, std::span<const std::byte> image)
        -> std::expected<void, ImageError>;

    // keep_image: makes the image with `digest` (in any slot) the LKG and
    // the old LKG previous. True if it changed anything; empty if no slot
    // holds that digest.
    auto promote(const proto::ImageDigest& digest) -> std::expected<bool, ImageError>;

    // Drops a slot (the staged image after a failed start, say).
    auto drop(ImageSlot slot) -> std::expected<void, ImageError>;

    // The slot's image bytes, checked again (Requirement 2.5).
    [[nodiscard]] auto read(ImageSlot slot) -> std::expected<std::vector<std::byte>, ImageError>;

    [[nodiscard]] auto slot(ImageSlot s) const noexcept -> const std::optional<CachedImage>&;
    // The slot's digest, all zero if it holds nothing.
    [[nodiscard]] auto digest(ImageSlot s) const noexcept -> proto::ImageDigest;
    // The slot holding `digest`, preferring lkg, then staged, then previous.
    [[nodiscard]] auto find(const proto::ImageDigest& digest) const noexcept
        -> std::optional<ImageSlot>;

    [[nodiscard]] auto faults() const noexcept -> std::uint32_t { return _faults; }
    [[nodiscard]] auto store_error() const noexcept -> StoreError { return _store_error; }

    // A slot object's encoding (exposed for tests).
    [[nodiscard]] static auto encode_slot(const CachedImage& image) -> std::vector<std::byte>;
    [[nodiscard]] static auto decode_slot(std::span<const std::byte> bytes)
        -> std::optional<CachedImage>;
    [[nodiscard]] static auto chunk_object(const proto::ImageDigest& chunk) -> std::string;

private:
    [[nodiscard]] auto check(std::span<const std::byte> frame) const
        -> std::expected<proto::HostImage, ImageError>;
    // Commits the slot changes in `next`, adding `new_chunks` and removing
    // chunks no slot names any more.
    auto commit(const std::array<std::optional<CachedImage>, 3>& next,
                std::vector<StoreWrite> new_chunks) -> std::expected<void, ImageError>;
    auto store_failed(StoreError e) -> ImageError;

    SealedStore* _store;
    const RecordVerifier* _keys;
    std::array<std::optional<CachedImage>, 3> _slots;
    std::uint32_t _faults{0};
    StoreError _store_error{StoreError::flash};
};

}  // namespace ak::helm
