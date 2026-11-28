// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/image_cache.hpp"

#include <algorithm>
#include <memory>
#include <set>
#include <utility>

#include <openssl/evp.h>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

constexpr std::size_t chunk_name_bytes = 16;
constexpr std::size_t slot_count = 3;

[[nodiscard]] auto index(ImageSlot s) noexcept -> std::size_t {
    return static_cast<std::size_t>(s);
}

class Sha256 {
public:
    Sha256()
        : _ctx{EVP_MD_CTX_new(), &EVP_MD_CTX_free},
          _ok{_ctx && EVP_DigestInit_ex(_ctx.get(), EVP_sha256(), nullptr) == 1} {}
    auto update(std::span<const std::byte> data) -> void {
        _ok = _ok && EVP_DigestUpdate(_ctx.get(), data.data(), data.size()) == 1;
    }
    [[nodiscard]] auto finish() -> std::optional<proto::ImageDigest> {
        proto::ImageDigest d{};
        unsigned len = 0;
        _ok =
            _ok &&
            EVP_DigestFinal_ex(_ctx.get(), reinterpret_cast<unsigned char*>(d.data()), &len) == 1 &&
            len == d.size();
        if (!_ok) {
            return std::nullopt;
        }
        return d;
    }

private:
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> _ctx;
    bool _ok{false};
};

[[nodiscard]] auto sha256(std::span<const std::byte> data) -> std::optional<proto::ImageDigest> {
    Sha256 h;
    h.update(data);
    return h.finish();
}

[[nodiscard]] auto chunk_count(std::uint64_t size) noexcept -> std::size_t {
    return static_cast<std::size_t>((size + image_chunk_size - 1) / image_chunk_size);
}

}  // namespace

auto to_string(ImageSlot s) noexcept -> const char* {
    switch (s) {
        case ImageSlot::staged:
            return "staged";
        case ImageSlot::lkg:
            return "lkg";
        case ImageSlot::previous:
            return "previous";
    }
    return "unknown";
}

auto image_slot_object(ImageSlot s) noexcept -> std::string_view {
    switch (s) {
        case ImageSlot::staged:
            return "helm.image.staged";
        case ImageSlot::lkg:
            return "helm.image.lkg";
        case ImageSlot::previous:
            return "helm.image.previous";
    }
    return "helm.image.unknown";
}

auto to_string(ImageError e) noexcept -> const char* {
    switch (e) {
        case ImageError::bad_descriptor:
            return "image descriptor does not decode";
        case ImageError::bad_signature:
            return "image descriptor does not verify under an image key";
        case ImageError::wrong_kind:
            return "not a hull image";
        case ImageError::size_mismatch:
            return "image is not the descriptor's size";
        case ImageError::digest_mismatch:
            return "image digest does not match its descriptor";
        case ImageError::empty:
            return "no image in that slot";
        case ImageError::corrupt:
            return "stored image is malformed or missing chunks";
        case ImageError::store:
            return "sealed store failed";
        case ImageError::crypto:
            return "crypto failure";
    }
    return "unknown";
}

auto ImageCache::chunk_object(const proto::ImageDigest& chunk) -> std::string {
    proto::ImageDigest head{};
    std::ranges::copy(std::span{chunk}.first(chunk_name_bytes), head.begin());
    return "helm.chunk." + proto::digest_hex(head).substr(0, 2 * chunk_name_bytes);
}

auto ImageCache::encode_slot(const CachedImage& image) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(image.frame.size() + 4 + (image.chunks.size() * proto::image_digest_size));
    wire::Writer w{out};
    w.bytes(image.frame);
    w.le32(static_cast<std::uint32_t>(image.chunks.size()));
    for (const auto& c : image.chunks) {
        w.bytes(c);
    }
    return out;
}

auto ImageCache::decode_slot(std::span<const std::byte> bytes) -> std::optional<CachedImage> {
    if (bytes.size() < proto::host_image_size + 4) {
        return std::nullopt;
    }
    auto d = proto::decode_host_image(bytes.first(proto::host_image_size));
    if (!d) {
        return std::nullopt;
    }
    wire::Reader r{bytes.subspan(proto::host_image_size)};
    const auto count = r.le32().value_or(0);
    if (count != chunk_count(d->size) ||
        bytes.size() != proto::host_image_size + 4 + (count * proto::image_digest_size)) {
        return std::nullopt;
    }
    CachedImage img{.descriptor = *d,
                    .frame = {bytes.begin(), bytes.begin() + proto::host_image_size},
                    .chunks = {}};
    img.chunks.resize(count);
    for (auto& c : img.chunks) {
        std::ranges::copy(r.bytes(c.size()).value_or(std::span<const std::byte>{}), c.begin());
    }
    return img;
}

auto ImageCache::store_failed(StoreError e) -> ImageError {
    _store_error = e;
    return ImageError::store;
}

auto ImageCache::check(std::span<const std::byte> frame) const
    -> std::expected<proto::HostImage, ImageError> {
    auto d = proto::decode_host_image(frame);
    if (!d) {
        return std::unexpected(ImageError::bad_descriptor);
    }
    if (_keys == nullptr ||
        !_keys->verify(proto::host_image_signed_bytes(frame),
                       std::span<const std::byte, proto::ed25519_signature_size>{d->signature},
                       d->key_id)) {
        return std::unexpected(ImageError::bad_signature);
    }
    if (d->kind != proto::HostImageKind::hull) {
        return std::unexpected(ImageError::wrong_kind);
    }
    return *d;
}

auto ImageCache::load() -> std::expected<void, ImageError> {
    for (const auto s : {ImageSlot::staged, ImageSlot::lkg, ImageSlot::previous}) {
        _slots.at(index(s)).reset();
        auto bytes = _store->get(image_slot_object(s));
        if (!bytes) {
            if (bytes.error() == StoreError::authentication_failed) {
                ++_faults;
                continue;
            }
            return std::unexpected(store_failed(bytes.error()));
        }
        if (!bytes->has_value()) {
            continue;
        }
        auto img = decode_slot(**bytes);
        if (!img) {
            ++_faults;
            continue;
        }
        _slots.at(index(s)) = std::move(*img);
    }
    // A previous image without an LKG cannot come from this code; treat
    // it as a fault rather than booting a fallback with no primary.
    if (!_slots.at(index(ImageSlot::lkg)) && _slots.at(index(ImageSlot::previous))) {
        _slots.at(index(ImageSlot::previous)).reset();
        ++_faults;
    }
    return {};
}

auto ImageCache::slot(ImageSlot s) const noexcept -> const std::optional<CachedImage>& {
    return _slots.at(index(s));
}

auto ImageCache::digest(ImageSlot s) const noexcept -> proto::ImageDigest {
    const auto& img = _slots.at(index(s));
    return img ? img->descriptor.digest : proto::ImageDigest{};
}

auto ImageCache::find(const proto::ImageDigest& d) const noexcept -> std::optional<ImageSlot> {
    for (const auto s : {ImageSlot::lkg, ImageSlot::staged, ImageSlot::previous}) {
        const auto& img = _slots.at(index(s));
        if (img && img->descriptor.digest == d) {
            return s;
        }
    }
    return std::nullopt;
}

auto ImageCache::commit(const std::array<std::optional<CachedImage>, 3>& next,
                        std::vector<StoreWrite> new_chunks) -> std::expected<void, ImageError> {
    std::set<std::string> before;
    std::set<std::string> after;
    for (std::size_t i = 0; i < slot_count; ++i) {
        if (_slots.at(i)) {
            for (const auto& c : _slots.at(i)->chunks) {
                before.insert(chunk_object(c));
            }
        }
        if (next.at(i)) {
            for (const auto& c : next.at(i)->chunks) {
                after.insert(chunk_object(c));
            }
        }
    }
    std::vector<StoreWrite> writes = std::move(new_chunks);
    for (const auto& name : before) {
        if (!after.contains(name)) {
            writes.push_back({.name = name, .data = std::nullopt});
        }
    }
    for (const auto s : {ImageSlot::staged, ImageSlot::lkg, ImageSlot::previous}) {
        const auto& was = _slots.at(index(s));
        const auto& now = next.at(index(s));
        const bool same = (was.has_value() == now.has_value()) &&
                          (!was || was->descriptor.digest == now->descriptor.digest);
        if (same) {
            continue;
        }
        writes.push_back({.name = std::string{image_slot_object(s)},
                          .data = now ? std::optional{encode_slot(*now)} : std::nullopt});
    }
    if (writes.empty()) {
        return {};
    }
    if (auto ok = _store->commit(writes); !ok) {
        return std::unexpected(store_failed(ok.error()));
    }
    _slots = next;
    return {};
}

auto ImageCache::stage(std::span<const std::byte> frame, std::span<const std::byte> image)
    -> std::expected<void, ImageError> {
    auto d = check(frame);
    if (!d) {
        return std::unexpected(d.error());
    }
    if (image.size() != d->size) {
        return std::unexpected(ImageError::size_mismatch);
    }
    const auto whole = sha256(image);
    if (!whole) {
        return std::unexpected(ImageError::crypto);
    }
    if (*whole != d->digest) {
        return std::unexpected(ImageError::digest_mismatch);
    }

    auto next = _slots;
    if (const auto held = find(d->digest); held) {
        if (*held == ImageSlot::staged) {
            return {};
        }
        next.at(index(ImageSlot::staged)) = *_slots.at(index(*held));
        return commit(next, {});
    }

    std::set<std::string> present;
    for (const auto& img : _slots) {
        if (img) {
            for (const auto& c : img->chunks) {
                present.insert(chunk_object(c));
            }
        }
    }
    CachedImage staged{.descriptor = *d, .frame = {frame.begin(), frame.end()}, .chunks = {}};
    std::vector<StoreWrite> new_chunks;
    for (std::size_t off = 0; off < image.size(); off += image_chunk_size) {
        const auto piece = image.subspan(off, std::min(image_chunk_size, image.size() - off));
        const auto cd = sha256(piece);
        if (!cd) {
            return std::unexpected(ImageError::crypto);
        }
        staged.chunks.push_back(*cd);
        auto name = chunk_object(*cd);
        if (present.insert(name).second) {
            new_chunks.push_back({.name = std::move(name),
                                  .data = std::vector<std::byte>{piece.begin(), piece.end()}});
        }
    }
    next.at(index(ImageSlot::staged)) = std::move(staged);
    return commit(next, std::move(new_chunks));
}

auto ImageCache::promote(const proto::ImageDigest& d) -> std::expected<bool, ImageError> {
    const auto held = find(d);
    if (!held) {
        return std::unexpected(ImageError::empty);
    }
    if (*held == ImageSlot::lkg) {
        return false;
    }
    auto next = _slots;
    auto chosen = *_slots.at(index(*held));
    next.at(index(ImageSlot::previous)) = _slots.at(index(ImageSlot::lkg));
    next.at(index(ImageSlot::lkg)) = std::move(chosen);
    // Promoting the staged image empties the staged slot; promoting the
    // previous image back swaps the two.
    if (*held == ImageSlot::staged) {
        next.at(index(ImageSlot::staged)).reset();
    }
    if (auto ok = commit(next, {}); !ok) {
        return std::unexpected(ok.error());
    }
    return true;
}

auto ImageCache::drop(ImageSlot s) -> std::expected<void, ImageError> {
    auto next = _slots;
    next.at(index(s)).reset();
    if (s == ImageSlot::lkg) {
        // The previous image moves up rather than standing alone.
        next.at(index(ImageSlot::lkg)) = std::move(next.at(index(ImageSlot::previous)));
        next.at(index(ImageSlot::previous)).reset();
    }
    return commit(next, {});
}

auto ImageCache::read(ImageSlot s) -> std::expected<std::vector<std::byte>, ImageError> {
    const auto& img = _slots.at(index(s));
    if (!img) {
        return std::unexpected(ImageError::empty);
    }
    const auto d = check(img->frame);
    if (!d) {
        return std::unexpected(d.error());
    }
    if (*d != img->descriptor) {
        return std::unexpected(ImageError::corrupt);
    }
    std::vector<std::byte> out;
    out.reserve(static_cast<std::size_t>(img->descriptor.size));
    Sha256 whole;
    for (const auto& c : img->chunks) {
        auto bytes = _store->get(chunk_object(c));
        if (!bytes) {
            if (bytes.error() == StoreError::authentication_failed) {
                return std::unexpected(ImageError::corrupt);
            }
            return std::unexpected(store_failed(bytes.error()));
        }
        if (!bytes->has_value()) {
            return std::unexpected(ImageError::corrupt);
        }
        const auto cd = sha256(**bytes);
        if (!cd) {
            return std::unexpected(ImageError::crypto);
        }
        if (*cd != c) {
            return std::unexpected(ImageError::corrupt);
        }
        whole.update(**bytes);
        out.insert(out.end(), (*bytes)->begin(), (*bytes)->end());
    }
    if (out.size() != img->descriptor.size) {
        return std::unexpected(ImageError::size_mismatch);
    }
    const auto got = whole.finish();
    if (!got) {
        return std::unexpected(ImageError::crypto);
    }
    if (*got != img->descriptor.digest) {
        return std::unexpected(ImageError::digest_mismatch);
    }
    return out;
}

}  // namespace ak::helm
