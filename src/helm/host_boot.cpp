// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/host_boot.hpp"

#include <algorithm>
#include <utility>

namespace ak::helm {

namespace {

auto all_zero(const proto::ImageDigest& d) -> bool {
    return std::ranges::all_of(d, [](std::byte b) { return b == std::byte{0}; });
}

}  // namespace

auto BootImageKeeper::verified(const proto::BootImage& b, std::span<const std::byte> frame) const
    -> bool {
    if (_controller == nullptr || _images == nullptr || frame.size() != proto::boot_image_size) {
        return false;
    }
    if (!_controller->verify(proto::boot_image_signed_bytes(frame), b.signature, b.key_id)) {
        return false;
    }
    // The release pipeline's signature: a controller cannot assign an
    // image it built itself.
    return _images->verify(proto::host_image_signed_bytes(proto::boot_image_descriptor(frame)),
                           b.image.signature, b.image.key_id);
}

auto BootImageKeeper::load() -> PolicyVerdict {
    if (_store == nullptr) {
        return PolicyVerdict::none;
    }
    if (_store->rolled_back() || _store->degraded()) {
        // As for the power policy (cold-start Requirement 1.5): an older
        // copy may hold an assignment the controller has replaced.
        if (_store->contains(boot_image_object)) {
            (void)_store->remove(boot_image_object);
        }
        return PolicyVerdict::none;
    }
    auto data = _store->get(boot_image_object);
    if (!data) {
        return PolicyVerdict::store_failed;
    }
    if (!*data) {
        return PolicyVerdict::none;
    }
    const auto b = proto::decode_boot_image(**data);
    if (!b) {
        return PolicyVerdict::corrupt;
    }
    if (b->server_id != _server_id) {
        return PolicyVerdict::wrong_server;
    }
    // Checked again: a key retired since it was stored no longer counts.
    if (!verified(*b, **data)) {
        return PolicyVerdict::bad_signature;
    }
    _current = *b;
    _frame = std::move(**data);
    return PolicyVerdict::kept;
}

auto BootImageKeeper::offer(const proto::BootImage& assignment, std::span<const std::byte> frame)
    -> PolicyVerdict {
    if (assignment.server_id != _server_id) {
        return PolicyVerdict::wrong_server;
    }
    if (_current && assignment.assignment_version <= _current->assignment_version) {
        return PolicyVerdict::stale;
    }
    if (!verified(assignment, frame)) {
        return PolicyVerdict::bad_signature;
    }
    if (_store != nullptr && !_store->put(boot_image_object, frame)) {
        return PolicyVerdict::store_failed;
    }
    _current = assignment;
    _frame.assign(frame.begin(), frame.end());
    return PolicyVerdict::kept;
}

auto object_store_fetch(objstore::ObjectStore& store) -> ImageFetch {
    return
        [&store](const proto::HostImage& image, objstore::ObjectStore::Clock::time_point deadline)
            -> std::expected<std::vector<std::byte>, objstore::FetchError> {
            auto bytes = store.get(proto::host_image_data_key(image.digest),
                                   static_cast<std::size_t>(image.size), deadline);
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            if (bytes->size() != image.size) {
                return std::unexpected(objstore::FetchError::bad_response);
            }
            return bytes;
        };
}

auto to_string(HostBootError e) noexcept -> const char* {
    switch (e) {
        case HostBootError::no_image:
            return "no image";
        case HostBootError::boot_state:
            return "boot state";
        case HostBootError::boot_disk:
            return "boot disk";
    }
    return "unknown";
}

HostBooter::HostBooter(HostBootConfig config, ImageCache& images, const BootImageKeeper& assignment,
                       SealedStore& store, StoreAnchor& anchor, ImageFetch fetch,
                       BootDiskWriter write, std::function<Clock::time_point()> clock)
    : _config{config},
      _images{&images},
      _assignment{&assignment},
      _store{&store},
      _anchor{&anchor},
      _fetch{std::move(fetch)},
      _write{std::move(write)},
      _clock{clock ? std::move(clock) : [] { return Clock::now(); }} {}

auto HostBooter::assigned_slot(HostBoot& out) -> std::optional<ImageSlot> {
    const auto& assigned = _assignment->current();
    if (auto held = _images->find(assigned->image.digest)) {
        return held;
    }
    // Only a change of image reaches the boot layer (server-provisioning
    // Requirement 4.4): everything else boots from the store.
    if (!_fetch) {
        return std::nullopt;
    }
    auto bytes = _fetch(assigned->image, _clock() + _config.fetch_limit);
    if (!bytes) {
        out.fetch_error = bytes.error();
        return std::nullopt;
    }
    if (auto ok = _images->stage(_assignment->descriptor(), *bytes); !ok) {
        out.image_error = ok.error();
        return std::nullopt;
    }
    return _images->find(assigned->image.digest);
}

auto HostBooter::choose(const std::optional<proto::ImageDigest>& failed, HostBoot& out)
    -> std::optional<Choice> {
    const auto usable = [&](ImageSlot s) {
        const auto d = _images->digest(s);
        return !all_zero(d) && (!failed || d != *failed);
    };
    const auto read = [&](ImageSlot s) -> std::optional<std::vector<std::byte>> {
        auto bytes = _images->read(s);
        if (!bytes) {
            out.image_error = bytes.error();
            return std::nullopt;
        }
        return std::move(*bytes);
    };

    if (_assignment->current() && (!failed || _assignment->current()->image.digest != *failed)) {
        if (auto slot = assigned_slot(out)) {
            if (auto uki = read(*slot)) {
                const auto source =
                    *slot == ImageSlot::lkg ? proto::BootSource::lkg : proto::BootSource::netboot;
                return Choice{.slot = *slot, .source = source, .uki = std::move(*uki)};
            }
        }
        out.assigned_unavailable = true;
    }
    for (const auto& [slot, source] :
         {std::pair{ImageSlot::lkg, proto::BootSource::lkg},
          std::pair{ImageSlot::previous, proto::BootSource::previous}}) {
        if (!usable(slot)) {
            continue;
        }
        if (auto uki = read(slot)) {
            return Choice{.slot = slot, .source = source, .uki = std::move(*uki)};
        }
    }
    return std::nullopt;
}

auto HostBooter::prepare(const std::optional<proto::ImageDigest>& failed)
    -> std::expected<HostBoot, HostBootFailure> {
    HostBoot out;
    auto choice = choose(failed, out);
    if (!choice) {
        return std::unexpected(HostBootFailure{.error = HostBootError::no_image});
    }
    auto provisioning = begin_host_boot(*_store, *_anchor, _config.server_id);
    if (!provisioning) {
        return std::unexpected(HostBootFailure{.error = HostBootError::boot_state,
                                               .boot_state = provisioning.error()});
    }
    if (auto ok = _write(choice->uki, *provisioning); !ok) {
        return std::unexpected(
            HostBootFailure{.error = HostBootError::boot_disk, .boot_disk = ok.error()});
    }
    const auto& held = _images->slot(choice->slot);
    out.source = choice->source;
    out.slot = choice->slot;
    out.digest = held->descriptor.digest;
    out.image_version = held->descriptor.image_version;
    out.provisioning = *provisioning;
    return out;
}

}  // namespace ak::helm
