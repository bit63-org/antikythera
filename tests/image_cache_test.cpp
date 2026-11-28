// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 2 and .kiro/specs/server-provisioning/
// Requirement 4.4: helm's hull image cache in the sealed store. Staging,
// promotion on keep_image, the previous-image fallback, chunk sharing and
// removal, power loss (reopening the store), and the checks made when an
// image is stored and again when it is read to boot.

#define BOOST_TEST_MODULE image_cache_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "helm/flash.hpp"
#include "helm/image_cache.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/host_image.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;
using helm::ImageError;
using helm::ImageSlot;

namespace {

constexpr std::uint64_t flash_size = std::uint64_t{32} << 20;
constexpr std::byte good_sig{0x5A};

// Accepts key 1 with a signature of 0x5A bytes, as a stand-in for the
// image keys' Ed25519 check (the codec's own test covers real signing).
struct FakeVerifier final : helm::RecordVerifier {
    [[nodiscard]] auto verify(std::span<const std::byte> /*message*/,
                              std::span<const std::byte, proto::ed25519_signature_size> sig,
                              std::uint16_t key_id) const -> bool override {
        return key_id == 1 && std::ranges::all_of(sig, [](std::byte b) { return b == good_sig; });
    }
};

// An image whose first `shared` MiB are the same in every image built with
// the same `shared`, and whose tail depends on `seed`.
auto image(std::uint8_t seed, std::size_t size, std::size_t shared = 0) -> std::vector<std::byte> {
    std::vector<std::byte> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        const bool common = i < shared * helm::image_chunk_size;
        // The chunk number keeps every chunk of one image distinct.
        const std::size_t chunk = i / helm::image_chunk_size;
        out[i] = std::byte{
            static_cast<std::uint8_t>(((i * 131) + (chunk * 37) + (common ? 7U : seed)) & 0xFFU)};
    }
    return out;
}

auto digest_of(std::span<const std::byte> b) -> proto::ImageDigest {
    proto::ImageDigest d{};
    SHA256(reinterpret_cast<const unsigned char*>(b.data()), b.size(),
           reinterpret_cast<unsigned char*>(d.data()));
    return d;
}

auto descriptor(std::span<const std::byte> img, std::uint64_t version = 1,
                proto::HostImageKind kind = proto::HostImageKind::hull) -> std::vector<std::byte> {
    proto::HostImage h{.key_id = 1,
                       .image_version = version,
                       .size = img.size(),
                       .kind = kind,
                       .digest = digest_of(img),
                       .signature = {}};
    h.signature.fill(good_sig);
    auto f = proto::encode_host_image(h);
    BOOST_REQUIRE(f.has_value());
    return *f;
}

struct Fixture {
    Fixture() {
        auto a = helm::SoftwareStoreAnchor::ephemeral();
        BOOST_REQUIRE(a.has_value());
        anchor = std::move(*a);
        reopen();
    }

    // As after a power cycle: the same flash and secure element.
    auto reopen() -> void {
        cache.reset();
        store.reset();
        auto s = helm::SealedStore::open(flash, *anchor);
        BOOST_REQUIRE(s.has_value());
        store = std::make_unique<helm::SealedStore>(std::move(*s));
        cache = std::make_unique<helm::ImageCache>(*store, &keys);
        BOOST_REQUIRE(cache->load().has_value());
    }

    auto stage(std::span<const std::byte> img, std::uint64_t version = 1) -> void {
        auto ok = cache->stage(descriptor(img, version), img);
        BOOST_REQUIRE_MESSAGE(ok.has_value(), (ok ? "" : helm::to_string(ok.error())));
    }

    [[nodiscard]] auto chunks_in_store() const -> std::size_t {
        return static_cast<std::size_t>(std::ranges::count_if(
            store->names(), [](const std::string& n) { return n.starts_with("helm.chunk."); }));
    }

    helm::MemoryFlash flash{flash_size};
    std::unique_ptr<helm::SoftwareStoreAnchor> anchor;
    std::unique_ptr<helm::SealedStore> store;
    FakeVerifier keys;
    std::unique_ptr<helm::ImageCache> cache;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(image_cache, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_FIXTURE_TEST_CASE(staged_image_reads_back_and_survives_power_loss, Fixture) {
    const auto img = image(1, (2 * helm::image_chunk_size) + 1234);
    stage(img);
    BOOST_TEST((cache->digest(ImageSlot::staged) == digest_of(img)));
    BOOST_TEST(cache->slot(ImageSlot::staged)->chunks.size() == 3U);
    BOOST_TEST(!cache->slot(ImageSlot::lkg).has_value());
    reopen();
    auto back = cache->read(ImageSlot::staged);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == img));
    BOOST_TEST((cache->read(ImageSlot::lkg).error() == ImageError::empty));
}

BOOST_FIXTURE_TEST_CASE(keep_image_promotes_and_keeps_the_previous_lkg, Fixture) {
    const auto a = image(1, helm::image_chunk_size + 10);
    const auto b = image(2, helm::image_chunk_size + 20);
    stage(a);
    BOOST_TEST(cache->promote(digest_of(a)).value());
    BOOST_TEST((cache->digest(ImageSlot::lkg) == digest_of(a)));
    BOOST_TEST(!cache->slot(ImageSlot::staged).has_value());
    BOOST_TEST(!cache->slot(ImageSlot::previous).has_value());
    // keep_image of the LKG itself changes nothing.
    BOOST_TEST(!cache->promote(digest_of(a)).value());

    stage(b, 2);
    BOOST_TEST(cache->promote(digest_of(b)).value());
    reopen();
    BOOST_TEST((cache->digest(ImageSlot::lkg) == digest_of(b)));
    BOOST_TEST((cache->digest(ImageSlot::previous) == digest_of(a)));
    BOOST_TEST((*cache->read(ImageSlot::previous) == a));
    BOOST_TEST((*cache->read(ImageSlot::lkg) == b));
    // An unknown digest is refused.
    BOOST_TEST((cache->promote(digest_of(image(9, 100))).error() == ImageError::empty));
}

BOOST_FIXTURE_TEST_CASE(slots_share_chunks_and_drop_unreferenced_ones, Fixture) {
    const auto a = image(1, 3 * helm::image_chunk_size, 2);
    const auto b = image(2, 3 * helm::image_chunk_size, 2);
    const auto c = image(3, 3 * helm::image_chunk_size, 2);
    stage(a);
    BOOST_TEST(chunks_in_store() == 3U);
    BOOST_REQUIRE(cache->promote(digest_of(a)).value());
    stage(b, 2);
    // The two shared MiB are stored once.
    BOOST_TEST(chunks_in_store() == 4U);
    BOOST_REQUIRE(cache->promote(digest_of(b)).value());
    stage(c, 3);
    BOOST_TEST(chunks_in_store() == 5U);
    BOOST_REQUIRE(cache->promote(digest_of(c)).value());
    // a fell out: its own last chunk went with it.
    BOOST_TEST(chunks_in_store() == 4U);
    BOOST_TEST(!cache->find(digest_of(a)).has_value());
    reopen();
    BOOST_TEST((*cache->read(ImageSlot::previous) == b));
}

BOOST_FIXTURE_TEST_CASE(staging_an_image_already_held_writes_no_chunks, Fixture) {
    const auto a = image(1, helm::image_chunk_size + 1);
    stage(a);
    BOOST_REQUIRE(cache->promote(digest_of(a)).value());
    const auto before = store->version();
    stage(a);
    BOOST_TEST((cache->digest(ImageSlot::staged) == digest_of(a)));
    BOOST_TEST(store->version() == before + 1);  // one small commit
    BOOST_TEST(chunks_in_store() == 2U);
    // Staging it again is a no-op.
    stage(a);
    BOOST_TEST(store->version() == before + 1);
}

BOOST_FIXTURE_TEST_CASE(failed_lkg_falls_back_to_previous, Fixture) {
    const auto a = image(1, 1000);
    const auto b = image(2, 2000);
    stage(a);
    BOOST_REQUIRE(cache->promote(digest_of(a)).value());
    stage(b, 2);
    BOOST_REQUIRE(cache->promote(digest_of(b)).value());
    // keep_image of the previous image swaps them back.
    BOOST_TEST(cache->promote(digest_of(a)).value());
    BOOST_TEST((cache->digest(ImageSlot::lkg) == digest_of(a)));
    BOOST_TEST((cache->digest(ImageSlot::previous) == digest_of(b)));
    // Dropping the LKG moves the previous image up.
    BOOST_REQUIRE(cache->drop(ImageSlot::lkg).has_value());
    BOOST_TEST((cache->digest(ImageSlot::lkg) == digest_of(b)));
    BOOST_TEST(!cache->slot(ImageSlot::previous).has_value());
    BOOST_TEST(chunks_in_store() == 1U);
}

BOOST_FIXTURE_TEST_CASE(stage_checks_the_descriptor_and_the_image, Fixture) {
    const auto a = image(1, 5000);
    auto f = descriptor(a);
    f.back() = std::byte{0};
    BOOST_TEST((cache->stage(f, a).error() == ImageError::bad_signature));
    BOOST_TEST((cache->stage(std::span{f}.first(10), a).error() == ImageError::bad_descriptor));
    BOOST_TEST((cache->stage(descriptor(a, 1, proto::HostImageKind::kythira_host), a).error() ==
                ImageError::wrong_kind));
    BOOST_TEST((cache->stage(descriptor(a), std::span{a}.first(4999)).error() ==
                ImageError::size_mismatch));
    auto changed = a;
    changed[17] ^= std::byte{1};
    BOOST_TEST((cache->stage(descriptor(a), changed).error() == ImageError::digest_mismatch));
    helm::ImageCache no_keys{*store, nullptr};
    BOOST_TEST((no_keys.stage(descriptor(a), a).error() == ImageError::bad_signature));
    BOOST_TEST(store->names().empty());
}

BOOST_FIXTURE_TEST_CASE(read_checks_the_image_again, Fixture) {
    const auto a = image(1, helm::image_chunk_size + 77);
    stage(a);
    // A chunk replaced in the store (by a bug, or a store that let it
    // through) is caught by its digest before the image is booted.
    const auto& chunks = cache->slot(ImageSlot::staged)->chunks;
    BOOST_REQUIRE(store->put(helm::ImageCache::chunk_object(chunks[1]), std::vector<std::byte>(77))
                      .has_value());
    BOOST_TEST((cache->read(ImageSlot::staged).error() == ImageError::corrupt));
    // A missing chunk too.
    BOOST_REQUIRE(store->remove(helm::ImageCache::chunk_object(chunks[1])).has_value());
    BOOST_TEST((cache->read(ImageSlot::staged).error() == ImageError::corrupt));
    // And a cache whose image keys no longer accept the descriptor.
    helm::ImageCache no_keys{*store, nullptr};
    BOOST_REQUIRE(no_keys.load().has_value());
    BOOST_TEST((no_keys.read(ImageSlot::staged).error() == ImageError::bad_signature));
}

BOOST_FIXTURE_TEST_CASE(malformed_slots_are_faults_not_images, Fixture) {
    BOOST_REQUIRE(store->put("helm.image.lkg", std::vector<std::byte>(40)).has_value());
    const auto b = image(2, 100);
    BOOST_REQUIRE(store
                      ->put("helm.image.previous",
                            helm::ImageCache::encode_slot(
                                {.descriptor = *proto::decode_host_image(descriptor(b)),
                                 .frame = descriptor(b),
                                 .chunks = {digest_of(b)}}))
                      .has_value());
    reopen();
    // The LKG does not decode, and a previous image without an LKG is
    // not booted either.
    BOOST_TEST(cache->faults() == 2U);
    BOOST_TEST(!cache->slot(ImageSlot::lkg).has_value());
    BOOST_TEST(!cache->slot(ImageSlot::previous).has_value());
}

BOOST_AUTO_TEST_CASE(slot_encoding_is_strict) {
    const auto a = image(1, helm::image_chunk_size + 1);
    helm::CachedImage img{.descriptor = *proto::decode_host_image(descriptor(a)),
                          .frame = descriptor(a),
                          .chunks = {digest_of(a), digest_of(a)}};
    const auto bytes = helm::ImageCache::encode_slot(img);
    const auto back = helm::ImageCache::decode_slot(bytes);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((back->chunks == img.chunks));
    BOOST_TEST(!helm::ImageCache::decode_slot(std::span{bytes}.first(bytes.size() - 1)));
    img.chunks.pop_back();  // one chunk short for the size
    BOOST_TEST(!helm::ImageCache::decode_slot(helm::ImageCache::encode_slot(img)));
    BOOST_TEST(helm::ImageCache::chunk_object(digest_of(a)).size() == 11U + 32U);
}

BOOST_AUTO_TEST_SUITE_END()
