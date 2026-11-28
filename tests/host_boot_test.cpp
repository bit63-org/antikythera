// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 2 and .kiro/specs/server-provisioning/
// Requirement 4: which hull image helm boots. The boot_image assignment
// (both signatures, newest only, kept across power loss), the order
// assigned -> LKG -> previous, the 30 s fetch limit and its fallback,
// fetching only to change images, skipping an image that failed to
// start, and the boot epoch taken only once an image is chosen.

#define BOOST_TEST_MODULE host_boot_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <unistd.h>

#include <openssl/sha.h>

#include "helm/boot_function.hpp"
#include "helm/flash.hpp"
#include "helm/host_boot.hpp"
#include "helm/image_cache.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "objstore/object_store.hpp"
#include "proto/boot_image.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
namespace helm = ak::helm;
namespace proto = ak::proto;
namespace objstore = ak::objstore;
using ak::test::unit_timeout_seconds;
using helm::ImageSlot;
using helm::PolicyVerdict;
using proto::BootSource;

namespace {

constexpr std::uint64_t flash_size = std::uint64_t{32} << 20;
constexpr std::uint64_t server = 7;
constexpr std::byte good_sig{0x5A};
constexpr std::byte bad_sig{0x00};

// Accepts key 1 with a signature of 0x5A bytes, standing in for Ed25519
// (the codec tests sign for real).
struct FakeVerifier final : helm::RecordVerifier {
    [[nodiscard]] auto verify(std::span<const std::byte> /*message*/,
                              std::span<const std::byte, proto::ed25519_signature_size> sig,
                              std::uint16_t key_id) const -> bool override {
        return key_id == 1 && std::ranges::all_of(sig, [](std::byte b) { return b == good_sig; });
    }
};

auto image(std::uint8_t seed, std::size_t size = 3000) -> std::vector<std::byte> {
    std::vector<std::byte> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = std::byte{static_cast<std::uint8_t>(((i * 131) + seed) & 0xFFU)};
    }
    return out;
}

auto digest_of(std::span<const std::byte> b) -> proto::ImageDigest {
    proto::ImageDigest d{};
    SHA256(reinterpret_cast<const unsigned char*>(b.data()), b.size(),
           reinterpret_cast<unsigned char*>(d.data()));
    return d;
}

auto host_image(std::span<const std::byte> img, std::uint64_t version, std::byte sig = good_sig)
    -> proto::HostImage {
    proto::HostImage h{.key_id = 1,
                       .image_version = version,
                       .size = img.size(),
                       .kind = proto::HostImageKind::hull,
                       .digest = digest_of(img),
                       .signature = {}};
    h.signature.fill(sig);
    return h;
}

auto descriptor(std::span<const std::byte> img, std::uint64_t version) -> std::vector<std::byte> {
    auto f = proto::encode_host_image(host_image(img, version));
    BOOST_REQUIRE(f.has_value());
    return *f;
}

struct Assignment {
    proto::BootImage record;
    std::vector<std::byte> frame;
};

auto assignment(std::span<const std::byte> img, std::uint64_t assignment_version,
                std::byte controller_sig = good_sig, std::byte image_sig = good_sig,
                std::uint64_t server_id = server) -> Assignment {
    proto::BootImage b{.key_id = 1,
                       .server_id = server_id,
                       .assignment_version = assignment_version,
                       .image = host_image(img, 100 + assignment_version, image_sig),
                       .signature = {}};
    b.signature.fill(controller_sig);
    auto f = proto::encode_boot_image(b);
    BOOST_REQUIRE(f.has_value());
    return {.record = b, .frame = *f};
}

// The metal boot layer: objects by key, a call count, and a way to fail.
class BootLayer final : public objstore::ObjectStore {
public:
    auto add(std::span<const std::byte> img) -> void {
        objects[proto::host_image_data_key(digest_of(img))].assign(img.begin(), img.end());
    }
    auto get_range(std::string_view /*key*/, std::uint64_t /*offset*/, std::span<std::byte> /*out*/,
                   Clock::time_point /*deadline*/)
        -> std::expected<void, objstore::FetchError> override {
        return std::unexpected(objstore::FetchError::denied);
    }
    auto get(std::string_view key, std::size_t max_bytes, Clock::time_point deadline)
        -> std::expected<std::vector<std::byte>, objstore::FetchError> override {
        ++gets;
        last_deadline = deadline;
        if (fail) {
            return std::unexpected(*fail);
        }
        const auto it = objects.find(std::string{key});
        if (it == objects.end()) {
            return std::unexpected(objstore::FetchError::not_found);
        }
        if (it->second.size() > max_bytes) {
            return std::unexpected(objstore::FetchError::too_large);
        }
        return it->second;
    }

    std::map<std::string, std::vector<std::byte>> objects;
    std::optional<objstore::FetchError> fail;
    int gets{0};
    Clock::time_point last_deadline{};
};

struct Fixture {
    using Clock = objstore::ObjectStore::Clock;

    Fixture() {
        auto a = helm::SoftwareStoreAnchor::ephemeral();
        BOOST_REQUIRE(a.has_value());
        anchor = std::move(*a);
        reopen();
    }

    // As after a power cycle: the same flash and secure element.
    auto reopen() -> void {
        booter.reset();
        keeper.reset();
        cache.reset();
        store.reset();
        auto s = helm::SealedStore::open(flash, *anchor);
        BOOST_REQUIRE(s.has_value());
        store = std::make_unique<helm::SealedStore>(std::move(*s));
        cache = std::make_unique<helm::ImageCache>(*store, &keys);
        BOOST_REQUIRE(cache->load().has_value());
        keeper = std::make_unique<helm::BootImageKeeper>(server, store.get(), &keys, &keys);
        (void)keeper->load();
        booter = std::make_unique<helm::HostBooter>(
            helm::HostBootConfig{.server_id = server}, *cache, *keeper, *store, *anchor,
            helm::object_store_fetch(layer),
            [this](std::span<const std::byte> uki,
                   const proto::Provisioning& p) -> std::expected<void, helm::BootDiskError> {
                if (write_fails) {
                    return std::unexpected(helm::BootDiskError::flash);
                }
                written.assign(uki.begin(), uki.end());
                provisioning = p;
                return {};
            },
            [this] { return now; });
    }

    // Stages `img` and makes it the LKG through keep_image.
    auto make_lkg(std::span<const std::byte> img, std::uint64_t version) -> void {
        BOOST_REQUIRE(cache->stage(descriptor(img, version), img).has_value());
        BOOST_REQUIRE(cache->promote(digest_of(img)).has_value());
    }

    auto assign(std::span<const std::byte> img, std::uint64_t version) -> void {
        const auto a = assignment(img, version);
        BOOST_REQUIRE((keeper->offer(a.record, a.frame) == PolicyVerdict::kept));
    }

    auto boot(const std::optional<proto::ImageDigest>& failed = std::nullopt) -> helm::HostBoot {
        auto b = booter->prepare(failed);
        BOOST_REQUIRE_MESSAGE(b.has_value(), (b ? "" : helm::to_string(b.error().error)));
        return *b;
    }

    helm::MemoryFlash flash{flash_size};
    std::unique_ptr<helm::SoftwareStoreAnchor> anchor;
    std::unique_ptr<helm::SealedStore> store;
    FakeVerifier keys;
    std::unique_ptr<helm::ImageCache> cache;
    std::unique_ptr<helm::BootImageKeeper> keeper;
    BootLayer layer;
    std::unique_ptr<helm::HostBooter> booter;
    Clock::time_point now{Clock::time_point{} + std::chrono::hours{1}};
    bool write_fails{false};
    std::vector<std::byte> written;
    proto::Provisioning provisioning{};
};

}  // namespace

BOOST_AUTO_TEST_SUITE(host_boot, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_FIXTURE_TEST_CASE(an_assignment_needs_both_signatures_and_only_grows, Fixture) {
    const auto img = image(1);
    auto a = assignment(img, 2, bad_sig);
    BOOST_TEST((keeper->offer(a.record, a.frame) == PolicyVerdict::bad_signature));
    // The controller signed it, but the release pipeline did not sign the image.
    a = assignment(img, 2, good_sig, bad_sig);
    BOOST_TEST((keeper->offer(a.record, a.frame) == PolicyVerdict::bad_signature));
    a = assignment(img, 2, good_sig, good_sig, server + 1);
    BOOST_TEST((keeper->offer(a.record, a.frame) == PolicyVerdict::wrong_server));
    BOOST_TEST(!keeper->current().has_value());
    BOOST_TEST(keeper->descriptor().empty());

    a = assignment(img, 2);
    BOOST_TEST((keeper->offer(a.record, a.frame) == PolicyVerdict::kept));
    BOOST_TEST(std::ranges::equal(keeper->descriptor(), proto::boot_image_descriptor(a.frame)));
    // A captured older or equal assignment cannot roll the server back.
    const auto older = assignment(image(2), 1);
    BOOST_TEST((keeper->offer(older.record, older.frame) == PolicyVerdict::stale));
    BOOST_TEST((keeper->offer(a.record, a.frame) == PolicyVerdict::stale));

    // Kept across power loss.
    reopen();
    BOOST_REQUIRE(keeper->current().has_value());
    BOOST_TEST(keeper->current()->assignment_version == 2U);
    BOOST_TEST((keeper->current()->image.digest == digest_of(img)));
}

BOOST_FIXTURE_TEST_CASE(no_image_burns_no_epoch, Fixture) {
    auto b = booter->prepare();
    BOOST_REQUIRE(!b.has_value());
    BOOST_TEST((b.error().error == helm::HostBootError::no_image));
    BOOST_TEST(written.empty());
    BOOST_TEST(anchor->counter(helm::Counter::boot_epoch).value() == 0U);
}

BOOST_FIXTURE_TEST_CASE(with_nothing_assigned_the_lkg_boots, Fixture) {
    const auto lkg = image(1);
    make_lkg(lkg, 5);
    const auto b = boot();
    BOOST_TEST((b.source == BootSource::lkg));
    BOOST_TEST((b.slot == ImageSlot::lkg));
    BOOST_TEST((b.digest == digest_of(lkg)));
    BOOST_TEST(b.image_version == 5U);
    BOOST_TEST(!b.assigned_unavailable);
    BOOST_TEST((written == lkg));
    BOOST_TEST(provisioning.server_id == server);
    BOOST_TEST(provisioning.boot_epoch == 1U);
    BOOST_TEST((b.provisioning == provisioning));
    BOOST_TEST(layer.gets == 0);
    // Each boot takes a new epoch.
    BOOST_TEST(boot().provisioning.boot_epoch == 2U);
}

BOOST_FIXTURE_TEST_CASE(an_assigned_image_is_fetched_once_within_the_limit, Fixture) {
    const auto lkg = image(1);
    const auto next = image(2, 5000);
    make_lkg(lkg, 5);
    layer.add(next);
    assign(next, 1);

    const auto b = boot();
    BOOST_TEST((b.source == BootSource::netboot));
    BOOST_TEST((b.slot == ImageSlot::staged));
    BOOST_TEST((written == next));
    BOOST_TEST(layer.gets == 1);
    BOOST_TEST((layer.last_deadline == now + std::chrono::seconds{30}));
    // Booting it does not make it the LKG (cold-start Requirement 2.3).
    BOOST_TEST((cache->digest(ImageSlot::lkg) == digest_of(lkg)));

    // The next boot, even after power loss, needs no boot layer.
    layer.fail = objstore::FetchError::io;
    reopen();
    const auto again = boot();
    BOOST_TEST((again.source == BootSource::netboot));
    BOOST_TEST((written == next));
    BOOST_TEST(layer.gets == 1);
}

BOOST_FIXTURE_TEST_CASE(an_assignment_naming_the_lkg_boots_it_without_a_fetch, Fixture) {
    const auto lkg = image(1);
    make_lkg(lkg, 5);
    assign(lkg, 1);
    const auto b = boot();
    BOOST_TEST((b.source == BootSource::lkg));
    BOOST_TEST(layer.gets == 0);
}

BOOST_FIXTURE_TEST_CASE(an_unreachable_boot_layer_falls_back_to_the_lkg, Fixture) {
    const auto lkg = image(1);
    const auto next = image(2);
    make_lkg(lkg, 5);
    assign(next, 1);
    layer.fail = objstore::FetchError::timed_out;
    const auto b = boot();
    BOOST_TEST((b.source == BootSource::lkg));
    BOOST_TEST((written == lkg));
    BOOST_TEST(b.assigned_unavailable);
    BOOST_TEST((b.fetch_error == objstore::FetchError::timed_out));
}

BOOST_FIXTURE_TEST_CASE(a_fetched_image_that_does_not_match_is_not_staged, Fixture) {
    const auto lkg = image(1);
    const auto next = image(2);
    make_lkg(lkg, 5);
    assign(next, 1);
    // The boot layer serves other bytes of the right size under its digest.
    layer.objects[proto::host_image_data_key(digest_of(next))] = image(3);
    const auto b = boot();
    BOOST_TEST((b.source == BootSource::lkg));
    BOOST_TEST(b.assigned_unavailable);
    BOOST_TEST((b.image_error == helm::ImageError::digest_mismatch));
    BOOST_TEST(!cache->slot(ImageSlot::staged).has_value());
    // The wrong size is refused before the cache sees it.
    layer.objects[proto::host_image_data_key(digest_of(next))] = image(3, 4000);
    BOOST_TEST((boot().fetch_error == objstore::FetchError::too_large));
    layer.objects[proto::host_image_data_key(digest_of(next))] = image(3, 10);
    BOOST_TEST((boot().fetch_error == objstore::FetchError::bad_response));
}

BOOST_FIXTURE_TEST_CASE(a_failed_start_skips_that_image_once_asked, Fixture) {
    const auto a = image(1);
    const auto b = image(2);
    make_lkg(a, 5);
    make_lkg(b, 6);  // a becomes previous
    BOOST_TEST((boot().source == BootSource::lkg));
    // The LKG did not bring hull up: the previous image (Requirement 2.4).
    const auto fallback = boot(digest_of(b));
    BOOST_TEST((fallback.source == BootSource::previous));
    BOOST_TEST((written == a));

    // An assigned image that failed to start falls back to the LKG.
    const auto c = image(3);
    layer.add(c);
    assign(c, 1);
    BOOST_TEST((boot().source == BootSource::netboot));
    const auto after = boot(digest_of(c));
    BOOST_TEST((after.source == BootSource::lkg));
    BOOST_TEST((written == b));
    BOOST_TEST(!after.assigned_unavailable);
}

BOOST_FIXTURE_TEST_CASE(an_lkg_that_failed_with_no_previous_leaves_nothing, Fixture) {
    const auto a = image(1);
    make_lkg(a, 5);
    auto b = booter->prepare(digest_of(a));
    BOOST_REQUIRE(!b.has_value());
    BOOST_TEST((b.error().error == helm::HostBootError::no_image));
}

BOOST_FIXTURE_TEST_CASE(a_staged_image_with_no_assignment_is_never_booted, Fixture) {
    const auto img = image(1);
    BOOST_REQUIRE(cache->stage(descriptor(img, 1), img).has_value());
    auto b = booter->prepare();
    BOOST_REQUIRE(!b.has_value());
    BOOST_TEST((b.error().error == helm::HostBootError::no_image));
}

BOOST_FIXTURE_TEST_CASE(a_failed_disk_write_is_an_error, Fixture) {
    make_lkg(image(1), 5);
    write_fails = true;
    auto b = booter->prepare();
    BOOST_REQUIRE(!b.has_value());
    BOOST_TEST((b.error().error == helm::HostBootError::boot_disk));
    BOOST_TEST((b.error().boot_disk == helm::BootDiskError::flash));
}

BOOST_AUTO_TEST_CASE(the_disk_file_is_replaced_whole) {
    const auto dir = fs::temp_directory_path() / ("host-boot-" + std::to_string(::getpid()));
    fs::create_directories(dir);
    const auto path = dir / "boot.img";
    const proto::Provisioning p{.server_id = server, .boot_epoch = 1, .sequence_floor = 0};
    const auto small = image(1, 1000);
    BOOST_REQUIRE(helm::write_boot_disk_file(path, small, p).has_value());
    BOOST_TEST(fs::file_size(path) == helm::boot_disk_size(small.size()));
    // A different UKI size changes the disk size: the file is replaced,
    // not reopened at the old size.
    const auto big = image(2, 3 << 20);
    BOOST_REQUIRE(helm::write_boot_disk_file(path, big, p).has_value());
    BOOST_TEST(fs::file_size(path) == helm::boot_disk_size(big.size()));
    BOOST_TEST(!fs::exists(dir / "boot.img.new"));
    BOOST_TEST((helm::write_boot_disk_file(path, {}, p).error() == helm::BootDiskError::empty_uki));
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
