// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/block-volume-service/ task 23 (Requirements 11.7, 12.5):
// HydratingBackend restores a network volume from a public or encrypted
// image under the volume's own key. Driven against an in-process hold over
// an in-memory replica through the real InitiatorCore, with the image in
// an in-memory object store behind the real chunk cache and Fetcher: reads
// of unhydrated regions hydrate them first, under K_vol (after K_img for
// an encrypted image), whatever the guest wrote stays, the background walk
// fills the rest at its pace and skips what is already whole, so a later
// attachment resumes without fetching again.

#define BOOST_TEST_MODULE hydrating_backend_test
#include <boost/test/unit_test.hpp>

#include <stdlib.h>  // NOLINT(modernize-deprecated-headers): mkdtemp

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "hold/server/server.hpp"
#include "hold/store/file_layer.hpp"
#include "objstore/chunk_cache.hpp"
#include "objstore/fetcher.hpp"
#include "objstore/image_manifest.hpp"
#include "objstore/object_store.hpp"
#include "oar/blk/hydrating_backend.hpp"
#include "oar/blk/initiator.hpp"
#include "oar/blk/xts_cipher.hpp"
#include "proto/hold_wire.hpp"
#include "proto/replica_config.hpp"
#include "test_support.hpp"

namespace ak::oar::blk {
auto operator<<(std::ostream& os, BackendError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, HydratingError e) -> std::ostream& {
    return os << to_string(e);
}
auto operator<<(std::ostream& os, HydratingKeyError e) -> std::ostream& {
    return os << to_string(e);
}
}  // namespace ak::oar::blk

namespace {

namespace blk = ak::oar::blk;
namespace objstore = ak::objstore;
namespace proto = ak::proto;
namespace utf = boost::unit_test;
using namespace std::chrono_literals;
using Clock = blk::InitiatorCore::Clock;
using Bytes = std::vector<std::byte>;
using Key = std::array<std::byte, blk::xts_key_size>;

constexpr std::uint64_t compute = 2;
constexpr std::uint64_t hold_id = 1;
constexpr std::uint64_t vol = 7;
constexpr std::uint64_t att = 100;
constexpr std::uint32_t bs = 512;
constexpr std::uint64_t chunk_bytes = 64ULL * 1024;  // chunk shift 16
constexpr std::uint64_t region_blocks = chunk_bytes / bs;
constexpr std::uint32_t image_chunks = 4;
constexpr std::uint64_t volume_chunks = 6;  // two past the image
constexpr std::uint64_t capacity_blocks = volume_chunks * region_blocks;

const Clock::time_point t0{std::chrono::seconds{1000}};

auto make_key(std::uint8_t seed) -> Key {
    Key key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(seed + (i < key.size() / 2 ? i : 0x80 + i));
    }
    return key;
}

class MemoryStore final : public objstore::ObjectStore {
public:
    using ObjectStore::put;
    auto put(const std::string& key, Bytes bytes) -> void {
        const std::scoped_lock lock{_mutex};
        _objects[key] = std::move(bytes);
    }
    auto get_range(std::string_view key, std::uint64_t offset, std::span<std::byte> out,
                   Clock::time_point /*deadline*/)
        -> std::expected<void, objstore::FetchError> override {
        const std::scoped_lock lock{_mutex};
        ++ranges;
        if (fail_next > 0) {
            --fail_next;
            return std::unexpected(objstore::FetchError::not_found);
        }
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end() || offset + out.size() > it->second.size()) {
            return std::unexpected(objstore::FetchError::not_found);
        }
        std::copy_n(it->second.begin() + static_cast<std::ptrdiff_t>(offset), out.size(),
                    out.begin());
        return {};
    }
    auto get(std::string_view key, std::size_t /*max_bytes*/, Clock::time_point /*deadline*/)
        -> std::expected<Bytes, objstore::FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end()) {
            return std::unexpected(objstore::FetchError::not_found);
        }
        return it->second;
    }
    [[nodiscard]] auto count() -> std::uint64_t {
        const std::scoped_lock lock{_mutex};
        return ranges;
    }
    auto fail(unsigned n) -> void {
        const std::scoped_lock lock{_mutex};
        fail_next = n;
    }

private:
    std::mutex _mutex;
    std::map<std::string, Bytes> _objects;
    std::uint64_t ranges{0};
    unsigned fail_next{0};
};

class TempDir {
public:
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-hyd-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        _path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return _path; }

private:
    std::filesystem::path _path;
};

class Sink final : public ak::hold::SessionSink {
public:
    auto send(ak::hold::SessionId session, Bytes frame) -> void override {
        frames.emplace_back(session, std::move(frame));
    }
    std::vector<std::pair<ak::hold::SessionId, Bytes>> frames;
};

auto replica_config(std::uint64_t epoch, std::uint64_t server) -> proto::ReplicaConfig {
    proto::ReplicaConfig c;
    c.key_id = 1;
    c.server_id = server;
    c.volume_id = vol;
    c.epoch = epoch;
    c.lineage_id = 9;
    c.capacity_blocks = capacity_blocks;
    c.block_size = bs;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    proto::ReplicaMember m;
    m.server_id = hold_id;
    m.endpoint[15] = std::byte{1};
    m.port = 4430;
    m.role = proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    c.attachments = {{.attachment_id = att,
                      .server_id = compute,
                      .generation = 1,
                      .mode = proto::AttachMode::rw}};
    c.source = {.kind = proto::SourceKind::image,
                .store_id = 3,
                .hydrate_mib_per_s = 50,
                .manifest_name = {}};
    c.source.manifest_name[0] = std::byte{1};
    return c;
}

// The volume's primary hold, in process, and the initiator's link to it:
// a HydrationTarget over the real InitiatorCore. Frames move inside each
// submit (completions run in the call), or only in poll() when deferred.
class Loop final : public blk::HydrationTarget {
public:
    Loop(ak::hold::HoldServer& hold, Sink& sink, const Clock::time_point& now)
        : _hold{&hold}, _sink{&sink}, _now{&now}, _core{{.attachment_id = att}} {
        BOOST_REQUIRE(_core.set_route(replica_config(1, compute), now).has_value());
        step();
    }
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override {
        return _core.capacity_bytes();
    }
    auto submit_read(std::uint64_t offset, std::span<std::byte> out, blk::BackendCompletion done)
        -> void override {
        ++reads;
        _core.submit_read(offset, out, std::move(done), *_now);
        maybe_step();
    }
    auto submit_write(std::uint64_t offset, std::span<const std::byte> in,
                      blk::BackendCompletion done) -> void override {
        _core.submit_write(offset, in, std::move(done), *_now);
        maybe_step();
    }
    auto submit_flush(blk::BackendCompletion done) -> void override {
        _core.submit_flush(std::move(done));
    }
    auto submit_hydrate(std::uint64_t offset, std::span<const std::byte> in,
                        blk::BackendCompletion done) -> void override {
        ++hydrates;
        _core.submit_hydrate(offset, in, std::move(done), *_now);
        maybe_step();
    }
    [[nodiscard]] auto poll() -> bool override {
        step();
        return _core.pending() != 0;
    }

    bool deferred{false};
    std::uint64_t reads{0};
    std::uint64_t hydrates{0};

private:
    auto maybe_step() -> void {
        if (!deferred) {
            step();
        }
    }
    auto step() -> void {
        for (int guard = 0; guard < 1000; ++guard) {
            bool moved = false;
            if (const auto t = _core.target(*_now); t && t->session != _session) {
                _session = t->session;
                _hold_session = _hold->open_session(compute);
                _core.connected(_session, *_now);
                moved = true;
            }
            for (auto& frame : _core.take_output()) {
                moved = true;
                const auto f = proto::decode_hold_frame(frame);
                BOOST_REQUIRE(f.has_value());
                _hold->on_frame(_hold_session, *f, *_now);
            }
            _hold->run(*_now);
            for (auto& [session, bytes] : std::exchange(_sink->frames, {})) {
                if (session != _hold_session) {
                    continue;
                }
                const auto f = proto::decode_hold_frame(bytes);
                BOOST_REQUIRE(f.has_value());
                moved = true;
                _core.on_frame(_session, *f, *_now);
            }
            if (!moved) {
                return;
            }
        }
        BOOST_FAIL("the loop did not settle");
    }

    ak::hold::HoldServer* _hold;
    Sink* _sink;
    const Clock::time_point* _now;
    blk::InitiatorCore _core;
    std::uint64_t _session{0};
    ak::hold::SessionId _hold_session{0};
};

// The image (4 chunks, chunk 2 a hole), its store, cache and fetcher, and
// the volume's hold.
struct Rig {
    explicit Rig(std::optional<Key> image_key = std::nullopt) {
        plain.resize(image_chunks * chunk_bytes);
        for (std::size_t i = 0; i < plain.size(); ++i) {
            plain[i] = static_cast<std::byte>(((i / bs) * 31) + (i % 251) + 1);
        }
        std::fill_n(plain.begin() + static_cast<std::ptrdiff_t>(2 * chunk_bytes), chunk_bytes,
                    std::byte{0});
        Bytes stored = plain;
        manifest.chunk_shift = objstore::min_chunk_shift;
        manifest.image_bytes = plain.size();
        if (image_key) {
            manifest.encrypted = true;
            manifest.key_id[0] = std::byte{7};
            auto c = blk::XtsCipher::create(*image_key, bs);
            BOOST_REQUIRE(c.has_value());
            BOOST_REQUIRE(c->encrypt(0, plain, stored).has_value());
        }
        for (std::uint32_t c = 0; c < image_chunks; ++c) {
            if (c == 2) {
                manifest.chunks.push_back(objstore::ImageDigest{});
                continue;
            }
            manifest.chunks.push_back(
                *objstore::sha256_digest(std::span{stored}.subspan(c * chunk_bytes, chunk_bytes)));
        }
        const auto bytes = objstore::encode_manifest(manifest);
        BOOST_REQUIRE(bytes.has_value());
        const auto name = *objstore::sha256_digest(*bytes);
        const auto key = objstore::image_data_key("images", objstore::image_name_hex(name));
        store.put(key, stored);
        auto cc = objstore::ChunkCache::create(dir.path(), 64 * chunk_bytes);
        BOOST_REQUIRE(cc.has_value());
        cache = std::move(*cc);
        fetcher = objstore::Fetcher::create(store, {.workers = 2,
                                                    .deadline = 2000ms,
                                                    .attempts = 1,
                                                    .backoff = 1ms,
                                                    .max_queued_prefetch = 8});
        auto ci = cache->open_image(name, manifest, key);
        BOOST_REQUIRE(ci.has_value());
        image = *ci;
        BOOST_REQUIRE(hold.apply_config(replica_config(1, hold_id), now).has_value());
    }

    auto backend(std::uint32_t mib_per_s = 0, bool deferred = false)
        -> std::unique_ptr<blk::HydratingBackend> {
        auto loop = std::make_unique<Loop>(hold, sink, now);
        loop->deferred = deferred;
        auto b = blk::HydratingBackend::create({.volume = std::move(loop),
                                                .image = image,
                                                .fetcher = fetcher.get(),
                                                .logical_block_size = bs,
                                                .hydrate_mib_per_s = mib_per_s,
                                                .max_background = 2,
                                                .max_read_tries = 3,
                                                .retry_backoff = 1000ms,
                                                .clock = [this] { return now; }});
        BOOST_REQUIRE(b.has_value());
        return std::move(*b);
    }

    // Polls until nothing is waiting on a fetch (the fetcher's workers
    // finish on their own threads).
    auto settle(blk::HydratingBackend& b) -> void {
        for (int i = 0; i < 2000; ++i) {
            fetcher->drain();
            const bool more = b.poll();
            if (!more) {
                fetcher->drain();
                if (!b.poll()) {
                    return;
                }
            }
            std::this_thread::sleep_for(1ms);
        }
        BOOST_FAIL("the backend did not settle");
    }

    auto read(blk::HydratingBackend& b, std::uint64_t lba, std::size_t blocks)
        -> std::pair<blk::BackendResult, Bytes> {
        Bytes out(blocks * bs);
        std::optional<blk::BackendResult> result;
        b.submit_read(lba * bs, out, [&](blk::BackendResult r) { result = r; });
        for (int i = 0; i < 2000 && !result; ++i) {
            fetcher->drain();
            static_cast<void>(b.poll());
            if (!result) {
                std::this_thread::sleep_for(1ms);
            }
        }
        BOOST_REQUIRE(result.has_value());
        return {*result, out};
    }

    auto write(blk::HydratingBackend& b, std::uint64_t lba, const Bytes& data) -> bool {
        std::optional<blk::BackendResult> result;
        b.submit_write(lba * bs, data, [&](blk::BackendResult r) { result = r; });
        for (int i = 0; i < 100 && !result; ++i) {
            static_cast<void>(b.poll());
        }
        return result && result->has_value();
    }

    // The guest's view of ciphertext read at `lba`.
    [[nodiscard]] auto view(const Bytes& cipher, std::uint64_t lba) const -> Bytes {
        auto c = blk::XtsCipher::create(k_vol, bs);
        BOOST_REQUIRE(c.has_value());
        Bytes out(cipher.size());
        BOOST_REQUIRE(c->decrypt(lba, cipher, out).has_value());
        return out;
    }
    [[nodiscard]] auto expected(std::uint64_t lba, std::size_t blocks) const -> Bytes {
        Bytes out(blocks * bs);
        for (std::size_t b = 0; b < blocks; ++b) {
            const std::uint64_t at = (lba + b) * bs;
            if (at < plain.size()) {
                std::copy_n(plain.begin() + static_cast<std::ptrdiff_t>(at), bs,
                            out.begin() + static_cast<std::ptrdiff_t>(b * bs));
            }
        }
        return out;
    }
    [[nodiscard]] auto unhydrated(std::uint64_t lba) -> bool {
        auto* r = hold.replica(vol);
        BOOST_REQUIRE(r != nullptr);
        return r->unhydrated(lba).value();
    }

    TempDir dir;
    MemoryStore store;
    Bytes plain;
    objstore::ImageManifest manifest;
    std::unique_ptr<objstore::ChunkCache> cache;
    std::unique_ptr<objstore::Fetcher> fetcher;
    std::shared_ptr<objstore::CachedImage> image;
    Clock::time_point now{t0};
    ak::hold::store::MemFiles files;
    Sink sink;
    ak::hold::HoldServer hold{
        files, {.server_id = hold_id, .data_dir = "/srv/hold", .leases = false}, sink};
    Key k_vol{make_key(0x40)};
};

}  // namespace

BOOST_AUTO_TEST_SUITE(hydrating, *utf::timeout(ak::test::unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(reads_hydrate_their_regions_under_the_volume_key) {
    Rig rig;
    auto b = rig.backend();
    BOOST_REQUIRE(b->load_keys(rig.k_vol, std::nullopt).has_value());
    BOOST_TEST(b->size_bytes() == capacity_blocks * bs);
    BOOST_TEST(b->regions() == volume_chunks);

    // A read across regions 0 and 1 hydrates both, then reads them.
    const std::uint64_t lba = region_blocks - 2;
    auto [r, cipher] = rig.read(*b, lba, 4);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((rig.view(cipher, lba) == rig.expected(lba, 4)));
    BOOST_TEST(cipher != rig.expected(lba, 4));  // the hold keeps ciphertext only
    BOOST_TEST(b->counters().not_hydrated == 1U);
    BOOST_TEST(b->counters().demand_regions == 2U);
    BOOST_TEST(b->counters().hydrated_bytes == 2 * chunk_bytes);
    BOOST_TEST(!rig.unhydrated(0));
    BOOST_TEST(!rig.unhydrated((2 * region_blocks) - 1));
    BOOST_TEST(rig.unhydrated(2 * region_blocks));  // not read: still waiting

    // The hole (region 2) and the part past the image (regions 4-5) are
    // zeros under K_vol, with no fetch.
    const auto fetched = rig.store.count();
    for (const std::uint64_t at : {2 * region_blocks, 5 * region_blocks}) {
        auto [rz, cz] = rig.read(*b, at, 2);
        BOOST_REQUIRE(rz.has_value());
        BOOST_TEST((rig.view(cz, at) == Bytes(2 * bs)));
    }
    BOOST_TEST(rig.store.count() == fetched);

    // A hydrated region reads at once.
    const auto nh = b->counters().not_hydrated;
    auto [r2, c2] = rig.read(*b, 3, 1);
    BOOST_REQUIRE(r2.has_value());
    BOOST_TEST(b->counters().not_hydrated == nh);
}

BOOST_AUTO_TEST_CASE(what_the_guest_wrote_stays) {
    Rig rig;
    auto b = rig.backend();
    BOOST_REQUIRE(b->load_keys(rig.k_vol, std::nullopt).has_value());
    // Ciphertext as VirtioBlkFunction would hand it down.
    const Bytes mine(2 * bs, std::byte{0xEE});
    BOOST_REQUIRE(rig.write(*b, 5, mine));
    auto [r, cipher] = rig.read(*b, 4, 4);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((Bytes(cipher.begin() + bs, cipher.begin() + (3 * bs)) == mine));
    const auto view = rig.view(cipher, 4);
    BOOST_TEST((Bytes(view.begin(), view.begin() + bs) == rig.expected(4, 1)));
    BOOST_TEST((Bytes(view.begin() + (3 * bs), view.end()) == rig.expected(7, 1)));
    BOOST_TEST(b->counters().demand_regions == 1U);
}

BOOST_AUTO_TEST_CASE(encrypted_images_are_re_keyed) {
    const auto k_img = make_key(0x11);
    Rig rig{k_img};
    auto b = rig.backend();
    BOOST_TEST(b->load_keys(rig.k_vol, std::nullopt).error() ==
               blk::HydratingKeyError::missing_image_key);
    BOOST_REQUIRE(b->load_keys(rig.k_vol, blk::XtsKey{k_img}).has_value());
    BOOST_TEST(b->load_keys(rig.k_vol, blk::XtsKey{k_img}).error() ==
               blk::HydratingKeyError::occupied);
    auto [r, cipher] = rig.read(*b, 10, 3);
    BOOST_REQUIRE(r.has_value());
    BOOST_TEST((rig.view(cipher, 10) == rig.expected(10, 3)));

    // A plain image takes no image key.
    Rig plain;
    auto p = plain.backend();
    BOOST_TEST(p->load_keys(plain.k_vol, blk::XtsKey{k_img}).error() ==
               blk::HydratingKeyError::unexpected_image_key);
}

BOOST_AUTO_TEST_CASE(without_keys_nothing_is_hydrated) {
    Rig rig;
    auto b = rig.backend(1000);
    auto [r, cipher] = rig.read(*b, 0, 1);
    BOOST_TEST(r.error() == blk::BackendError::io);  // never not_hydrated past it
    rig.now += 10s;
    rig.settle(*b);
    BOOST_TEST(b->cursor() == 0U);
    BOOST_TEST(rig.unhydrated(0));
    BOOST_REQUIRE(b->load_keys(rig.k_vol, std::nullopt).has_value());
    b->drop_keys();
    BOOST_TEST(!b->holds_keys());
    auto [r2, c2] = rig.read(*b, 0, 1);
    BOOST_TEST(r2.error() == blk::BackendError::io);
}

BOOST_AUTO_TEST_CASE(the_background_walk_fills_the_volume_and_resumes) {
    Rig rig;
    {
        auto b = rig.backend(1000, true);
        BOOST_REQUIRE(b->load_keys(rig.k_vol, std::nullopt).has_value());
        // While the walker starts on regions 0 and 1, the guest reads
        // region 4 and writes into region 3.
        auto [r, c] = rig.read(*b, 4 * region_blocks, 1);
        BOOST_REQUIRE(r.has_value());
        const Bytes mine(bs, std::byte{0xAB});
        BOOST_REQUIRE(rig.write(*b, (3 * region_blocks) + 1, mine));
        for (int i = 0; i < 100 && !b->done(); ++i) {
            rig.now += 100ms;
            rig.settle(*b);
        }
        BOOST_TEST(b->done());
        BOOST_TEST(b->counters().skipped_regions == 1U);  // region 4, read before
        BOOST_TEST(b->counters().demand_regions == 1U);
        BOOST_TEST(b->counters().background_regions == volume_chunks - 1);
        for (std::uint64_t lba = 0; lba < capacity_blocks; lba += 61) {
            BOOST_TEST_INFO("block " << lba);
            BOOST_TEST(!rig.unhydrated(lba));
        }
        auto [rw, cw] = rig.read(*b, (3 * region_blocks) + 1, 1);
        BOOST_REQUIRE(rw.has_value());
        BOOST_TEST((cw == mine));
        auto [ri, ci] = rig.read(*b, (3 * region_blocks) + 2, 1);
        BOOST_REQUIRE(ri.has_value());
        BOOST_TEST(
            (rig.view(ci, (3 * region_blocks) + 2) == rig.expected((3 * region_blocks) + 2, 1)));
    }
    // The next attachment walks again and finds every region whole: no
    // fetch, no hydrate write.
    const auto fetched = rig.store.count();
    auto again = rig.backend(1000, true);
    BOOST_REQUIRE(again->load_keys(rig.k_vol, std::nullopt).has_value());
    for (int i = 0; i < 100 && !again->done(); ++i) {
        rig.now += 100ms;
        rig.settle(*again);
    }
    BOOST_TEST(again->done());
    BOOST_TEST(again->counters().skipped_regions == volume_chunks);
    BOOST_TEST(again->counters().hydrated_bytes == 0U);
    BOOST_TEST(rig.store.count() == fetched);
}

BOOST_AUTO_TEST_CASE(the_walk_keeps_its_pace) {
    Rig rig;
    // 1 MiB/s and 64 KiB regions: about 16 a second, never a burst.
    auto b = rig.backend(1, true);
    BOOST_REQUIRE(b->load_keys(rig.k_vol, std::nullopt).has_value());
    rig.settle(*b);
    BOOST_TEST(b->cursor() <= 2U);
    BOOST_TEST(!b->done());
    // A long pause earns no burst: at most one region ahead of the pace.
    rig.now += 10s;
    rig.settle(*b);
    BOOST_TEST(b->cursor() <= 4U);
    BOOST_TEST(!b->done());
    // Woken at its timer, one region each 1/16 s.
    for (int i = 0; i < 8 && !b->done(); ++i) {
        rig.now += 63ms;
        rig.settle(*b);
    }
    BOOST_TEST(b->done());
}

BOOST_AUTO_TEST_CASE(failed_fetches_fail_the_read_and_the_walk_retries) {
    Rig rig;
    auto b = rig.backend(1000, true);
    rig.store.fail(1);
    BOOST_REQUIRE(b->load_keys(rig.k_vol, std::nullopt).has_value());
    rig.settle(*b);
    BOOST_TEST(b->counters().failures == 1U);
    BOOST_TEST(!b->done());
    // One of the first two regions (the fetchers race for the failure).
    BOOST_TEST(rig.unhydrated(0) != rig.unhydrated(region_blocks));
    // After the backoff the walker goes back to it.
    for (int i = 0; i < 100 && !b->done(); ++i) {
        rig.now += 500ms;
        rig.settle(*b);
    }
    BOOST_TEST(b->done());
    BOOST_TEST(!rig.unhydrated(0));
    BOOST_TEST(!rig.unhydrated(region_blocks));

    // A guest read whose fetch fails gets io.
    Rig other;
    auto g = other.backend();
    BOOST_REQUIRE(g->load_keys(other.k_vol, std::nullopt).has_value());
    other.store.fail(1);
    auto [r, c] = other.read(*g, 0, 1);
    BOOST_TEST(r.error() == blk::BackendError::io);
    auto [r2, c2] = other.read(*g, 0, 1);  // the next one fetches again
    BOOST_REQUIRE(r2.has_value());
    BOOST_TEST((other.view(c2, 0) == other.expected(0, 1)));
}

BOOST_AUTO_TEST_CASE(refuses_what_it_cannot_hydrate) {
    Rig rig;
    BOOST_TEST(blk::HydratingBackend::create({.volume = nullptr,
                                              .image = rig.image,
                                              .fetcher = rig.fetcher.get(),
                                              .logical_block_size = bs,
                                              .hydrate_mib_per_s = 0,
                                              .max_background = 1,
                                              .max_read_tries = 1,
                                              .retry_backoff = 1s,
                                              .clock = {}})
                   .error() == blk::HydratingError::no_image);
    BOOST_TEST(blk::HydratingBackend::create(
                   {.volume = std::make_unique<Loop>(rig.hold, rig.sink, rig.now),
                    .image = rig.image,
                    .fetcher = rig.fetcher.get(),
                    .logical_block_size = 1024,
                    .hydrate_mib_per_s = 0,
                    .max_background = 1,
                    .max_read_tries = 1,
                    .retry_backoff = 1s,
                    .clock = {}})
                   .error() == blk::HydratingError::bad_block_size);
}

BOOST_AUTO_TEST_SUITE_END()
