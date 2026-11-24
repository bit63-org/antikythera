// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/oar-blk-data-plane/ Requirement 3 (task 6): the storage role
// behind helm's sideband. Volume files, prepare/deliver/clean on a
// function whose transport swaps between a placeholder and the attached
// volume, the attach-window wait for the key, rewrap and delete, and the
// whole path from helm's KeyStore through OarLink to guest I/O.

#define BOOST_TEST_MODULE blk_role_test
#include <boost/test/unit_test.hpp>

#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <mutex>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "helm/key_store.hpp"
#include "helm/oar_link.hpp"
#include "helm/secure_element.hpp"
#include "helm/sideband_binding.hpp"
#include "hold/server/node.hpp"
#include "hold/store/file_layer.hpp"
#include "oar/blk/blk_role.hpp"
#include "oar/blk/file_backend.hpp"
#include "objstore/image_manifest.hpp"
#include "oar/blk/image_pack.hpp"
#include "proto/replica_config.hpp"
#include "proto/server_identity.hpp"
#include "test_support.hpp"
#include "tls/role_identity.hpp"
#include "tls_test_support.hpp"
#include "virtio_driver_support.hpp"

// Boost.Test's customization point for types it cannot print itself.
namespace std {  // NOLINT(cert-dcl58-cpp): boost_test_print_type is found by ADL
auto boost_test_print_type(std::ostream& os, std::byte b) -> std::ostream& {
    return os << "0x" << std::hex << std::to_integer<unsigned>(b) << std::dec;
}
}  // namespace std

namespace blk = ak::oar::blk;
namespace objstore = ak::objstore;
namespace oar = ak::helm::oar;
namespace vio = ak::oar::virtio;
using ak::test::Buffer;
using ak::test::GuestRam;
using ak::test::RecordingInterrupts;
using ak::test::unit_timeout_seconds;
using ak::test::VirtioDriver;
using blk::RequestType;
using blk::Status;

namespace {

constexpr std::uint64_t vm_one = 0x101;
constexpr std::uint64_t vm_two = 0x102;
constexpr std::uint64_t vol_one = 0x201;
constexpr std::uint64_t vol_two = 0x202;
constexpr std::uint64_t volume_sectors = 256;  // 128 KiB
constexpr std::uint32_t test_seg_max = 4;
constexpr std::uint32_t test_max_transfer = 16 * 1024;
constexpr std::size_t function_count = 2;
constexpr oar::FunctionNumber fn0 = 0;
constexpr oar::FunctionNumber fn1 = 1;
constexpr std::uint16_t queue0 = 0;
constexpr std::size_t half_key = blk::xts_key_size / 2;
constexpr std::uint8_t data_key_base = 0x11;
constexpr std::uint8_t tweak_key_base = 0x91;
constexpr std::byte status_canary{0xAA};
constexpr std::uint8_t wrapped_fill = 0x5C;
constexpr std::uint8_t rewrapped_fill = 0x6D;
constexpr std::size_t wrapped_size = 95;
constexpr std::uint64_t marker_sector = 12;
constexpr std::uint64_t far_sector = 200;
constexpr auto serve_poll = std::chrono::milliseconds{5};
constexpr auto link_timeout = std::chrono::seconds{5};
constexpr ak::helm::LinkAddress helm_side{
    .local_addr = 0x08, .peer_addr = 0x12, .local_eid = 8, .peer_eid = 18};

auto test_key() -> std::array<std::byte, blk::xts_key_size> {
    std::array<std::byte, blk::xts_key_size> k{};
    for (std::size_t i = 0; i < half_key; ++i) {
        k[i] = static_cast<std::byte>(data_key_base + i);
        k[half_key + i] = static_cast<std::byte>(tweak_key_base + i);
    }
    return k;
}

// A recognisable guest pattern, one sector long.
auto marker() -> std::vector<std::byte> {
    std::vector<std::byte> out(blk::sector_size);
    constexpr std::string_view text = "antikythera-plaintext-marker:";
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::byte>(text[i % text.size()]);
    }
    return out;
}

auto file_bytes(const std::filesystem::path& p) -> std::vector<std::byte> {
    std::ifstream in{p, std::ios::binary};
    const std::vector<char> raw{std::istreambuf_iterator<char>{in},
                                std::istreambuf_iterator<char>{}};
    std::vector<std::byte> out(raw.size());
    std::ranges::transform(raw, out.begin(), [](char c) { return static_cast<std::byte>(c); });
    return out;
}

auto contains(std::span<const std::byte> hay, std::span<const std::byte> needle) -> bool {
    return !std::ranges::search(hay, needle).empty();
}

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-blkrole-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

// A transport that records what it serves; flr() is the VMM's open (or the
// L1 host's reset) arriving through it.
class FakeTransport final : public blk::FunctionTransport {
public:
    explicit FakeTransport(GuestRam& ram) : _ram{&ram} {}

    [[nodiscard]] auto memory() -> const vio::GuestMemory& override { return _ram->memory(); }
    [[nodiscard]] auto interrupts() -> vio::InterruptSink& override { return _irq; }
    [[nodiscard]] auto serve(vio::PciFunction& function, std::function<void()> on_flr)
        -> std::expected<void, std::string> override {
        if (fail) {
            return std::unexpected("refused");
        }
        _served = &function;
        _on_flr = std::move(on_flr);
        ++serves;
        return {};
    }

    auto flr() -> void { _on_flr(); }
    [[nodiscard]] auto served() const -> vio::PciFunction* { return _served; }

    bool fail{false};
    unsigned serves{0};

private:
    GuestRam* _ram;
    RecordingInterrupts _irq;
    vio::PciFunction* _served{nullptr};
    std::function<void()> _on_flr;
};

// A guest driver for whatever function a transport serves right now.
// With `role`, a read that parks (an image volume's miss) is waited for
// the way the role's event loop would: sleep on the wake descriptors,
// then poll.
class Guest {
public:
    Guest(GuestRam& ram, vio::PciFunction& fn, blk::BlkRole* role = nullptr)
        : _ram{&ram}, _driver{ram, fn}, _role{role} {}

    // The guest's driver lets go of the device (device_status = 0), as
    // Linux does when the PCI device is removed.
    auto release() -> bool {
        return _driver.common_write(vio::common_cfg::device_status, ak::test::width8, 0)
            .has_value();
    }

    auto up() -> bool {
        namespace cc = vio::common_cfg;
        std::uint64_t f = 0;
        for (std::uint32_t word = 0; word < 2; ++word) {
            if (!_driver.common_write(cc::device_feature_select, ak::test::width32, word)) {
                return false;
            }
            f |= _driver.common_read(cc::device_feature, ak::test::width32).value_or(0)
                 << (32U * word);
        }
        return _driver.bring_up(f, {queue0});
    }

    // Posts and notifies one request; returns its id.
    auto post(RequestType type, std::uint64_t sector, std::span<const std::byte> out = {},
              std::uint32_t in_len = 0) -> std::size_t {
        std::vector<Buffer> bufs{{.len = blk::header_size, .writable = false}};
        if (!out.empty()) {
            bufs.push_back({.len = static_cast<std::uint32_t>(out.size()), .writable = false});
        }
        if (in_len != 0) {
            bufs.push_back({.len = in_len, .writable = true});
        }
        bufs.push_back({.len = blk::status_size, .writable = true});
        std::vector<vio::Gpa> gpas;
        _driver.post(queue0, bufs, &gpas);
        std::vector<std::byte> hdr;
        ak::wire::Writer w{hdr};
        w.le32(static_cast<std::uint32_t>(type));
        w.le32(0);
        w.le64(sector);
        _ram->put_bytes(gpas[0], hdr);
        if (!out.empty()) {
            _ram->put_bytes(gpas[1], out);
        }
        _ram->put<std::byte>(gpas.back(), status_canary);
        _requests.push_back({.data = in_len != 0 ? gpas[gpas.size() - 2] : 0,
                             .len = in_len,
                             .status = gpas.back()});
        BOOST_REQUIRE(_driver.notify(queue0));
        return _requests.size() - 1;
    }

    // By the status byte, since requests may complete out of order.
    [[nodiscard]] auto completed(std::size_t id) const -> bool {
        return _ram->get<std::byte>(_requests.at(id).status) != status_canary;
    }
    [[nodiscard]] auto status(std::size_t id) const -> Status {
        return static_cast<Status>(_ram->get<std::byte>(_requests.at(id).status));
    }
    [[nodiscard]] auto data(std::size_t id) const -> std::vector<std::byte> {
        return _ram->bytes(_requests.at(id).data, _requests.at(id).len);
    }
    // Runs the role until request `id` completes or about five seconds pass.
    auto wait(std::size_t id) -> bool {
        settle(id);
        return completed(id);
    }

    auto write(std::uint64_t sector, std::span<const std::byte> d) -> Status {
        return status(post(RequestType::out, sector, d));
    }
    auto read(std::uint64_t sector) -> std::vector<std::byte> {
        const auto id = post(RequestType::in, sector, {}, blk::sector_size);
        settle(id);
        BOOST_REQUIRE(completed(id));
        BOOST_REQUIRE(status(id) == Status::ok);
        return data(id);
    }
    auto serial() -> std::string {
        const auto id = post(RequestType::get_id, 0, {}, blk::id_bytes);
        const auto raw = data(id);
        std::string s;
        for (const auto b : raw) {
            if (b == std::byte{0}) {
                break;
            }
            s.push_back(static_cast<char>(b));
        }
        return s;
    }

private:
    struct Request {
        vio::Gpa data;
        std::uint32_t len;
        vio::Gpa status;
    };

    auto settle(std::size_t id) -> void {
        constexpr int wake_wait_ms = 50;
        constexpr int max_wakes = 100;
        for (int i = 0; _role != nullptr && i < max_wakes && !completed(id); ++i) {
            std::vector<pollfd> fds;
            for (const int fd : _role->wake_fds()) {
                fds.push_back({.fd = fd, .events = POLLIN, .revents = 0});
            }
            static_cast<void>(::poll(fds.data(), fds.size(), wake_wait_ms));
            static_cast<void>(_role->poll());
        }
    }

    GuestRam* _ram;
    VirtioDriver _driver;
    blk::BlkRole* _role;
    std::vector<Request> _requests;
};

// An object store in memory, for image volumes. While held, range reads
// (chunk fetches) wait for release(); whole-object reads (manifests) don't.
class MemoryStore final : public objstore::ObjectStore {
public:
    using ObjectStore::put;  // the store's own put() stays visible
    auto put(const std::string& key, std::vector<std::byte> bytes) -> void {
        const std::scoped_lock lock{_mutex};
        _objects[key] = std::move(bytes);
    }
    auto hold() -> void {
        const std::scoped_lock lock{_mutex};
        _held = true;
    }
    auto release() -> void {
        {
            const std::scoped_lock lock{_mutex};
            _held = false;
        }
        _released.notify_all();
    }
    auto get_range(std::string_view key, std::uint64_t offset, std::span<std::byte> out,
                   Clock::time_point /*deadline*/)
        -> std::expected<void, objstore::FetchError> override {
        std::unique_lock lock{_mutex};
        _released.wait(lock, [this] { return !_held; });
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end() || offset > it->second.size() ||
            out.size() > it->second.size() - offset) {
            return std::unexpected(objstore::FetchError::not_found);
        }
        std::copy_n(it->second.begin() + static_cast<std::ptrdiff_t>(offset), out.size(),
                    out.begin());
        return {};
    }
    auto get(std::string_view key, std::size_t max_bytes, Clock::time_point /*deadline*/)
        -> std::expected<std::vector<std::byte>, objstore::FetchError> override {
        const std::scoped_lock lock{_mutex};
        const auto it = _objects.find(std::string{key});
        if (it == _objects.end()) {
            return std::unexpected(objstore::FetchError::not_found);
        }
        if (it->second.size() > max_bytes) {
            return std::unexpected(objstore::FetchError::too_large);
        }
        return it->second;
    }

private:
    std::mutex _mutex;
    std::condition_variable _released;
    bool _held{false};
    std::map<std::string, std::vector<std::byte>> _objects;
};

constexpr std::uint16_t image_store_id = 4;
constexpr std::string_view image_prefix = "images";

// Network volumes (block-volume-service task 12).
constexpr std::uint64_t compute_id = 2;  // this server
constexpr std::uint64_t hold_id = 5;
constexpr std::uint64_t net_attachment = 77;
constexpr std::uint16_t controller_key = 3;
constexpr auto good_sig = std::byte{0xA5};

// A hung-up hold must not end the test (the roles' mains ignore SIGPIPE).
struct IgnoreSigpipe {
    IgnoreSigpipe() { static_cast<void>(std::signal(SIGPIPE, SIG_IGN)); }
};
const IgnoreSigpipe ignore_sigpipe;

auto server_san(std::uint64_t id) -> std::string {
    return "URI:" + ak::proto::server_uri(id);
}

// A network volume's ReplicaConfig as the controller signs it for
// `server`: one primary hold on 127.0.0.1:`port`, attached here.
auto net_config(std::uint64_t server, std::uint16_t port, std::uint64_t epoch = 1,
                ak::proto::AttachMode mode = ak::proto::AttachMode::rw)
    -> ak::proto::ReplicaConfig {
    ak::proto::ReplicaConfig c;
    c.key_id = controller_key;
    c.server_id = server;
    c.volume_id = vol_one;
    c.epoch = epoch;
    c.lineage_id = 9;
    c.capacity_blocks = volume_sectors;
    c.block_size = blk::sector_size;
    c.qos = {.iops = 100000, .mib_per_s = 10000, .burst_iops = 100000, .burst_mib = 10000};
    c.lease_ms = 4000;
    ak::proto::ReplicaMember m;
    m.server_id = hold_id;
    m.endpoint[10] = std::byte{0xFF};  // ::ffff:127.0.0.1
    m.endpoint[11] = std::byte{0xFF};
    m.endpoint[12] = std::byte{127};
    m.endpoint[15] = std::byte{1};
    m.port = port;
    m.role = ak::proto::ReplicaRole::primary;
    m.replica_gen = 1;
    c.members = {m};
    c.attachments = {
        {.attachment_id = net_attachment, .server_id = compute_id, .generation = 1, .mode = mode}};
    c.signature.fill(good_sig);
    return c;
}

auto frame_of(const ak::proto::ReplicaConfig& c) -> std::vector<std::byte> {
    auto f = ak::proto::encode_replica_config(c);
    BOOST_REQUIRE(f.has_value());
    return *f;
}

// A hold primary on 127.0.0.1, on its own thread.
class Hold {
public:
    explicit Hold(ak::test::TestCa& ca) {
        const auto pem = ca.issue("hold", "IP:127.0.0.1, " + server_san(hold_id));
        auto node = ak::hold::Node::create(
            _files, {.host = "127.0.0.1",
                     .port = 0,
                     .tls = {.role = ak::tls::Role::server,
                             .ca_pem = ca.cert_pem(),
                             .cert_pem = pem.cert,
                             .key_pem = pem.key,
                             .peer_name = {}},
                     .server = {.server_id = hold_id, .data_dir = "/srv/hold", .leases = false},
                     .handshake_timeout = std::chrono::milliseconds{2000},
                     .write_timeout = std::chrono::milliseconds{2000}});
        BOOST_REQUIRE(node.has_value());
        _node = std::move(*node);
        BOOST_REQUIRE(_node->server()
                          .apply_config(net_config(hold_id, port()), ak::hold::Clock::now())
                          .has_value());
        _thread = std::thread{[this] {
            while (!_stop.load()) {
                {
                    const std::scoped_lock lock{_mutex};
                    if (_pending) {
                        _applied = _node->server()
                                       .apply_config(*_pending, ak::hold::Clock::now())
                                       .has_value();
                        _pending.reset();
                    }
                }
                _node->run_once(std::chrono::milliseconds{20});
            }
        }};
    }
    // Applies `c` on the node's thread (the server is single-threaded).
    auto apply(const ak::proto::ReplicaConfig& c) -> bool {
        {
            const std::scoped_lock lock{_mutex};
            _applied.reset();
            _pending = c;
        }
        for (int i = 0; i < 200; ++i) {
            {
                const std::scoped_lock lock{_mutex};
                if (_applied) {
                    return *_applied;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        return false;
    }
    Hold(const Hold&) = delete;
    auto operator=(const Hold&) -> Hold& = delete;
    Hold(Hold&&) = delete;
    auto operator=(Hold&&) -> Hold& = delete;
    ~Hold() {
        _stop.store(true);
        _thread.join();
    }
    [[nodiscard]] auto port() const -> std::uint16_t { return _node->port(); }

private:
    ak::hold::store::MemFiles _files;
    std::unique_ptr<ak::hold::Node> _node;
    std::atomic<bool> _stop{false};
    std::mutex _mutex;
    std::optional<ak::proto::ReplicaConfig> _pending;
    std::optional<bool> _applied;
    std::thread _thread;
};

// The storage certificate of this (compute) server.
auto compute_tls(ak::test::TestCa& ca) -> ak::tls::Config {
    const auto pem = ca.issue("compute", server_san(compute_id));
    return {.role = ak::tls::Role::client,
            .ca_pem = ca.cert_pem(),
            .cert_pem = pem.cert,
            .key_pem = pem.key,
            .peer_name = {}};
}

// A role over two fake transports and a fresh volume directory; with
// `images`, also an image store (in memory) and a chunk cache.
struct Rig {
    TempDir dir;
    GuestRam ram0;
    GuestRam ram1;
    FakeTransport t0{ram0};
    FakeTransport t1{ram1};
    MemoryStore store;
    std::unique_ptr<objstore::ChunkCache> cache;
    std::unique_ptr<objstore::Fetcher> fetcher;
    std::uint64_t network_server{compute_id};
    // A stand-in for Ed25519: every signature byte good_sig, the known key.
    std::function<bool(std::span<const std::byte>, std::span<const std::byte, 64>, std::uint16_t)>
        verify = [](std::span<const std::byte> /*msg*/, std::span<const std::byte, 64> sig,
                    std::uint16_t key) {
            return key == controller_key &&
                   std::ranges::all_of(sig, [](std::byte b) { return b == good_sig; });
        };
    std::optional<ak::tls::Config> storage_tls;
    // The role's clock, which tests move by hand.
    blk::RoleConfig::Clock::time_point now{std::chrono::hours{1}};
    std::unique_ptr<blk::BlkRole> role;

    explicit Rig(bool images = false, std::optional<ak::tls::Config> tls = std::nullopt,
                 bool keys = true)
        : storage_tls{std::move(tls)} {
        if (!keys) {
            verify = nullptr;
        }
        std::map<std::uint16_t, blk::ImageStore> stores;
        if (images) {
            auto c = objstore::ChunkCache::create(dir.path, std::uint64_t{16} << 20U);
            BOOST_REQUIRE(c.has_value());
            cache = std::move(*c);
            fetcher = objstore::Fetcher::create(store, {.workers = 2,
                                                        .deadline = std::chrono::milliseconds{2000},
                                                        .attempts = 2,
                                                        .backoff = std::chrono::milliseconds{1},
                                                        .max_queued_prefetch = 8});
            stores[image_store_id] = {
                .store = &store, .fetcher = fetcher.get(), .prefix = std::string{image_prefix}};
        }
        auto r = blk::BlkRole::create({.volume_dir = dir.path,
                                       .num_queues = 1,
                                       .queue_size = ak::test::test_queue_size,
                                       .seg_max = test_seg_max,
                                       .max_transfer_bytes = test_max_transfer,
                                       .budget = ak::test::test_queue_size,
                                       .image_stores = std::move(stores),
                                       .image_cache = cache.get(),
                                       .overlay_dir = {},
                                       .overlay_limit_bytes = 0,
                                       .max_readahead_chunks = 8,
                                       .image_max_in_flight = 4,
                                       .manifest_deadline = std::chrono::milliseconds{1000},
                                       .server_id = network_server,
                                       .verify_config = verify,
                                       .storage_tls = storage_tls,
                                       .initiator = {},
                                       .clock = [this] { return now; }},
                                      {&t0, &t1});
        BOOST_REQUIRE(r);
        role = std::move(*r);
    }

    // Packs `raw` and publishes it to the store; the image name.
    auto publish(const std::vector<std::byte>& raw,
                 std::optional<blk::XtsKey> image_key = std::nullopt) -> oar::ImageName {
        const int in = ::memfd_create("image", MFD_CLOEXEC);
        const int data = ::memfd_create("data", MFD_CLOEXEC);
        BOOST_REQUIRE(in >= 0 && data >= 0);
        BOOST_REQUIRE(::write(in, raw.data(), raw.size()) == static_cast<ssize_t>(raw.size()));
        blk::PackOptions o{.logical_block_size = blk::sector_size,
                           .chunk_shift = objstore::min_chunk_shift,
                           .image_key = image_key,
                           .key_id = {}};
        if (image_key) {
            o.key_id[0] = std::byte{1};
        }
        const auto packed = blk::pack_image(in, raw.size(), data, o);
        BOOST_REQUIRE(packed.has_value());
        std::vector<std::byte> stored(raw.size());
        BOOST_REQUIRE(::pread(data, stored.data(), stored.size(), 0) ==
                      static_cast<ssize_t>(stored.size()));
        ::close(in);
        ::close(data);
        const auto hex = objstore::image_name_hex(packed->name);
        store.put(objstore::image_manifest_key(image_prefix, hex), packed->manifest_bytes);
        store.put(objstore::image_data_key(image_prefix, hex), std::move(stored));
        return packed->name;
    }

    auto create_image(std::uint64_t volume, std::uint64_t owner, const oar::ImageName& name,
                      std::uint16_t store_id = image_store_id) -> oar::Status {
        return role->create_volume({.volume_id = volume,
                                    .owner_vm = owner,
                                    .capacity_sectors = volume_sectors,
                                    .block_size = blk::sector_size,
                                    .wrapped_key = {},
                                    .image_store = store_id,
                                    .image_name = name});
    }

    auto create(std::uint64_t volume, std::uint64_t owner, std::uint8_t fill = wrapped_fill)
        -> oar::Status {
        const std::vector<std::byte> wrapped(wrapped_size, std::byte{fill});
        return role->create_volume({.volume_id = volume,
                                    .owner_vm = owner,
                                    .capacity_sectors = volume_sectors,
                                    .block_size = blk::sector_size,
                                    .wrapped_key = wrapped,
                                    .image_store = 0,
                                    .image_name = {}});
    }
    auto prepare(oar::FunctionNumber fn, std::uint64_t vm, std::uint64_t volume) -> oar::Status {
        return role->prepare_function({.fn = fn,
                                       .type = ak::helm::FunctionType::blk_fn,
                                       .vm_id = vm,
                                       .config = oar::BlkConfig{.volume_id = volume}});
    }
    auto deliver(oar::FunctionNumber fn, std::uint64_t volume) -> oar::Status {
        const auto key = test_key();
        return role->deliver_key({.fn = fn, .volume_id = volume, .key = key});
    }
    auto clean(oar::FunctionNumber fn) -> oar::Status {
        return role->clean_function(
            {.fn = fn, .action = ak::helm::CleaningAction::drop_volume_key});
    }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(blk_role, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(inventory_and_placeholders) {
    Rig rig;
    auto inv = rig.role->function_inventory();
    BOOST_REQUIRE(inv.has_value());
    BOOST_TEST((inv->role == oar::Role::blk));
    BOOST_REQUIRE(inv->functions.size() == function_count);
    BOOST_TEST(inv->functions[1].fn == fn1);
    BOOST_TEST((inv->functions[1].type == ak::helm::FunctionType::blk_fn));
    // Each transport serves a placeholder from the start: a disk with no
    // key, whose I/O reaches nothing.
    BOOST_REQUIRE(rig.t0.served() != nullptr);
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    BOOST_TEST(rig.role->function(fn0) == nullptr);
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST((g.write(0, marker()) == Status::ioerr));
    BOOST_TEST(g.serial() == "akv-none");

    BOOST_TEST(rig.role->health().has_value());
    BOOST_TEST((rig.role->map_update({}) == oar::Status::unsupported));
    BOOST_TEST(blk::volume_serial(vol_one) == "akv-0000000000000201");
}

BOOST_AUTO_TEST_CASE(create_writes_the_wrapped_key_and_never_overwrites) {
    Rig rig;
    BOOST_TEST((rig.create(vol_one, vm_one) == oar::Status::ok));
    const auto path = rig.role->volume_path(vol_one);
    BOOST_TEST(path.filename() == "vol-0000000000000201.akv");
    auto b = blk::FileBackend::open(path);
    BOOST_REQUIRE(b);
    BOOST_TEST((*b)->metadata().owner_vm == vm_one);
    BOOST_TEST((*b)->metadata().capacity_sectors == volume_sectors);
    BOOST_TEST(((*b)->metadata().wrapped_key ==
                std::vector<std::byte>(wrapped_size, std::byte{wrapped_fill})));
    // A second create for the same volume is refused and changes nothing.
    BOOST_TEST((rig.create(vol_one, vm_two, rewrapped_fill) == oar::Status::failed));
    BOOST_TEST(blk::FileBackend::open(path).value()->metadata().owner_vm == vm_one);
}

BOOST_AUTO_TEST_CASE(attach_holds_io_until_the_key_then_encrypts) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    const unsigned serves = rig.t0.serves;
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok));
    BOOST_TEST(rig.t0.serves == serves + 1);
    BOOST_TEST((rig.role->attached(fn0) == vol_one));
    BOOST_REQUIRE(rig.role->function(fn0) != nullptr);
    BOOST_TEST(rig.t0.served() == &rig.role->function(fn0)->pci());
    BOOST_TEST(rig.role->function(fn0)->awaiting_key());

    // The VMM opens the function: an FLR. The wait survives it.
    rig.t0.flr();
    BOOST_TEST(rig.role->function(fn0)->awaiting_key());

    // The guest probes before helm's key arrives: its I/O waits.
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    const auto plain = marker();
    const auto w = g.post(RequestType::out, marker_sector, plain);
    BOOST_TEST(!rig.role->poll());
    BOOST_TEST(!g.completed(w));

    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::ok));
    static_cast<void>(rig.role->poll());
    BOOST_REQUIRE(g.completed(w));
    BOOST_TEST((g.status(w) == Status::ok));
    BOOST_TEST(g.read(marker_sector) == plain, boost::test_tools::per_element());
    BOOST_TEST(g.serial() == blk::volume_serial(vol_one));

    // Only ciphertext reaches the file, and never the key.
    const auto bytes = file_bytes(rig.role->volume_path(vol_one));
    BOOST_TEST(!contains(bytes, plain));
    const auto key = test_key();
    BOOST_TEST(!contains(bytes, key));
}

BOOST_AUTO_TEST_CASE(prepare_and_key_rules) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.create(vol_two, vm_two) == oar::Status::ok);

    BOOST_TEST((rig.prepare(7, vm_one, vol_one) == oar::Status::unknown_function));
    BOOST_TEST(
        (rig.role->prepare_function({.fn = fn0,
                                     .type = ak::helm::FunctionType::nic_vf,
                                     .vm_id = vm_one,
                                     .config = oar::NicConfig{}}) == oar::Status::wrong_type));
    // Not the owner, or no such volume: refused, nothing attached.
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_one) == oar::Status::failed));
    BOOST_TEST((rig.prepare(fn0, vm_one, 0x999) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    // A key for a function with nothing prepared, or for another volume.
    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::busy));
    BOOST_TEST((rig.deliver(9, vol_one) == oar::Status::unknown_function));

    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_two) == oar::Status::busy));  // fn taken
    BOOST_TEST((rig.prepare(fn1, vm_one, vol_one) == oar::Status::busy));  // volume taken
    BOOST_TEST((rig.deliver(fn0, vol_two) == oar::Status::busy));
    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::ok));
    BOOST_TEST((rig.deliver(fn0, vol_one) == oar::Status::busy));  // drop first
    BOOST_TEST((rig.role->drop_key({.fn = fn0, .volume_id = vol_two}) == oar::Status::busy));
    BOOST_TEST((rig.role->drop_key({.fn = fn0, .volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST(!rig.role->function(fn0)->holds_key());
    BOOST_TEST((rig.role->drop_key({.fn = fn1, .volume_id = vol_one}) == oar::Status::ok));

    // A transport that cannot take the function leaves the placeholder.
    rig.t1.fail = true;
    BOOST_TEST((rig.prepare(fn1, vm_two, vol_two) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn1).has_value());
}

BOOST_AUTO_TEST_CASE(cleaning_closes_the_volume) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    {
        Guest g{rig.ram0, *rig.t0.served()};
        BOOST_REQUIRE(g.up());
        BOOST_TEST((g.write(far_sector, marker()) == Status::ok));
    }
    auto* const attached_pci = rig.t0.served();

    BOOST_TEST(
        (rig.role->clean_function({.fn = fn0, .action = ak::helm::CleaningAction::reset_nic_vf}) ==
         oar::Status::wrong_type));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    BOOST_TEST(rig.role->function(fn0) == nullptr);
    BOOST_TEST(rig.t0.served() != attached_pci);
    // The placeholder is back: a driver finds a disk it cannot read.
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    const auto id = g.post(RequestType::in, far_sector, {}, blk::sector_size);
    BOOST_TEST((g.status(id) == Status::ioerr));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));  // idempotent
    BOOST_TEST((rig.clean(5) == oar::Status::unknown_function));

    // The volume opens again, for its owner, with its data.
    BOOST_REQUIRE(rig.prepare(fn1, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn1, vol_one) == oar::Status::ok);
    Guest g1{rig.ram1, *rig.t1.served()};
    BOOST_REQUIRE(g1.up());
    BOOST_TEST(g1.read(far_sector) == marker(), boost::test_tools::per_element());
}

// .kiro/specs/block-volume-service/ Requirement 3.3: helm asks for the
// guest to let go, and the role says when it has.
BOOST_AUTO_TEST_CASE(eject_waits_for_the_guest_to_let_go) {
    Rig rig;
    const auto ask = [&](oar::EjectOp op, oar::FunctionNumber fn = fn0) {
        return rig.role->eject({.fn = fn, .op = op});
    };
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    // Nothing attached: nothing to ask for.
    BOOST_TEST((ask(oar::EjectOp::request).error() == oar::Status::busy));
    BOOST_TEST((ask(oar::EjectOp::query).value() == oar::EjectState::none));
    BOOST_TEST((ask(oar::EjectOp::query, 5).error() == oar::Status::unknown_function));

    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    Guest g{rig.ram0, *rig.t0.served()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST((ask(oar::EjectOp::query).value() == oar::EjectState::none));
    BOOST_TEST((ask(oar::EjectOp::request).value() == oar::EjectState::requested));
    BOOST_TEST(rig.t0.served()->eject_requested());
    // Still mounted, as far as the device can tell: it keeps serving.
    rig.now += std::chrono::minutes{10};
    BOOST_TEST((ask(oar::EjectOp::query).value() == oar::EjectState::requested));
    BOOST_TEST((g.write(far_sector, marker()) == Status::ok));

    // The guest withdraws the disk.
    BOOST_REQUIRE(g.release());
    BOOST_TEST((ask(oar::EjectOp::query).value() == oar::EjectState::requested));
    rig.now += blk::release_quiet;
    BOOST_TEST((ask(oar::EjectOp::query).value() == oar::EjectState::released));
    BOOST_TEST((ask(oar::EjectOp::request).value() == oar::EjectState::released));  // idempotent

    // Withdrawn, then cleaned: the placeholder carries no request.
    BOOST_TEST((ask(oar::EjectOp::cancel).value() == oar::EjectState::none));
    BOOST_TEST((ask(oar::EjectOp::request).value() == oar::EjectState::requested));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));
    BOOST_TEST(!rig.t0.served()->eject_requested());
    BOOST_TEST((ask(oar::EjectOp::query).value() == oar::EjectState::none));
}

BOOST_AUTO_TEST_CASE(rewrap_changes_the_owner_on_the_media) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    const std::vector<std::byte> rewrapped(wrapped_size, std::byte{rewrapped_fill});
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    // Not while it is attached.
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = vol_one, .owner_vm = vm_two, .wrapped_key = rewrapped}) ==
                oar::Status::busy));
    BOOST_REQUIRE(rig.clean(fn0) == oar::Status::ok);
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = vol_one, .owner_vm = vm_two, .wrapped_key = rewrapped}) ==
                oar::Status::ok));
    const auto m = blk::FileBackend::open(rig.role->volume_path(vol_one)).value()->metadata();
    BOOST_TEST(m.owner_vm == vm_two);
    BOOST_TEST((m.wrapped_key == rewrapped));
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::failed));
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_one) == oar::Status::ok));
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = 0x999, .owner_vm = vm_two, .wrapped_key = rewrapped}) ==
                oar::Status::failed));
}

BOOST_AUTO_TEST_CASE(delete_erases_even_an_attached_volume) {
    Rig rig;
    BOOST_REQUIRE(rig.create(vol_one, vm_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    const auto path = rig.role->volume_path(vol_one);
    BOOST_REQUIRE(std::filesystem::exists(path));

    // DESTROY_VM without persist_volumes: helm deletes before the function
    // is cleaned. The role lets go of it, then erases.
    BOOST_TEST((rig.role->delete_volume({.volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST(!std::filesystem::exists(path));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    // A retried delete is not an error.
    BOOST_TEST((rig.role->delete_volume({.volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST((rig.clean(fn0) == oar::Status::ok));
}

// helm's real KeyStore and OarLink against the role over a socket pair:
// the wrapped key helm keeps is the one on the media, and the unwrapped key
// helm delivers is the one the data is encrypted with.
BOOST_AUTO_TEST_CASE(helm_drives_the_role_over_the_sideband) {
    Rig rig;
    auto se = ak::helm::SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se);
    ak::helm::KeyStore keys{*se};
    BOOST_REQUIRE(keys.create_vm_key(vm_one));
    BOOST_REQUIRE(keys.create_volume_key(vol_one, vm_one));
    const auto wrapped = keys.find_volume_key(vol_one).value();

    auto pair = ak::helm::SocketBinding::make_pair();
    BOOST_REQUIRE(pair);
    ak::helm::OarLink link{*pair->first, {.address = helm_side, .timeout = link_timeout}};
    ak::helm::OarEndpoint endpoint{*pair->second, {.address = helm_side.reversed()}};
    {
        const std::jthread server{[&](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                auto r = endpoint.serve_one(*rig.role, serve_poll);
                if (!r && r.error() != ak::helm::BindingError::timed_out) {
                    return;
                }
            }
        }};
        BOOST_TEST(link.function_inventory().value().functions.size() == function_count);
        BOOST_TEST(link.create_volume({.volume_id = vol_one,
                                       .owner_vm = vm_one,
                                       .capacity_sectors = volume_sectors,
                                       .block_size = blk::sector_size,
                                       .wrapped_key = wrapped.key.bytes()})
                       .has_value());
        BOOST_TEST(link.prepare_function({.fn = fn1,
                                          .type = ak::helm::FunctionType::blk_fn,
                                          .vm_id = vm_one,
                                          .config = oar::BlkConfig{.volume_id = vol_one}})
                       .has_value());
        auto key = keys.unwrap_volume_key(vol_one, vm_one);
        BOOST_REQUIRE(key);
        BOOST_TEST(link.deliver_key(fn1, vol_one, std::move(*key)).has_value());
    }
    // The media holds exactly helm's wrapped blob.
    const auto m = blk::FileBackend::open(rig.role->volume_path(vol_one)).value()->metadata();
    BOOST_TEST(std::ranges::equal(m.wrapped_key, wrapped.key.bytes()));

    Guest g{rig.ram1, *rig.t1.served()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST((g.write(marker_sector, marker()) == Status::ok));
    BOOST_TEST(g.read(marker_sector) == marker(), boost::test_tools::per_element());
    BOOST_TEST(!contains(file_bytes(rig.role->volume_path(vol_one)), marker()));
}

// ---- image volumes (task 13) ---------------------------------------------

// A 96 KiB image (one full 64 KiB chunk and a 32 KiB tail) of numbered
// sectors, the marker at marker_sector; the 128 KiB volume reads zeros past it.
constexpr std::uint64_t image_sectors = 192;

auto image_raw() -> std::vector<std::byte> {
    std::vector<std::byte> raw(image_sectors * blk::sector_size);
    for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<std::byte>((i / blk::sector_size) + 1);
    }
    const auto m = marker();
    std::ranges::copy(m,
                      raw.begin() + static_cast<std::ptrdiff_t>(marker_sector * blk::sector_size));
    return raw;
}

auto sector_of(const std::vector<std::byte>& raw, std::uint64_t sector) -> std::vector<std::byte> {
    const auto from = static_cast<std::ptrdiff_t>(sector * blk::sector_size);
    return {raw.begin() + from, raw.begin() + from + static_cast<std::ptrdiff_t>(blk::sector_size)};
}

BOOST_AUTO_TEST_CASE(image_volume_create_writes_only_a_header) {
    Rig rig{true};
    const auto name = rig.publish(image_raw());
    BOOST_TEST((rig.create_image(vol_one, vm_one, name) == oar::Status::ok));
    const auto path = rig.role->volume_path(vol_one);
    BOOST_TEST(std::filesystem::file_size(path) == blk::metadata_block_size);
    const auto m = blk::FileBackend::read_metadata(path);
    BOOST_REQUIRE(m.has_value());
    BOOST_REQUIRE(m->image.has_value());
    BOOST_TEST(m->image->store_id == image_store_id);
    BOOST_TEST((m->image->name == name));
    BOOST_TEST(m->wrapped_key.empty());
    BOOST_TEST((rig.create_image(vol_one, vm_one, name) == oar::Status::failed));  // exists
    // A store the role does not know, or a role with no image stores.
    BOOST_TEST((rig.create_image(vol_two, vm_one, name, 9) == oar::Status::unsupported));
    Rig plain;
    BOOST_TEST((plain.create_image(vol_two, vm_one, name) == oar::Status::unsupported));
    // Image volumes cannot be rewrapped yet (no key to rewrap); delete works.
    const std::vector<std::byte> wrapped(wrapped_size, std::byte{wrapped_fill});
    BOOST_TEST((rig.role->rewrap_volume(
                    {.volume_id = vol_one, .owner_vm = vm_two, .wrapped_key = wrapped}) ==
                oar::Status::failed));
    BOOST_TEST((rig.role->delete_volume({.volume_id = vol_one}) == oar::Status::ok));
    BOOST_TEST(!std::filesystem::exists(path));
}

BOOST_AUTO_TEST_CASE(image_volume_serves_the_image_and_forgets_writes) {
    Rig rig{true};
    const auto raw = image_raw();
    const auto name = rig.publish(raw);
    BOOST_REQUIRE(rig.create_image(vol_one, vm_one, name) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_two, vol_one) == oar::Status::failed));  // not the owner
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    rig.t0.flr();  // the VMM opens the function
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);

    Guest g{rig.ram0, *rig.t0.served(), rig.role.get()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST(g.read(marker_sector) == marker(), boost::test_tools::per_element());
    BOOST_TEST(g.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST(g.read(far_sector) == std::vector<std::byte>(blk::sector_size),
               boost::test_tools::per_element());  // past the image: zeros
    BOOST_TEST(g.serial() == blk::volume_serial(vol_one));

    // Writes land in the overlay and read back...
    const std::vector<std::byte> mine(blk::sector_size, std::byte{0xEE});
    BOOST_TEST((g.write(3, mine) == Status::ok));
    BOOST_TEST((g.write(far_sector, mine) == Status::ok));
    BOOST_TEST(g.read(3) == mine, boost::test_tools::per_element());
    BOOST_TEST(g.read(far_sector) == mine, boost::test_tools::per_element());
    // ...never reaching the object store or the volume file.
    const auto stored = rig.store.get(
        objstore::image_data_key(image_prefix, objstore::image_name_hex(name)), 1U << 20U, {});
    BOOST_TEST(!contains(*stored, mine));
    BOOST_TEST(std::filesystem::file_size(rig.role->volume_path(vol_one)) ==
               blk::metadata_block_size);

    // An FLR takes the key and the overlay: with a new key the image is as
    // it was.
    rig.t0.flr();
    BOOST_TEST(!rig.role->function(fn0)->holds_key());
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    Guest g2{rig.ram0, *rig.t0.served(), rig.role.get()};
    BOOST_REQUIRE(g2.up());
    BOOST_TEST(g2.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST(g2.read(far_sector) == std::vector<std::byte>(blk::sector_size),
               boost::test_tools::per_element());

    // So does drop_key, and so does detach (cleaning) and a new attachment.
    BOOST_TEST((g2.write(3, mine) == Status::ok));
    BOOST_TEST((rig.role->drop_key({.fn = fn0, .volume_id = vol_one}) == oar::Status::ok));
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    BOOST_TEST(g2.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST((g2.write(3, mine) == Status::ok));
    BOOST_REQUIRE(rig.clean(fn0) == oar::Status::ok);
    BOOST_TEST(!rig.role->attached(fn0).has_value());
    BOOST_REQUIRE(rig.prepare(fn1, vm_one, vol_one) == oar::Status::ok);
    BOOST_REQUIRE(rig.deliver(fn1, vol_one) == oar::Status::ok);
    Guest g3{rig.ram1, *rig.t1.served(), rig.role.get()};
    BOOST_REQUIRE(g3.up());
    BOOST_TEST(g3.read(3) == sector_of(raw, 3), boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(image_volume_serves_writes_and_flushes_behind_a_miss) {
    Rig rig{true};
    const auto raw = image_raw();
    const auto name = rig.publish(raw);
    BOOST_REQUIRE(rig.create_image(vol_one, vm_one, name) == oar::Status::ok);
    BOOST_REQUIRE(rig.prepare(fn0, vm_one, vol_one) == oar::Status::ok);
    rig.t0.flr();
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    Guest g{rig.ram0, *rig.t0.served(), rig.role.get()};
    BOOST_REQUIRE(g.up());

    // The read misses and waits for a fetch the store holds back; the
    // write and flush queued behind it complete anyway.
    rig.store.hold();
    const auto read = g.post(RequestType::in, 3, {}, blk::sector_size);
    const std::vector<std::byte> mine(blk::sector_size, std::byte{0xEE});
    const auto write = g.post(RequestType::out, far_sector, mine);
    const auto flush = g.post(RequestType::flush, 0);
    BOOST_TEST(!g.completed(read));
    BOOST_REQUIRE(g.completed(write));
    BOOST_REQUIRE(g.completed(flush));
    BOOST_TEST((g.status(write) == Status::ok));
    BOOST_TEST((g.status(flush) == Status::ok));

    rig.store.release();
    BOOST_REQUIRE(g.wait(read));
    BOOST_TEST((g.status(read) == Status::ok));
    BOOST_TEST(g.data(read) == sector_of(raw, 3), boost::test_tools::per_element());
    BOOST_TEST(g.read(far_sector) == mine, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(image_in_flight_must_fit_the_queue) {
    TempDir dir;
    GuestRam ram;
    FakeTransport t{ram};
    for (const std::uint16_t n : {std::uint16_t{0}, std::uint16_t{ak::test::test_queue_size + 1}}) {
        blk::RoleConfig c;
        c.volume_dir = dir.path;
        c.queue_size = ak::test::test_queue_size;
        c.image_max_in_flight = n;
        const bool created = blk::BlkRole::create(std::move(c), {&t}).has_value();
        BOOST_TEST(!created);
    }
}

BOOST_AUTO_TEST_CASE(image_volume_refuses_a_missing_or_wrong_image) {
    Rig rig{true};
    const auto name = rig.publish(image_raw());
    // Named but never published.
    oar::ImageName missing = name;
    missing[0] ^= std::byte{1};
    BOOST_REQUIRE(rig.create_image(vol_one, vm_one, missing) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn0).has_value());

    // The store answers with another image's manifest under this name.
    auto other = image_raw();
    other[0] = std::byte{0x77};
    const auto other_name = rig.publish(other);
    const auto other_manifest = rig.store.get(
        objstore::image_manifest_key(image_prefix, objstore::image_name_hex(other_name)), 1U << 26U,
        {});
    rig.store.put(objstore::image_manifest_key(image_prefix, objstore::image_name_hex(missing)),
                  *other_manifest);
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_one) == oar::Status::failed));

    // An encrypted image waits for helm to deliver its key (task 15).
    const auto key = test_key();
    const auto secret = rig.publish(image_raw(), blk::XtsKey{key});
    BOOST_REQUIRE(rig.create_image(vol_two, vm_one, secret) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_one, vol_two) == oar::Status::failed));

    // The image is fine but the volume is smaller than it.
    BOOST_REQUIRE(rig.role->create_volume({.volume_id = 0x203,
                                           .owner_vm = vm_one,
                                           .capacity_sectors = image_sectors - 8,
                                           .block_size = blk::sector_size,
                                           .wrapped_key = {},
                                           .image_store = image_store_id,
                                           .image_name = name}) == oar::Status::ok);
    BOOST_TEST((rig.prepare(fn0, vm_one, 0x203) == oar::Status::failed));
    BOOST_TEST(!rig.role->attached(fn0).has_value());
}

BOOST_AUTO_TEST_CASE(network_volume_serves_the_guest_through_hold) {
    ak::test::TestCa ca{"storage CA"};
    Hold hold{ca};
    Rig rig{false, compute_tls(ca)};
    BOOST_REQUIRE((rig.role->replica_config(frame_of(net_config(compute_id, hold.port()))) ==
                   oar::Status::ok));
    BOOST_REQUIRE((rig.role->prepare_function(
                       {.fn = fn0,
                        .type = ak::helm::FunctionType::blk_fn,
                        .vm_id = vm_one,
                        .config = oar::BlkConfig{.volume_id = vol_one,
                                                 .attachment_id = net_attachment,
                                                 .generation = 1}}) == oar::Status::ok));
    BOOST_TEST((rig.role->attached(fn0) == vol_one));
    BOOST_TEST(rig.role->function(fn0)->awaiting_key());
    rig.t0.flr();  // the VMM opens the function
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);

    Guest g{rig.ram0, *rig.t0.served(), rig.role.get()};
    BOOST_REQUIRE(g.up());
    BOOST_TEST(g.serial() == blk::volume_serial(vol_one));
    const auto plain = marker();
    const auto w = g.post(RequestType::out, marker_sector, plain);
    BOOST_REQUIRE(g.wait(w));
    BOOST_TEST((g.status(w) == Status::ok));
    BOOST_TEST(g.read(marker_sector) == plain, boost::test_tools::per_element());

    // A new epoch re-routes the live attachment; it keeps serving.
    BOOST_REQUIRE(hold.apply(net_config(hold_id, hold.port(), 2)));
    BOOST_TEST((rig.role->replica_config(frame_of(net_config(compute_id, hold.port(), 2))) ==
                oar::Status::ok));
    BOOST_TEST(g.read(marker_sector) == plain, boost::test_tools::per_element());
    BOOST_TEST(rig.role->function(fn0)->geometry().capacity_sectors == volume_sectors);

    // A resize epoch grows the guest's disk online (Requirement 10.3): the
    // hold first, then the function, whose capacity the guest can re-read.
    auto grown = net_config(hold_id, hold.port(), 3);
    grown.capacity_blocks = 2 * volume_sectors;
    BOOST_REQUIRE(hold.apply(grown));
    grown.server_id = compute_id;
    BOOST_TEST((rig.role->replica_config(frame_of(grown)) == oar::Status::ok));
    BOOST_TEST(rig.role->function(fn0)->geometry().capacity_sectors == 2 * volume_sectors);
    BOOST_TEST(*rig.role->function(fn0)->read_config(blk::blk_cfg::capacity, 8) ==
               2 * volume_sectors);
    BOOST_TEST(g.read(marker_sector) == plain, boost::test_tools::per_element());

    // Detach closes the session and frees the function.
    BOOST_REQUIRE(rig.clean(fn0) == oar::Status::ok);
    BOOST_TEST(!rig.role->attached(fn0).has_value());
}

BOOST_AUTO_TEST_CASE(network_volume_configs_must_be_signed_for_this_server) {
    ak::test::TestCa ca{"storage CA"};
    {
        Rig plain{false, std::nullopt, false};  // no controller keys: no network volumes
        BOOST_TEST((plain.role->replica_config(frame_of(net_config(compute_id, 4430))) ==
                    oar::Status::unsupported));
    }
    Rig rig{false, compute_tls(ca)};
    auto bad_sig = net_config(compute_id, 4430);
    bad_sig.signature[0] = std::byte{0};
    BOOST_TEST((rig.role->replica_config(frame_of(bad_sig)) == oar::Status::failed));
    BOOST_TEST((rig.role->replica_config(frame_of(net_config(hold_id, 4430))) ==
                oar::Status::failed));  // signed for another server
    BOOST_TEST((rig.role->replica_config(std::vector<std::byte>(12)) == oar::Status::bad_request));

    const auto prepare = [&](std::uint64_t attachment, std::uint32_t generation) {
        return rig.role->prepare_function(
            {.fn = fn0,
             .type = ak::helm::FunctionType::blk_fn,
             .vm_id = vm_one,
             .config = oar::BlkConfig{
                 .volume_id = vol_one, .attachment_id = attachment, .generation = generation}});
    };
    BOOST_TEST((prepare(net_attachment, 1) == oar::Status::failed));  // no config yet
    BOOST_REQUIRE(
        (rig.role->replica_config(frame_of(net_config(compute_id, 4430, 2))) == oar::Status::ok));
    BOOST_TEST((rig.role->replica_config(frame_of(net_config(compute_id, 4430, 1))) ==
                oar::Status::failed));                                    // stale
    BOOST_TEST((prepare(net_attachment, 2) == oar::Status::failed));      // wrong generation
    BOOST_TEST((prepare(net_attachment + 1, 1) == oar::Status::failed));  // unknown attachment
    BOOST_TEST(!rig.role->attached(fn0).has_value());
}

BOOST_AUTO_TEST_CASE(network_volume_waits_for_the_storage_certificate) {
    ak::test::TestCa ca{"storage CA"};
    Hold hold{ca};
    Rig rig;  // controller keys, but no storage certificate yet
    TempDir idir;
    auto identity = ak::tls::RoleIdentity::open({.key_path = idir.path / "storage.key",
                                                 .cert_path = idir.path / "storage.crt",
                                                 .ca_pem = ca.cert_pem(),
                                                 .server_id = compute_id,
                                                 .common_name = "oar-blk",
                                                 .addresses = {}});
    BOOST_REQUIRE(identity.has_value());
    ak::helm::RoleEnrollment enrollment{*identity, oar::Role::blk, ak::tls::Role::client,
                                        [&rig](const ak::tls::Config& cfg) {
                                            rig.role->set_storage_tls(cfg);
                                            return true;
                                        }};
    rig.role->set_enrollment(enrollment);

    const oar::PrepareFunction prep{
        .fn = fn0,
        .type = ak::helm::FunctionType::blk_fn,
        .vm_id = vm_one,
        .config =
            oar::BlkConfig{.volume_id = vol_one, .attachment_id = net_attachment, .generation = 1}};
    // Configs are taken (they only need the controller's key), but an
    // attachment waits for a certificate to present.
    BOOST_REQUIRE((rig.role->replica_config(frame_of(net_config(compute_id, hold.port()))) ==
                   oar::Status::ok));
    BOOST_TEST((rig.role->prepare_function(prep) == oar::Status::failed));

    auto asked = rig.role->cert_request();
    BOOST_REQUIRE(asked.has_value());
    BOOST_TEST((asked->role == oar::Role::blk));
    BOOST_REQUIRE(!asked->csr.empty());
    const std::vector<std::byte> csr{asked->csr.begin(), asked->csr.end()};
    // helm passes on whatever it is given; the role checks it.
    BOOST_TEST((rig.role->role_certificate(ca.sign_request(csr, server_san(hold_id))) ==
                oar::Status::failed));
    BOOST_TEST((rig.role->prepare_function(prep) == oar::Status::failed));
    BOOST_TEST((rig.role->role_certificate(ca.sign_request(csr, server_san(compute_id))) ==
                oar::Status::ok));
    BOOST_TEST(enrollment.stats().installed == 1U);
    BOOST_TEST(enrollment.stats().refused == 1U);
    BOOST_TEST(rig.role->cert_request().value().csr.empty());

    BOOST_REQUIRE((rig.role->prepare_function(prep) == oar::Status::ok));
    rig.t0.flr();
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    Guest g{rig.ram0, *rig.t0.served(), rig.role.get()};
    BOOST_REQUIRE(g.up());
    const auto plain = marker();
    const auto w = g.post(RequestType::out, marker_sector, plain);
    BOOST_REQUIRE(g.wait(w));
    BOOST_TEST((g.status(w) == Status::ok));
    BOOST_TEST(g.read(marker_sector) == plain, boost::test_tools::per_element());
    BOOST_REQUIRE(rig.clean(fn0) == oar::Status::ok);
}

BOOST_AUTO_TEST_CASE(roles_without_enrollment_answer_unsupported) {
    Rig rig;
    BOOST_TEST((rig.role->cert_request().error() == oar::Status::unsupported));
    BOOST_TEST((rig.role->role_certificate(std::vector<std::byte>(4)) == oar::Status::unsupported));
}

BOOST_AUTO_TEST_CASE(network_volume_read_only_attachment_refuses_writes) {
    ak::test::TestCa ca{"storage CA"};
    const Hold hold{ca};
    Rig rig{false, compute_tls(ca)};
    BOOST_REQUIRE(
        (rig.role->replica_config(frame_of(net_config(
             compute_id, hold.port(), 1, ak::proto::AttachMode::ro))) == oar::Status::ok));
    BOOST_REQUIRE((rig.role->prepare_function(
                       {.fn = fn0,
                        .type = ak::helm::FunctionType::blk_fn,
                        .vm_id = vm_one,
                        .config = oar::BlkConfig{.volume_id = vol_one,
                                                 .attachment_id = net_attachment,
                                                 .generation = 1}}) == oar::Status::ok));
    rig.t0.flr();
    BOOST_REQUIRE(rig.deliver(fn0, vol_one) == oar::Status::ok);
    Guest g{rig.ram0, *rig.t0.served(), rig.role.get()};
    BOOST_REQUIRE(g.up());
    const auto w = g.post(RequestType::out, marker_sector, marker());
    BOOST_REQUIRE(g.wait(w));
    BOOST_TEST((g.status(w) != Status::ok));
    static_cast<void>(g.read(marker_sector));  // reads still work
}

BOOST_AUTO_TEST_SUITE_END()
