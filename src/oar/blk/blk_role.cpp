// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/blk_role.hpp"

#include <format>
#include <limits>
#include <utility>

#include "oar/blk/file_backend.hpp"
#include "objstore/image_manifest.hpp"

namespace ak::oar::blk {

namespace {

namespace oar = helm::oar;

// The placeholder's whole "volume": one 4 KiB block nobody can read.
constexpr std::uint64_t placeholder_sectors = 8;
constexpr std::uint64_t placeholder_bytes = placeholder_sectors * sector_size;
constexpr std::string_view placeholder_serial = "akv-none";

// Every access fails: the placeholder never holds a key, so its requests
// never get this far, and if one did it would still reach nothing.
class NullBackend final : public SyncBlockBackend {
public:
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t override {
        return placeholder_bytes;
    }
    [[nodiscard]] auto read(std::uint64_t /*offset*/, std::span<std::byte> /*out*/)
        -> std::expected<void, BackendError> override {
        return std::unexpected(BackendError::io);
    }
    [[nodiscard]] auto write(std::uint64_t /*offset*/, std::span<const std::byte> /*in*/)
        -> std::expected<void, BackendError> override {
        return std::unexpected(BackendError::io);
    }
    [[nodiscard]] auto flush() -> std::expected<void, BackendError> override {
        return std::unexpected(BackendError::io);
    }
};

// FLR wipes the function's key; for an image volume the backend's copy
// goes too, and the overlay with it.
auto on_flr(VirtioBlkFunction& f, LazyImageBackend* image = nullptr,
            HydratingBackend* hydrating = nullptr) -> std::function<void()> {
    return [fn = &f, image, hydrating] {
        fn->function_reset();
        if (image != nullptr) {
            image->drop_keys();
        }
        if (hydrating != nullptr) {
            hydrating->drop_keys();
        }
    };
}

// Largest manifest: the header and 2^20 chunk digests (32 MiB).
constexpr std::size_t max_manifest_bytes =
    objstore::manifest_header_size_chunked +
    (std::size_t{objstore::max_image_chunks} * objstore::image_digest_size);

}  // namespace

auto volume_serial(std::uint64_t volume_id) -> std::string {
    return std::format("akv-{:016x}", volume_id);
}

auto BlkRole::create(RoleConfig config, const std::vector<FunctionTransport*>& transports)
    -> std::expected<std::unique_ptr<BlkRole>, std::string> {
    if (transports.empty() || transports.size() > std::numeric_limits<oar::FunctionNumber>::max()) {
        return std::unexpected("need between 1 and 65535 functions");
    }
    if (config.image_max_in_flight == 0 || config.image_max_in_flight > config.queue_size) {
        return std::unexpected("image_max_in_flight must be between 1 and queue_size");
    }
    if (!config.clock) {
        config.clock = [] { return RoleConfig::Clock::now(); };
    }
    std::unique_ptr<BlkRole> role{new BlkRole{std::move(config)}};
    role->_started = role->_config.clock();
    role->_slots.resize(transports.size());
    for (std::size_t i = 0; i < transports.size(); ++i) {
        Slot& s = role->_slots[i];
        s.transport = transports[i];
        if (s.transport == nullptr) {
            return std::unexpected(std::format("function {}: no transport", i));
        }
        const VolumeGeometry g{.capacity_sectors = placeholder_sectors,
                               .logical_block_size = sector_size,
                               .read_only = false,
                               .seg_max = role->_config.seg_max,
                               .max_transfer_bytes = role->_config.max_transfer_bytes};
        auto f =
            VirtioBlkFunction::create(role->params(g, placeholder_serial), s.transport->memory(),
                                      s.transport->interrupts(), std::make_unique<NullBackend>());
        if (!f) {
            return std::unexpected(std::format("function {}: {}", i, to_string(f.error())));
        }
        s.placeholder = std::move(*f);
        if (auto ok = s.transport->serve(s.placeholder->pci(), on_flr(*s.placeholder)); !ok) {
            return std::unexpected(std::format("function {}: {}", i, ok.error()));
        }
    }
    return role;
}

BlkRole::~BlkRole() = default;

auto BlkRole::params(const VolumeGeometry& geometry, std::string_view serial,
                     std::uint16_t max_in_flight) const -> BlkParams {
    return BlkParams{.geometry = geometry,
                     .num_queues = _config.num_queues,
                     .queue_size = _config.queue_size,
                     .budget = _config.budget,
                     .serial = serial,
                     .max_in_flight = max_in_flight};
}

auto BlkRole::volume_path(std::uint64_t volume_id) const -> std::filesystem::path {
    return _config.volume_dir / std::format("vol-{:016x}.akv", volume_id);
}

auto BlkRole::slot(oar::FunctionNumber fn) -> Slot* {
    return fn < _slots.size() ? &_slots[fn] : nullptr;
}

auto BlkRole::slot_of_volume(std::uint64_t volume) -> Slot* {
    for (auto& s : _slots) {
        if (s.active && s.volume == volume) {
            return &s;
        }
    }
    return nullptr;
}

auto BlkRole::attached(oar::FunctionNumber fn) const -> std::optional<std::uint64_t> {
    if (fn >= _slots.size() || !_slots[fn].active) {
        return std::nullopt;
    }
    return _slots[fn].volume;
}

auto BlkRole::function(oar::FunctionNumber fn) -> VirtioBlkFunction* {
    Slot* s = slot(fn);
    return s == nullptr ? nullptr : s->active.get();
}

auto BlkRole::close(Slot& s) -> bool {
    if (!s.active) {
        return true;
    }
    s.active->drop_key();
    if (s.image != nullptr) {
        s.image->drop_keys();
    }
    if (s.hydrating != nullptr) {
        s.hydrating->drop_keys();
    }
    // The placeholder goes back first, so the transport never points at a
    // destroyed function.
    s.placeholder->function_reset();
    if (auto ok = s.transport->serve(s.placeholder->pci(), on_flr(*s.placeholder)); !ok) {
        return false;
    }
    s.image = nullptr;
    s.network = nullptr;
    s.hydrating = nullptr;
    s.active.reset();
    s.volume = 0;
    return true;
}

auto BlkRole::open_image(std::uint32_t store_id, const objstore::ImageDigest& name)
    -> std::expected<OpenedImage, std::string> {
    const auto store = store_id > std::numeric_limits<std::uint16_t>::max()
                           ? _config.image_stores.end()
                           : _config.image_stores.find(static_cast<std::uint16_t>(store_id));
    if (_config.image_cache == nullptr || store == _config.image_stores.end() ||
        store->second.store == nullptr || store->second.fetcher == nullptr) {
        return std::unexpected(std::format("no image store {}", store_id));
    }
    const ImageStore& is = store->second;
    const std::string hex = objstore::image_name_hex(name);
    const auto deadline = objstore::ObjectStore::Clock::now() + _config.manifest_deadline;
    const auto bytes =
        is.store->get(objstore::image_manifest_key(is.prefix, hex), max_manifest_bytes, deadline);
    if (!bytes) {
        return std::unexpected(std::format("manifest {}: {}", hex, to_string(bytes.error())));
    }
    // The name pins the manifest: a store that returns another one is caught here.
    const auto manifest = objstore::decode_named_manifest(*bytes, name);
    if (!manifest) {
        return std::unexpected(std::format("manifest {}: {}", hex, to_string(manifest.error())));
    }
    if (manifest->chunked) {
        // A snapshot, not an image: restores hydrate through hold
        // (block-volume-service task 22), never from oar-blk.
        return std::unexpected(std::format("image {} is a snapshot", hex));
    }
    auto image =
        _config.image_cache->open_image(name, *manifest, objstore::image_data_key(is.prefix, hex));
    if (!image) {
        return std::unexpected(std::format("image {}: cache errno {}", hex, image.error()));
    }
    return OpenedImage{.image = std::move(*image), .fetcher = is.fetcher};
}

auto BlkRole::open_image_volume(const VolumeMetadata& m)
    -> std::expected<std::unique_ptr<LazyImageBackend>, std::string> {
    auto opened = open_image(m.image->store_id, m.image->name);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    const std::string hex = objstore::image_name_hex(m.image->name);
    const objstore::ImageManifest& mf = opened->image->manifest();
    // An encrypted image's volume holds K_img wrapped by helm (task 15),
    // and a plain image's holds no key: one without the other would only
    // fail at delivery, after the VMM has the function.
    if (mf.encrypted && m.wrapped_key.empty()) {
        return std::unexpected(std::format("image {} is encrypted and the volume has no key", hex));
    }
    if (!mf.encrypted && !m.wrapped_key.empty()) {
        return std::unexpected(std::format("image {} is plain and the volume has a key", hex));
    }
    auto backend = LazyImageBackend::create(
        {.image = std::move(opened->image),
         .fetcher = opened->fetcher,
         .overlay_dir = _config.overlay_dir.empty() ? _config.volume_dir : _config.overlay_dir,
         .capacity_bytes = m.capacity_sectors * sector_size,
         .logical_block_size = m.logical_block_size,
         .overlay_limit_bytes = _config.overlay_limit_bytes,
         .max_readahead_chunks = _config.max_readahead_chunks});
    if (!backend) {
        return std::unexpected(std::format("image {}: {}", hex, to_string(backend.error())));
    }
    return std::move(*backend);
}

// ---- functions -------------------------------------------------------------

auto BlkRole::function_inventory() -> std::expected<oar::Inventory, oar::Status> {
    oar::Inventory inv{.role = oar::Role::blk, .vtep = {}, .functions = {}};
    for (std::size_t i = 0; i < _slots.size(); ++i) {
        inv.functions.push_back(
            {.fn = static_cast<oar::FunctionNumber>(i), .type = helm::FunctionType::blk_fn});
    }
    return inv;
}

auto BlkRole::prepare_function(const oar::PrepareFunction& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    const auto* cfg = std::get_if<oar::BlkConfig>(&request.config);
    if (request.type != helm::FunctionType::blk_fn || cfg == nullptr) {
        return oar::Status::wrong_type;
    }
    if (s->active || slot_of_volume(cfg->volume_id) != nullptr) {
        return oar::Status::busy;
    }
    if (cfg->network()) {
        return prepare_network(*s, request, *cfg);
    }
    const auto m = FileBackend::read_metadata(volume_path(cfg->volume_id));
    if (!m || m->volume_id != cfg->volume_id || m->owner_vm != request.vm_id) {
        return oar::Status::failed;
    }
    std::unique_ptr<BlockBackend> backend;
    LazyImageBackend* image = nullptr;
    if (m->image) {
        auto lazy = open_image_volume(*m);
        if (!lazy) {
            return oar::Status::failed;
        }
        image = lazy->get();
        backend = std::move(*lazy);
    } else {
        auto file = FileBackend::open(volume_path(cfg->volume_id));
        // The file was read just now; refuse one that changed underneath.
        if (!file || (*file)->metadata() != *m) {
            return oar::Status::failed;
        }
        backend = std::move(*file);
    }
    const VolumeGeometry g{.capacity_sectors = m->capacity_sectors,
                           .logical_block_size = m->logical_block_size,
                           .read_only = false,
                           .seg_max = _config.seg_max,
                           .max_transfer_bytes = _config.max_transfer_bytes};
    const std::string serial = volume_serial(cfg->volume_id);
    // An image volume's misses park in the backend; let the rest of the
    // ring go on past them.
    const std::uint16_t in_flight = image != nullptr ? _config.image_max_in_flight : 1;
    auto f = VirtioBlkFunction::create(params(g, serial, in_flight), s->transport->memory(),
                                       s->transport->interrupts(), std::move(backend));
    if (!f) {
        return oar::Status::failed;
    }
    return serve_active(*s, std::move(*f), cfg->volume_id, image, nullptr);
}

auto BlkRole::serve_active(Slot& s, std::unique_ptr<VirtioBlkFunction> f, std::uint64_t volume,
                           LazyImageBackend* image, NetworkVolumeBackend* network,
                           HydratingBackend* hydrating) -> oar::Status {
    // Until helm's key arrives (after the VMM opened the function), the
    // guest's requests wait in the rings.
    f->await_key();
    if (auto ok = s.transport->serve(f->pci(), on_flr(*f, image, hydrating)); !ok) {
        // Back to the placeholder; if even that fails the transport is lost.
        static_cast<void>(s.transport->serve(s.placeholder->pci(), on_flr(*s.placeholder)));
        return oar::Status::failed;
    }
    s.active = std::move(f);
    s.volume = volume;
    s.image = image;
    s.network = network;
    s.hydrating = hydrating;
    return oar::Status::ok;
}

auto BlkRole::prepare_network(Slot& s, const oar::PrepareFunction& /*request*/,
                              const oar::BlkConfig& cfg) -> oar::Status {
    if (!_config.verify_config) {
        return oar::Status::unsupported;
    }
    if (!_config.storage_tls) {
        return oar::Status::failed;  // not enrolled yet: no certificate to present
    }
    const auto c = _configs.find(cfg.volume_id);
    if (c == _configs.end()) {
        return oar::Status::failed;  // helm sends the config first
    }
    const auto& rc = c->second;
    const auto att = std::ranges::find_if(rc.attachments, [&](const proto::VolumeAttachment& a) {
        return a.attachment_id == cfg.attachment_id;
    });
    if (att == rc.attachments.end() || att->generation != cfg.generation ||
        att->server_id != _config.server_id) {
        return oar::Status::failed;
    }
    auto initiator = _config.initiator;
    initiator.attachment_id = cfg.attachment_id;
    auto backend =
        NetworkVolumeBackend::create({.initiator = initiator,
                                      .tls = *_config.storage_tls,
                                      .connect_timeout = NetworkVolumeConfig{}.connect_timeout,
                                      .write_timeout = NetworkVolumeConfig{}.write_timeout});
    if (!backend || !(*backend)->set_route(rc)) {
        return oar::Status::failed;
    }
    NetworkVolumeBackend* network = backend->get();
    // A volume restored from an image under another key (task 23): oar-blk
    // hydrates it, in front of the network backend.
    std::unique_ptr<BlockBackend> served = std::move(*backend);
    HydratingBackend* hydrating = nullptr;
    if (rc.source.kind == proto::SourceKind::image) {
        auto opened = open_image(rc.source.store_id, rc.source.manifest_name);
        if (!opened) {
            return oar::Status::failed;
        }
        std::unique_ptr<HydrationTarget> target{
            static_cast<NetworkVolumeBackend*>(served.release())};
        auto h = HydratingBackend::create({.volume = std::move(target),
                                           .image = std::move(opened->image),
                                           .fetcher = opened->fetcher,
                                           .logical_block_size = rc.block_size,
                                           .hydrate_mib_per_s = rc.source.hydrate_mib_per_s,
                                           .max_background = _config.hydrate_max_background,
                                           .max_read_tries = HydratingParams{}.max_read_tries,
                                           .retry_backoff = HydratingParams{}.retry_backoff,
                                           .clock = {}});
        if (!h) {
            return oar::Status::failed;
        }
        hydrating = h->get();
        served = std::move(*h);
    }
    const VolumeGeometry g{
        .capacity_sectors = rc.capacity_blocks * (rc.block_size / oar::sector_size),
        .logical_block_size = rc.block_size,
        .read_only = att->mode == proto::AttachMode::ro,
        .seg_max = _config.seg_max,
        .max_transfer_bytes = _config.max_transfer_bytes};
    // Requests wait on the network: let the rest of the ring go past them.
    auto f = VirtioBlkFunction::create(
        params(g, volume_serial(cfg.volume_id), _config.image_max_in_flight), s.transport->memory(),
        s.transport->interrupts(), std::move(served));
    if (!f) {
        return oar::Status::failed;
    }
    return serve_active(s, std::move(*f), cfg.volume_id, nullptr, network, hydrating);
}

auto BlkRole::cert_request() -> std::expected<oar::CertAnswer, oar::Status> {
    if (_enrollment == nullptr) {
        return std::unexpected(oar::Status::unsupported);
    }
    return _enrollment->answer();
}

auto BlkRole::eject(const oar::Eject& request) -> std::expected<oar::EjectState, oar::Status> {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return std::unexpected(oar::Status::unknown_function);
    }
    if (!s->active) {
        // Nothing attached: nothing to release, and nothing to ask for.
        if (request.op == oar::EjectOp::request) {
            return std::unexpected(oar::Status::busy);
        }
        return oar::EjectState::none;
    }
    if (request.op == oar::EjectOp::request) {
        s->active->request_eject();
    } else if (request.op == oar::EjectOp::cancel) {
        s->active->cancel_eject();
    }
    switch (s->active->eject_state(_config.clock())) {
        case EjectState::none:
            return oar::EjectState::none;
        case EjectState::requested:
            return oar::EjectState::requested;
        case EjectState::released:
            return oar::EjectState::released;
    }
    return std::unexpected(oar::Status::failed);
}

auto BlkRole::role_certificate(std::span<const std::byte> chain) -> oar::Status {
    return _enrollment == nullptr ? oar::Status::unsupported : _enrollment->install(chain);
}

auto BlkRole::set_storage_tls(const tls::Config& config) -> void {
    _config.storage_tls = config;
    for (auto& s : _slots) {
        if (s.network != nullptr) {
            s.network->set_tls(config);
        }
    }
}

auto BlkRole::replica_config(std::span<const std::byte> frame) -> oar::Status {
    if (!_config.verify_config) {
        return oar::Status::unsupported;
    }
    auto c = proto::decode_replica_config(frame);
    if (!c) {
        return oar::Status::bad_request;
    }
    if (c->server_id != _config.server_id ||
        !_config.verify_config(proto::replica_config_signed_bytes(frame), c->signature,
                               c->key_id)) {
        return oar::Status::failed;
    }
    auto it = _configs.find(c->volume_id);
    if (it == _configs.end()) {
        if (_configs.size() >= max_network_configs) {
            return oar::Status::busy;
        }
    } else if (c->epoch < it->second.epoch) {
        return oar::Status::failed;
    }
    // A live attachment follows the new epoch: a new primary, fencing, new
    // QoS limits, or a larger capacity, which the guest then sees through
    // a configuration-change interrupt (Requirement 10.3).
    if (Slot* s = slot_of_volume(c->volume_id); s != nullptr && s->network != nullptr) {
        if (!s->network->set_route(*c)) {
            return oar::Status::failed;
        }
        const std::uint64_t sectors = s->network->size_bytes() / oar::sector_size;
        if (s->active && !s->network->fenced() &&
            sectors > s->active->geometry().capacity_sectors && !s->active->grow(sectors)) {
            return oar::Status::failed;
        }
    }
    _configs[c->volume_id] = std::move(*c);
    return oar::Status::ok;
}

auto BlkRole::clean_function(const oar::CleanFunction& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (request.action != helm::CleaningAction::drop_volume_key) {
        return oar::Status::wrong_type;
    }
    return close(*s) ? oar::Status::ok : oar::Status::failed;
}

auto BlkRole::deliver_key(const oar::DeliverKey& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (!s->active || s->volume != request.volume_id) {
        return oar::Status::busy;
    }
    // Only an image volume, or a network volume hydrating from an
    // encrypted image, takes an image key.
    if (request.image_key && s->image == nullptr && s->hydrating == nullptr) {
        return oar::Status::failed;
    }
    // The span views helm's message, which OarEndpoint wipes after this
    // returns; the function copies it into its key slot now.
    auto ok = s->active->deliver_key(request.key);
    if (!ok) {
        return ok.error() == KeyError::occupied ? oar::Status::busy : oar::Status::failed;
    }
    // An image volume's backend re-encrypts image blocks under the same
    // (ephemeral) key, decrypting an encrypted image's under K_img first
    // (task 15). Both hold the key or neither does; the backend refuses a
    // K_img for a plain image and its absence for an encrypted one.
    std::optional<XtsKey> image_key;
    if (request.image_key) {
        image_key = *request.image_key;
    }
    if (s->image != nullptr && !s->image->load_keys(request.key, image_key)) {
        s->active->drop_key();
        s->image->drop_keys();
        return oar::Status::failed;
    }
    // A hydrating network volume encrypts image blocks under the volume
    // key the function holds (task 23), decrypting an encrypted image's
    // with K_img first; the same both-or-neither rule.
    if (s->hydrating != nullptr && !s->hydrating->load_keys(request.key, image_key)) {
        s->active->drop_key();
        s->hydrating->drop_keys();
        return oar::Status::failed;
    }
    return oar::Status::ok;
}

auto BlkRole::drop_key(const oar::DropKey& request) -> oar::Status {
    Slot* s = slot(request.fn);
    if (s == nullptr) {
        return oar::Status::unknown_function;
    }
    if (s->active) {
        if (s->volume != request.volume_id) {
            return oar::Status::busy;
        }
        s->active->drop_key();
        if (s->image != nullptr) {
            s->image->drop_keys();  // and the overlay with it
        }
        if (s->hydrating != nullptr) {
            s->hydrating->drop_keys();
        }
    }
    return oar::Status::ok;
}

auto BlkRole::map_update(std::span<const std::byte> /*frame*/) -> oar::Status {
    return oar::Status::unsupported;
}

auto BlkRole::health() -> std::expected<oar::Health, oar::Status> {
    const auto up = std::chrono::duration_cast<std::chrono::seconds>(_config.clock() - _started);
    const auto secs = static_cast<std::uint64_t>(std::max<std::int64_t>(0, up.count()));
    return oar::Health{.state = oar::HealthState::ok,
                       .fault_code = 0,
                       .uptime_seconds = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                           secs, std::numeric_limits<std::uint32_t>::max()))};
}

auto BlkRole::poll() -> bool {
    bool more = false;
    for (auto& s : _slots) {
        if (s.active) {
            // The function itself, not pci().poll(): completions of requests
            // abandoned by a reset must run even while the driver is not live.
            more = s.active->poll() || more;
        }
    }
    return more;
}

auto BlkRole::wake_fds() const -> std::vector<int> {
    std::vector<int> fds;
    for (const auto& s : _slots) {
        if (s.active && s.active->wake_fd() >= 0) {
            fds.push_back(s.active->wake_fd());
        }
    }
    return fds;
}

// ---- volumes ---------------------------------------------------------------

auto BlkRole::create_volume(const oar::CreateVolume& request) -> oar::Status {
    VolumeMetadata m{.volume_id = request.volume_id,
                     .owner_vm = request.owner_vm,
                     .capacity_sectors = request.capacity_sectors,
                     .logical_block_size = request.block_size,
                     .wrapped_key = {request.wrapped_key.begin(), request.wrapped_key.end()},
                     .image = std::nullopt};
    // create() never overwrites: an existing volume file is refused.
    if (request.image_store == 0) {
        return FileBackend::create(volume_path(request.volume_id), m) ? oar::Status::ok
                                                                      : oar::Status::failed;
    }
    // An image volume names a store this role knows; whether the image is
    // there is checked when the volume is attached.
    if (_config.image_cache == nullptr || !_config.image_stores.contains(request.image_store)) {
        return oar::Status::unsupported;
    }
    m.image = ImageSource{.store_id = request.image_store, .name = request.image_name};
    return FileBackend::create_image_volume(volume_path(request.volume_id), m)
               ? oar::Status::ok
               : oar::Status::failed;
}

auto BlkRole::delete_volume(const oar::DeleteVolume& request) -> oar::Status {
    // helm crypto-erased the key first; a function still holding the volume
    // (its VM was destroyed and the function not yet cleaned) lets go now.
    if (Slot* s = slot_of_volume(request.volume_id); s != nullptr && !close(*s)) {
        return oar::Status::failed;
    }
    auto erased = FileBackend::erase(volume_path(request.volume_id));
    if (!erased && erased.error().error != FileError::not_found) {
        return oar::Status::failed;
    }
    // Already gone counts as done: a retried delete must not fail.
    return oar::Status::ok;
}

auto BlkRole::rewrap_volume(const oar::RewrapVolume& request) -> oar::Status {
    if (slot_of_volume(request.volume_id) != nullptr) {
        return oar::Status::busy;
    }
    // An encrypted image volume's key is K_img (task 15); a plain image
    // volume has none, and rewrap_image_volume refuses it.
    const auto m = FileBackend::read_metadata(volume_path(request.volume_id));
    if (m && m->image) {
        return FileBackend::rewrap_image_volume(volume_path(request.volume_id), request.owner_vm,
                                                request.wrapped_key)
                   ? oar::Status::ok
                   : oar::Status::failed;
    }
    auto backend = FileBackend::open(volume_path(request.volume_id));
    if (!backend) {
        return oar::Status::failed;
    }
    return (*backend)->rewrap(request.owner_vm, request.wrapped_key) ? oar::Status::ok
                                                                     : oar::Status::failed;
}

}  // namespace ak::oar::blk
