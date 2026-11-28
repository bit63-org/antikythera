// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/command_router.hpp"

#include <algorithm>
#include <utility>
#include <variant>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

constexpr std::size_t slot_type_offset = 0x06;

// The message type in a slot header, read without decoding the slot, so a
// malformed command's outcome can still name what it claimed to be.
auto slot_type(const proto::Slot& slot) noexcept -> std::uint16_t {
    wire::Reader r{std::span<const std::byte>{slot}.subspan(slot_type_offset)};
    return r.le16().value_or(0);
}

auto to_mailbox_slot(const proto::Slot& slot) noexcept -> mailbox::Slot {
    mailbox::Slot out{};
    std::ranges::copy(slot, out.begin());
    return out;
}

// A copy_volume query or release: it names the pair and carries no keys.
auto copy_request(oar::CopyOp op, VolumeId local, VolumeId network) -> oar::CopyVolume {
    return {.op = op,
            .direction = oar::CopyDirection::to_network,
            .mib_per_s = 0,
            .local_volume_id = local,
            .network_volume_id = network,
            .attachment_id = 0,
            .generation = 0,
            .local_key = std::nullopt,
            .network_key = std::nullopt};
}

auto link_status(const LinkError& e) noexcept -> mailbox::Status {
    switch (e.code) {
        case LinkErrc::timed_out:
            return mailbox::Status::timed_out;
        case LinkErrc::refused:
            switch (e.status) {
                case oar::Status::unknown_function:
                case oar::Status::wrong_type:
                    return mailbox::Status::unknown_device;
                case oar::Status::busy:
                    return mailbox::Status::conflict;
                case oar::Status::unsupported:
                    return mailbox::Status::unsupported;
                default:
                    return mailbox::Status::internal_error;
            }
        default:
            return mailbox::Status::internal_error;
    }
}

auto succeeded(mailbox::Status s) noexcept -> bool {
    return s == mailbox::Status::ok || s == mailbox::Status::accepted;
}

auto to_proto(FunctionType t) noexcept -> proto::FunctionType {
    return static_cast<proto::FunctionType>(t);
}

auto to_proto(FunctionState s) noexcept -> proto::FunctionState {
    return static_cast<proto::FunctionState>(s);
}

auto function_id(const mailbox::DeviceRef& d) noexcept -> FunctionId {
    return make_function_id(d.slot, d.function);
}

auto command_code(mailbox::Type t) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(t);
}

auto status_code(mailbox::Status s) noexcept -> std::uint16_t {
    return static_cast<std::uint16_t>(s);
}

// 512-byte sectors in a CREATE_VOLUME size (1 GiB = 2^21 sectors).
constexpr unsigned gib_sector_shift = 21;

}  // namespace

// ---- OarLinkPort -----------------------------------------------------------

auto OarLinkPort::prepare_function(const oar::PrepareFunction& request)
    -> std::expected<void, LinkError> {
    return _link->prepare_function(request);
}

auto OarLinkPort::clean_function(const oar::CleanFunction& request)
    -> std::expected<void, LinkError> {
    return _link->clean_function(request);
}

auto OarLinkPort::replica_config(std::span<const std::byte> frame)
    -> std::expected<void, LinkError> {
    return _link->replica_config(frame);
}

auto OarLinkPort::eject(const oar::Eject& request) -> std::expected<oar::EjectState, LinkError> {
    return _link->eject(request);
}

auto OarLinkPort::copy_volume(const oar::CopyVolume& request, std::optional<ScopedKey> local_key,
                              std::optional<ScopedKey> network_key)
    -> std::expected<oar::CopyAnswer, LinkError> {
    return _link->copy_volume(request, std::move(local_key), std::move(network_key));
}

auto OarLinkPort::group_policy(std::span<const std::byte> frame) -> std::expected<void, LinkError> {
    return _link->group_policy(frame);
}

auto OarLinkPort::group_usage() -> std::expected<std::vector<oar::UsageEntry>, LinkError> {
    return _link->group_usage();
}

auto OarLinkPort::group_members(std::span<const std::byte> frame)
    -> std::expected<void, LinkError> {
    return _link->group_members(frame);
}

auto OarLinkPort::group_membership(std::optional<std::uint32_t> since)
    -> std::expected<std::optional<OarLink::Memberships>, LinkError> {
    return _link->group_membership(since);
}

auto OarLinkPort::deliver_key(oar::FunctionNumber fn, VolumeId volume, ScopedKey key,
                              std::optional<ScopedKey> image_key)
    -> std::expected<void, LinkError> {
    return _link->deliver_key(fn, volume, std::move(key), std::move(image_key));
}

auto OarLinkPort::drop_key(const oar::DropKey& request) -> std::expected<void, LinkError> {
    return _link->drop_key(request);
}

auto OarLinkPort::create_volume(const oar::CreateVolume& request)
    -> std::expected<void, LinkError> {
    return _link->create_volume(request);
}

auto OarLinkPort::delete_volume(const oar::DeleteVolume& request)
    -> std::expected<void, LinkError> {
    return _link->delete_volume(request);
}

auto OarLinkPort::rewrap_volume(const oar::RewrapVolume& request)
    -> std::expected<void, LinkError> {
    return _link->rewrap_volume(request);
}

// ---- CommandRouter ---------------------------------------------------------

CommandRouter::CommandRouter(RouterConfig config, DevicePool& pool, KeyStore& keys, HostPort& host,
                             ReportSink& reports, AuditLog& audit)
    : _config{std::move(config)},
      _pool{&pool},
      _keys{&keys},
      _host{&host},
      _reports{&reports},
      _audit{&audit},
      _last_seq{_config.last_seq} {
    if (!_config.clock) {
        _config.clock = [] { return Clock::now(); };
    }
}

auto CommandRouter::now() const -> Clock::time_point {
    return _config.clock();
}

auto CommandRouter::audit(const AuditRecord& record) -> bool {
    if (!_audit->append(record)) {
        ++_stats.audit_failures;
        return false;
    }
    return true;
}

auto CommandRouter::port_for(std::uint8_t slot) -> OarPort* {
    const auto it = _ports.find(slot);
    return it == _ports.end() ? nullptr : it->second;
}

auto CommandRouter::storage_slot() const -> std::optional<std::uint8_t> {
    for (const auto& [slot, role] : _roles) {
        if (role == oar::Role::blk && _ports.contains(slot)) {
            return slot;
        }
    }
    return std::nullopt;
}

// ---- slots -----------------------------------------------------------------

auto CommandRouter::add_slot(std::uint8_t slot, OarPort& port, const oar::Inventory& inventory)
    -> void {
    _ports[slot] = &port;
    _roles[slot] = inventory.role;
    for (const auto& entry : inventory.functions) {
        const auto id = make_function_id(slot, entry.fn);
        // A function already known (the slot came back after a power
        // cycle) keeps its state; slot_power_cycled handles it.
        if (_pool->add(id, entry.type)) {
            start_cleaning(id);
        }
    }
}

auto CommandRouter::slot_power_cycled(std::uint8_t slot) -> void {
    for (const auto& info : _pool->all()) {
        if (slot_of(info.id) == slot && info.state == FunctionState::faulted &&
            pool_event(info.id, PoolEvent::power_cycle_done)) {
            start_cleaning(info.id);
        }
    }
}

// ---- envelopes -------------------------------------------------------------

auto CommandRouter::on_envelope(const proto::Envelope& envelope) -> void {
    const auto seq = proto::slot_seq(envelope.slot);
    const auto type = static_cast<mailbox::Type>(slot_type(envelope.slot));

    if (seq <= _last_seq) {
        if (const auto it = _history.find(seq); it != _history.end()) {
            ++_stats.duplicates;
            _reports->report(it->second);
            return;
        }
        const bool pending = (_in_flight && _in_flight->seq == seq) ||
                             std::ranges::any_of(_queue, [seq](const proto::Envelope& e) {
                                 return proto::slot_seq(e.slot) == seq;
                             });
        if (pending) {
            ++_stats.duplicates;
            return;
        }
        // Not recorded in the history: the sequence number belongs to some
        // other (older) command.
        ++_stats.refused;
        audit(AuditRecord::of(AuditEvent::command_refused)
                  .with_seq(seq)
                  .with_command(command_code(type))
                  .with_status(status_code(mailbox::Status::stale_sequence)));
        _reports->report(Outcome{.in_reply_to = seq,
                                 .command = command_code(type),
                                 .status = proto::CommandStatus::stale_sequence,
                                 .payload = {}});
        return;
    }
    if (_queue.size() >= _config.max_queued) {
        // Not accepted: the controller may send this sequence number again.
        ++_stats.refused;
        audit(AuditRecord::of(AuditEvent::command_refused)
                  .with_seq(seq)
                  .with_command(command_code(type))
                  .with_status(status_code(mailbox::Status::insufficient_resources)));
        _reports->report(Outcome{.in_reply_to = seq,
                                 .command = command_code(type),
                                 .status = proto::CommandStatus::insufficient_resources,
                                 .payload = {}});
        return;
    }
    _last_seq = seq;
    _queue.push_back(envelope);
    audit(AuditRecord::of(AuditEvent::command_received)
              .with_seq(seq)
              .with_command(command_code(type)));
    pump();
}

auto CommandRouter::pump() -> void {
    while (!_in_flight && !_waiting && !_queue.empty()) {
        const auto envelope = _queue.front();
        _queue.pop_front();
        dispatch(envelope);
    }
}

auto CommandRouter::dispatch(const proto::Envelope& envelope) -> void {
    const auto seq = proto::slot_seq(envelope.slot);
    const auto claimed = static_cast<mailbox::Type>(slot_type(envelope.slot));
    const auto slot = to_mailbox_slot(envelope.slot);

    const auto msg = mailbox::decode(slot);
    if (!msg || !mailbox::is_command(msg->header.type)) {
        refuse(seq, claimed, mailbox::Status::malformed);
        return;
    }
    const auto body = mailbox::decode_body(*msg);
    if (!body) {
        refuse(seq, claimed,
               body.error() == mailbox::BodyError::reserved_type ? mailbox::Status::unsupported
                                                                 : mailbox::Status::malformed);
        return;
    }

    Undo undo;
    if (auto ok = prepare(seq, *body, undo); !ok) {
        compensate(seq, undo);
        refuse(seq, claimed, ok.error());
        return;
    }
    if (const auto* d = std::get_if<mailbox::DetachVolume>(&*body);
        d != nullptr && d->policy == mailbox::DetachPolicy::wait) {
        start_wait(seq, slot, *d);  // prepare reserved nothing: no undo
        return;
    }
    if (const auto* w = std::get_if<mailbox::WithdrawDetach>(&*body)) {
        withdraw(seq, *w);  // helm's alone: never relayed
        return;
    }
    relay(seq, slot, *body, undo);
}

auto CommandRouter::relay(std::uint64_t seq, const mailbox::Slot& slot, const mailbox::Body& body,
                          Undo undo) -> void {
    const auto type = mailbox::type_of(body);
    // The relay record comes first; if it cannot be written the command is
    // not relayed.
    if (!audit(AuditRecord::of(AuditEvent::command_relayed)
                   .with_seq(seq)
                   .with_command(command_code(type)))) {
        compensate(seq, undo);
        refuse(seq, type, mailbox::Status::internal_error);
        return;
    }
    if (_config.sequence_recorder != nullptr && !_config.sequence_recorder->record(seq)) {
        ++_stats.sequence_record_failures;
        compensate(seq, undo);
        refuse(seq, type, mailbox::Status::internal_error);
        return;
    }
    if (!_host->post_command(slot)) {
        compensate(seq, undo);
        refuse(seq, type, mailbox::Status::internal_error);
        return;
    }
    ++_stats.relayed;
    _in_flight = InFlight{
        .seq = seq, .body = body, .undo = undo, .deadline = now() + _config.command_timeout};
}

// ---- cooperative detach ----------------------------------------------------

auto CommandRouter::start_wait(std::uint64_t seq, const mailbox::Slot& slot,
                               const mailbox::DetachVolume& detach) -> void {
    const auto id = function_id(detach.device);
    auto* port = port_for(detach.device.slot);
    if (port == nullptr) {
        refuse(seq, mailbox::Type::detach_volume, mailbox::Status::unknown_device);
        return;
    }
    // request is idempotent: a function already asked (an earlier detach
    // went busy) is asked again, which changes nothing on the role.
    const auto state = port->eject({.fn = detach.device.function, .op = oar::EjectOp::request});
    if (!state) {
        refuse(seq, mailbox::Type::detach_volume, link_status(state.error()));
        return;
    }
    const auto t = now();
    auto [it, fresh] = _ejecting.try_emplace(id);
    it->second.volume = detach.volume_id;
    it->second.next_query = t + _config.eject_poll_interval;
    if (fresh) {
        audit(AuditRecord::of(AuditEvent::eject_requested)
                  .with_seq(seq)
                  .with_vm(detach.vm_id)
                  .with_volume(detach.volume_id)
                  .with_function(id));
        report_attachment(detach.volume_id, detach.device.slot,
                          proto::AttachmentState::eject_requested);
    }
    note_eject(id, *state);
    if (*state == oar::EjectState::released) {
        ++_stats.detaches_released;
        relay(seq, slot, detach, Undo{});
        return;
    }
    _waiting = Waiting{.seq = seq,
                       .slot = slot,
                       .body = detach,
                       .deadline = t + std::chrono::seconds{detach.timeout_s}};
}

auto CommandRouter::withdraw(std::uint64_t seq, const mailbox::WithdrawDetach& withdraw) -> void {
    const auto id = function_id(withdraw.device);
    auto* port = port_for(withdraw.device.slot);
    if (port == nullptr) {
        refuse(seq, mailbox::Type::withdraw_detach, mailbox::Status::unknown_device);
        return;
    }
    // Always ask the role, even with nothing pending here: cancel is
    // idempotent there, and a request helm forgot (a restart) is cleared.
    const auto state = port->eject({.fn = withdraw.device.function, .op = oar::EjectOp::cancel});
    if (!state) {
        refuse(seq, mailbox::Type::withdraw_detach, link_status(state.error()));
        return;
    }
    if (_ejecting.erase(id) != 0) {
        ++_stats.detaches_withdrawn;
        audit(AuditRecord::of(AuditEvent::detach_withdrawn)
                  .with_seq(seq)
                  .with_vm(withdraw.vm_id)
                  .with_volume(withdraw.volume_id)
                  .with_function(id));
        report_attachment(withdraw.volume_id, withdraw.device.slot,
                          proto::AttachmentState::attached);
    }
    audit(AuditRecord::of(AuditEvent::command_outcome)
              .with_seq(seq)
              .with_command(command_code(mailbox::Type::withdraw_detach))
              .with_status(status_code(mailbox::Status::ok)));
    finish(seq, mailbox::Type::withdraw_detach, mailbox::Status::ok);
}

auto CommandRouter::query_eject(FunctionId id) -> std::optional<oar::EjectState> {
    const auto it = _ejecting.find(id);
    auto* port = port_for(slot_of(id));
    if (it == _ejecting.end() || port == nullptr) {
        return std::nullopt;
    }
    if (it->second.released) {
        return oar::EjectState::released;
    }
    const auto state = port->eject({.fn = function_number_of(id), .op = oar::EjectOp::query});
    if (!state) {
        return std::nullopt;
    }
    note_eject(id, *state);
    return *state;
}

auto CommandRouter::note_eject(FunctionId id, oar::EjectState state) -> void {
    const auto it = _ejecting.find(id);
    if (it == _ejecting.end() || it->second.released) {
        return;
    }
    if (state == oar::EjectState::released) {
        it->second.released = true;
        const auto info = _pool->find(id);
        audit(AuditRecord::of(AuditEvent::eject_released)
                  .with_vm(info && info->owner ? *info->owner : VmId{0})
                  .with_volume(it->second.volume)
                  .with_function(id));
        report_attachment(it->second.volume, slot_of(id), proto::AttachmentState::released);
    }
}

auto CommandRouter::poll_ejects(Clock::time_point t) -> void {
    if (_waiting) {
        const auto id = function_id(_waiting->body.device);
        auto it = _ejecting.find(id);
        const bool due = it == _ejecting.end() || t >= it->second.next_query;
        if (due && it != _ejecting.end()) {
            it->second.next_query = t + _config.eject_poll_interval;
        }
        if (due && query_eject(id) == oar::EjectState::released) {
            auto w = std::move(*_waiting);
            _waiting.reset();
            ++_stats.detaches_released;
            relay(w.seq, w.slot, w.body, Undo{});
        } else if (t >= _waiting->deadline) {
            // The guest still holds it: stay attached and serving
            // (Requirement 3.3). The request stays set.
            auto w = std::move(*_waiting);
            _waiting.reset();
            ++_stats.detaches_busy;
            if (it != _ejecting.end()) {
                it->second.busy = true;
            }
            audit(AuditRecord::of(AuditEvent::detach_busy)
                      .with_seq(w.seq)
                      .with_vm(w.body.vm_id)
                      .with_volume(w.body.volume_id)
                      .with_function(id));
            report_attachment(w.body.volume_id, w.body.device.slot, proto::AttachmentState::busy);
            finish(w.seq, mailbox::Type::detach_volume, mailbox::Status::busy);
        }
        if (!_waiting) {
            pump();
        }
    }
    // Busy detaches: a guest that lets go later is reported, so the
    // controller can detach again.
    for (auto& [id, e] : _ejecting) {
        if (!e.busy || e.released || t < e.next_query) {
            continue;
        }
        e.next_query = t + _config.eject_poll_interval;
        (void)query_eject(id);
    }
}

auto CommandRouter::report_attachment(VolumeId volume, std::uint8_t slot,
                                      proto::AttachmentState state) -> void {
    const auto it = _network.find(volume);
    if (it == _network.end() || it->second.attached_by == 0 || it->second.attachment == 0 ||
        it->second.generation == 0) {
        return;
    }
    _reports->report(proto::AttachmentStatus{.attachment_id = it->second.attachment,
                                             .volume_id = volume,
                                             .generation = it->second.generation,
                                             .state = state,
                                             .slot = slot,
                                             .in_flight = 0});
}

auto CommandRouter::fenced(const NetworkVolume& net) const -> bool {
    const auto c = proto::decode_replica_config(net.frame);
    if (!c) {
        return false;
    }
    // hold authorizes a session by the server its certificate names and
    // the generation, so the attachment is fenced once no entry grants
    // that pair to this server.
    return std::ranges::none_of(c->attachments, [&](const proto::VolumeAttachment& a) {
        return a.server_id == _config.server_id && a.attachment_id == net.attachment &&
               a.generation == net.generation;
    });
}

auto CommandRouter::reserve(VmId vm, const mailbox::DeviceRef& device, Undo& undo)
    -> std::expected<FunctionId, mailbox::Status> {
    const auto id = function_id(device);
    const auto info = _pool->find(id);
    if (!info || info->type != static_cast<FunctionType>(device.type) ||
        port_for(device.slot) == nullptr) {
        return std::unexpected(mailbox::Status::unknown_device);
    }
    if (!assign(id, vm)) {
        return std::unexpected(mailbox::Status::conflict);
    }
    undo.reserved = id;
    return id;
}

auto CommandRouter::assign(FunctionId id, VmId vm) -> bool {
    const auto before = _pool->find(id);
    if (!before || !_pool->assign(id, vm)) {
        return false;
    }
    report_transition(id, before->state, *_pool->find(id), vm);
    return true;
}

auto CommandRouter::prepare(std::uint64_t seq, const mailbox::Body& body, Undo& undo)
    -> std::expected<void, mailbox::Status> {
    using mailbox::Status;

    if (const auto* c = std::get_if<mailbox::CreateVm>(&body)) {
        if (_vms.contains(c->vm_id)) {
            return std::unexpected(Status::conflict);
        }
        if (auto k = _keys->create_vm_key(c->vm_id); !k) {
            return std::unexpected(k.error() == KeyError::duplicate_vm ? Status::conflict
                                                                       : Status::internal_error);
        }
        undo.created_vm_key = c->vm_id;
        audit(AuditRecord::of(AuditEvent::vm_key_created).with_seq(seq).with_vm(c->vm_id));
        return {};
    }

    if (const auto* a = std::get_if<mailbox::AttachDevice>(&body)) {
        const auto type = static_cast<FunctionType>(a->device.type);
        oar::FunctionConfig config;
        if (type == FunctionType::nic_vf) {
            // decode_attach_device has checked these (non-zero VNI and NIC
            // ID, locally administered unicast MAC).
            config = oar::NicConfig{.nic_id = a->nic_id, .vni = a->vni, .mac = a->mac};
        }
        auto reserved = reserve(a->vm_id, a->device, undo);
        if (!reserved) {
            return std::unexpected(reserved.error());
        }
        auto* port = port_for(a->device.slot);
        if (port == nullptr) {  // reserve() checked; say so to the optimizer
            return std::unexpected(Status::unknown_device);
        }
        auto ok = port->prepare_function(
            {.fn = a->device.function, .type = type, .vm_id = a->vm_id, .config = config});
        if (!ok) {
            return std::unexpected(link_status(ok.error()));
        }
        return {};
    }

    if (const auto* d = std::get_if<mailbox::DetachDevice>(&body)) {
        const auto info = _pool->find(function_id(d->device));
        if (!info || info->type != static_cast<FunctionType>(d->device.type)) {
            return std::unexpected(Status::unknown_device);
        }
        if (info->state != FunctionState::assigned || info->owner != d->vm_id) {
            return std::unexpected(Status::conflict);
        }
        return {};
    }

    if (const auto* c = std::get_if<mailbox::CreateVolume>(&body);
        c != nullptr && c->image_store != 0) {
        if (_volumes.contains(c->volume_id) || _keys->owner(c->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        if (!_keys->find_vm_key(c->owner_vm)) {
            return std::unexpected(Status::unknown_vm);
        }
        const auto slot = storage_slot();
        if (!slot) {
            return std::unexpected(Status::insufficient_resources);
        }
        // An encrypted image: the controller sent K_img for this volume
        // ahead of the command. It becomes the volume's key, wrapped by the
        // owner's VM key, and the role keeps that on the media as it would
        // a disk volume's (task 15). Without one the image must be plain;
        // the role refuses to attach an encrypted image that has no key.
        std::optional<WrappedVolumeKey> image_key;
        if (_keys->image_key(c->volume_id)) {
            if (auto k = _keys->import_image_key(c->volume_id, c->owner_vm); !k) {
                switch (k.error()) {
                    case KeyError::wrong_vm:  // K_img was sent for another owner
                        return std::unexpected(Status::conflict);
                    case KeyError::unknown_vm:
                        return std::unexpected(Status::unknown_vm);
                    default:
                        return std::unexpected(Status::internal_error);
                }
            }
            undo.created_volume_key = c->volume_id;
            audit(AuditRecord::of(AuditEvent::volume_key_created)
                      .with_seq(seq)
                      .with_vm(c->owner_vm)
                      .with_volume(c->volume_id));
            image_key = _keys->find_volume_key(c->volume_id);
            if (!image_key) {
                return std::unexpected(Status::internal_error);
            }
        }
        auto* port = port_for(*slot);
        if (port == nullptr) {  // storage_slot() checked; say so to the optimizer
            return std::unexpected(Status::insufficient_resources);
        }
        auto stored = port->create_volume(
            {.volume_id = c->volume_id,
             .owner_vm = c->owner_vm,
             .capacity_sectors = std::uint64_t{c->size_gib} << gib_sector_shift,
             .block_size = oar::sector_size,
             .wrapped_key = image_key ? image_key->key.bytes() : std::span<const std::byte>{},
             .image_store = c->image_store,
             .image_name = c->image_name});
        if (!stored) {
            return std::unexpected(link_status(stored.error()));
        }
        undo.stored_volume = StoredVolume{.volume = c->volume_id, .slot = *slot};
        return {};
    }

    if (const auto* c = std::get_if<mailbox::CreateVolume>(&body)) {
        if (_volumes.contains(c->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        if (auto k = _keys->create_volume_key(c->volume_id, c->owner_vm); !k) {
            switch (k.error()) {
                case KeyError::unknown_vm:
                    return std::unexpected(Status::unknown_vm);
                case KeyError::duplicate_volume:
                    return std::unexpected(Status::conflict);
                default:
                    return std::unexpected(Status::internal_error);
            }
        }
        undo.created_volume_key = c->volume_id;
        audit(AuditRecord::of(AuditEvent::volume_key_created)
                  .with_seq(seq)
                  .with_vm(c->owner_vm)
                  .with_volume(c->volume_id));
        const auto slot = storage_slot();
        if (!slot) {
            return std::unexpected(Status::insufficient_resources);
        }
        const auto wrapped = _keys->find_volume_key(c->volume_id);
        if (!wrapped) {
            return std::unexpected(Status::internal_error);
        }
        auto* port = port_for(*slot);
        if (port == nullptr) {  // storage_slot() checked; say so to the optimizer
            return std::unexpected(Status::insufficient_resources);
        }
        auto stored =
            port->create_volume({.volume_id = c->volume_id,
                                 .owner_vm = c->owner_vm,
                                 .capacity_sectors = std::uint64_t{c->size_gib} << gib_sector_shift,
                                 .block_size = oar::sector_size,
                                 .wrapped_key = wrapped->key.bytes(),
                                 .image_store = 0,
                                 .image_name = {}});
        if (!stored) {
            // Not marked for undo: a refused create (the volume exists on
            // the media, say) must not be answered by erasing it.
            return std::unexpected(link_status(stored.error()));
        }
        undo.stored_volume = StoredVolume{.volume = c->volume_id, .slot = *slot};
        return {};
    }

    if (const auto* d = std::get_if<mailbox::DeleteVolume>(&body)) {
        if (!volume_owner(d->volume_id)) {
            return std::unexpected(Status::unknown_volume);
        }
        if (_attached.contains(d->volume_id) || is_converting(d->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        return {};
    }

    if (const auto* a = std::get_if<mailbox::AttachVolume>(&body)) {
        if (is_converting(a->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        const auto owner = volume_owner(a->volume_id);
        if (!owner && _network.contains(a->volume_id)) {
            return prepare_network_attach(*a, undo);
        }
        if (!owner) {
            return std::unexpected(Status::unknown_volume);
        }
        if (*owner != a->vm_id || _attached.contains(a->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        // Only the board that stores the volume can serve it.
        if (const auto v = _volumes.find(a->volume_id);
            v != _volumes.end() && v->second.slot != a->device.slot) {
            return std::unexpected(Status::conflict);
        }
        auto reserved = reserve(a->vm_id, a->device, undo);
        if (!reserved) {
            return std::unexpected(reserved.error());
        }
        auto* port = port_for(a->device.slot);
        if (port == nullptr) {  // reserve() checked; say so to the optimizer
            return std::unexpected(Status::unknown_device);
        }
        auto ok = port->prepare_function({.fn = a->device.function,
                                          .type = FunctionType::blk_fn,
                                          .vm_id = a->vm_id,
                                          .config = oar::BlkConfig{.volume_id = a->volume_id}});
        if (!ok) {
            return std::unexpected(link_status(ok.error()));
        }
        // The key goes on commit, after the VMM has opened (and reset) the
        // function. Its cleaning, should the attach fail, closes the volume.
        return {};
    }

    if (const auto* d = std::get_if<mailbox::DetachVolume>(&body)) {
        if (auto ok = check_attached(d->volume_id, d->vm_id, d->device); !ok) {
            return ok;
        }
        // Removing a network volume the guest may still be using needs the
        // attachment fenced first, so no request of its can reach the
        // volume afterwards (Requirements 3.5, 3.6): the controller
        // publishes a config without its generation before it forces.
        // Under wait, the guest's release is what makes it safe.
        const auto net = _network.find(d->volume_id);
        const bool network = net != _network.end() && net->second.attached_by != 0;
        if (network && d->policy != mailbox::DetachPolicy::wait && !fenced(net->second)) {
            return std::unexpected(Status::conflict);
        }
        return {};
    }

    if (const auto* w = std::get_if<mailbox::WithdrawDetach>(&body)) {
        return check_attached(w->volume_id, w->vm_id, w->device);
    }

    if (const auto* r = std::get_if<mailbox::RewrapVolume>(&body)) {
        if (is_image_volume(r->volume_id) && !_keys->owner(r->volume_id)) {
            return std::unexpected(Status::unsupported);  // a plain image: no key to rewrap
        }
        const auto owner = _keys->owner(r->volume_id);
        if (!owner) {
            return std::unexpected(Status::unknown_volume);
        }
        if (*owner != r->from_vm || _attached.contains(r->volume_id) ||
            is_converting(r->volume_id)) {
            return std::unexpected(Status::conflict);
        }
        if (!_keys->find_vm_key(r->to_vm)) {
            return std::unexpected(Status::unknown_vm);
        }
        return {};
    }

    if (const auto* c = std::get_if<mailbox::ConvertVolume>(&body)) {
        return prepare_convert(*c);
    }

    // DESTROY_VM, LIST_VMS, VM_STATUS, CREATE_NETWORK, DELETE_NETWORK: hull
    // decides; helm commits on its answer.
    return {};
}

// ---- local <-> network conversion ---------------------------------------

auto CommandRouter::is_converting(VolumeId volume) const -> bool {
    return _converting.contains(volume) || std::ranges::any_of(_converting, [&](const auto& entry) {
               return entry.second.network == volume;
           });
}

auto CommandRouter::prepare_convert(const mailbox::ConvertVolume& convert)
    -> std::expected<void, mailbox::Status> {
    using mailbox::Status;
    const auto local = convert.local_volume_id;
    const auto network = convert.network_volume_id;
    if (is_image_volume(local)) {
        return std::unexpected(Status::unsupported);  // an image's overlay is not a volume to copy
    }
    const auto owner = _keys->owner(local);
    const auto stored = _volumes.find(local);
    if (!owner || stored == _volumes.end()) {
        return std::unexpected(Status::unknown_volume);
    }
    if (*owner != convert.owner_vm || _attached.contains(local) || is_converting(local) ||
        is_converting(network)) {
        return std::unexpected(Status::conflict);
    }
    const auto net = _network.find(network);
    if (net == _network.end()) {
        return std::unexpected(Status::unknown_volume);
    }
    if (net->second.attached_by != 0 || _attached.contains(network)) {
        return std::unexpected(Status::conflict);
    }
    const auto att = network_attachment(network);
    if (!att) {
        return std::unexpected(att.error());
    }
    // The key must be here before the copy: it goes to the role on commit.
    const auto key = _keys->attachment_key(att->attachment_id);
    if (!key || key->generation != att->generation || key->volume_id != network) {
        return std::unexpected(Status::unknown_volume);
    }
    auto* port = port_for(stored->second.slot);
    if (port == nullptr) {
        return std::unexpected(Status::internal_error);
    }
    // The role opens the network volume from this config; one that cannot
    // take it (not a storage role, a stale epoch) refuses here, before
    // hull sees the command.
    if (auto ok = port->replica_config(net->second.frame); !ok) {
        return std::unexpected(link_status(ok.error()));
    }
    return {};
}

auto CommandRouter::start_conversion(std::uint64_t seq, const mailbox::ConvertVolume& convert)
    -> void {
    const auto local = convert.local_volume_id;
    const auto stored = _volumes.find(local);
    const auto att = network_attachment(convert.network_volume_id);
    Conversion c{.network = convert.network_volume_id,
                 .attachment = att ? att->attachment_id : 0,
                 .direction = convert.direction,
                 .slot = stored == _volumes.end() ? std::uint8_t{0} : stored->second.slot,
                 .seq = seq,
                 .next_query = now() + _config.conversion_poll_interval,
                 .failures = 0};
    auto* port = stored == _volumes.end() ? nullptr : port_for(c.slot);
    bool started = false;
    oar::CopyAnswer answer;
    if (port != nullptr && att) {
        auto local_key = _keys->unwrap_volume_key(local, convert.owner_vm);
        auto network_key = _keys->open_attachment_key(att->attachment_id, att->generation);
        if (local_key && network_key) {
            auto r = port->copy_volume(
                {.op = oar::CopyOp::start,
                 .direction = convert.direction == mailbox::ConvertDirection::to_network
                                  ? oar::CopyDirection::to_network
                                  : oar::CopyDirection::to_local,
                 .mib_per_s = convert.mib_per_s,
                 .local_volume_id = local,
                 .network_volume_id = convert.network_volume_id,
                 .attachment_id = att->attachment_id,
                 .generation = att->generation,
                 .local_key = std::nullopt,
                 .network_key = std::nullopt},
                std::move(*local_key), std::move(*network_key));
            if (r) {
                started = true;
                answer = *r;
            }
        }
    }
    if (!started) {
        // The command itself succeeded (hull's ok); the copy did not.
        report_conversion(local, c, {}, proto::ConversionFailure::start);
        end_conversion(local, c, proto::ConversionFailure::start, 0);
        return;
    }
    audit(AuditRecord::of(AuditEvent::conversion_started)
              .with_seq(seq)
              .with_vm(convert.owner_vm)
              .with_volume(local));
    const auto [it, inserted] = _converting.insert_or_assign(local, c);
    (void)inserted;
    // A copy that finishes inside its start (an empty volume) is reported
    // and released at the first poll, like any other.
    report_conversion(local, it->second, answer, proto::ConversionFailure::none);
}

auto CommandRouter::poll_conversions(Clock::time_point t) -> void {
    for (auto it = _converting.begin(); it != _converting.end();) {
        auto& [local, c] = *it;
        if (t < c.next_query) {
            ++it;
            continue;
        }
        c.next_query = t + _config.conversion_poll_interval;
        auto* port = port_for(c.slot);
        auto answer = port == nullptr
                          ? std::expected<oar::CopyAnswer, LinkError>{std::unexpected(LinkError{
                                .code = LinkErrc::disconnected, .status = oar::Status::ok})}
                          : port->copy_volume(copy_request(oar::CopyOp::query, local, c.network),
                                              std::nullopt, std::nullopt);
        if (!answer) {
            if (++c.failures < _config.max_conversion_query_failures) {
                ++it;
                continue;
            }
        } else {
            c.failures = 0;
        }
        proto::ConversionFailure failure = proto::ConversionFailure::none;
        bool ended = true;
        if (!answer || answer->state == oar::CopyVolumeState::none) {
            failure = proto::ConversionFailure::lost;
        } else if (answer->state == oar::CopyVolumeState::failed) {
            failure = static_cast<proto::ConversionFailure>(std::to_underlying(answer->failure));
            if (failure == proto::ConversionFailure::none) {
                failure = proto::ConversionFailure::lost;  // a failure the role did not name
            }
        } else if (answer->state == oar::CopyVolumeState::copying) {
            ended = false;
        }
        const auto progress = answer.value_or(oar::CopyAnswer{});
        report_conversion(local, c, progress, failure);
        if (!ended) {
            ++it;
            continue;
        }
        const auto done = *it;
        it = _converting.erase(it);
        end_conversion(done.first, done.second, failure, progress.written_bytes);
    }
}

auto CommandRouter::report_conversion(VolumeId local, const Conversion& c,
                                      const oar::CopyAnswer& answer,
                                      proto::ConversionFailure failure) -> void {
    proto::ConversionState state = proto::ConversionState::copying;
    if (failure != proto::ConversionFailure::none) {
        state = proto::ConversionState::failed;
    } else if (answer.state == oar::CopyVolumeState::completed) {
        state = proto::ConversionState::completed;
    }
    // The role's figures, kept within what the report allows.
    const auto total = answer.total_bytes;
    _reports->report(
        proto::ConversionProgress{.local_volume_id = local,
                                  .network_volume_id = c.network,
                                  .total_bytes = total,
                                  .done_bytes = std::min(answer.done_bytes, total),
                                  .written_bytes = std::min(answer.written_bytes, total),
                                  .direction = c.direction == mailbox::ConvertDirection::to_network
                                                   ? proto::ConversionDirection::to_network
                                                   : proto::ConversionDirection::to_local,
                                  .state = state,
                                  .failure = failure,
                                  .slot = c.slot});
}

auto CommandRouter::end_conversion(VolumeId local, const Conversion& c,
                                   proto::ConversionFailure failure, std::uint64_t written)
    -> void {
    if (failure == proto::ConversionFailure::none) {
        ++_stats.conversions_completed;
        audit(AuditRecord::of(AuditEvent::conversion_completed)
                  .with_seq(c.seq)
                  .with_volume(local)
                  .with_count(written));
    } else {
        ++_stats.conversions_failed;
        audit(AuditRecord::of(AuditEvent::conversion_failed)
                  .with_seq(c.seq)
                  .with_volume(local)
                  .with_status(std::to_underlying(failure)));
    }
    // Released even after a start that failed: a start that timed out may
    // have begun on the role. Releasing a copy the role does not have is a
    // no-op, and one that fails leaves only a copier the next delete or
    // restart drops.
    if (auto* port = port_for(c.slot); port != nullptr) {
        (void)port->copy_volume(copy_request(oar::CopyOp::release, local, c.network), std::nullopt,
                                std::nullopt);
    }
    // The utility attachment served this copy only: the controller retires it.
    if (c.attachment != 0) {
        _keys->drop_attachment_key(c.attachment);
    }
    drop_unattached(c.network);
}

auto CommandRouter::check_attached(VolumeId volume, VmId vm, const mailbox::DeviceRef& device) const
    -> std::expected<void, mailbox::Status> {
    using mailbox::Status;
    const auto net = _network.find(volume);
    const bool network = net != _network.end() && net->second.attached_by != 0;
    if (!network && !volume_owner(volume)) {
        return std::unexpected(Status::unknown_volume);
    }
    if (network && net->second.attached_by != vm) {
        return std::unexpected(Status::conflict);
    }
    const auto id = function_id(device);
    const auto it = _attached.find(volume);
    const auto info = _pool->find(id);
    if (it == _attached.end() || it->second != id || !info ||
        info->state != FunctionState::assigned || info->owner != vm) {
        return std::unexpected(Status::conflict);
    }
    return {};
}

auto CommandRouter::compensate(std::uint64_t seq, Undo& undo) -> void {
    if (undo.stored_volume) {
        auto* port = port_for(undo.stored_volume->slot);
        if (port == nullptr || !port->delete_volume({.volume_id = undo.stored_volume->volume})) {
            ++_stats.storage_failures;
        }
    }
    if (undo.reserved && pool_event(*undo.reserved, PoolEvent::attach_failed)) {
        start_cleaning(*undo.reserved);
    }
    if (undo.created_volume_key && _keys->destroy_volume_key(*undo.created_volume_key)) {
        audit(AuditRecord::of(AuditEvent::volume_key_destroyed)
                  .with_seq(seq)
                  .with_volume(*undo.created_volume_key));
    }
    if (undo.created_vm_key) {
        if (auto erased = _keys->destroy_vm_key(*undo.created_vm_key)) {
            audit(AuditRecord::of(AuditEvent::vm_key_destroyed)
                      .with_seq(seq)
                      .with_vm(*undo.created_vm_key)
                      .with_count(erased->size()));
        }
    }
    undo = Undo{};
}

auto CommandRouter::commit(std::uint64_t seq, const mailbox::Body& body, const Undo& undo) -> void {
    if (const auto* c = std::get_if<mailbox::CreateVm>(&body)) {
        _vms[c->vm_id] = Vm{.vcpus = c->vcpus, .memory_mib = c->memory_mib};
    } else if (const auto* d = std::get_if<mailbox::DestroyVm>(&body)) {
        for (const auto id : _pool->held_by(d->vm_id)) {
            if (_pool->find(id)->state == FunctionState::assigned) {
                (void)release(id, d->vm_id);
            }
        }
        std::erase_if(_attached,
                      [&](const auto& entry) { return volume_owner(entry.first) == d->vm_id; });
        std::vector<VolumeId> detached;
        for (auto& [volume, net] : _network) {
            if (net.attached_by == d->vm_id) {
                _attached.erase(volume);
                forget_attachment(net);
                detached.push_back(volume);
            }
        }
        for (const auto volume : detached) {
            drop_unattached(volume);
        }
        if (!d->persist_volumes) {
            // Plain image volumes have no key to erase: only their
            // descriptors go. An encrypted image's K_img copy goes with
            // the VM key, below, like a disk volume's key.
            std::vector<VolumeId> images;
            for (const auto& [id, volume] : _volumes) {
                if (volume.image && volume.owner == d->vm_id && !_keys->owner(id)) {
                    images.push_back(id);
                }
            }
            for (const auto volume : images) {
                erase_volume(volume);
                _volumes.erase(volume);
            }
            if (auto erased = _keys->destroy_vm_key(d->vm_id)) {
                audit(AuditRecord::of(AuditEvent::vm_key_destroyed)
                          .with_seq(seq)
                          .with_vm(d->vm_id)
                          .with_count(erased->size()));
                for (const auto volume : *erased) {
                    erase_volume(volume);
                    _volumes.erase(volume);
                }
            }
        }
        _vms.erase(d->vm_id);
    } else if (const auto* dd = std::get_if<mailbox::DetachDevice>(&body)) {
        if (!release(function_id(dd->device), dd->vm_id, std::chrono::seconds{dd->timeout_s})) {
            ++_stats.inconsistencies;
        }
    } else if (const auto* cv = std::get_if<mailbox::CreateVolume>(&body)) {
        _volumes[cv->volume_id] =
            Volume{.owner = cv->owner_vm,
                   .size_gib = cv->size_gib,
                   .slot = undo.stored_volume ? undo.stored_volume->slot : std::uint8_t{0},
                   .image = cv->image_store != 0};
    } else if (const auto* dv = std::get_if<mailbox::DeleteVolume>(&body)) {
        // A plain image volume has nothing to crypto-erase: each
        // attachment's key died with the attachment. An encrypted one's
        // copy of K_img goes like a disk volume's key.
        if (_keys->destroy_volume_key(dv->volume_id)) {
            audit(AuditRecord::of(AuditEvent::volume_key_destroyed)
                      .with_seq(seq)
                      .with_volume(dv->volume_id));
        } else if (!is_image_volume(dv->volume_id)) {
            ++_stats.inconsistencies;
        }
        _keys->drop_image_key(dv->volume_id);
        erase_volume(dv->volume_id);
        _volumes.erase(dv->volume_id);
    } else if (const auto* av = std::get_if<mailbox::AttachVolume>(&body)) {
        _attached[av->volume_id] = function_id(av->device);
        if (const auto net = _network.find(av->volume_id);
            net != _network.end() && !volume_owner(av->volume_id)) {
            if (const auto att = network_attachment(av->volume_id)) {
                net->second.attached_by = av->vm_id;
                net->second.attachment = att->attachment_id;
                net->second.generation = att->generation;
            }
        }
        deliver_volume_key(seq, *av);
    } else if (const auto* xv = std::get_if<mailbox::DetachVolume>(&body)) {
        if (!release(function_id(xv->device), xv->vm_id, std::chrono::seconds{xv->timeout_s})) {
            ++_stats.inconsistencies;
        }
        _attached.erase(xv->volume_id);
        if (const auto net = _network.find(xv->volume_id); net != _network.end()) {
            forget_attachment(net->second);
        }
        drop_unattached(xv->volume_id);
    } else if (const auto* r = std::get_if<mailbox::RewrapVolume>(&body)) {
        if (_keys->rewrap(r->volume_id, r->to_vm)) {
            audit(AuditRecord::of(AuditEvent::volume_key_rewrapped)
                      .with_seq(seq)
                      .with_vm(r->to_vm)
                      .with_volume(r->volume_id));
            auto it = _volumes.find(r->volume_id);
            if (it != _volumes.end()) {
                it->second.owner = r->to_vm;
            }
            const auto wrapped = _keys->find_volume_key(r->volume_id);
            auto* port = it == _volumes.end() ? nullptr : port_for(it->second.slot);
            if (!wrapped || port == nullptr ||
                !port->rewrap_volume({.volume_id = r->volume_id,
                                      .owner_vm = r->to_vm,
                                      .wrapped_key = wrapped->key.bytes()})) {
                ++_stats.storage_failures;
            }
        } else {
            ++_stats.inconsistencies;
        }
    } else if (const auto* cv2 = std::get_if<mailbox::ConvertVolume>(&body)) {
        start_conversion(seq, *cv2);
    } else if (const auto* cn = std::get_if<mailbox::CreateNetwork>(&body)) {
        _networks.try_emplace(cn->vni, 0);
    } else if (const auto* dn = std::get_if<mailbox::DeleteNetwork>(&body)) {
        _networks.erase(dn->vni);
    }
}

auto CommandRouter::deliver_volume_key(std::uint64_t seq, const mailbox::AttachVolume& attach)
    -> void {
    const auto id = function_id(attach.device);
    auto* port = port_for(attach.device.slot);
    // An image volume's key exists only for this attachment; a network
    // volume's is the controller's, opened for this attachment. An
    // encrypted image volume's own (wrapped) key is K_img, which goes
    // along with that ephemeral key.
    const auto net = _network.find(attach.volume_id);
    const bool image = is_image_volume(attach.volume_id);
    auto key = net != _network.end() && net->second.attached_by == attach.vm_id
                   ? _keys->open_attachment_key(net->second.attachment, net->second.generation)
               : image ? _keys->create_ephemeral_key()
                       : _keys->unwrap_volume_key(attach.volume_id, attach.vm_id);
    std::optional<std::expected<ScopedKey, KeyError>> image_key;
    if (image && _keys->owner(attach.volume_id)) {
        image_key = _keys->unwrap_volume_key(attach.volume_id, attach.vm_id);
    }
    bool delivered = false;
    if (port != nullptr && key && (!image_key || image_key->has_value())) {
        std::optional<ScopedKey> k_img;
        if (image_key) {
            k_img = std::move(**image_key);
        }
        delivered = port->deliver_key(attach.device.function, attach.volume_id, std::move(*key),
                                      std::move(k_img))
                        .has_value();
    }
    const auto record = AuditRecord::of(delivered ? AuditEvent::volume_key_delivered
                                                  : AuditEvent::volume_key_delivery_failed)
                            .with_seq(seq)
                            .with_vm(attach.vm_id)
                            .with_volume(attach.volume_id)
                            .with_function(id);
    audit(record);
    if (!delivered) {
        ++_stats.key_delivery_failures;
        _reports->report(proto::HostFaultReport{.code = proto::FaultCode::device_lost,
                                                .slot = attach.device.slot,
                                                .detail = attach.volume_id});
    }
}

auto CommandRouter::volume_owner(VolumeId volume) const -> std::optional<VmId> {
    if (const auto it = _volumes.find(volume); it != _volumes.end() && it->second.image) {
        return it->second.owner;
    }
    return _keys->owner(volume);
}

auto CommandRouter::on_replica_config(std::span<const std::byte> frame) -> bool {
    const auto c = proto::decode_replica_config(frame);
    if (!c) {
        return false;
    }
    const bool ours = std::ranges::any_of(c->attachments, [&](const proto::VolumeAttachment& a) {
        return a.server_id == _config.server_id;
    });
    auto it = _network.find(c->volume_id);
    if (it == _network.end()) {
        if (!ours || _network.size() >= max_network_volumes) {
            return false;
        }
        it = _network.try_emplace(c->volume_id).first;
    } else if (c->epoch < it->second.epoch) {
        return false;  // the roles refuse it too
    }
    it->second.epoch = c->epoch;
    it->second.frame.assign(frame.begin(), frame.end());
    // A volume no longer attached here is forgotten once it is detached;
    // until then the role must see the config that fences it.
    if (!ours && it->second.attached_by == 0 && !is_converting(c->volume_id)) {
        _network.erase(it);
    }
    return true;
}

auto CommandRouter::network_configs() const -> std::vector<std::span<const std::byte>> {
    std::vector<std::span<const std::byte>> out;
    out.reserve(_network.size());
    for (const auto& [volume, net] : _network) {
        out.emplace_back(net.frame);
    }
    return out;
}

auto CommandRouter::network_attachment(VolumeId volume) const
    -> std::expected<proto::VolumeAttachment, mailbox::Status> {
    const auto it = _network.find(volume);
    if (it == _network.end()) {
        return std::unexpected(mailbox::Status::unknown_volume);
    }
    const auto c = proto::decode_replica_config(it->second.frame);
    if (!c) {
        return std::unexpected(mailbox::Status::internal_error);
    }
    std::optional<proto::VolumeAttachment> found;
    for (const auto& a : c->attachments) {
        if (a.server_id != _config.server_id) {
            continue;
        }
        if (found) {
            return std::unexpected(mailbox::Status::conflict);  // two here: which one?
        }
        found = a;
    }
    if (!found) {
        return std::unexpected(mailbox::Status::unknown_volume);
    }
    return *found;
}

auto CommandRouter::prepare_network_attach(const mailbox::AttachVolume& attach, Undo& undo)
    -> std::expected<void, mailbox::Status> {
    using mailbox::Status;
    if (_attached.contains(attach.volume_id)) {
        return std::unexpected(Status::conflict);
    }
    const auto att = network_attachment(attach.volume_id);
    if (!att) {
        return std::unexpected(att.error());
    }
    // The key must be here before the attach: it is delivered on commit.
    const auto key = _keys->attachment_key(att->attachment_id);
    if (!key || key->generation != att->generation || key->volume_id != attach.volume_id) {
        return std::unexpected(Status::unknown_volume);
    }
    auto reserved = reserve(attach.vm_id, attach.device, undo);
    if (!reserved) {
        return std::unexpected(reserved.error());
    }
    auto* port = port_for(attach.device.slot);
    if (port == nullptr) {  // reserve() checked; say so to the optimizer
        return std::unexpected(mailbox::Status::unknown_device);
    }
    if (auto ok = port->replica_config(_network.at(attach.volume_id).frame); !ok) {
        return std::unexpected(link_status(ok.error()));
    }
    auto ok = port->prepare_function({.fn = attach.device.function,
                                      .type = FunctionType::blk_fn,
                                      .vm_id = attach.vm_id,
                                      .config = oar::BlkConfig{.volume_id = attach.volume_id,
                                                               .attachment_id = att->attachment_id,
                                                               .generation = att->generation}});
    if (!ok) {
        return std::unexpected(link_status(ok.error()));
    }
    return {};
}

auto CommandRouter::drop_unattached(VolumeId volume) -> void {
    const auto it = _network.find(volume);
    if (it != _network.end() && it->second.attached_by == 0 && !is_converting(volume) &&
        network_attachment(volume).error_or(mailbox::Status::ok) ==
            mailbox::Status::unknown_volume) {
        _network.erase(it);
    }
}

auto CommandRouter::forget_attachment(NetworkVolume& net) -> void {
    if (net.attachment != 0) {
        _keys->drop_attachment_key(net.attachment);
    }
    net.attached_by = 0;
    net.attachment = 0;
    net.generation = 0;
}

auto CommandRouter::is_image_volume(VolumeId volume) const -> bool {
    const auto it = _volumes.find(volume);
    return it != _volumes.end() && it->second.image;
}

auto CommandRouter::erase_volume(VolumeId volume) -> void {
    const auto it = _volumes.find(volume);
    auto* port = it == _volumes.end() ? nullptr : port_for(it->second.slot);
    if (port == nullptr || !port->delete_volume({.volume_id = volume})) {
        ++_stats.storage_failures;
    }
}

auto CommandRouter::refuse(std::uint64_t seq, mailbox::Type command, mailbox::Status status)
    -> void {
    ++_stats.refused;
    audit(AuditRecord::of(AuditEvent::command_refused)
              .with_seq(seq)
              .with_command(command_code(command))
              .with_status(status_code(status)));
    finish(seq, command, status);
}

auto CommandRouter::finish(std::uint64_t seq, mailbox::Type command, mailbox::Status status,
                           std::span<const std::byte> payload) -> void {
    Outcome outcome{.in_reply_to = seq,
                    .command = command_code(command),
                    .status = static_cast<proto::CommandStatus>(status),
                    .payload = {payload.begin(), payload.end()}};
    _history.insert_or_assign(seq, outcome);
    while (_history.size() > _config.outcome_history) {
        _history.erase(_history.begin());
    }
    _reports->report(std::move(outcome));
}

// ---- hull ------------------------------------------------------------------

auto CommandRouter::on_host_slot(const mailbox::Slot& slot) -> void {
    const auto msg = mailbox::decode(slot);
    if (!msg || mailbox::is_command(msg->header.type)) {
        ++_stats.stray_messages;
        return;
    }
    const auto body = mailbox::decode_body(*msg);
    if (!body) {
        ++_stats.stray_messages;
        return;
    }
    if (std::holds_alternative<mailbox::Response>(*body)) {
        on_response(*msg);
    } else {
        on_event(*body);
    }
}

auto CommandRouter::on_response(const mailbox::Message& msg) -> void {
    const auto rsp = std::get<mailbox::Response>(*mailbox::decode_body(msg));
    if (_in_flight && rsp.in_reply_to == _in_flight->seq &&
        rsp.command == mailbox::type_of(_in_flight->body)) {
        auto done = std::move(*_in_flight);
        _in_flight.reset();
        audit(AuditRecord::of(AuditEvent::command_outcome)
                  .with_seq(done.seq)
                  .with_command(command_code(rsp.command))
                  .with_status(status_code(rsp.status)));
        if (succeeded(rsp.status)) {
            commit(done.seq, done.body, done.undo);
        } else {
            compensate(done.seq, done.undo);
        }
        finish(done.seq, rsp.command, rsp.status, rsp.payload_bytes());
        pump();
        return;
    }
    ++_stats.stray_messages;
    if (_timed_out.erase(rsp.in_reply_to) != 0) {
        audit(AuditRecord::of(AuditEvent::late_response)
                  .with_seq(rsp.in_reply_to)
                  .with_command(command_code(rsp.command))
                  .with_status(status_code(rsp.status)));
    }
}

auto CommandRouter::on_event(const mailbox::Body& body) -> void {
    if (const auto* r = std::get_if<mailbox::DeviceReleased>(&body)) {
        const auto id = function_id(r->device);
        const auto info = _pool->find(id);
        if (!info || info->owner != r->vm_id) {
            ++_stats.inconsistencies;
            return;
        }
        // hull may reset a function before helm has processed the response
        // that released it (DESTROY_VM, or the VM died): hull is the
        // authority on what the VM still holds, so release it first.
        if (info->state == FunctionState::assigned && !release(id, r->vm_id)) {
            ++_stats.inconsistencies;
            return;
        }
        _deadlines.erase(id);
        if (r->reset == mailbox::ResetResult::ok) {
            if (pool_event(id, PoolEvent::device_released)) {
                start_cleaning(id);
            }
        } else {
            (void)pool_event(id, PoolEvent::reset_failed);
        }
    } else if (const auto* s = std::get_if<mailbox::ScrubDone>(&body)) {
        const auto id = function_id(s->device);
        _deadlines.erase(id);
        if (!pool_event(id, s->result == mailbox::ScrubResult::ok ? PoolEvent::scrub_done
                                                                  : PoolEvent::clean_failed)) {
            ++_stats.inconsistencies;
        }
    } else if (const auto* e = std::get_if<mailbox::VmExited>(&body)) {
        _reports->report(
            proto::VmExitedReport{.vm_id = e->vm_id,
                                  .exit_status = e->exit_status,
                                  .reason = static_cast<proto::ExitReason>(e->reason)});
    } else if (const auto* f = std::get_if<mailbox::HostFault>(&body)) {
        _reports->report(proto::HostFaultReport{
            .code = static_cast<proto::FaultCode>(f->code), .slot = f->slot, .detail = f->detail});
    }
}

auto CommandRouter::on_map_applied(std::uint32_t vni, std::uint64_t map_version) -> void {
    _networks[vni] = map_version;
    _reports->report(proto::MapApplied{.vni = vni, .map_version = map_version});
}

auto CommandRouter::poll() -> void {
    const auto t = now();
    if (_in_flight && t >= _in_flight->deadline) {
        const auto seq = _in_flight->seq;
        const auto command = mailbox::type_of(_in_flight->body);
        _in_flight.reset();
        ++_stats.timed_out;
        _timed_out.insert(seq);
        while (_timed_out.size() > _config.outcome_history) {
            _timed_out.erase(_timed_out.begin());
        }
        audit(AuditRecord::of(AuditEvent::command_timed_out)
                  .with_seq(seq)
                  .with_command(command_code(command)));
        finish(seq, command, mailbox::Status::timed_out);
        pump();
    }
    poll_ejects(t);
    poll_conversions(t);
    for (auto it = _deadlines.begin(); it != _deadlines.end();) {
        if (t < it->second) {
            ++it;
            continue;
        }
        const auto id = it->first;
        it = _deadlines.erase(it);
        (void)pool_event(id, PoolEvent::timed_out);
    }
}

// ---- pool ------------------------------------------------------------------

auto CommandRouter::pool_event(FunctionId id, PoolEvent event) -> bool {
    const auto before = _pool->find(id);
    if (!before || !_pool->apply(id, event)) {
        return false;
    }
    report_transition(id, before->state, *_pool->find(id), before->owner);
    return true;
}

auto CommandRouter::release(FunctionId id, VmId vm, std::chrono::milliseconds grace) -> bool {
    const auto before = _pool->find(id);
    if (!before || !_pool->release(id, vm)) {
        return false;
    }
    report_transition(id, before->state, *_pool->find(id), vm);
    _deadlines[id] = now() + _config.release_timeout + grace;
    _ejecting.erase(id);  // detached: cleaning clears the request on the role
    return true;
}

auto CommandRouter::start_cleaning(FunctionId id) -> void {
    const auto info = _pool->find(id);
    if (!info || info->state != FunctionState::cleaning) {
        return;
    }
    if (is_gpu(info->type)) {
        // GPU memory is scrubbed through hull (scrubber or manager VM);
        // SCRUB_DONE finishes it.
        _deadlines[id] = now() + _config.clean_timeout;
        return;
    }
    auto* port = port_for(slot_of(id));
    if (port == nullptr) {
        (void)pool_event(id, PoolEvent::clean_failed);
        return;
    }
    const auto ok =
        port->clean_function({.fn = function_number_of(id), .action = cleaning_action(info->type)});
    if (info->type == FunctionType::blk_fn) {
        audit(AuditRecord::of(AuditEvent::volume_key_dropped).with_function(id));
    }
    if (ok) {
        (void)pool_event(id, PoolEvent::clean_done);
    } else {
        (void)pool_event(id, ok.error().code == LinkErrc::timed_out ? PoolEvent::timed_out
                                                                    : PoolEvent::clean_failed);
    }
}

auto CommandRouter::report_transition(FunctionId id, FunctionState from, const FunctionInfo& after,
                                      std::optional<VmId> vm) -> void {
    _reports->report(proto::PoolStateChange{.slot = slot_of(id),
                                            .type = to_proto(after.type),
                                            .function = function_number_of(id),
                                            .from = to_proto(from),
                                            .to = to_proto(after.state),
                                            .owner_vm = vm.value_or(after.owner.value_or(0))});
}

// ---- status ----------------------------------------------------------------

auto CommandRouter::inventory() const -> proto::Inventory {
    proto::Inventory inv;
    inv.last_command_seq = _last_seq;
    bool faulted = false;
    for (const auto& f : _pool->all()) {
        faulted = faulted || f.state == FunctionState::faulted;
        inv.functions.push_back({.slot = slot_of(f.id),
                                 .type = to_proto(f.type),
                                 .function = function_number_of(f.id),
                                 .state = to_proto(f.state),
                                 .owner_vm = f.owner.value_or(0)});
    }
    inv.health = faulted ? proto::Health::degraded : proto::Health::ok;
    for (const auto& [id, vm] : _vms) {
        inv.vms.push_back({.vm_id = id, .vcpus = vm.vcpus, .memory_mib = vm.memory_mib});
    }
    for (const auto& [id, volume] : _volumes) {
        inv.volumes.push_back(
            {.volume_id = id, .owner_vm = volume.owner, .size_gib = volume.size_gib});
    }
    for (const auto& [vni, version] : _networks) {
        inv.networks.push_back({.vni = vni, .map_version = version});
    }
    return inv;
}

}  // namespace ak::helm
