// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/cold-start/ Requirement 4.4-4.5, task 6: helm's STANDING_CHUNK
// and STANDING_START mailbox commands, and hull's StandingStarts. hull runs
// a standing instance only from a complete set that verifies under a
// compiled-in controller key and names this server, only before the
// first signed command of the boot, never consuming a sequence number,
// and undoes a start that fails part way.

#define BOOST_TEST_MODULE standing_starts_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

#include "common/wire.hpp"
#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "helm/mailbox_device.hpp"
#include "hull/mailbox_client.hpp"
#include "hull/standing_starts.hpp"
#include "proto/standing_set.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
namespace proto = ak::proto;
using ak::helm::HostSlotKind;
using ak::helm::MailboxDevice;
using ak::hull::CommandOutcome;
using ak::hull::KeyId;
using ak::hull::MailboxClient;
using ak::hull::SequenceTracker;
using ak::hull::SignatureVerifier;
using ak::hull::StandingStarts;
using ak::test::controller_key;
using ak::test::TestSigner;
using ak::test::unit_timeout_seconds;

namespace {

constexpr KeyId controller = 1;
constexpr mb::ServerId this_server = 7;
constexpr mb::ServerId other_server = 8;
constexpr std::uint64_t generation = 5;
constexpr std::uint64_t vm_a = 0x1001;
constexpr std::uint64_t vm_b = 0x1002;
constexpr std::uint16_t vcpus = 2;
constexpr std::uint32_t memory_mib = 2048;
constexpr std::uint32_t vni = 100;
constexpr std::uint64_t nic_id = 9;
constexpr std::uint8_t nic_slot = 1;
constexpr std::uint16_t nic_function = 3;
constexpr std::uint64_t helm_seq = 1;
constexpr std::size_t word = 4;

auto make_verifier() -> SignatureVerifier {
    const std::array keys{controller_key(controller, ak::test::rfc_test1_public)};
    auto v = SignatureVerifier::create(keys);
    if (!v) {
        throw std::runtime_error("key table");
    }
    return std::move(*v);
}

auto create_vm(std::uint64_t vm) -> mb::CreateVm {
    return {
        .vm_id = vm, .vcpus = vcpus, .memory_mib = memory_mib, .boot_mode = mb::BootMode::volume};
}

auto attach_nic(std::uint64_t vm) -> mb::AttachDevice {
    return {.vm_id = vm,
            .device = {.slot = nic_slot, .type = mb::DeviceType::nic_vf, .function = nic_function},
            .vni = vni,
            .nic_id = nic_id,
            .mac = {std::byte{0x02}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{1}}};
}

auto command(const mb::Body& body) -> proto::StandingCommand {
    return {.type = static_cast<proto::StandingCommandType>(std::to_underlying(mb::type_of(body))),
            .body = mb::encode_body(body)};
}

auto instance(std::uint64_t vm, std::vector<proto::StandingCommand> commands)
    -> proto::StandingInstance {
    proto::StandingInstance in;
    in.vm_id = vm;
    in.manifest_digest.fill(std::byte{0xAB});
    in.commands = std::move(commands);
    return in;
}

auto default_instances() -> std::vector<proto::StandingInstance> {
    return {instance(vm_a, {command(create_vm(vm_a)), command(attach_nic(vm_a))}),
            instance(vm_b, {command(create_vm(vm_b))})};
}

// A standing set, encoded and signed by `by`.
auto signed_set(const TestSigner& by, std::vector<proto::StandingInstance> instances,
                std::uint64_t server = this_server, std::uint64_t gen = generation)
    -> std::vector<std::byte> {
    const proto::StandingSet set{.server_id = server,
                                 .key_id = controller,
                                 .generation = gen,
                                 .time_floor = 0,
                                 .instances = std::move(instances),
                                 .signature = {}};
    auto frame = proto::encode_standing_set(set);
    if (!frame) {
        throw std::runtime_error("encode_standing_set");
    }
    const auto sig = by.sign(proto::standing_set_signed_bytes(*frame));
    proto::set_standing_set_signature(*frame, sig);
    return *frame;
}

// The set in STANDING_CHUNK pieces, `piece` bytes at a time.
auto chunks_of(const std::vector<std::byte>& frame, std::size_t piece = mb::max_standing_chunk)
    -> std::vector<mb::StandingChunk> {
    std::vector<mb::StandingChunk> out;
    for (std::size_t off = 0; off < frame.size(); off += piece) {
        const std::size_t n = std::min(piece, frame.size() - off);
        mb::StandingChunk c{.total = static_cast<std::uint32_t>(frame.size()),
                            .offset = static_cast<std::uint32_t>(off),
                            .len = static_cast<std::uint16_t>(n),
                            .bytes = {}};
        std::copy_n(frame.begin() + static_cast<std::ptrdiff_t>(off), n, c.bytes.begin());
        out.push_back(c);
    }
    return out;
}

struct RecordingHandler final : ak::hull::CommandHandler {
    auto handle(const mb::Message& msg, const mb::Body& body) -> CommandOutcome override {
        seen.emplace_back(msg.header, body);
        const auto t = mb::type_of(body);
        if (fail_type && *fail_type == t) {
            return {.status = fail_status, .payload = {}};
        }
        return {};
    }
    std::vector<std::pair<mb::Header, mb::Body>> seen;
    std::optional<mb::Type> fail_type;
    mb::Status fail_status{mb::Status::unknown_device};
};

// Sends every chunk, expecting ok for all but the last, and returns the
// last chunk's answer.
auto upload(StandingStarts& s, const std::vector<std::byte>& frame) -> mb::Status {
    const auto pieces = chunks_of(frame);
    for (std::size_t i = 0; i + 1 < pieces.size(); ++i) {
        BOOST_REQUIRE((s.chunk(pieces[i]) == mb::Status::ok));
    }
    return s.chunk(pieces.back());
}

struct Fixture {
    TestSigner signer{ak::test::rfc_test1_secret};
    TestSigner forger{ak::test::rfc_test2_secret};
    SignatureVerifier verifier = make_verifier();
    StandingStarts standing{this_server, verifier};
    RecordingHandler handler;
};

}  // namespace

// ---- The mailbox bodies -----------------------------------------------------

BOOST_AUTO_TEST_SUITE(codec)

auto helm_message(const mb::Body& body, mb::KeyId key = mb::no_key_id,
                  mb::ServerId server = this_server)
    -> std::expected<mb::Message, mb::DecodeError> {
    const auto bytes = mb::encode_body(body);
    const std::array<std::byte, mb::signature_size> blank{};
    const auto slot = mb::encode({.type = mb::type_of(body),
                                  .seq = helm_seq,
                                  .body_len = static_cast<std::uint16_t>(bytes.size()),
                                  .key_id = key,
                                  .server_id = server},
                                 bytes, blank);
    if (!slot) {
        return std::unexpected(slot.error());
    }
    return mb::decode(*slot);
}

BOOST_AUTO_TEST_CASE(round_trips, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(mb::is_helm_command(mb::Type::standing_chunk));
    BOOST_TEST(mb::is_helm_command(mb::Type::standing_start));
    BOOST_TEST(mb::is_command(mb::Type::standing_start));
    BOOST_TEST(!mb::is_helm_command(mb::Type::create_vm));
    BOOST_TEST(mb::max_standing_chunk == 148U);

    const auto frame = signed_set(TestSigner{ak::test::rfc_test1_secret}, default_instances());
    for (const auto& c : chunks_of(frame)) {
        const auto msg = helm_message(c);
        BOOST_REQUIRE(msg.has_value());
        const auto body = mb::decode_body(*msg);
        BOOST_REQUIRE(body.has_value());
        BOOST_TEST((std::get<mb::StandingChunk>(*body) == c));
        BOOST_TEST((mb::encode_body(*body) ==
                    std::vector<std::byte>(msg->body_bytes().begin(), msg->body_bytes().end())));
    }
    const mb::StandingStart start{.generation = generation, .index = 1};
    const auto msg = helm_message(start);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST(msg->header.body_len == 16U);
    BOOST_TEST((std::get<mb::StandingStart>(*mb::decode_body(*msg)) == start));
}

BOOST_AUTO_TEST_CASE(header_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const mb::StandingStart start{.generation = generation, .index = 0};
    // Unsigned: a key ID is refused, and so is a missing server.
    BOOST_TEST((helm_message(start, controller).error() == mb::DecodeError::bad_key_id));
    BOOST_TEST((helm_message(start, mb::no_key_id, mb::no_server_id).error() ==
                mb::DecodeError::bad_server_id));
    // No bytes may hide where a signature would go.
    const auto bytes = mb::encode_body(start);
    std::array<std::byte, mb::signature_size> sig{};
    sig[3] = std::byte{1};
    const mb::Header h{.type = mb::Type::standing_start,
                       .seq = helm_seq,
                       .body_len = static_cast<std::uint16_t>(bytes.size()),
                       .key_id = mb::no_key_id,
                       .server_id = this_server};
    BOOST_TEST((mb::encode(h, bytes, sig).error() == mb::DecodeError::reserved_not_zero));
    auto slot = mb::encode(h, bytes, std::array<std::byte, mb::signature_size>{});
    BOOST_REQUIRE(slot.has_value());
    (*slot)[mb::signature_offset + 3] = std::byte{1};
    BOOST_TEST((mb::decode(*slot).error() == mb::DecodeError::reserved_not_zero));
    // A controller command still needs its key ID.
    const auto vm = mb::encode_body(create_vm(vm_a));
    BOOST_TEST((mb::encode({.type = mb::Type::create_vm,
                            .seq = helm_seq,
                            .body_len = static_cast<std::uint16_t>(vm.size()),
                            .key_id = mb::no_key_id,
                            .server_id = this_server},
                           vm, std::array<std::byte, mb::signature_size>{})
                    .error() == mb::DecodeError::bad_key_id));
}

auto body_error(mb::Type type, std::span<const std::byte> body) -> mb::BodyError {
    mb::Message msg{};
    msg.header = {.type = type,
                  .seq = helm_seq,
                  .body_len = static_cast<std::uint16_t>(body.size()),
                  .key_id = mb::no_key_id,
                  .server_id = this_server};
    std::ranges::copy(body, msg.body.begin());
    const auto r = mb::decode_body(msg);
    BOOST_REQUIRE(!r.has_value());
    return r.error();
}

auto chunk_bytes(std::uint32_t total, std::uint32_t offset, std::uint16_t len, std::uint16_t rsvd,
                 std::size_t actual) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    ak::wire::Writer w{out};
    w.le32(total);
    w.le32(offset);
    w.le16(len);
    w.le16(rsvd);
    out.resize(out.size() + actual, std::byte{0x5A});
    return out;
}

BOOST_AUTO_TEST_CASE(chunk_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    using mb::BodyError;
    const auto t = mb::Type::standing_chunk;
    BOOST_TEST((body_error(t, chunk_bytes(10, 0, 0, 0, 0)) == BodyError::wrong_length));
    BOOST_TEST((body_error(t, chunk_bytes(10, 0, 4, 0, 3)) == BodyError::wrong_length));
    BOOST_TEST((body_error(t, chunk_bytes(10, 0, 4, 1, 4)) == BodyError::invalid_field));
    BOOST_TEST((body_error(t, chunk_bytes(0, 0, 4, 0, 4)) == BodyError::invalid_field));
    BOOST_TEST((body_error(t, chunk_bytes(mb::max_standing_transfer + 1, 0, 4, 0, 4)) ==
                BodyError::invalid_field));
    BOOST_TEST((body_error(t, chunk_bytes(10, 8, 4, 0, 4)) == BodyError::invalid_field));
    BOOST_TEST((body_error(t, chunk_bytes(10, 11, 4, 0, 4)) == BodyError::invalid_field));

    std::vector<std::byte> start;
    ak::wire::Writer w{start};
    w.le64(0);
    w.le16(0);
    w.bytes(std::array<std::byte, 6>{});
    BOOST_TEST((body_error(mb::Type::standing_start, start) == BodyError::invalid_field));
    start[0] = std::byte{1};
    start[8] = std::byte{mb::max_standing_index};
    BOOST_TEST((body_error(mb::Type::standing_start, start) == BodyError::invalid_field));
    start[8] = std::byte{0};
    start[15] = std::byte{1};
    BOOST_TEST((body_error(mb::Type::standing_start, start) == BodyError::invalid_field));
    BOOST_TEST((body_error(mb::Type::standing_start, std::span{start}.first(15)) ==
                BodyError::wrong_length));
}

BOOST_AUTO_TEST_SUITE_END()

// ---- StandingStarts ---------------------------------------------------------

BOOST_FIXTURE_TEST_SUITE(standing_starts, Fixture)

BOOST_AUTO_TEST_CASE(starts_each_instance_once, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((upload(standing, signed_set(signer, default_instances())) == mb::Status::ok));
    BOOST_TEST((standing.generation() == generation));

    BOOST_TEST((standing.start({.generation = generation, .index = 0}, handler) == mb::Status::ok));
    BOOST_REQUIRE(handler.seen.size() == 2U);
    BOOST_TEST((handler.seen[0].second == mb::Body{create_vm(vm_a)}));
    BOOST_TEST((handler.seen[1].second == mb::Body{attach_nic(vm_a)}));
    for (const auto& [header, body] : handler.seen) {
        BOOST_TEST(header.seq == 0U);  // no sequence number consumed
        BOOST_TEST(header.server_id == this_server);
        BOOST_TEST(header.key_id == controller);
    }
    BOOST_TEST((standing.start({.generation = generation, .index = 1}, handler) == mb::Status::ok));
    BOOST_TEST(handler.seen.size() == 3U);

    // Never twice in a boot.
    BOOST_TEST(
        (standing.start({.generation = generation, .index = 0}, handler) == mb::Status::conflict));
    BOOST_TEST(handler.seen.size() == 3U);
    BOOST_TEST(standing.stats().started == 2U);
    BOOST_TEST(standing.stats().refused == 1U);
}

BOOST_AUTO_TEST_CASE(small_chunks_reassemble, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto frame = signed_set(signer, default_instances());
    for (const auto& piece : chunks_of(frame, 7)) {
        BOOST_TEST((standing.chunk(piece) == mb::Status::ok));
    }
    BOOST_TEST(standing.stats().sets_accepted == 1U);
}

BOOST_AUTO_TEST_CASE(refuses_sets_that_do_not_verify,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(
        (upload(standing, signed_set(forger, default_instances())) == mb::Status::bad_signature));
    BOOST_TEST((upload(standing, signed_set(signer, default_instances(), other_server)) ==
                mb::Status::wrong_server));
    auto corrupt = signed_set(signer, default_instances());
    corrupt[0] = std::byte{'X'};
    BOOST_TEST((upload(standing, corrupt) == mb::Status::malformed));
    // A flipped byte inside the signed region fails the signature.
    auto flipped = signed_set(signer, default_instances());
    flipped[proto::standing_set_header_size] ^= std::byte{1};  // vm_a 0x1001 -> 0x1000
    BOOST_TEST((upload(standing, flipped) == mb::Status::bad_signature));

    BOOST_TEST(!standing.generation().has_value());
    BOOST_TEST(standing.stats().sets_refused == 4U);
    BOOST_TEST(
        (standing.start({.generation = generation, .index = 0}, handler) == mb::Status::conflict));
    BOOST_TEST(handler.seen.empty());
}

BOOST_AUTO_TEST_CASE(a_broken_transfer_aborts, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto pieces = chunks_of(signed_set(signer, default_instances()), 32);
    BOOST_REQUIRE(pieces.size() > 3U);
    BOOST_TEST((standing.chunk(pieces[0]) == mb::Status::ok));
    BOOST_TEST((standing.chunk(pieces[2]) == mb::Status::malformed));  // a gap
    BOOST_TEST((standing.chunk(pieces[3]) == mb::Status::malformed));  // nothing to continue
    auto changed = pieces[1];
    BOOST_TEST((standing.chunk(pieces[0]) == mb::Status::ok));
    changed.total += 1;
    BOOST_TEST((standing.chunk(changed) == mb::Status::malformed));  // a changed total
    BOOST_TEST(standing.stats().transfers_aborted == 3U);

    // Offset 0 starts over, and a complete transfer is taken.
    BOOST_TEST((upload(standing, signed_set(signer, default_instances())) == mb::Status::ok));
}

BOOST_AUTO_TEST_CASE(a_newer_set_replaces_the_held_one,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((upload(standing, signed_set(signer, default_instances())) == mb::Status::ok));
    BOOST_TEST((upload(standing, signed_set(signer, default_instances(), this_server,
                                            generation + 1)) == mb::Status::ok));
    BOOST_TEST((standing.generation() == generation + 1));
    // A start for the old generation is not for the set hull holds.
    BOOST_TEST(
        (standing.start({.generation = generation, .index = 0}, handler) == mb::Status::conflict));
    BOOST_TEST((standing.start({.generation = generation + 1, .index = 2}, handler) ==
                mb::Status::malformed));
    BOOST_TEST(handler.seen.empty());
}

BOOST_AUTO_TEST_CASE(a_failed_start_is_undone_and_may_be_retried,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((upload(standing, signed_set(signer, default_instances())) == mb::Status::ok));
    handler.fail_type = mb::Type::attach_device;
    BOOST_TEST((standing.start({.generation = generation, .index = 0}, handler) ==
                mb::Status::unknown_device));
    BOOST_REQUIRE(handler.seen.size() == 3U);
    const auto* destroy = std::get_if<mb::DestroyVm>(&handler.seen[2].second);
    BOOST_REQUIRE(destroy != nullptr);
    BOOST_TEST(destroy->vm_id == vm_a);
    BOOST_TEST(destroy->persist_volumes);  // the instance's volumes outlive the attempt
    BOOST_TEST(standing.stats().failed == 1U);

    handler.fail_type.reset();
    handler.seen.clear();
    BOOST_TEST((standing.start({.generation = generation, .index = 0}, handler) == mb::Status::ok));
    BOOST_TEST(handler.seen.size() == 2U);

    // A CREATE_VM that fails leaves nothing to destroy.
    handler.fail_type = mb::Type::create_vm;
    handler.fail_status = mb::Status::insufficient_resources;
    handler.seen.clear();
    BOOST_TEST((standing.start({.generation = generation, .index = 1}, handler) ==
                mb::Status::insufficient_resources));
    BOOST_TEST(handler.seen.size() == 1U);
}

BOOST_AUTO_TEST_CASE(every_command_names_the_instance,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Signed, but an attach for another VM: refused and undone.
    const auto frame =
        signed_set(signer, {instance(vm_a, {command(create_vm(vm_a)), command(attach_nic(vm_b))})});
    BOOST_TEST((upload(standing, frame) == mb::Status::ok));
    BOOST_TEST(
        (standing.start({.generation = generation, .index = 0}, handler) == mb::Status::malformed));
    BOOST_REQUIRE(handler.seen.size() == 2U);
    BOOST_TEST(std::holds_alternative<mb::DestroyVm>(handler.seen[1].second));

    // A CREATE_VM for another VM never runs.
    handler.seen.clear();
    const auto other = signed_set(signer, {instance(vm_a, {command(create_vm(vm_b))})});
    BOOST_TEST((upload(standing, other) == mb::Status::ok));
    BOOST_TEST(
        (standing.start({.generation = generation, .index = 0}, handler) == mb::Status::malformed));
    BOOST_TEST(handler.seen.empty());
}

BOOST_AUTO_TEST_CASE(closing_ends_standing_starts,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((upload(standing, signed_set(signer, default_instances())) == mb::Status::ok));
    standing.close();
    BOOST_TEST(!standing.open());
    BOOST_TEST(!standing.generation().has_value());  // the set is dropped
    BOOST_TEST(
        (standing.start({.generation = generation, .index = 0}, handler) == mb::Status::conflict));
    BOOST_TEST((standing.chunk(chunks_of(signed_set(signer, default_instances()))[0]) ==
                mb::Status::conflict));
    BOOST_TEST(handler.seen.empty());
}

BOOST_AUTO_TEST_SUITE_END()

// ---- Through the mailbox ----------------------------------------------------

namespace {

class DeviceWindow final : public ak::hull::MmioWindow {
public:
    explicit DeviceWindow(MailboxDevice& device) : _device{&device} {}
    auto read32(std::size_t offset) -> std::uint32_t override {
        std::array<std::byte, word> b{};
        if (!_device->read(offset, b)) {
            throw std::logic_error("bad read");
        }
        ak::wire::Reader r{b};
        return *r.le32();
    }
    auto write32(std::size_t offset, std::uint32_t value) -> void override {
        std::array<std::byte, word> b{};
        ak::wire::SpanWriter w{b};
        (void)w.write(value, ak::wire::Order::little);
        if (!_device->write(offset, b)) {
            throw std::logic_error("bad write");
        }
    }

private:
    MailboxDevice* _device;
};

struct MailboxFixture : Fixture {
    SequenceTracker sequence;
    std::vector<mb::Slot> responses;
    MailboxDevice device{[] { return true; },
                         [this](HostSlotKind kind, const mb::Slot& slot) {
                             if (kind == HostSlotKind::response) {
                                 responses.push_back(slot);
                             }
                         }};
    DeviceWindow window{device};
    MailboxClient client{window, this_server, verifier, sequence, handler};
    std::uint64_t next_helm_seq{1};

    MailboxFixture() {
        client.set_standing_starts(&standing);
        BOOST_REQUIRE(client.attach().has_value());
    }

    auto helm_slot(const mb::Body& body, mb::ServerId server = this_server) -> mb::Slot {
        const auto bytes = mb::encode_body(body);
        auto slot = mb::encode({.type = mb::type_of(body),
                                .seq = next_helm_seq++,
                                .body_len = static_cast<std::uint16_t>(bytes.size()),
                                .key_id = mb::no_key_id,
                                .server_id = server},
                               bytes, std::array<std::byte, mb::signature_size>{});
        BOOST_REQUIRE(slot.has_value());
        return *slot;
    }

    // Posts a slot, services it, and returns hull's answer.
    auto exchange(const mb::Slot& slot) -> mb::Response {
        responses.clear();
        BOOST_REQUIRE(device.post_command(slot));
        BOOST_REQUIRE(client.service());
        BOOST_REQUIRE(responses.size() == 1U);
        const auto msg = mb::decode(responses[0]);
        BOOST_REQUIRE(msg.has_value());
        return std::get<mb::Response>(*mb::decode_body(*msg));
    }

    auto send_set(const std::vector<std::byte>& frame) -> mb::Status {
        mb::Status last = mb::Status::internal_error;
        for (const auto& c : chunks_of(frame)) {
            last = exchange(helm_slot(c)).status;
        }
        return last;
    }
};

}  // namespace

BOOST_FIXTURE_TEST_SUITE(mailbox, MailboxFixture)

BOOST_AUTO_TEST_CASE(helm_commands_reach_standing_starts,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((send_set(signed_set(signer, default_instances())) == mb::Status::ok));
    const auto rsp = exchange(helm_slot(mb::StandingStart{.generation = generation, .index = 1}));
    BOOST_TEST((rsp.command == mb::Type::standing_start));
    BOOST_TEST(rsp.in_reply_to == next_helm_seq - 1);
    BOOST_TEST((rsp.status == mb::Status::ok));
    BOOST_TEST(handler.seen.size() == 1U);
    BOOST_TEST(sequence.last_accepted() == 0U);  // untouched

    // Another server's helm command is refused before anything else.
    const auto wrong =
        exchange(helm_slot(mb::StandingStart{.generation = generation, .index = 0}, other_server));
    BOOST_TEST((wrong.status == mb::Status::wrong_server));
    BOOST_TEST(handler.seen.size() == 1U);
}

BOOST_AUTO_TEST_CASE(the_first_signed_command_closes_them,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((send_set(signed_set(signer, default_instances())) == mb::Status::ok));
    const auto vm = mb::encode_body(create_vm(vm_b));
    const auto live = signer.signed_slot({.type = mb::Type::create_vm,
                                          .seq = 1,
                                          .body_len = static_cast<std::uint16_t>(vm.size()),
                                          .key_id = controller,
                                          .server_id = this_server},
                                         vm);
    BOOST_TEST((exchange(live).status == mb::Status::ok));
    BOOST_TEST(!standing.open());
    const auto rsp = exchange(helm_slot(mb::StandingStart{.generation = generation, .index = 0}));
    BOOST_TEST((rsp.status == mb::Status::conflict));
    BOOST_TEST(handler.seen.size() == 1U);  // only the live command ran
}

BOOST_AUTO_TEST_CASE(a_forged_command_does_not_close_them,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto vm = mb::encode_body(create_vm(vm_b));
    const auto forged = forger.signed_slot({.type = mb::Type::create_vm,
                                            .seq = 1,
                                            .body_len = static_cast<std::uint16_t>(vm.size()),
                                            .key_id = controller,
                                            .server_id = this_server},
                                           vm);
    BOOST_TEST((exchange(forged).status == mb::Status::bad_signature));
    BOOST_TEST(standing.open());
}

BOOST_AUTO_TEST_CASE(without_standing_starts_they_are_unsupported,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    client.set_standing_starts(nullptr);
    const auto rsp = exchange(helm_slot(mb::StandingStart{.generation = generation, .index = 0}));
    BOOST_TEST((rsp.status == mb::Status::unsupported));
    BOOST_TEST(client.stats().unsupported == 1U);
}

BOOST_AUTO_TEST_CASE(a_signed_slot_of_a_helm_type_is_malformed,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A slot that claims a helm type but carries a signature does not
    // decode, and authenticate() never takes a helm type either.
    auto slot = helm_slot(mb::StandingStart{.generation = generation, .index = 0});
    slot[mb::signature_offset] = std::byte{1};
    const auto rsp = exchange(slot);
    BOOST_TEST((rsp.command == mb::Type::standing_start));
    BOOST_TEST((rsp.status == mb::Status::malformed));

    const auto clean = helm_slot(mb::StandingStart{.generation = generation, .index = 0});
    BOOST_TEST((ak::hull::authenticate(clean, this_server, verifier, sequence).error().failure ==
                ak::hull::AuthFailure::not_a_command));
}

BOOST_AUTO_TEST_SUITE_END()
