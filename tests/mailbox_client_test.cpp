// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ task 4, Requirements 3 and 4: hull's
// MailboxClient against helm's MailboxDevice register file, joined by a
// 32-bit MMIO window as VFIO joins them on a real host. Every command gets
// exactly one response, the command slot is copied out once, a response
// slot is complete before its doorbell, and nothing unauthenticated reaches
// the handler.

#define BOOST_TEST_MODULE mailbox_client_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include "common/wire.hpp"
#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "helm/mailbox_device.hpp"
#include "hull/mailbox_client.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::helm::HostSlotKind;
using ak::helm::MailboxDevice;
using ak::hull::AttachError;
using ak::hull::CommandOutcome;
using ak::hull::KeyId;
using ak::hull::MailboxClient;
using ak::hull::SequenceTracker;
using ak::hull::SignatureVerifier;
using ak::test::controller_key;
using ak::test::TestSigner;
using ak::test::unit_timeout_seconds;

namespace {

constexpr KeyId controller = 1;
constexpr mb::ServerId this_server = 7;
constexpr mb::ServerId other_server = 8;
constexpr std::uint64_t sample_vm = 42;
constexpr std::uint16_t sample_vcpus = 4;
constexpr std::uint32_t sample_memory_mib = 8192;
constexpr std::size_t word = 4;
constexpr std::size_t slot_words = mb::slot_size / word;
constexpr std::uint64_t garbage_seq = 77;

// helm's register file seen through aligned 32-bit MMIO, with a log of
// every access so tests can check the order and count.
struct Access {
    bool write;
    std::size_t offset;
};

class DeviceWindow final : public ak::hull::MmioWindow {
public:
    explicit DeviceWindow(MailboxDevice& device) : _device{&device} {}

    auto read32(std::size_t offset) -> std::uint32_t override {
        log.push_back({.write = false, .offset = offset});
        std::array<std::byte, word> b{};
        if (!_device->read(offset, b)) {
            throw std::logic_error("bad read");
        }
        ak::wire::Reader r{b};
        return *r.le32();
    }
    auto write32(std::size_t offset, std::uint32_t value) -> void override {
        log.push_back({.write = true, .offset = offset});
        std::array<std::byte, word> b{};
        ak::wire::SpanWriter w{b};
        (void)w.write(value, ak::wire::Order::little);
        if (!_device->write(offset, b)) {
            throw std::logic_error("bad write");
        }
    }

    std::vector<Access> log;

private:
    MailboxDevice* _device;
};

// Plain memory standing in for a BAR that holds something else.
class MemoryWindow final : public ak::hull::MmioWindow {
public:
    auto read32(std::size_t offset) -> std::uint32_t override { return regs.at(offset / word); }
    auto write32(std::size_t offset, std::uint32_t value) -> void override {
        regs.at(offset / word) = value;
    }
    std::array<std::uint32_t, mb::reg::bar0_size / word> regs{};
};

struct RecordingHandler final : ak::hull::CommandHandler {
    auto handle(const mb::Message& msg, const mb::Body& body) -> CommandOutcome override {
        seen.emplace_back(msg.header.seq, body);
        return next;
    }
    std::vector<std::pair<std::uint64_t, mb::Body>> seen;
    CommandOutcome next{};
};

auto make_verifier() -> SignatureVerifier {
    const std::array keys{controller_key(controller, ak::test::rfc_test1_public)};
    auto v = SignatureVerifier::create(keys);
    if (!v) {
        throw std::runtime_error("key table");
    }
    return std::move(*v);
}

struct Fixture {
    TestSigner signer{ak::test::rfc_test1_secret};
    TestSigner forger{ak::test::rfc_test2_secret};
    SignatureVerifier verifier = make_verifier();
    SequenceTracker sequence;
    RecordingHandler handler;
    std::vector<std::pair<HostSlotKind, mb::Slot>> to_helm;
    MailboxDevice device{
        [] { return true; },
        [this](HostSlotKind kind, const mb::Slot& slot) { to_helm.emplace_back(kind, slot); }};
    DeviceWindow window{device};
    MailboxClient client{window, this_server, verifier, sequence, handler};

    Fixture() { BOOST_REQUIRE(client.attach().has_value()); }

    [[nodiscard]] auto command(const TestSigner& by, std::uint64_t seq, const mb::Body& body,
                               mb::ServerId server = this_server) const -> mb::Slot {
        const auto bytes = mb::encode_body(body);
        return by.signed_slot({.type = mb::type_of(body),
                               .seq = seq,
                               .body_len = static_cast<std::uint16_t>(bytes.size()),
                               .key_id = controller,
                               .server_id = server},
                              bytes);
    }

    // helm posts a slot; hull services the interrupt.
    auto exchange(const mb::Slot& slot) -> bool {
        BOOST_REQUIRE(device.post_command(slot));
        return client.service();
    }

    // The only response helm has received since the last call.
    auto take_response() -> std::pair<mb::Message, mb::Response> {
        BOOST_REQUIRE(to_helm.size() == 1U);
        BOOST_REQUIRE((to_helm[0].first == HostSlotKind::response));
        const auto msg = mb::decode(to_helm[0].second);
        BOOST_REQUIRE(msg.has_value());
        const auto body = mb::decode_body(*msg);
        BOOST_REQUIRE(body.has_value());
        to_helm.clear();
        return {*msg, std::get<mb::Response>(*body)};
    }
};

auto create_vm() -> mb::Body {
    return mb::CreateVm{.vm_id = sample_vm,
                        .vcpus = sample_vcpus,
                        .memory_mib = sample_memory_mib,
                        .boot_mode = mb::BootMode::volume};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(attach)

BOOST_AUTO_TEST_CASE(checks_identity, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto verifier = make_verifier();
    SequenceTracker sequence;
    RecordingHandler handler;
    MemoryWindow bar;
    MailboxClient client{bar, this_server, verifier, sequence, handler};
    BOOST_TEST((client.attach().error() == AttachError::bad_magic));
    bar.regs[mb::reg::magic / word] = mb::magic;
    bar.regs[mb::reg::version / word] = mb::protocol_version + 1;
    BOOST_TEST((client.attach().error() == AttachError::bad_version));
    bar.regs[mb::reg::version / word] = mb::protocol_version;
    BOOST_TEST(client.attach().has_value());
    BOOST_TEST(ak::hull::to_string(AttachError::bad_version) == std::string_view{"bad_version"});
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(mailbox_client, Fixture)

BOOST_AUTO_TEST_CASE(runs_signed_command_and_responds,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(exchange(command(signer, 1, create_vm())));
    BOOST_REQUIRE(handler.seen.size() == 1U);
    BOOST_TEST(handler.seen[0].first == 1U);
    BOOST_TEST((handler.seen[0].second == create_vm()));

    const auto [msg, rsp] = take_response();
    BOOST_TEST((msg.header.type == mb::Type::response));
    BOOST_TEST(msg.header.key_id == mb::no_key_id);
    BOOST_TEST(msg.header.seq == 1U);
    BOOST_TEST(rsp.in_reply_to == 1U);
    BOOST_TEST((rsp.command == mb::Type::create_vm));
    BOOST_TEST((rsp.status == mb::Status::ok));
    BOOST_TEST(client.stats().commands == 1U);

    // A second interrupt with nothing new does nothing.
    BOOST_TEST(!client.service());
    BOOST_TEST(client.stats().spurious == 1U);
    BOOST_TEST(to_helm.empty());

    // Header sequence numbers of hull's own messages keep counting.
    handler.next = {.status = mb::Status::accepted, .payload = {}};
    BOOST_TEST(exchange(command(signer, 2, mb::DestroyVm{.vm_id = sample_vm})));
    const auto [msg2, rsp2] = take_response();
    BOOST_TEST(msg2.header.seq == 2U);
    BOOST_TEST((rsp2.status == mb::Status::accepted));
}

BOOST_AUTO_TEST_CASE(copies_slot_once_and_rings_last,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    window.log.clear();
    BOOST_TEST(exchange(command(signer, 1, create_vm())));

    std::size_t cmd_reads = 0;
    std::size_t rsp_writes = 0;
    std::optional<std::size_t> last_rsp_write;
    std::optional<std::size_t> doorbell;
    for (std::size_t i = 0; i < window.log.size(); ++i) {
        const auto& a = window.log[i];
        const bool in_cmd = a.offset >= mb::reg::cmd_slot && a.offset < mb::reg::rsp_slot;
        const bool in_rsp = a.offset >= mb::reg::rsp_slot && a.offset < mb::reg::evt_slot;
        cmd_reads += (!a.write && in_cmd) ? 1 : 0;
        if (a.write && in_rsp) {
            ++rsp_writes;
            last_rsp_write = i;
        }
        if (a.write && a.offset == mb::reg::rsp_doorbell) {
            BOOST_TEST(!doorbell.has_value());
            doorbell = i;
        }
        BOOST_TEST((a.offset % word) == 0U);
    }
    BOOST_TEST(cmd_reads == slot_words);   // the slot is read exactly once
    BOOST_TEST(rsp_writes == slot_words);  // every response byte is written
    BOOST_REQUIRE(doorbell.has_value());
    BOOST_REQUIRE(last_rsp_write.has_value());
    BOOST_TEST(*last_rsp_write < *doorbell);
    BOOST_TEST(*doorbell == window.log.size() - 1);
}

BOOST_AUTO_TEST_CASE(ignores_command_present_before_attach,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_REQUIRE(device.post_command(command(signer, 1, create_vm())));
    MailboxClient late{window, this_server, verifier, sequence, handler};
    BOOST_REQUIRE(late.attach().has_value());
    BOOST_TEST(!late.service());
    BOOST_TEST(handler.seen.empty());
    BOOST_TEST(to_helm.empty());
}

BOOST_AUTO_TEST_CASE(forgery_is_refused, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(exchange(command(forger, 5, create_vm())));
    BOOST_TEST(handler.seen.empty());
    const auto [msg, rsp] = take_response();
    BOOST_TEST(rsp.in_reply_to == 5U);
    BOOST_TEST((rsp.status == mb::Status::bad_signature));
    BOOST_TEST(sequence.last_accepted() == 0U);
    BOOST_TEST(client.stats().bad_signature == 1U);
}

BOOST_AUTO_TEST_CASE(other_servers_command_is_refused,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(exchange(command(signer, 9, create_vm(), other_server)));
    BOOST_TEST(handler.seen.empty());
    const auto [msg, rsp] = take_response();
    BOOST_TEST(rsp.in_reply_to == 9U);
    BOOST_TEST((rsp.status == mb::Status::wrong_server));
    BOOST_TEST(sequence.last_accepted() == 0U);
    BOOST_TEST(client.stats().wrong_server == 1U);
}

BOOST_AUTO_TEST_CASE(replay_is_refused, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto slot = command(signer, 3, create_vm());
    BOOST_TEST(exchange(slot));
    (void)take_response();
    BOOST_TEST(exchange(slot));
    const auto [msg, rsp] = take_response();
    BOOST_TEST(rsp.in_reply_to == 3U);
    BOOST_TEST((rsp.status == mb::Status::stale_sequence));
    BOOST_TEST(handler.seen.size() == 1U);
    BOOST_TEST(client.stats().replayed == 1U);
}

BOOST_AUTO_TEST_CASE(malformed_slots, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // A known command type and sequence number in a slot that fails decode
    // (bad magic): answered malformed, addressed by the claimed fields.
    auto slot = command(signer, garbage_seq, create_vm());
    slot[0] = std::byte{'X'};
    BOOST_TEST(exchange(slot));
    const auto [msg, rsp] = take_response();
    BOOST_TEST(rsp.in_reply_to == garbage_seq);
    BOOST_TEST((rsp.command == mb::Type::create_vm));
    BOOST_TEST((rsp.status == mb::Status::malformed));

    // A slot naming no command type: nothing to address a response to.
    mb::Slot junk{};
    junk.fill(std::byte{0xEE});
    BOOST_TEST(exchange(junk));
    BOOST_TEST(to_helm.empty());
    BOOST_TEST(client.stats().unanswerable == 1U);

    // A response type in the command slot is malformed too.
    const auto bytes = mb::encode_body(
        mb::Response{.in_reply_to = 1, .command = mb::Type::create_vm, .status = mb::Status::ok});
    const std::array<std::byte, mb::signature_size> sig{};
    const auto rsp_slot = mb::encode({.type = mb::Type::response,
                                      .seq = garbage_seq,
                                      .body_len = static_cast<std::uint16_t>(bytes.size()),
                                      .key_id = mb::no_key_id},
                                     bytes, sig);
    BOOST_REQUIRE(rsp_slot.has_value());
    BOOST_TEST(exchange(*rsp_slot));
    BOOST_TEST(to_helm.empty());  // its type is not a command
    BOOST_TEST(handler.seen.empty());
    BOOST_TEST(sequence.last_accepted() == 0U);
}

BOOST_AUTO_TEST_CASE(bad_body_and_reserved_type, *boost::unit_test::timeout(unit_timeout_seconds)) {
    // Authentic, but the body is wrong for its type.
    const std::array<std::byte, 3> short_body{};
    BOOST_TEST(exchange(signer.signed_slot({.type = mb::Type::create_vm,
                                            .seq = 1,
                                            .body_len = 3,
                                            .key_id = controller,
                                            .server_id = this_server},
                                           short_body)));
    BOOST_TEST((take_response().second.status == mb::Status::malformed));

    BOOST_TEST(exchange(signer.signed_slot({.type = mb::Type::gpu_vf_config,
                                            .seq = 2,
                                            .body_len = 0,
                                            .key_id = controller,
                                            .server_id = this_server},
                                           {})));
    const auto [msg, rsp] = take_response();
    BOOST_TEST((rsp.command == mb::Type::gpu_vf_config));
    BOOST_TEST((rsp.status == mb::Status::unsupported));
    BOOST_TEST(handler.seen.empty());
    BOOST_TEST(client.stats().unsupported == 1U);
}

BOOST_AUTO_TEST_CASE(payload_rules, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const std::vector<std::byte> payload{std::byte{1}, std::byte{2}, std::byte{3}};
    handler.next = {.status = mb::Status::ok, .payload = payload};
    BOOST_TEST(exchange(command(signer, 1, mb::ListVms{})));
    const auto [msg, rsp] = take_response();
    BOOST_TEST((rsp.status == mb::Status::ok));
    BOOST_TEST(std::ranges::equal(rsp.payload_bytes(), payload));

    // A payload the protocol cannot carry becomes internal_error.
    BOOST_TEST(exchange(command(signer, 2, create_vm())));
    const auto [msg2, rsp2] = take_response();
    BOOST_TEST((rsp2.status == mb::Status::internal_error));
    BOOST_TEST(rsp2.payload_bytes().empty());

    handler.next.payload.assign(mb::max_response_payload + 1, std::byte{9});
    BOOST_TEST(exchange(command(signer, 3, mb::VmStatus{.vm_id = sample_vm})));
    BOOST_TEST((take_response().second.status == mb::Status::internal_error));
}

BOOST_AUTO_TEST_CASE(sends_events, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const mb::Body released =
        mb::DeviceReleased{.vm_id = sample_vm,
                           .device = {.slot = 2, .type = mb::DeviceType::nic_vf, .function = 3},
                           .reset = mb::ResetResult::ok};
    BOOST_TEST(client.send_event(released));
    BOOST_REQUIRE(to_helm.size() == 1U);
    BOOST_TEST((to_helm[0].first == HostSlotKind::event));
    const auto msg = mb::decode(to_helm[0].second);
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST((mb::decode_body(*msg).value() == released));

    BOOST_TEST(!client.send_event(mb::Response{}));
    BOOST_TEST(!client.send_event(create_vm()));
    BOOST_TEST(client.stats().events == 1U);
}

BOOST_AUTO_TEST_CASE(device_reset_is_not_a_command,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST(exchange(command(signer, 1, create_vm())));
    (void)take_response();
    device.reset();  // doorbell back to 0, slots zeroed
    BOOST_TEST(client.service());
    BOOST_TEST(to_helm.empty());
    BOOST_TEST(handler.seen.size() == 1U);
    // Commands after the reset are taken normally.
    BOOST_TEST(exchange(command(signer, 2, create_vm())));
    BOOST_TEST((take_response().second.status == mb::Status::ok));
}

BOOST_AUTO_TEST_SUITE_END()
