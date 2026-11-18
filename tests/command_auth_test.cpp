// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ Requirements 3.4, 4.2 and 4.3: decode, then
// signature, then sequence number, with the sequence advancing only for
// authentic commands.

#define BOOST_TEST_MODULE command_auth_test
#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "common/wire.hpp"
#include "ed25519_test_support.hpp"
#include "helm/mailbox.hpp"
#include "hull/command_auth.hpp"
#include "test_support.hpp"

namespace mb = ak::helm::mailbox;
using ak::hull::AuthError;
using ak::hull::AuthFailure;
using ak::hull::KeyId;
using ak::hull::SequenceError;
using ak::hull::SequenceTracker;
using ak::hull::SignatureVerifier;
using ak::test::controller_key;
using ak::test::TestSigner;
using ak::test::unit_timeout_seconds;

namespace {

constexpr KeyId controller = 1;
constexpr KeyId other_key = 2;
constexpr std::uint64_t first_seq = 1;
constexpr std::uint64_t second_seq = 2;
constexpr std::uint64_t gap_seq = 50;
constexpr std::uint64_t forged_seq = 1'000'000;
constexpr std::uint64_t restored_floor = 400;
constexpr std::uint64_t sample_vm = 42;
constexpr std::uint16_t sample_vcpus = 4;
constexpr std::uint32_t sample_memory_mib = 8192;
constexpr std::uint8_t boot_volume = 1;
constexpr std::byte flip{0x01};
constexpr std::size_t body_offset = mb::header_size;
constexpr std::byte not_magic{'X'};

auto create_vm_body() -> std::vector<std::byte> {
    std::vector<std::byte> b;
    ak::wire::Writer w{b};
    w.le64(sample_vm);
    w.le16(sample_vcpus);
    w.le32(sample_memory_mib);
    w.u8(boot_volume);
    w.u8(0);
    return b;
}

struct Fixture {
    TestSigner signer{ak::test::rfc_test1_secret};
    TestSigner forger{ak::test::rfc_test2_secret};
    SignatureVerifier verifier = [] {
        const std::array keys{controller_key(controller, ak::test::rfc_test1_public)};
        auto v = SignatureVerifier::create(keys);
        if (!v) {
            throw std::runtime_error("key table");
        }
        return std::move(*v);
    }();
    SequenceTracker sequence;

    // `key` goes in the slot header; responses and events carry no key ID.
    [[nodiscard]] auto command(const TestSigner& by, std::uint64_t seq,
                               mb::Type type = mb::Type::create_vm, KeyId key = controller) const
        -> mb::Slot {
        const auto body = create_vm_body();
        return by.signed_slot({.type = type,
                               .seq = seq,
                               .body_len = static_cast<std::uint16_t>(body.size()),
                               .key_id = mb::is_command(type) ? key : mb::no_key_id},
                              body);
    }

    auto auth(const mb::Slot& slot) { return ak::hull::authenticate(slot, verifier, sequence); }
};

auto failure(AuthFailure f) -> AuthError {
    return {.failure = f};
}

}  // namespace

BOOST_AUTO_TEST_SUITE(sequence_tracker)

BOOST_AUTO_TEST_CASE(strictly_increasing_with_gaps,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    SequenceTracker t;
    BOOST_TEST((t.accept(0).error() == SequenceError::replayed));
    BOOST_TEST(t.accept(first_seq).has_value());
    BOOST_TEST((t.accept(first_seq).error() == SequenceError::replayed));
    BOOST_TEST(t.accept(gap_seq).has_value());
    BOOST_TEST((t.accept(second_seq).error() == SequenceError::replayed));
    BOOST_TEST(t.last_accepted() == gap_seq);
}

BOOST_AUTO_TEST_CASE(floor_and_limits, *boost::unit_test::timeout(unit_timeout_seconds)) {
    SequenceTracker t{restored_floor};
    BOOST_TEST((t.accept(restored_floor).error() == SequenceError::replayed));
    BOOST_TEST(t.accept(restored_floor + 1).has_value());

    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    BOOST_TEST(t.accept(max).has_value());
    BOOST_TEST((t.accept(max).error() == SequenceError::replayed));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(authenticate, Fixture)

BOOST_AUTO_TEST_CASE(accepts_signed_command, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto msg = auth(command(signer, first_seq));
    BOOST_REQUIRE(msg.has_value());
    BOOST_TEST((msg->header.type == mb::Type::create_vm));
    BOOST_TEST(msg->header.seq == first_seq);
    const auto vm = mb::decode_create_vm(*msg);
    BOOST_REQUIRE(vm.has_value());
    BOOST_TEST(vm->vm_id == sample_vm);
    BOOST_TEST(sequence.last_accepted() == first_seq);
}

BOOST_AUTO_TEST_CASE(rejects_replay, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto slot = command(signer, gap_seq);
    BOOST_REQUIRE(auth(slot).has_value());
    BOOST_TEST((auth(slot).error() == failure(AuthFailure::replayed)));
    BOOST_TEST((auth(command(signer, second_seq)).error() == failure(AuthFailure::replayed)));
    BOOST_TEST(auth(command(signer, gap_seq + 1)).has_value());
}

BOOST_AUTO_TEST_CASE(forgery_does_not_consume_sequence,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((auth(command(forger, forged_seq)).error() == failure(AuthFailure::bad_signature)));
    BOOST_TEST(sequence.last_accepted() == 0);

    // A genuine command with a tampered body is a forgery too.
    auto tampered = command(signer, forged_seq);
    tampered[body_offset] ^= flip;
    BOOST_TEST((auth(tampered).error() == failure(AuthFailure::bad_signature)));
    BOOST_TEST(sequence.last_accepted() == 0);

    BOOST_TEST(auth(command(signer, first_seq)).has_value());
}

BOOST_AUTO_TEST_CASE(rejects_unknown_key_id, *boost::unit_test::timeout(unit_timeout_seconds)) {
    BOOST_TEST((auth(command(signer, first_seq, mb::Type::create_vm, other_key)).error() ==
                failure(AuthFailure::unknown_key)));
    BOOST_TEST(sequence.last_accepted() == 0);
}

BOOST_AUTO_TEST_CASE(rejects_malformed_before_signature,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto slot = command(signer, first_seq);
    slot[0] = not_magic;
    BOOST_TEST((auth(slot).error() == AuthError{.failure = AuthFailure::malformed,
                                                .decode = mb::DecodeError::bad_magic}));
    BOOST_TEST(sequence.last_accepted() == 0);
}

BOOST_AUTO_TEST_CASE(rejects_non_command_types, *boost::unit_test::timeout(unit_timeout_seconds)) {
    for (const auto type : {mb::Type::response, mb::Type::vm_exited, mb::Type::device_released}) {
        BOOST_TEST((auth(command(signer, first_seq, type)).error() ==
                    failure(AuthFailure::not_a_command)));
    }
    BOOST_TEST(sequence.last_accepted() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
