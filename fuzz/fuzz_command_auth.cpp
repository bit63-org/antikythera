// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes hull's command authentication: arbitrary slots through
// authenticate(), and arbitrary signature/message pairs through
// SignatureVerifier::verify(), which must reject without crashing (OpenSSL
// sees attacker-chosen signature encodings, including S >= L). A random
// input never carries a valid signature, so the sequence floor must never
// move.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "helm/mailbox.hpp"
#include "hull/command_auth.hpp"

namespace mb = ak::helm::mailbox;

namespace {

constexpr ak::hull::KeyId fuzz_key_id = 1;

// RFC 8032 7.1 TEST 1 public key.
constexpr std::array<std::uint8_t, ak::hull::ed25519_public_key_size> fuzz_public_key{
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

auto make_verifier() -> ak::hull::SignatureVerifier {
    ak::hull::ControllerKey key{.id = fuzz_key_id};
    std::ranges::transform(fuzz_public_key, key.key.begin(),
                           [](std::uint8_t b) { return static_cast<std::byte>(b); });
    auto v = ak::hull::SignatureVerifier::create(std::span{&key, 1});
    if (!v) {
        std::abort();
    }
    return std::move(*v);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const auto verifier = make_verifier();
    const std::span<const std::byte> input{reinterpret_cast<const std::byte*>(data), size};

    mb::Slot slot{};
    std::ranges::copy(input.first(std::min(size, slot.size())), slot.begin());
    ak::hull::SequenceTracker sequence;
    if (ak::hull::authenticate(slot, fuzz_key_id, verifier, sequence) ||
        sequence.last_accepted() != 0) {
        std::abort();
    }

    if (size >= ak::hull::ed25519_signature_size) {
        const auto sig = input.first<ak::hull::ed25519_signature_size>();
        if (verifier.verify(input.subspan(ak::hull::ed25519_signature_size), sig, fuzz_key_id)) {
            std::abort();
        }
    }
    return 0;
}
