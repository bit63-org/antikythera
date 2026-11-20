// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes hull's whole MailboxClient path from slot bytes
// (.kiro/specs/hull-host-agent/ design, "Testing strategy"): arbitrary bytes
// in CMD_SLOT behind a rung doorbell. A random slot never carries a valid
// signature, so the handler must never run and the sequence floor must not
// move; whatever hull writes back must be a well-formed response that helm
// decodes, and at most one per command.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <variant>

#include "helm/mailbox.hpp"
#include "hull/mailbox_client.hpp"

namespace mb = ak::helm::mailbox;

namespace {

constexpr ak::hull::KeyId fuzz_key_id = 1;
constexpr mb::ServerId fuzz_server_id = 7;

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

class Bar final : public ak::hull::MmioWindow {
public:
    auto read32(std::size_t offset) -> std::uint32_t override {
        std::uint32_t v = 0;
        std::memcpy(&v, bytes.data() + offset, sizeof(v));
        return v;
    }
    auto write32(std::size_t offset, std::uint32_t value) -> void override {
        if (offset == mb::reg::rsp_doorbell) {
            ++responses;
        } else if (offset == mb::reg::evt_doorbell) {
            std::abort();  // no events from servicing a command
        }
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }
    std::array<std::byte, mb::reg::bar0_size> bytes{};
    int responses{0};
};

struct NeverCalled final : ak::hull::CommandHandler {
    auto handle(const mb::Message& /*msg*/, const mb::Body& /*body*/)
        -> ak::hull::CommandOutcome override {
        std::abort();
    }
};

auto put32(Bar& bar, std::size_t offset, std::uint32_t v) -> void {
    std::memcpy(bar.bytes.data() + offset, &v, sizeof(v));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const auto verifier = make_verifier();
    Bar bar;
    put32(bar, mb::reg::magic, mb::magic);
    put32(bar, mb::reg::version, mb::protocol_version);
    ak::hull::SequenceTracker sequence;
    NeverCalled handler;
    ak::hull::MailboxClient client{bar, fuzz_server_id, verifier, sequence, handler};
    if (!client.attach()) {
        std::abort();
    }
    std::memcpy(bar.bytes.data() + mb::reg::cmd_slot, data, std::min(size, mb::slot_size));
    put32(bar, mb::reg::cmd_doorbell, 1);
    if (!client.service() || client.service() || sequence.last_accepted() != 0 ||
        bar.responses > 1) {
        std::abort();
    }
    if (bar.responses == 1) {
        mb::Slot slot{};
        std::memcpy(slot.data(), bar.bytes.data() + mb::reg::rsp_slot, slot.size());
        const auto msg = mb::decode(slot);
        if (!msg) {
            std::abort();
        }
        const auto body = mb::decode_body(*msg);
        if (!body || !std::holds_alternative<mb::Response>(*body) ||
            std::get<mb::Response>(*body).status == mb::Status::ok) {
            std::abort();
        }
    }
    return 0;
}
