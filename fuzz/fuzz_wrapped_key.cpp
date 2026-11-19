// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the wrapped-key decoder (wrapped volume keys are read back from the
// media, so they are untrusted). An accepted blob must re-encode to the same
// bytes, and unwrapping it, as a VM key or as a volume key, must fail
// authentication cleanly: random bytes never carry a valid GCM tag.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <span>
#include <utility>

#include "helm/secure_element.hpp"

namespace helm = ak::helm;

namespace {

constexpr helm::VmId fuzz_vm = 1;
constexpr helm::VolumeId fuzz_volume = 2;

struct State {
    helm::SoftwareSecureElement se;
    helm::WrappedVmKey vm;
};

auto state() -> State& {
    static State s = [] {
        auto se = helm::SoftwareSecureElement::ephemeral();
        if (!se) {
            std::abort();
        }
        auto vm = se->create_vm_key(fuzz_vm);
        if (!vm) {
            std::abort();
        }
        return State{.se = std::move(*se), .vm = std::move(*vm)};
    }();
    return s;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    auto key = helm::WrappedKey::decode(bytes);
    if (!key) {
        return 0;
    }
    if (key->bytes().size() != size ||
        !std::equal(key->bytes().begin(), key->bytes().end(), bytes.begin())) {
        std::abort();
    }
    auto& s = state();
    if (key->kind() == helm::KeyKind::volume) {
        const helm::WrappedVolumeKey vol{.volume = fuzz_volume, .owner = fuzz_vm, .key = *key};
        if (s.se.unwrap_volume_key(s.vm, vol)) {
            std::abort();
        }
    } else {
        const helm::WrappedVmKey vm{.vm = fuzz_vm, .key = *key};
        if (s.se.create_volume_key(vm, fuzz_volume)) {
            std::abort();
        }
    }
    return 0;
}
