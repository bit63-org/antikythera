// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the VtepCredential and CredentialRevocations decoders and the
// network role's CredentialStore (fleet-scale-networking task 2). Whatever
// decodes must re-encode to identical bytes and satisfy the rules the role
// relies on (a non-empty validity window; revoked serials strictly
// ascending). The verifier accepts everything, so the store sees each
// accepted frame: an installed list is reported as revoking exactly its
// unexpired entries, a peer credential is accepted only from its own VTEP,
// and a second delivery of the same bytes is never a fresh install.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "oar/net/credentials.hpp"
#include "proto/vtep_credential.hpp"

namespace {

namespace net = ak::oar::net;
namespace proto = ak::proto;

// A fixed clock: the frame decides whether it is inside its window.
constexpr std::int64_t fuzz_now = 1'800'000'000;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): libFuzzer's byte API
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    net::CredentialStore store{
        net::CredentialConfig{.server_id = 1,
                              .vtep = {},
                              .skew = std::chrono::minutes{5},
                              .wall_clock =
                                  [] {
                                      return std::chrono::system_clock::time_point{
                                          std::chrono::seconds{fuzz_now}};
                                  }},
        [](auto /*signed_bytes*/, auto /*signature*/, auto /*key_id*/) { return true; }};

    if (auto c = proto::decode_vtep_credential(bytes); c) {
        auto again = proto::encode_vtep_credential(*c);
        if (!again || !std::ranges::equal(*again, bytes) || c->not_before >= c->not_after ||
            c->server_id == 0 || c->key_epoch == 0 || c->serial == 0) {
            std::abort();
        }
        // From any address but its own VTEP it is refused.
        auto elsewhere = c->vtep;
        elsewhere[elsewhere.size() - 1] ^= std::byte{1};
        if (store.verify_peer(bytes, elsewhere).has_value()) {
            std::abort();
        }
        if (auto v = store.verify_peer(bytes, c->vtep); v && !(*v == *c)) {
            std::abort();
        }
        // As the role's own: a target that is not this store's.
        if (store.install_own(bytes, c->public_key) == net::CredentialResult::installed &&
            (c->server_id != 1 ||
             store.install_own(bytes, c->public_key) != net::CredentialResult::redelivered)) {
            std::abort();
        }
    }

    if (auto l = proto::decode_credential_revocations(bytes); l) {
        auto again = proto::encode_credential_revocations(*l);
        if (!again || !std::ranges::equal(*again, bytes) ||
            l->entries.size() > proto::max_revocations ||
            !std::ranges::is_sorted(l->entries, std::ranges::less_equal{},
                                    &proto::Revocation::serial)) {
            std::abort();
        }
        if (store.install_revocations(bytes) != net::CredentialResult::installed ||
            store.install_revocations(bytes) != net::CredentialResult::redelivered ||
            store.revocations_version(l->cell_id) != l->list_version) {
            std::abort();
        }
        const auto now = static_cast<std::uint64_t>(fuzz_now);
        for (const auto& e : l->entries) {
            const bool live = now < e.not_after + 300;
            if (store.revoked(l->cell_id, e.serial) != live) {
                std::abort();
            }
        }
    }
    return 0;
}
