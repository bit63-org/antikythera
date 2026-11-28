// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MetadataStore: a network role's instance metadata records, one per NIC
// (.kiro/specs/oar-net-data-plane/ Requirement 13.4, design "Metadata
// service"; controller-interface Requirement 11).
//
// helm forwards the controller's InstanceMetadata frames unmodified and
// reads none of them, so this is where a record is trusted or not. put():
//
//   1. decodes the frame strictly and checks that it names this server;
//   2. verifies the Ed25519 signature over instance_metadata_signed_bytes
//      with the controller's key `key_id` (the same verifier the role
//      uses for MapUpdates);
//   3. compares the version with the record kept for the NIC: the same
//      version is a re-delivery (helm replays after a sideband reopen) and
//      changes nothing; an older one is refused;
//   4. keeps the decoded record for the NIC, replacing the older one.
//
// A record arrives before the attach that plugs its NIC and stays until
// the role cleans that NIC (drop()).
//
// It also holds the NIC's instance secrets (.kiro/specs/cold-start/
// Requirement 5.4), which helm opened in its secure element and sent for
// a standing instance (put_secrets()). They are in the clear, so they
// are wiped when replaced, dropped with the NIC, or the store goes. They
// count against the same capacity as records. At most `capacity` records are kept,
// one per NIC the role can host; a record for a new NIC when the store is
// full is refused, so a misbehaving sender cannot grow the role's memory
// (each record may hold 16 KiB of user data).
//
// Not thread-safe: it belongs to the role's data-plane thread.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <vector>

#include "oar/net/metadata_http.hpp"
#include "proto/instance_metadata.hpp"

namespace ak::oar::net {

// Checks a controller frame signature: Ed25519 over `signed_bytes` under
// the controller key `key_id`. True only if it verifies.
using MetadataVerifier = std::function<bool(
    std::span<const std::byte> signed_bytes,
    std::span<const std::byte, proto::ed25519_signature_size> signature, std::uint16_t key_id)>;

enum class MetadataResult : std::uint8_t {
    kept,           // the record is now the NIC's
    redelivered,    // the version already kept: nothing changed
    undecodable,    // proto::decode_instance_metadata refused it
    wrong_server,   // for another server
    bad_signature,  // the signature does not verify
    stale,          // older than the version kept
    full,           // a new NIC, and `capacity` records are kept already
};

[[nodiscard]] auto to_string(MetadataResult r) noexcept -> const char*;
// True for the results the role answers ok to.
[[nodiscard]] constexpr auto accepted(MetadataResult r) noexcept -> bool {
    return r == MetadataResult::kept || r == MetadataResult::redelivered;
}

struct MetadataCounters {
    std::uint64_t kept{0};
    std::uint64_t redelivered{0};
    std::uint64_t undecodable{0};
    std::uint64_t wrong_server{0};
    std::uint64_t bad_signature{0};
    std::uint64_t stale{0};
    std::uint64_t full{0};
    std::uint64_t dropped{0};  // records removed by drop()
};

class MetadataStore {
public:
    MetadataStore(std::uint64_t server_id, std::size_t capacity, MetadataVerifier verifier);
    ~MetadataStore();
    MetadataStore(const MetadataStore&) = delete;
    auto operator=(const MetadataStore&) -> MetadataStore& = delete;
    MetadataStore(MetadataStore&&) = delete;
    auto operator=(MetadataStore&&) -> MetadataStore& = delete;

    auto put(std::span<const std::byte> frame) -> MetadataResult;
    // The NIC was cleaned: its record and secrets go. False if it had no
    // record.
    auto drop(std::uint64_t nic_id) -> bool;
    // Replaces the NIC's secrets, taking the values (an empty list removes
    // them). False, keeping nothing, for a new NIC when `capacity` NICs
    // have secrets already.
    auto put_secrets(std::uint64_t nic_id, std::vector<InstanceSecret> secrets) -> bool;
    // The NIC's secrets, if any; valid until the next put_secrets() or drop().
    [[nodiscard]] auto secrets(std::uint64_t nic_id) const -> const std::vector<InstanceSecret>*;

    // The NIC's record, if any; valid until the next put() or drop().
    [[nodiscard]] auto find(std::uint64_t nic_id) const -> const proto::InstanceMetadata*;
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _records.size(); }
    [[nodiscard]] auto capacity() const noexcept -> std::size_t { return _capacity; }
    [[nodiscard]] auto counters() const noexcept -> const MetadataCounters& { return _counters; }

private:
    std::uint64_t _server_id;
    std::size_t _capacity;
    MetadataVerifier _verifier;
    std::map<std::uint64_t, proto::InstanceMetadata> _records;      // by NIC ID
    std::map<std::uint64_t, std::vector<InstanceSecret>> _secrets;  // by NIC ID
    MetadataCounters _counters;
};

}  // namespace ak::oar::net
