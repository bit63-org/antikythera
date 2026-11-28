// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The local power-on policy (.kiro/specs/cold-start/ Requirement 3, task
// 5): after helm's own power returns, it holds the host in reset for
// tier_delay + slot x slot_interval + jitter, with no controller, so tiers
// start in order and the power domain's breakers do not trip on inrush.
//
//   PowerPolicyKeeper  keeps the newest verified power_policy record (link
//                      type 24) in the sealed store and loads it at start
//                      (Requirement 3.1); with none, the default policy:
//                      tier 3, slot 0, kythira az-cold-start Requirement
//                      5.2's delays (3.4). A store that opened rolled back
//                      or degraded loses its policy (Requirement 1.5): the
//                      old copy cannot be trusted to be the newest.
//   plan_power_on()    the wait and whether the host is held, from the
//                      policy, whether helm itself lost power (3.6: a
//                      helm restart with power on releases the host at
//                      once), and a host_power override (3.5: `on` starts
//                      the host now, `hold` keeps it in reset).
//   helm_power_returned()  whether this is helm's first start since its
//                      power returned, from a marker in a tmpfs (/run)
//                      that power loss clears and a process restart does
//                      not.
//
// helm verifies the record's Ed25519 signature itself, through a
// RecordVerifier: the policy changes what helm does with no controller
// watching, so a frame from the link alone is not enough. With no
// verifier (no controller keys configured) every record is refused and
// the default applies.
//
// The slot stagger (3.3) is PowerSequencer's slot_stagger; HelmDaemon
// waits the planned time before PowerSequencer::boot().

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>

#include "helm/sealed_store.hpp"
#include "proto/power_policy.hpp"

namespace ak::helm {

// Verifies a controller signature on a link record: Ed25519 over
// `message` under the controller key `key_id`.
class RecordVerifier {
public:
    RecordVerifier() = default;
    RecordVerifier(const RecordVerifier&) = delete;
    auto operator=(const RecordVerifier&) -> RecordVerifier& = delete;
    RecordVerifier(RecordVerifier&&) = delete;
    auto operator=(RecordVerifier&&) -> RecordVerifier& = delete;
    virtual ~RecordVerifier() = default;

    [[nodiscard]] virtual auto verify(std::span<const std::byte> message,
                                      std::span<const std::byte, proto::ed25519_signature_size> sig,
                                      std::uint16_t key_id) const -> bool = 0;
};

inline constexpr std::string_view power_policy_object = "helm.power-policy";

enum class PolicyVerdict : std::uint8_t {
    kept,           // verified, newer, stored
    none,           // load(): nothing stored (or discarded); the default applies
    stale,          // not newer than the policy held
    wrong_server,   // names another server
    bad_signature,  // does not verify, or no verifier to check it
    corrupt,        // load(): the stored frame does not decode
    store_failed,   // could not be written (or read); the policy held is unchanged
};

[[nodiscard]] auto to_string(PolicyVerdict v) noexcept -> const char*;

class PowerPolicyKeeper {
public:
    // `store` may be null (the policy then lives in memory only) and
    // `verifier` may be null (every record is refused). Neither is owned.
    PowerPolicyKeeper(std::uint64_t server_id, SealedStore* store,
                      const RecordVerifier* verifier) noexcept;

    // Loads the stored policy, if any. Call once at start.
    auto load() -> PolicyVerdict;
    // A power_policy record from the controller and its exact encoding.
    auto offer(const proto::PowerPolicy& policy, std::span<const std::byte> frame) -> PolicyVerdict;

    // The policy in force: the newest kept, or the default.
    [[nodiscard]] auto current() const noexcept -> const proto::PowerPolicy& { return _current; }
    // Whether current() came from a record rather than the default.
    [[nodiscard]] auto from_record() const noexcept -> bool { return _from_record; }

private:
    [[nodiscard]] auto verified(const proto::PowerPolicy& p, std::span<const std::byte> frame) const
        -> bool;

    std::uint64_t _server_id;
    SealedStore* _store;
    const RecordVerifier* _verifier;
    proto::PowerPolicy _current;
    bool _from_record{false};
};

// The host_power record's override (kythira server-provisioning).
enum class HostPowerOverride : std::uint8_t {
    none,
    on,    // start the host now, whatever the policy says
    hold,  // keep the host in reset until told otherwise
};

struct PowerOnPlan {
    std::chrono::milliseconds wait{0};
    bool hold{false};
    friend auto operator==(const PowerOnPlan&, const PowerOnPlan&) -> bool = default;
};

// `jitter_ms` is draw_jitter(policy.max_jitter_ms) (taken as an argument so
// tests choose it); values above the policy's maximum are clamped.
[[nodiscard]] auto plan_power_on(const proto::PowerPolicy& policy, bool helm_power_returned,
                                 HostPowerOverride override_, std::uint32_t jitter_ms) noexcept
    -> PowerOnPlan;

// Uniform in [0, max_jitter_ms].
[[nodiscard]] auto draw_jitter(std::uint16_t max_jitter_ms) -> std::uint32_t;

// True the first time it is called after `marker` (in a tmpfs) vanished,
// which is when helm's power returned; it then creates the marker. False
// on every later start until power is lost again. An error (errno) if the
// marker can neither be read nor created: the caller should treat that as
// power returned, which only ever waits longer.
[[nodiscard]] auto helm_power_returned(const std::filesystem::path& marker)
    -> std::expected<bool, int>;

}  // namespace ak::helm
