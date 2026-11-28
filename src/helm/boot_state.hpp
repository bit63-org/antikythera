// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Replay protection across reboots (.kiro/specs/cold-start/ Requirement 6,
// task 3; design "Why a boot epoch"): what helm keeps so that a command
// captured before a power cycle is refused after it.
//
//   - The last sequence number helm relayed to hull is kept in the sealed
//     store (object `helm.last-command-seq`, u64 little-endian), recorded
//     by StoreSequenceRecorder before each command is relayed
//     (Requirement 6.3; CommandRouter calls it).
//   - Before every host boot, begin_host_boot() advances the secure
//     element's boot_epoch counter and returns the Provisioning frame for
//     the boot function: server ID, the new epoch, and the recorded
//     sequence number as hull's floor (Requirement 6.1). hull refuses
//     every sequence number at or below it (Requirement 6.2).
//
// The epoch is advanced before the boot is allowed: a boot never reuses a
// number, even if power fails right after, because the counter only moves
// forward. A failure to advance it is an error and the host must not boot
// with a stale epoch.
//
// A store that opened rolled back (its partition restored from an older
// copy) yields the floor that copy holds, which may be below the true
// one. Recovering the true floor is impossible without the lost copy, so
// the store's rolled_back() flag goes to the controller in the cold-start
// report (task 9), and the controller numbers new commands above every
// command it has sent, as it always does. A command captured between the
// old floor and the true one could still be replayed until the
// controller's first new command passes it; that needs physical access to
// the flash, which the rollback report surfaces.

#include <cstdint>
#include <expected>
#include <string_view>

#include "helm/command_router.hpp"
#include "helm/sealed_store.hpp"
#include "helm/store_anchor.hpp"
#include "proto/provisioning.hpp"

namespace ak::helm {

inline constexpr std::string_view last_command_seq_object = "helm.last-command-seq";

enum class BootStateError : std::uint8_t {
    store,       // the sealed store failed (store_error says how)
    anchor,      // the secure element failed (anchor_error says how)
    corrupt,     // the recorded sequence number is not 8 bytes
    bad_server,  // server ID 0
};

[[nodiscard]] auto to_string(BootStateError e) noexcept -> const char*;

struct BootStateFailure {
    BootStateError error{BootStateError::store};
    StoreError store_error{StoreError::flash};
    AnchorError anchor_error{AnchorError::io};
};

// The last sequence number recorded in `store`, or 0 if none was.
[[nodiscard]] auto load_sequence_floor(SealedStore& store)
    -> std::expected<std::uint64_t, BootStateFailure>;

// Advances the boot epoch and returns this boot's provisioning frame.
[[nodiscard]] auto begin_host_boot(SealedStore& store, StoreAnchor& anchor, std::uint64_t server_id)
    -> std::expected<proto::Provisioning, BootStateFailure>;

// Records each relayed sequence number in the sealed store. A number not
// above the last one recorded is already covered and is not written again.
class StoreSequenceRecorder final : public SequenceRecorder {
public:
    // `last_recorded` is what load_sequence_floor() returned. `store` is
    // not owned and must outlive the recorder.
    StoreSequenceRecorder(SealedStore& store, std::uint64_t last_recorded) noexcept
        : _store{&store}, _recorded{last_recorded} {}

    [[nodiscard]] auto record(std::uint64_t seq) -> bool override;

    [[nodiscard]] auto recorded() const noexcept -> std::uint64_t { return _recorded; }
    [[nodiscard]] auto failures() const noexcept -> std::uint64_t { return _failures; }
    [[nodiscard]] auto last_error() const noexcept -> StoreError { return _last_error; }

private:
    SealedStore* _store;
    std::uint64_t _recorded;
    std::uint64_t _failures{0};
    StoreError _last_error{StoreError::flash};
};

}  // namespace ak::helm
