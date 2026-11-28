// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Standing starts (.kiro/specs/cold-start/ Requirement 4.4-4.5, design
// "Standing starts are verified by hull, not trusted from helm").
//
// After a power loss helm starts the server's pinned instances with no
// controller. It sends hull the controller's signed standing set in
// STANDING_CHUNK pieces, then one STANDING_START per instance. hull
// trusts none of it until the set verifies:
//
//   - the set decodes strictly (proto::decode_standing_set);
//   - it names this server;
//   - its Ed25519 signature verifies under the compiled-in controller key
//     it names, exactly as an envelope's would.
//
// A STANDING_START then runs the entry's commands (CREATE_VM, then each
// ATTACH_VOLUME and ATTACH_DEVICE) through the same CommandHandler as a
// signed command. It consumes no command sequence number, and every
// command must name the entry's VM. A command that fails stops the start
// and destroys the VM it created, keeping its volumes, so that helm's
// retry starts clean. A VM that started is never started again in this
// boot.
//
// Standing starts are taken only at the start of a boot. close() is called
// when the first signed command is accepted. From then on chunks and
// starts are refused (`conflict`) and the set is dropped, so a compromised
// helm cannot use an old set while the controller is talking to the
// server. Replay of an older set across boots is refused by helm, whose
// secure element anchors the newest generation (Requirement 4.2).

#include <cstdint>
#include <optional>
#include <set>
#include <vector>

#include "helm/mailbox.hpp"
#include "hull/mailbox_client.hpp"
#include "hull/signature_verifier.hpp"
#include "proto/standing_set.hpp"

namespace ak::hull {

struct StandingStartStats {
    std::uint64_t chunks{0};
    std::uint64_t sets_accepted{0};
    std::uint64_t sets_refused{0};       // did not decode, wrong server or bad signature
    std::uint64_t transfers_aborted{0};  // a gap or a changed total
    std::uint64_t started{0};
    std::uint64_t failed{0};   // a command failed; the VM was destroyed again
    std::uint64_t refused{0};  // closed, no set, wrong generation or index, already started
};

class StandingStarts {
public:
    StandingStarts(helm::mailbox::ServerId server_id, const SignatureVerifier& verifier) noexcept
        : _server_id{server_id}, _verifier{&verifier} {}

    // A STANDING_CHUNK. The chunk that completes a transfer is answered
    // with the verdict on the whole set: ok (it replaces any set held),
    // malformed, wrong_server or bad_signature. Earlier chunks are
    // answered ok, and a chunk that breaks the transfer malformed.
    auto chunk(const helm::mailbox::StandingChunk& c) -> helm::mailbox::Status;

    // A STANDING_START: runs the entry's commands through `handler`.
    // ok once every command succeeded; otherwise the status of the first
    // that failed (malformed for one that does not decode or names
    // another VM), or conflict when standing starts are closed, no set is
    // held, the generation differs or the instance already started.
    auto start(const helm::mailbox::StandingStart& s, CommandHandler& handler)
        -> helm::mailbox::Status;

    // The first signed command was accepted: refuse everything from now on.
    auto close() noexcept -> void;

    [[nodiscard]] auto open() const noexcept -> bool { return _open; }
    [[nodiscard]] auto generation() const noexcept -> std::optional<std::uint64_t> {
        return _set ? std::optional{_set->generation} : std::nullopt;
    }
    [[nodiscard]] auto stats() const noexcept -> const StandingStartStats& { return _stats; }

private:
    auto accept_transfer() -> helm::mailbox::Status;
    auto run(const proto::StandingSet& set, const proto::StandingInstance& in,
             CommandHandler& handler) -> helm::mailbox::Status;

    helm::mailbox::ServerId _server_id;
    const SignatureVerifier* _verifier;
    bool _open{true};
    std::vector<std::byte> _buffer;  // the transfer in progress
    std::uint32_t _total{0};         // its total; 0 when none is in progress
    std::optional<proto::StandingSet> _set;
    std::set<std::uint64_t> _started;  // VM IDs started in this boot
    StandingStartStats _stats;
};

}  // namespace ak::hull
