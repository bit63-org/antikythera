// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// AgentHandler: what hull does with each authenticated command
// (.kiro/specs/hull-host-agent/ tasks 8 and 9; design.md "Error handling").
//
//   CREATE_VM, DESTROY_VM, LIST_VMS, VM_STATUS   the VmSupervisor
//   ATTACH_DEVICE, DETACH_DEVICE,
//   ATTACH_VOLUME, DETACH_VOLUME                 the VmSupervisor (task 9); the
//                                                volume key and the network
//                                                identity are helm's, so hull
//                                                sees only the function
//   CREATE_VOLUME, DELETE_VOLUME, REWRAP_VOLUME,
//   CREATE_NETWORK, DELETE_NETWORK               ok: the work is helm's and
//                                                the data-plane roles'. hull's
//                                                part is the check the mailbox
//                                                client already made: helm
//                                                commits these only on hull's
//                                                ok, i.e. once the controller's
//                                                signature has verified here.
//
// Every command gets exactly one outcome; nothing here throws.

#include "hull/mailbox_client.hpp"
#include "hull/vm_supervisor.hpp"

namespace ak::hull {

class AgentHandler final : public CommandHandler {
public:
    explicit AgentHandler(VmSupervisor& supervisor) noexcept : _supervisor{&supervisor} {}

    auto handle(const helm::mailbox::Message& msg, const helm::mailbox::Body& body)
        -> CommandOutcome override;

private:
    VmSupervisor* _supervisor;
};

}  // namespace ak::hull
