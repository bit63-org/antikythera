// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Dropping the agent's capabilities after setup (.kiro/specs/hull-host-agent/
// Requirement 9.1).
//
// Once the agent has mapped the mailbox and read its inventory it needs
// only what starting and stopping jailed VMMs takes:
//
//   CAP_SYS_ADMIN     clone3 into new namespaces, cgroup placement
//   CAP_SETUID/SETGID writing a VMM's uid_map / gid_map
//   CAP_CHOWN         the run directory and VFIO group nodes
//   CAP_FOWNER        chmod of a group node the VM's UID owns
//   CAP_SYS_RESOURCE  raising a VMM's RLIMIT_MEMLOCK
//   CAP_KILL          signalling a VMM that runs under another UID
//
// Everything else leaves the bounding, permitted, effective, inheritable
// and ambient sets, and PR_SET_NO_NEW_PRIVS stops an exec from gaining
// any back.

#include <expected>
#include <span>

namespace ak::hull {

// The set above, as CAP_* numbers.
[[nodiscard]] auto agent_capabilities() -> std::span<const int>;

// Keeps exactly `keep` (those the process has) and drops the rest from
// every set. Returns errno on failure, in which case the process should
// not continue.
[[nodiscard]] auto drop_capabilities_except(std::span<const int> keep) -> std::expected<void, int>;

}  // namespace ak::hull
