// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ak-helm's configuration file: one directive per line, words separated by
// spaces or tabs, blank lines and text after '#' ignored. Numbers are
// decimal or 0x-prefixed hex. Words cannot contain spaces (no quoting).
//
//   server-id N                 this server's controller-assigned ID (non-zero)
//   controller HOST:PORT        the controller, over helm's management NIC
//   controller-name NAME        its certificate's DNS name or IP (default HOST)
//   ca PATH                     PEM trust anchor for the controller's chain
//   cert PATH                   helm's certificate chain (PEM)
//   key PATH                    helm's private key (PEM)
//   audit-log PATH              hash-chained audit log (created 0600)
//   master-key PATH|ephemeral   software secure element master key file
//                               (created 0600); `ephemeral` keeps a random
//                               key in memory only (throwaway harbor runs)
//   slot N SOCKET ADDR PEER_ADDR EID PEER_EID ARGV...
//                               a data-plane slot: the board process to
//                               launch (ARGV, argv[0] an absolute path), the
//                               SOCK_SEQPACKET sideband socket it listens on
//                               once ready, and both ends' 7-bit bus
//                               addresses and MCTP EIDs (helm's first)
//   host ARGV...                the host process released after the slots
//                               (harbor: the L1 QEMU)
//   command-timeout-ms N        CommandRouter timeouts and sequencer timings,
//   release-timeout-ms N        each optional (their defaults otherwise)
//   clean-timeout-ms N
//   link-timeout-ms N
//   sideband-timeout-ms N       how long OarLink waits for each response
//   check-interval-ms N         how often lost links are looked for
//
// Required: server-id, controller, ca, cert, key, audit-log, master-key and
// at least one slot. Each directive appears once, except slot (once per
// slot number). The parser checks syntax and ranges; whether the files
// exist is found when they are opened.

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "helm/oar_link.hpp"
#include "helm/power_sequencer.hpp"

namespace ak::helm {

struct SlotEntry {
    LinkAddress address;
    ProcessSpec process;  // ready_path is the sideband socket
};

struct HelmConfig {
    std::uint64_t server_id{0};
    std::string controller_host;
    std::uint16_t controller_port{0};
    std::string controller_name;
    std::filesystem::path ca;
    std::filesystem::path cert;
    std::filesystem::path key;
    std::filesystem::path audit_log;
    std::optional<std::filesystem::path> master_key;  // nullopt: ephemeral
    std::map<SlotNumber, SlotEntry> slots;
    std::vector<std::string> host_argv;  // empty: no host process

    std::optional<std::chrono::milliseconds> command_timeout;
    std::optional<std::chrono::milliseconds> release_timeout;
    std::optional<std::chrono::milliseconds> clean_timeout;
    std::optional<std::chrono::milliseconds> link_timeout;
    std::optional<std::chrono::milliseconds> sideband_timeout;
    std::optional<std::chrono::milliseconds> check_interval;
};

// Errors name the line ("line 4: ...") or the missing directive.
[[nodiscard]] auto parse_helm_config(std::string_view text)
    -> std::expected<HelmConfig, std::string>;

}  // namespace ak::helm
