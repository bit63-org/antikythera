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
//   store PATH                  sealed store flash partition (a file here,
//                               created 0600; .kiro/specs/cold-start/
//                               Requirement 1); optional
//   store-size N                its size in bytes (default 1 MiB; a multiple
//                               of 4096, at least 16 KiB)
//   store-anchor PATH|ephemeral the software secure element's store key and
//                               monotonic counters (created 0600); required
//                               with store. With a store, helm records each
//                               relayed command's sequence number there
//                               (cold-start Requirement 6.3)
//   controller-keys ID:HEX;...  the controller's Ed25519 public keys, as hull's
//                               AK_HULL_CONTROLLER_KEYS; helm verifies signed
//                               records it acts on alone (power_policy) with
//                               them. Optional: without, every such record is
//                               refused and the defaults apply
//   image-keys ID:HEX;...       image signing public keys (same format) that
//                               hull images in the sealed store must verify
//                               under (cold-start Requirement 2.5); refused
//                               when ak-helm was built with
//                               AK_HELM_IMAGE_KEYS. Optional: without either,
//                               no image is stored or promoted
//   boot-function PATH          the boot function's disk image (a file here,
//                               rewritten before every host release; harbor's
//                               QEMU attaches it read-only). helm then boots
//                               hull from its sealed store: requires store
//                               (server-provisioning Requirement 4,
//                               cold-start Requirement 2). Optional: without,
//                               the host boots however it is configured
//   boot-layer PATH             the metal boot layer as an image store file
//                               (objstore/image_store_config.hpp), where an
//                               assigned image not in the store is fetched;
//                               requires boot-function. Optional: without,
//                               only stored images boot
//   host-start-timeout-ms N     how long hull's agent has to come up before
//                               helm reboots the host once onto another
//                               image (default 120000; cold-start 2.4)
//   power-marker PATH           a file in a tmpfs whose absence means helm's
//                               own power returned (default
//                               /run/ak-helm/powered; cold-start Requirement 3.6)
//   power-on-policy apply|skip  `apply` (default) waits out the power-on
//                               policy after helm's power returns; `skip`
//                               releases the host at once (a harbor run that
//                               is not testing cold start)
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
    std::optional<std::filesystem::path> store;       // nullopt: no sealed store
    std::uint64_t store_size{std::uint64_t{1} << 20};
    std::optional<std::filesystem::path> store_anchor;   // nullopt: ephemeral
    std::string controller_keys;                         // empty: none
    std::string image_keys;                              // empty: none
    std::optional<std::filesystem::path> boot_function;  // nullopt: helm does not fill it
    std::optional<std::filesystem::path> boot_layer;     // nullopt: no fetches
    std::optional<std::chrono::milliseconds> host_start_timeout;
    std::filesystem::path power_marker{"/run/ak-helm/powered"};
    bool apply_power_policy{true};
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
