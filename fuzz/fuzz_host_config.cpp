// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the text hull's init and agent read (.kiro/specs/hull-host-agent/
// task 3): the allow-list, the inventory file, the server ID sources and
// the controller key list. None may crash; an accepted inventory must
// survive a format/parse round trip unchanged; an accepted config must
// name valid ports, no slot or SR-IOV port twice, and no SR-IOV PF a
// slot could hand out.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string_view>

#include "hull/host_setup.hpp"

using namespace ak::hull;

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    const std::string_view text{reinterpret_cast<const char*>(data), size};

    if (const auto c = parse_host_config(text)) {
        std::set<unsigned> slots;
        for (const auto& s : c->slots) {
            if (!valid_bdf(s.port) || s.slot == 0xFF || !slots.insert(s.slot).second) {
                std::abort();
            }
        }
        std::set<std::string_view> ports;
        for (const auto& r : c->sriov) {
            if (!valid_bdf(r.port) || r.vfs == 0 || !ports.insert(r.port).second) {
                std::abort();
            }
            for (const auto& s : c->slots) {
                if (s.port == r.port && s.id == r.pf) {
                    std::abort();
                }
            }
        }
    }

    if (const auto inv = parse_inventory(text)) {
        const auto again = parse_inventory(format_inventory(*inv));
        if (!again || *again != *inv) {
            std::abort();
        }
    }

    if (const auto id = server_id_from_cmdline(text); id && *id == 0) {
        std::abort();
    }
    if (const auto id = server_id_from_text(text); id && *id == 0) {
        std::abort();
    }

    if (const auto keys = parse_controller_keys(text)) {
        for (const auto& k : *keys) {
            if (k.id == 0) {
                std::abort();
            }
        }
    }
    return 0;
}
