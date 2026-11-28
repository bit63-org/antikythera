// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes hull's provisioning file reader (.kiro/specs/cold-start/
// Requirement 6): a Provisioning frame must decode to something that
// re-encodes to identical bytes, and anything else is read only as the
// older decimal server ID, never with an epoch or a floor.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "hull/host_setup.hpp"
#include "proto/provisioning.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    const auto p = ak::hull::provisioning_from_file(bytes);
    if (!p) {
        return 0;
    }
    if (p->server_id == 0) {
        std::abort();
    }
    if (ak::proto::is_provisioning_frame(bytes)) {
        const auto again = ak::proto::encode_provisioning(*p);
        if (!again || !std::ranges::equal(*again, bytes)) {
            std::abort();
        }
    } else if (p->boot_epoch != 0 || p->sequence_floor != 0) {
        std::abort();
    }
    return 0;
}
