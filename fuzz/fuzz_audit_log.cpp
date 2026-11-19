// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the audit log verifier (an operator may hand helm, or a review
// tool, a copied log, so its text is untrusted). Whatever the input,
// verification must not crash, and an accepted log must verify the same
// when a record formatted from its tail is appended.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "helm/audit_log.hpp"

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) -> int {
    const std::string text(reinterpret_cast<const char*>(data), size);
    const auto tail = ak::helm::verify_audit_log(text);
    if (!tail) {
        return 0;
    }
    const auto extended = text + ak::helm::format_audit_line(*tail, 0, ak::helm::AuditRecord{});
    const auto again = ak::helm::verify_audit_log(extended);
    if (!again || again->next_index != tail->next_index + 1) {
        std::abort();
    }
    return 0;
}
