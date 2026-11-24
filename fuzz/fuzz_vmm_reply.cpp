// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes what the agent reads from a VMM's API socket: the HTTP reply
// parser (complete and still-arriving), the strict JSON reader and the
// vm.info extraction (.kiro/specs/hull-host-agent/ task 8, Requirement
// 9.2). None may crash; an accepted reply's body must fit the limits; every
// string the JSON reader returns must survive a quote/parse round trip.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string_view>

#include "hull/json.hpp"
#include "hull/vmm_api.hpp"

namespace json = ak::hull::json;

namespace {

auto check_strings(const json::Value& v) -> void {
    if (const auto* s = v.as_string()) {
        const auto again = json::parse(json::quote(*s));
        if (!again || again->as_string() == nullptr || *again->as_string() != *s) {
            std::abort();
        }
    } else if (const auto* a = v.as_array()) {
        for (const auto& item : *a) {
            check_strings(item);
        }
    } else if (const auto* o = v.as_object()) {
        for (const auto& [key, item] : *o) {
            check_strings(json::Value{key});
            check_strings(item);
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::span bytes{reinterpret_cast<const std::byte*>(data), size};
    const std::string_view text{reinterpret_cast<const char*>(data), size};

    for (const bool closed : {false, true}) {
        ak::hull::HttpReply reply;
        const auto r = ak::hull::parse_reply(bytes, closed, reply);
        if (r && *r == ak::hull::ReplyParse::complete) {
            if (reply.status < 100 || reply.status > 999 ||
                reply.body.size() > ak::hull::max_reply_body) {
                std::abort();
            }
            (void)ak::hull::parse_vm_info(reply.body);
        }
    }

    if (const auto v = json::parse(text)) {
        check_strings(*v);
    }
    if (const auto info = ak::hull::parse_vm_info(text)) {
        for (std::size_t i = 0; i < info->device_ids.size(); ++i) {
            for (std::size_t j = i + 1; j < info->device_ids.size(); ++j) {
                if (info->device_ids[i] == info->device_ids[j]) {
                    std::abort();
                }
            }
        }
    }
    return 0;
}
