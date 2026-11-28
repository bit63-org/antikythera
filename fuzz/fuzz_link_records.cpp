// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Fuzzes the ControllerLink record decoder. The first input byte picks a
// chunk size, so the same stream is also exercised split across reads.
// Every record must re-frame to the bytes it came from, the decoder must
// never buffer more than one maximum record plus one chunk, and once it
// fails it must keep failing. A lease_grant, role_certificate or self_test
// payload that decodes must encode back to the same bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <vector>

#include "proto/link.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    const std::size_t chunk = 1 + data[0];
    const std::span stream{reinterpret_cast<const std::byte*>(data) + 1, size - 1};
    ak::proto::RecordDecoder d;
    std::vector<std::byte> reframed;
    bool failed = false;
    for (std::size_t i = 0; i < stream.size(); i += chunk) {
        d.feed(stream.subspan(i, std::min(chunk, stream.size() - i)));
        for (;;) {
            auto r = d.next();
            if (!r) {
                failed = true;
                break;
            }
            if (failed) {
                std::abort();
            }
            if (!r->has_value()) {
                break;
            }
            if ((*r)->type == ak::proto::RecordType::lease_grant) {
                if (auto g = ak::proto::decode_lease_grant((*r)->payload); g) {
                    auto again = ak::proto::encode_lease_grant(*g);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                }
            }
            if ((*r)->type == ak::proto::RecordType::self_test) {
                if (auto t = ak::proto::decode_self_test((*r)->payload); t) {
                    auto again = ak::proto::encode_self_test(*t);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                }
            }
            if ((*r)->type == ak::proto::RecordType::rotate_vtep_key) {
                if (auto k = ak::proto::decode_rotate_vtep_key((*r)->payload); k) {
                    auto again = ak::proto::encode_rotate_vtep_key(*k);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                }
            }
            if ((*r)->type == ak::proto::RecordType::frame_notice) {
                if (auto n = ak::proto::decode_frame_notice_record((*r)->payload); n) {
                    auto again = ak::proto::encode_frame_notice_record(*n);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                    // The notice alone, as helm passes it to the role.
                    auto body = ak::proto::encode_frame_notice(n->notice);
                    if (!body || !std::ranges::equal(*body, std::span{(*r)->payload}.subspan(8)) ||
                        ak::proto::decode_frame_notice(*body) != n->notice) {
                        std::abort();
                    }
                }
            }
            if ((*r)->type == ak::proto::RecordType::vtep_credential) {
                if (auto c = ak::proto::decode_vtep_credential((*r)->payload); c) {
                    auto again = ak::proto::encode_vtep_credential(*c);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                }
            }
            if ((*r)->type == ak::proto::RecordType::credential_revocations) {
                if (auto l = ak::proto::decode_credential_revocations((*r)->payload); l) {
                    auto again = ak::proto::encode_credential_revocations(*l);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                }
            }
            if ((*r)->type == ak::proto::RecordType::role_certificate) {
                if (auto c = ak::proto::decode_role_certificate((*r)->payload); c) {
                    auto again = ak::proto::encode_role_certificate(*c);
                    if (!again || *again != (*r)->payload) {
                        std::abort();
                    }
                }
            }
            auto b = ak::proto::encode_record((*r)->type, (*r)->payload);
            if (!b) {
                std::abort();
            }
            reframed.insert(reframed.end(), b->begin(), b->end());
        }
        if (d.buffered() > ak::proto::record_header_size + ak::proto::max_record_payload + chunk) {
            std::abort();
        }
    }
    if (!failed && !std::ranges::equal(reframed, stream.first(reframed.size()))) {
        std::abort();
    }
    return 0;
}
