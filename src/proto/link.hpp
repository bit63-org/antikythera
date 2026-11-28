// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// ControllerLink record framing (.kiro/specs/controller-interface/
// Requirement 2, design "ControllerLink"). The mTLS stream between the
// controller and one helm is a sequence of records:
//
//   0x00  length    u32  payload bytes after this 8-byte header
//   0x04  type      u16  RecordType
//   0x06  reserved  u16  zero
//   0x08  payload
//
//   type          direction            payload
//   hello         helm -> controller   server_id u64 | boot_id u64; first on
//                                      every connection
//   envelope      controller -> helm   an Envelope (envelope.hpp)
//   map_update    controller -> helm   a MapUpdate (map_update.hpp)
//   group_policy  controller -> helm   a GroupPolicy (group_policy.hpp), version 1 or 2
//   report        helm -> controller   a Report (report.hpp)
//   report_ack    controller -> helm   server_id u64 | report_seq u64: every
//                                      report up to report_seq is processed
//   tunnel_peers  controller -> helm   a TunnelPeers frame (tunnel_peers.hpp)
//   replica_config controller -> helm  a ReplicaConfig (replica_config.hpp)
//   volume_op     controller -> helm   a VolumeOp (volume_op.hpp)
//   volume_key    controller -> helm   a VolumeKey (volume_key.hpp)
//   lease_grant   controller -> helm   server_id u64 | volume_id u64 | epoch u64:
//                                      the controller acknowledged this
//                                      server's lease request as primary of
//                                      the volume at that epoch
//   role_certificate controller -> helm server_id u64 | slot u8 | rsvd [3]
//                                      | chain_len u32 | chain [chain_len]:
//                                      the storage certificate for the role
//                                      in that slot, answering its
//                                      cert_request report
//   image_key     controller -> helm   an ImageKey (image_key.hpp)
//   vpc_config    controller -> helm   a VpcConfig (vpc_config.hpp)
//   group_members controller -> helm   a GroupMembers (group_members.hpp)
//   instance_metadata controller -> helm an InstanceMetadata
//                                      (instance_metadata.hpp), for the
//                                      NIC's network role
//   volume_layout controller -> helm   a VolumeLayout (volume_layout.hpp),
//                                      for this server's khold role (a
//                                      member or gateway) or blk role (an
//                                      attachment)
//   self_test     controller -> helm   server_id u64 | slot u8 | scope u8
//                                      (SelfTestScope) | rsvd [6]: run the
//                                      storage self-test on the khold role
//                                      in that slot (scope slot) or on
//                                      every khold role (scope all, slot 0)
//   standing_set  controller -> helm   a StandingSet (standing_set.hpp): the
//                                      pinned instances helm starts after
//                                      power returns, with no controller
//   power_policy  controller -> helm   a PowerPolicy (power_policy.hpp): when
//                                      helm releases the host after power
//                                      returns, and which image to keep
//   vtep_credential controller -> helm a VtepCredential (vtep_credential.hpp)
//                                      for one of this server's network
//                                      roles, answering its credential_request
//   credential_revocations controller -> helm a CredentialRevocations
//                                      (vtep_credential.hpp): the revoked
//                                      credentials of one cell
//   frame_notice  controller -> helm   server_id u64 | FrameNotice (frame_notice.hpp):
//                                      a signed frame waiting in a frame
//                                      store, for the network roles to
//                                      fetch over their bulk channel
//   vpc_stream    controller -> helm   a VpcStream (vpc_stream.hpp): one
//                                      VPC's snapshot part or delta, signed
//                                      once for every server, for the
//                                      network roles
//   rotate_vtep_key controller -> helm server_id u64 | slot u8 | rsvd [3]
//                                      | key_epoch u32: derive a new tunnel
//                                      key for the network role in that slot
//                                      at key_epoch (.kiro/specs/
//                                      fleet-scale-networking/ Requirement 1)
//
// Record numbers 19-22 are claimed by specs still being built
// (vpc-security-groups, vpc-internet-gateways, server provisioning) and
// 30-35 by fleet-scale-networking; the AZ cold start (.kiro/specs/
// cold-start/) owns 23-24. The known types are not one contiguous range.
//
// standing_set and power_policy are signed and kept by helm in its sealed
// store across power loss; helm verifies them itself (it acts on them with
// no controller), and hull verifies a standing set again before it starts
// anything from it.
//
// The block volume records (.kiro/specs/block-volume-service/ task 12):
// helm forwards replica_config, volume_op and lease_grant to its storage
// roles (the signed frames unmodified; the roles verify them, as oar-net
// does a MapUpdate), and opens volume_key in its secure element. A
// lease_grant is unsigned: it travels only on this authenticated link and
// helm's own sideband, and fences nothing but the reads of the role it
// names (design "Epochs, leases and fencing").
//
// image_key carries an encrypted image's key for the image volume a
// CREATE_VOLUME is about to create (.kiro/specs/oar-blk-data-plane/ task
// 15). helm opens it in its secure element to refuse a bad one, and keeps
// it until that command re-wraps it under the owner's VM key.
//
// The khold records (kythira .kiro/specs/khold-block-service/ task 17):
// helm forwards volume_layout unmodified, keeping the newest epoch of each
// volume to replay to a role whose sideband reopens; the role verifies
// the signature. self_test is unsigned like lease_grant: it only asks a
// khold role to measure its drives and link again (Requirement 12.1), and
// the answer is the role's next capacity report.
//
// rotate_vtep_key is unsigned too: it travels only on this authenticated
// link, carries no key, and only moves the slot's key epoch forward. helm
// derives the new key from its secure element, keeps the epoch in its
// state file, and ignores an epoch at or below the one it holds, so a
// replayed or repeated record changes nothing. key_epoch is 1 to 65,535
// (the VtepCredential's key_epoch field is 16 bits).
//
// role_certificate's chain is DER certificates back to back, leaf first,
// at most max_cert_chain_certs of them and max_cert_chain_size bytes in
// all (der.hpp checks the outer framing). helm passes it to the role in
// that slot unmodified; the role parses it, checks it chains to the
// storage CA, names this server, and holds the key the role generated,
// before using it. Like lease_grant it is unsigned: a certificate is
// public, and the CA's signature is what the role trusts.
//
// Report sequence numbers restart when helm reboots, so they are only
// meaningful together with the boot ID: hello names it before any report,
// and every report and ack on the connection belongs to that boot. The
// controller drops a report whose (boot_id, report_seq) it has already
// processed, which makes helm's replay after a reconnect idempotent.
//
// The framing only delimits; the receiver decodes each payload with its own
// strict decoder and refuses a record that arrived in the wrong direction.
// A record longer than max_record_payload ends the connection before its
// payload is buffered, so a peer cannot make the other side allocate more
// than one maximum-size frame.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include "common/wire.hpp"
#include "proto/codec.hpp"
#include "proto/der.hpp"
#include "proto/envelope.hpp"
#include "proto/group_members.hpp"
#include "proto/group_policy.hpp"
#include "proto/image_key.hpp"
#include "proto/instance_metadata.hpp"
#include "proto/map_update.hpp"
#include "proto/power_policy.hpp"
#include "proto/replica_config.hpp"
#include "proto/report.hpp"
#include "proto/standing_set.hpp"
#include "proto/tunnel_peers.hpp"
#include "proto/volume_key.hpp"
#include "proto/volume_layout.hpp"
#include "proto/volume_op.hpp"
#include "proto/vpc_config.hpp"
#include "proto/vpc_stream.hpp"
#include "proto/frame_notice.hpp"
#include "proto/vtep_credential.hpp"

namespace ak::proto {

inline constexpr std::size_t record_header_size = 8;
inline constexpr std::size_t report_ack_size = 16;
inline constexpr std::size_t hello_size = 16;
inline constexpr std::size_t lease_grant_size = 24;
inline constexpr std::size_t role_certificate_fixed_size = 16;
inline constexpr std::size_t max_cert_chain_size = 16384;
inline constexpr std::size_t max_cert_chain_certs = 4;
inline constexpr std::size_t self_test_size = 16;
inline constexpr std::size_t rotate_vtep_key_size = 16;
inline constexpr std::uint32_t max_key_epoch = 0xFFFF;
inline constexpr std::size_t max_record_payload =
    std::max({envelope_size,
              max_map_update_size,
              max_report_size,
              report_ack_size,
              hello_size,
              max_group_policy_size,
              max_tunnel_peers_size,
              max_replica_config_size,
              volume_op_size,
              volume_key_size,
              lease_grant_size,
              role_certificate_fixed_size + max_cert_chain_size,
              image_key_size,
              max_vpc_config_size,
              max_group_members_size,
              max_instance_metadata_size,
              max_volume_layout_size,
              self_test_size,
              max_standing_set_size,
              power_policy_size,
              rotate_vtep_key_size,
              vtep_credential_size,
              max_credential_revocations_size,
              frame_notice_record_size,
              max_vpc_stream_size});

// Values are part of the wire protocol: never renumber.
enum class RecordType : std::uint16_t {
    envelope = 1,
    map_update = 2,
    report = 3,
    report_ack = 4,
    hello = 5,
    group_policy = 6,
    tunnel_peers = 7,
    replica_config = 8,
    volume_op = 9,
    volume_key = 10,
    lease_grant = 11,
    role_certificate = 12,
    image_key = 13,
    vpc_config = 14,
    group_members = 15,
    instance_metadata = 16,
    volume_layout = 17,
    self_test = 18,
    standing_set = 23,
    power_policy = 24,
    vtep_credential = 30,
    credential_revocations = 31,
    vpc_stream = 32,
    frame_notice = 33,
    rotate_vtep_key = 35,
};

// Which khold roles a self_test record asks.
enum class SelfTestScope : std::uint8_t {
    slot = 1,  // the khold role in `slot`
    all = 2,   // every khold role on the server; `slot` is 0
};

struct Record {
    RecordType type{RecordType::envelope};
    std::vector<std::byte> payload;
    friend auto operator==(const Record&, const Record&) -> bool = default;
};

struct Hello {
    std::uint64_t server_id{0};
    std::uint64_t boot_id{0};
    friend auto operator==(const Hello&, const Hello&) -> bool = default;
};

struct ReportAck {
    std::uint64_t server_id{0};
    std::uint64_t report_seq{0};
    friend auto operator==(const ReportAck&, const ReportAck&) -> bool = default;
};

struct LeaseGrant {
    std::uint64_t server_id{0};
    std::uint64_t volume_id{0};
    std::uint64_t epoch{0};
    friend auto operator==(const LeaseGrant&, const LeaseGrant&) -> bool = default;
};

struct SelfTest {
    std::uint64_t server_id{0};
    std::uint8_t slot{0};
    SelfTestScope scope{SelfTestScope::all};
    friend auto operator==(const SelfTest&, const SelfTest&) -> bool = default;
};

struct RotateVtepKey {
    std::uint64_t server_id{0};
    std::uint8_t slot{0};
    std::uint32_t key_epoch{0};
    friend auto operator==(const RotateVtepKey&, const RotateVtepKey&) -> bool = default;
};

struct RoleCertificate {
    std::uint64_t server_id{0};
    std::uint8_t slot{0};
    std::vector<std::byte> chain;  // DER certificates, leaf first
    friend auto operator==(const RoleCertificate&, const RoleCertificate&) -> bool = default;
};

namespace detail {

[[nodiscard]] constexpr auto known(RecordType t) noexcept -> bool {
    return (t >= RecordType::envelope && t <= RecordType::self_test) ||
           t == RecordType::standing_set || t == RecordType::power_policy ||
           t == RecordType::vtep_credential || t == RecordType::credential_revocations ||
           t == RecordType::vpc_stream || t == RecordType::frame_notice ||
           t == RecordType::rotate_vtep_key;
}

}  // namespace detail

// Frames one record. Fails for an unknown type or an oversized payload.
[[nodiscard]] inline auto encode_record(RecordType type, std::span<const std::byte> payload)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (!detail::known(type)) {
        return std::unexpected(DecodeError::bad_record_type);
    }
    if (payload.size() > max_record_payload) {
        return std::unexpected(DecodeError::record_too_large);
    }
    std::vector<std::byte> out;
    out.reserve(record_header_size + payload.size());
    wire::Writer w{out};
    w.le32(static_cast<std::uint32_t>(payload.size()));
    w.le16(static_cast<std::uint16_t>(type));
    w.le16(0);
    w.bytes(payload);
    return out;
}

[[nodiscard]] inline auto encode_report_ack(const ReportAck& ack)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (ack.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (ack.report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    std::vector<std::byte> out;
    wire::Writer w{out};
    w.le64(ack.server_id);
    w.le64(ack.report_seq);
    return out;
}

[[nodiscard]] inline auto decode_report_ack(std::span<const std::byte> bytes) noexcept
    -> std::expected<ReportAck, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto report_seq = r.le64();
    if (!server_id || !report_seq) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (*report_seq == 0) {
        return std::unexpected(DecodeError::bad_report_seq);
    }
    return ReportAck{.server_id = *server_id, .report_seq = *report_seq};
}

[[nodiscard]] inline auto encode_hello(const Hello& hello)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (hello.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (hello.boot_id == 0) {
        return std::unexpected(DecodeError::bad_boot_id);
    }
    std::vector<std::byte> out;
    wire::Writer w{out};
    w.le64(hello.server_id);
    w.le64(hello.boot_id);
    return out;
}

[[nodiscard]] inline auto decode_hello(std::span<const std::byte> bytes) noexcept
    -> std::expected<Hello, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto boot_id = r.le64();
    if (!server_id || !boot_id) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (*boot_id == 0) {
        return std::unexpected(DecodeError::bad_boot_id);
    }
    return Hello{.server_id = *server_id, .boot_id = *boot_id};
}

[[nodiscard]] inline auto check_lease_grant(const LeaseGrant& g) noexcept
    -> std::expected<void, DecodeError> {
    if (g.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (g.volume_id == 0) {
        return std::unexpected(DecodeError::bad_id);
    }
    if (g.epoch == 0) {
        return std::unexpected(DecodeError::bad_epoch);
    }
    return {};
}

[[nodiscard]] inline auto encode_lease_grant(const LeaseGrant& g)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = check_lease_grant(g); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(lease_grant_size);
    wire::Writer w{out};
    w.le64(g.server_id);
    w.le64(g.volume_id);
    w.le64(g.epoch);
    return out;
}

[[nodiscard]] inline auto decode_lease_grant(std::span<const std::byte> bytes) noexcept
    -> std::expected<LeaseGrant, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto volume_id = r.le64();
    auto epoch = r.le64();
    if (!server_id || !volume_id || !epoch) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    const LeaseGrant g{.server_id = *server_id, .volume_id = *volume_id, .epoch = *epoch};
    if (auto ok = check_lease_grant(g); !ok) {
        return std::unexpected(ok.error());
    }
    return g;
}

[[nodiscard]] inline auto check_self_test(const SelfTest& t) noexcept
    -> std::expected<void, DecodeError> {
    if (t.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (t.scope != SelfTestScope::slot && t.scope != SelfTestScope::all) {
        return std::unexpected(DecodeError::unknown_value);
    }
    if (t.scope == SelfTestScope::all && t.slot != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    return {};
}

[[nodiscard]] inline auto encode_self_test(const SelfTest& t)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = check_self_test(t); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(self_test_size);
    wire::Writer w{out};
    w.le64(t.server_id);
    w.u8(t.slot);
    w.u8(static_cast<std::uint8_t>(t.scope));
    w.le16(0);
    w.le32(0);
    return out;
}

[[nodiscard]] inline auto decode_self_test(std::span<const std::byte> bytes) noexcept
    -> std::expected<SelfTest, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto slot = r.u8();
    auto scope = r.u8();
    auto reserved1 = r.le16();
    auto reserved2 = r.le32();
    if (!server_id || !slot || !scope || !reserved1 || !reserved2) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*reserved1 != 0 || *reserved2 != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    const SelfTest t{
        .server_id = *server_id, .slot = *slot, .scope = static_cast<SelfTestScope>(*scope)};
    if (auto ok = check_self_test(t); !ok) {
        return std::unexpected(ok.error());
    }
    return t;
}

[[nodiscard]] inline auto check_rotate_vtep_key(const RotateVtepKey& k) noexcept
    -> std::expected<void, DecodeError> {
    if (k.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (k.key_epoch == 0 || k.key_epoch > max_key_epoch) {
        return std::unexpected(DecodeError::unknown_value);
    }
    return {};
}

[[nodiscard]] inline auto encode_rotate_vtep_key(const RotateVtepKey& k)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = check_rotate_vtep_key(k); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(rotate_vtep_key_size);
    wire::Writer w{out};
    w.le64(k.server_id);
    w.u8(k.slot);
    w.u8(0);
    w.le16(0);
    w.le32(k.key_epoch);
    return out;
}

[[nodiscard]] inline auto decode_rotate_vtep_key(std::span<const std::byte> bytes) noexcept
    -> std::expected<RotateVtepKey, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto slot = r.u8();
    auto reserved1 = r.u8();
    auto reserved2 = r.le16();
    auto epoch = r.le32();
    if (!server_id || !slot || !reserved1 || !reserved2 || !epoch) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() != 0) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    if (*reserved1 != 0 || *reserved2 != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    const RotateVtepKey k{.server_id = *server_id, .slot = *slot, .key_epoch = *epoch};
    if (auto ok = check_rotate_vtep_key(k); !ok) {
        return std::unexpected(ok.error());
    }
    return k;
}

[[nodiscard]] inline auto check_role_certificate(const RoleCertificate& c) noexcept
    -> std::expected<void, DecodeError> {
    if (c.server_id == 0) {
        return std::unexpected(DecodeError::bad_server_id);
    }
    if (c.chain.size() > max_cert_chain_size) {
        return std::unexpected(DecodeError::bad_der);
    }
    if (auto n = der_sequences(c.chain, max_cert_chain_certs); !n) {
        return std::unexpected(n.error());
    }
    return {};
}

[[nodiscard]] inline auto encode_role_certificate(const RoleCertificate& c)
    -> std::expected<std::vector<std::byte>, DecodeError> {
    if (auto ok = check_role_certificate(c); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> out;
    out.reserve(role_certificate_fixed_size + c.chain.size());
    wire::Writer w{out};
    w.le64(c.server_id);
    w.u8(c.slot);
    w.u8(0);
    w.le16(0);
    w.le32(static_cast<std::uint32_t>(c.chain.size()));
    w.bytes(c.chain);
    return out;
}

[[nodiscard]] inline auto decode_role_certificate(std::span<const std::byte> bytes)
    -> std::expected<RoleCertificate, DecodeError> {
    wire::Reader r{bytes};
    auto server_id = r.le64();
    auto slot = r.u8();
    auto reserved1 = r.u8();
    auto reserved2 = r.le16();
    auto chain_len = r.le32();
    if (!server_id || !slot || !reserved1 || !reserved2 || !chain_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (*reserved1 != 0 || *reserved2 != 0) {
        return std::unexpected(DecodeError::reserved_not_zero);
    }
    if (r.remaining() < *chain_len) {
        return std::unexpected(DecodeError::truncated);
    }
    if (r.remaining() > *chain_len) {
        return std::unexpected(DecodeError::trailing_bytes);
    }
    const auto chain = r.rest();
    RoleCertificate c{
        .server_id = *server_id, .slot = *slot, .chain = {chain.begin(), chain.end()}};
    if (auto ok = check_role_certificate(c); !ok) {
        return std::unexpected(ok.error());
    }
    return c;
}

// Incremental record parser for a byte stream. Feed it whatever the socket
// returned, then call next() until it yields nothing. After any error the
// stream is out of sync and the connection must be closed; the decoder
// keeps returning that error.
class RecordDecoder {
public:
    auto feed(std::span<const std::byte> bytes) -> void {
        if (!_error) {
            _buffer.insert(_buffer.end(), bytes.begin(), bytes.end());
        }
    }

    // A complete record, std::nullopt when more bytes are needed, or the
    // error that broke the stream.
    [[nodiscard]] auto next() -> std::expected<std::optional<Record>, DecodeError> {
        if (_error) {
            return std::unexpected(*_error);
        }
        const auto avail = std::span<const std::byte>{_buffer}.subspan(_start);
        wire::Reader r{avail};
        auto length = r.le32();
        auto type = r.le16();
        auto reserved = r.le16();
        if (!length || !type || !reserved) {
            return std::optional<Record>{};
        }
        if (*reserved != 0) {
            return fail(DecodeError::reserved_not_zero);
        }
        if (!detail::known(static_cast<RecordType>(*type))) {
            return fail(DecodeError::bad_record_type);
        }
        if (*length > max_record_payload) {
            return fail(DecodeError::record_too_large);
        }
        auto payload = r.bytes(*length);
        if (!payload) {
            return std::optional<Record>{};
        }
        Record rec{.type = static_cast<RecordType>(*type),
                   .payload = {payload->begin(), payload->end()}};
        _start += record_header_size + *length;
        compact();
        return std::optional<Record>{std::move(rec)};
    }

    // Bytes received but not yet returned as a record.
    [[nodiscard]] auto buffered() const noexcept -> std::size_t { return _buffer.size() - _start; }

private:
    auto fail(DecodeError e) -> std::expected<std::optional<Record>, DecodeError> {
        _error = e;
        _buffer.clear();
        _start = 0;
        return std::unexpected(e);
    }

    // Drops consumed bytes once they are at least half the buffer, so
    // compaction is amortized O(1) per byte.
    auto compact() -> void {
        if (_start == _buffer.size()) {
            _buffer.clear();
            _start = 0;
        } else if (_start * 2 >= _buffer.size()) {
            _buffer.erase(_buffer.begin(), _buffer.begin() + static_cast<std::ptrdiff_t>(_start));
            _start = 0;
        }
    }

    std::vector<std::byte> _buffer;
    std::size_t _start{0};
    std::optional<DecodeError> _error;
};

}  // namespace ak::proto
