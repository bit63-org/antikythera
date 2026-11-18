// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/net/geneve.hpp"

#include "common/wire.hpp"

namespace ak::oar::net::geneve {

namespace {

constexpr std::uint8_t version_shift = 6;
constexpr std::uint8_t opt_len_mask = 0x3F;
constexpr std::uint8_t flag_oam = 0x80;
constexpr std::uint8_t flag_critical = 0x40;
constexpr std::uint8_t option_length_mask = 0x1F;
constexpr std::uint8_t nic_pair_length_words = 4;  // 16 bytes of data

constexpr bool valid_src(NicId id) noexcept { return id != nic_invalid && id != nic_broadcast; }
constexpr bool valid_dst(NicId id) noexcept { return id != nic_invalid; }

}  // namespace

const char* to_string(DecodeError e) noexcept {
    switch (e) {
        case DecodeError::truncated: return "truncated";
        case DecodeError::bad_version: return "bad_version";
        case DecodeError::options_overrun: return "options_overrun";
        case DecodeError::bad_option_length: return "bad_option_length";
        case DecodeError::unknown_critical_option: return "unknown_critical_option";
        case DecodeError::critical_flag_mismatch: return "critical_flag_mismatch";
        case DecodeError::missing_nic_pair: return "missing_nic_pair";
        case DecodeError::duplicate_nic_pair: return "duplicate_nic_pair";
        case DecodeError::invalid_nic_id: return "invalid_nic_id";
        case DecodeError::bad_protocol: return "bad_protocol";
        case DecodeError::inner_frame_too_short: return "inner_frame_too_short";
    }
    return "unknown";
}

const char* to_string(EncodeError e) noexcept {
    switch (e) {
        case EncodeError::vni_out_of_range: return "vni_out_of_range";
        case EncodeError::invalid_nic_id: return "invalid_nic_id";
        case EncodeError::inner_frame_too_short: return "inner_frame_too_short";
    }
    return "unknown";
}

std::expected<Packet, DecodeError> decode(std::span<const std::byte> udp_payload) noexcept {
    wire::Reader r{udp_payload};

    // Base header. Every read below is bounds-checked; map any truncation to
    // DecodeError::truncated.
    auto b0 = r.u8();
    auto b1 = r.u8();
    auto proto = r.be16();
    auto vni_word = r.be32();
    if (!b0 || !b1 || !proto || !vni_word) {
        return std::unexpected(DecodeError::truncated);
    }

    if ((*b0 >> version_shift) != 0) {
        return std::unexpected(DecodeError::bad_version);
    }
    const std::size_t opt_bytes = std::size_t{static_cast<std::uint8_t>(*b0 & opt_len_mask)} * 4;
    const bool oam = (*b1 & flag_oam) != 0;
    const bool critical_flag = (*b1 & flag_critical) != 0;

    auto opts = r.bytes(opt_bytes);
    if (!opts) {
        return std::unexpected(DecodeError::options_overrun);
    }

    Packet pkt;
    pkt.vni = *vni_word >> 8;  // low byte is reserved: ignored on receipt
    pkt.oam = oam;
    pkt.protocol = *proto;

    bool saw_critical = false;
    wire::Reader opt_reader{*opts};
    while (opt_reader.remaining() > 0) {
        auto cls = opt_reader.be16();
        auto type = opt_reader.u8();
        auto len_byte = opt_reader.u8();
        if (!cls || !type || !len_byte) {
            return std::unexpected(DecodeError::truncated);
        }
        const std::size_t data_len = std::size_t{static_cast<std::uint8_t>(*len_byte & option_length_mask)} * 4;
        auto data = opt_reader.bytes(data_len);
        if (!data) {
            return std::unexpected(DecodeError::truncated);
        }

        const bool critical = (*type & option_type_critical_bit) != 0;
        saw_critical = saw_critical || critical;

        if (*cls == option_class && *type == option_type_nic_pair) {
            if (data_len != std::size_t{nic_pair_length_words} * 4) {
                return std::unexpected(DecodeError::bad_option_length);
            }
            if (pkt.nics) {
                return std::unexpected(DecodeError::duplicate_nic_pair);
            }
            wire::Reader d{*data};
            const NicId src{*d.be64()};  // length checked above: cannot fail
            const NicId dst{*d.be64()};
            if (!valid_src(src) || !valid_dst(dst)) {
                return std::unexpected(DecodeError::invalid_nic_id);
            }
            pkt.nics = NicPair{src, dst};
        } else if (critical) {
            return std::unexpected(DecodeError::unknown_critical_option);
        }
        // Unknown non-critical options are skipped, as RFC 8926 requires.
    }

    if (saw_critical && !critical_flag) {
        return std::unexpected(DecodeError::critical_flag_mismatch);
    }

    pkt.inner = r.rest();

    if (!oam) {
        if (!pkt.nics) {
            return std::unexpected(DecodeError::missing_nic_pair);
        }
        if (pkt.protocol != protocol_ethernet) {
            return std::unexpected(DecodeError::bad_protocol);
        }
        if (pkt.inner.size() < ethernet_header_size) {
            return std::unexpected(DecodeError::inner_frame_too_short);
        }
    }
    return pkt;
}

std::expected<std::vector<std::byte>, EncodeError> encode(const EncodeParams& params,
                                                          std::span<const std::byte> inner_frame) {
    if (params.vni > vni_max) {
        return std::unexpected(EncodeError::vni_out_of_range);
    }
    if (!valid_src(params.nics.src) || !valid_dst(params.nics.dst)) {
        return std::unexpected(EncodeError::invalid_nic_id);
    }
    if (!params.oam && inner_frame.size() < ethernet_header_size) {
        return std::unexpected(EncodeError::inner_frame_too_short);
    }

    std::vector<std::byte> out;
    out.reserve(base_header_size + nic_pair_option_size + inner_frame.size());
    wire::Writer w{out};

    constexpr std::uint8_t opt_len_words = nic_pair_option_size / 4;
    w.u8(opt_len_words);  // Ver = 0
    w.u8(static_cast<std::uint8_t>(flag_critical | (params.oam ? flag_oam : 0)));
    w.be16(protocol_ethernet);
    w.be32(params.vni << 8);  // reserved low byte = 0

    w.be16(option_class);
    w.u8(option_type_nic_pair);
    w.u8(nic_pair_length_words);  // reserved bits = 0
    w.be64(params.nics.src.value);
    w.be64(params.nics.dst.value);

    w.bytes(inner_frame);
    return out;
}

}  // namespace ak::oar::net::geneve
