// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/sealed_store.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <memory>
#include <set>
#include <utility>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

constexpr std::uint32_t superblock_magic = 0x4253'4B41;  // "AKSB" as little-endian bytes
constexpr std::uint32_t record_magic = 0x4F53'4B41;      // "AKSO" as little-endian bytes
constexpr std::uint16_t superblock_format = 1;
constexpr std::uint16_t record_flag_removed = 0x0001;
constexpr std::size_t nonce_size = 12;
constexpr std::size_t digest_size = 32;
constexpr std::size_t superblock_mac_offset = store_superblock_size - digest_size;
constexpr std::uint64_t data_base = 2 * store_page_size;

constexpr std::string_view object_key_label = "antikythera sealed store object key v1";
constexpr std::string_view superblock_key_label = "antikythera sealed store superblock key v1";
constexpr std::string_view chain_label = "antikythera sealed store chain v1";

struct CipherCtxDeleter {
    auto operator()(EVP_CIPHER_CTX* c) const noexcept -> void { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

struct MdCtxDeleter {
    auto operator()(EVP_MD_CTX* c) const noexcept -> void { EVP_MD_CTX_free(c); }
};
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

auto as_uchar(std::span<const std::byte> b) noexcept -> const unsigned char* {
    return reinterpret_cast<const unsigned char*>(b.data());
}

auto as_uchar_mut(std::span<std::byte> b) noexcept -> unsigned char* {
    return reinterpret_cast<unsigned char*>(b.data());
}

auto as_bytes(std::string_view s) noexcept -> std::span<const std::byte> {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

auto hmac(std::span<const std::byte> key, std::span<const std::byte> data,
          std::span<std::byte, digest_size> out) -> bool {
    unsigned int len = 0;
    const bool ok = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), as_uchar(data),
                         data.size(), as_uchar_mut(out), &len) != nullptr &&
                    len == digest_size;
    if (!ok) {
        ERR_clear_error();
    }
    return ok;
}

// SHA-256 over the concatenation of `parts`.
auto sha256(std::initializer_list<std::span<const std::byte>> parts,
            std::span<std::byte, digest_size> out) -> bool {
    MdCtx ctx{EVP_MD_CTX_new()};
    bool ok = ctx && EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1;
    for (auto p : parts) {
        ok = ok && EVP_DigestUpdate(ctx.get(), p.data(), p.size()) == 1;
    }
    unsigned int len = 0;
    ok = ok && EVP_DigestFinal_ex(ctx.get(), as_uchar_mut(out), &len) == 1 && len == digest_size;
    if (!ok) {
        ERR_clear_error();
    }
    return ok;
}

auto le64_bytes(std::uint64_t v) -> std::array<std::byte, 8> {
    std::array<std::byte, 8> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out.at(i) = static_cast<std::byte>((v >> (8 * i)) & 0xFF);
    }
    return out;
}

[[nodiscard]] constexpr auto valid_name(std::string_view name) noexcept -> bool {
    if (name.empty() || name.size() > max_store_name_size) {
        return false;
    }
    return std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}

struct RecordHeader {
    std::uint8_t name_len{0};
    std::uint16_t flags{0};
    std::uint64_t version{0};
    std::uint32_t ciphertext_len{0};
    std::array<std::byte, nonce_size> nonce{};
};

auto encode_header(const RecordHeader& h) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(store_record_header_size);
    wire::Writer w{out};
    w.le32(record_magic);
    w.u8(h.name_len);
    w.u8(0);
    w.le16(h.flags);
    w.le64(h.version);
    w.le32(h.ciphertext_len);
    w.le32(0);
    w.bytes(h.nonce);
    w.le32(0);
    return out;
}

auto decode_header(std::span<const std::byte> b) -> std::optional<RecordHeader> {
    wire::Reader r{b};
    const auto magic = r.le32();
    const auto name_len = r.u8();
    const auto rsvd1 = r.u8();
    const auto flags = r.le16();
    const auto version = r.le64();
    const auto ct_len = r.le32();
    const auto rsvd2 = r.le32();
    const auto nonce = r.bytes(nonce_size);
    const auto rsvd3 = r.le32();
    if (!magic || !name_len || !rsvd1 || !flags || !version || !ct_len || !rsvd2 || !nonce ||
        !rsvd3 || *magic != record_magic || *rsvd1 != 0 || *rsvd2 != 0 || *rsvd3 != 0 ||
        *name_len == 0 || *name_len > max_store_name_size || (*flags & ~record_flag_removed) != 0 ||
        *version == 0) {
        return std::nullopt;
    }
    RecordHeader h{.name_len = *name_len,
                   .flags = *flags,
                   .version = *version,
                   .ciphertext_len = *ct_len,
                   .nonce = {}};
    std::ranges::copy(*nonce, h.nonce.begin());
    return h;
}

// AAD: header | name | half generation | offset.
auto record_aad(std::span<const std::byte> header, std::string_view name, std::uint64_t generation,
                std::uint64_t offset) -> std::vector<std::byte> {
    std::vector<std::byte> aad(header.begin(), header.end());
    const auto n = as_bytes(name);
    aad.insert(aad.end(), n.begin(), n.end());
    const auto g = le64_bytes(generation);
    const auto o = le64_bytes(offset);
    aad.insert(aad.end(), g.begin(), g.end());
    aad.insert(aad.end(), o.begin(), o.end());
    return aad;
}

auto chain_seed(std::uint64_t generation, std::span<std::byte, digest_size> out) -> bool {
    const auto g = le64_bytes(generation);
    return sha256({as_bytes(chain_label), g}, out);
}

}  // namespace

auto to_string(StoreError e) noexcept -> const char* {
    switch (e) {
        case StoreError::flash:
            return "sealed store flash failed";
        case StoreError::anchor:
            return "secure element failed";
        case StoreError::too_small:
            return "sealed store partition too small";
        case StoreError::bad_name:
            return "bad sealed store object name";
        case StoreError::no_space:
            return "sealed store full";
        case StoreError::authentication_failed:
            return "sealed store object failed authentication";
        case StoreError::crypto:
            return "sealed store crypto failure";
        case StoreError::closed:
            return "sealed store closed";
    }
    return "unknown";
}

auto SealedStore::record_size(std::size_t name_size, std::size_t data_size) noexcept
    -> std::uint64_t {
    return store_record_header_size + name_size + data_size + store_tag_size;
}

auto SealedStore::flash_failed(FlashError e) -> StoreError {
    _flash_error = e;
    return StoreError::flash;
}

auto SealedStore::anchor_failed(AnchorError e) -> StoreError {
    _anchor_error = e;
    return StoreError::anchor;
}

auto SealedStore::half_base(std::uint8_t half) const noexcept -> std::uint64_t {
    return data_base + (std::uint64_t{half} * _half_size);
}

auto SealedStore::open(Flash& flash, StoreAnchor& anchor)
    -> std::expected<SealedStore, StoreError> {
    if (flash.size() < min_store_size) {
        return std::unexpected(StoreError::too_small);
    }
    SealedStore store{flash, anchor};
    store._half_size = ((flash.size() - data_base) / 2) / store_page_size * store_page_size;
    if (auto ok = store.load(); !ok) {
        return std::unexpected(ok.error());
    }
    return store;
}

auto SealedStore::load() -> std::expected<void, StoreError> {
    auto key = _anchor->store_key();
    if (!key) {
        return std::unexpected(anchor_failed(key.error()));
    }
    if (!hmac(key->span(), as_bytes(object_key_label), _object_key.span()) ||
        !hmac(key->span(), as_bytes(superblock_key_label), _superblock_key.span())) {
        return std::unexpected(StoreError::crypto);
    }
    auto counter = _anchor->counter(Counter::store_version);
    if (!counter) {
        return std::unexpected(anchor_failed(counter.error()));
    }
    std::optional<Superblock> best;
    for (std::size_t slot = 0; slot < 2; ++slot) {
        auto sb = read_superblock(slot);
        if (sb && (!best || sb->version > best->version)) {
            best = sb;
        }
    }
    if (!best) {
        // Nothing valid: a new partition, or one whose superblocks are gone
        // (erased, or written under a destroyed key). Only a counter still
        // at zero means nothing was ever committed here.
        _rolled_back = *counter != 0;
        return format(*counter + 1);
    }
    _rolled_back = best->version < *counter;
    if (auto ok = scan(*best); !ok) {
        return ok;
    }
    if (_rolled_back) {
        // The next commit must land above the counter, re-anchoring the
        // store; until then rolled_back() stays set for helm to act on.
        _version = *counter;
    } else if (best->version > *counter) {
        // A commit whose counter update was cut by power loss.
        if (auto ok = _anchor->advance(Counter::store_version, best->version); !ok) {
            return std::unexpected(anchor_failed(ok.error()));
        }
    }
    return {};
}

auto SealedStore::format(std::uint64_t version) -> std::expected<void, StoreError> {
    Digest chain{};
    if (!chain_seed(1, chain)) {
        return std::unexpected(StoreError::crypto);
    }
    _version = version - 1;
    _index.clear();
    return finish_commit(0, 1, 0, chain);
}

auto SealedStore::read_superblock(std::size_t slot) -> std::optional<Superblock> {
    std::array<std::byte, store_superblock_size> b{};
    if (!_flash->read(slot * store_page_size, b)) {
        return std::nullopt;
    }
    Digest mac{};
    if (!hmac(_superblock_key.span(), std::span{b}.first(superblock_mac_offset), mac) ||
        CRYPTO_memcmp(mac.data(), b.data() + superblock_mac_offset, digest_size) != 0) {
        return std::nullopt;
    }
    wire::Reader r{b};
    const auto magic = r.le32().value_or(0);
    const auto format = r.le16().value_or(0);
    Superblock sb;
    sb.active_half = r.u8().value_or(0xFF);
    const auto reserved = r.u8().value_or(1);
    sb.version = r.le64().value_or(0);
    sb.generation = r.le64().value_or(0);
    sb.tail = r.le64().value_or(~std::uint64_t{0});
    std::ranges::copy(r.bytes(digest_size).value_or(std::span<const std::byte>{}),
                      sb.chain.begin());
    if (magic != superblock_magic || format != superblock_format || reserved != 0 ||
        sb.active_half > 1 || sb.version == 0 || sb.generation == 0 || sb.tail > _half_size) {
        return std::nullopt;
    }
    return sb;
}

auto SealedStore::write_superblock(const Superblock& sb) -> std::expected<void, StoreError> {
    std::vector<std::byte> b;
    b.reserve(store_superblock_size);
    wire::Writer w{b};
    w.le32(superblock_magic);
    w.le16(superblock_format);
    w.u8(sb.active_half);
    w.u8(0);
    w.le64(sb.version);
    w.le64(sb.generation);
    w.le64(sb.tail);
    w.bytes(sb.chain);
    Digest mac{};
    if (!hmac(_superblock_key.span(), b, mac)) {
        return std::unexpected(StoreError::crypto);
    }
    w.bytes(mac);
    const std::uint64_t slot = sb.version % 2;
    if (auto ok = _flash->write(slot * store_page_size, b); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    if (auto ok = _flash->sync(); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    return {};
}

auto SealedStore::scan(const Superblock& sb) -> std::expected<void, StoreError> {
    Digest chain{};
    if (!chain_seed(sb.generation, chain)) {
        return std::unexpected(StoreError::crypto);
    }
    std::map<std::string, Entry, std::less<>> index;
    const auto base = data_base + (std::uint64_t{sb.active_half} * _half_size);
    std::uint64_t offset = 0;
    bool intact = true;
    while (offset < sb.tail) {
        std::array<std::byte, store_record_header_size> hb{};
        if (sb.tail - offset < hb.size() || !_flash->read(base + offset, hb)) {
            intact = false;
            break;
        }
        const auto h = decode_header(hb);
        if (!h || record_size(h->name_len, h->ciphertext_len) > sb.tail - offset) {
            intact = false;
            break;
        }
        std::vector<std::byte> rec(record_size(h->name_len, h->ciphertext_len));
        if (!_flash->read(base + offset, rec)) {
            intact = false;
            break;
        }
        if (!sha256({chain, rec}, chain)) {
            return std::unexpected(StoreError::crypto);
        }
        std::string name(h->name_len, '\0');
        std::ranges::transform(
            std::span{rec}.subspan(store_record_header_size, h->name_len), name.begin(),
            [](std::byte c) { return static_cast<char>(std::to_integer<unsigned char>(c)); });
        auto& e = index[name];
        if (h->version > e.version) {
            e = Entry{.offset = offset,
                      .version = h->version,
                      .ciphertext_len = h->ciphertext_len,
                      .removed = (h->flags & record_flag_removed) != 0};
        }
        offset += rec.size();
    }
    _active_half = sb.active_half;
    _half_generation = sb.generation;
    _version = sb.version;
    _tail = sb.tail;
    _chain = sb.chain;
    _index = std::move(index);
    if (intact && offset == sb.tail &&
        CRYPTO_memcmp(chain.data(), sb.chain.data(), digest_size) == 0) {
        return {};
    }
    // The log does not match its superblock: check each object on its own
    // and keep only the ones that open.
    _degraded = true;
    if (!intact) {
        ++_faults;
    }
    for (auto it = _index.begin(); it != _index.end();) {
        if (!valid_name(it->first) || !open_record(_active_half, _half_generation,
                                                   it->second.offset, it->first, it->second)) {
            ++_faults;
            it = _index.erase(it);
        } else {
            ++it;
        }
    }
    return {};
}

auto SealedStore::seal_record(std::uint64_t generation, std::uint64_t offset, std::string_view name,
                              std::uint64_t version, bool removed, std::span<const std::byte> data)
    -> std::expected<std::vector<std::byte>, StoreError> {
    RecordHeader h{.name_len = static_cast<std::uint8_t>(name.size()),
                   .flags = removed ? record_flag_removed : std::uint16_t{0},
                   .version = version,
                   .ciphertext_len = static_cast<std::uint32_t>(data.size()),
                   .nonce = {}};
    if (RAND_bytes(as_uchar_mut(h.nonce), static_cast<int>(h.nonce.size())) != 1) {
        ERR_clear_error();
        return std::unexpected(StoreError::crypto);
    }
    auto rec = encode_header(h);
    const auto aad = record_aad(rec, name, generation, offset);
    const auto n = as_bytes(name);
    rec.insert(rec.end(), n.begin(), n.end());
    const auto ct_at = rec.size();
    rec.resize(ct_at + data.size() + store_tag_size);
    const auto ct = std::span{rec}.subspan(ct_at, data.size());
    const auto tag = std::span{rec}.subspan(ct_at + data.size(), store_tag_size);
    CipherCtx ctx{EVP_CIPHER_CTX_new()};
    int len = 0;
    const bool ok =
        ctx && EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_size),
                            nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, as_uchar(_object_key.span()),
                           as_uchar(h.nonce)) == 1 &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, as_uchar(aad), static_cast<int>(aad.size())) ==
            1 &&
        (data.empty() || EVP_EncryptUpdate(ctx.get(), as_uchar_mut(ct), &len, as_uchar(data),
                                           static_cast<int>(data.size())) == 1) &&
        EVP_EncryptFinal_ex(ctx.get(), as_uchar_mut(ct.subspan(data.size())), &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(store_tag_size),
                            as_uchar_mut(tag)) == 1;
    if (!ok) {
        ERR_clear_error();
        return std::unexpected(StoreError::crypto);
    }
    return rec;
}

auto SealedStore::open_record(std::uint8_t half, std::uint64_t generation, std::uint64_t offset,
                              std::string_view name, const Entry& entry)
    -> std::expected<std::vector<std::byte>, StoreError> {
    std::vector<std::byte> rec(record_size(name.size(), entry.ciphertext_len));
    if (auto ok = _flash->read(half_base(half) + offset, rec); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    const auto h = decode_header(std::span{rec}.first(store_record_header_size));
    if (!h || h->name_len != name.size() || h->version != entry.version ||
        h->ciphertext_len != entry.ciphertext_len) {
        return std::unexpected(StoreError::authentication_failed);
    }
    const auto aad =
        record_aad(std::span{rec}.first(store_record_header_size), name, generation, offset);
    const auto ct =
        std::span{rec}.subspan(store_record_header_size + name.size(), entry.ciphertext_len);
    auto tag = std::span{rec}.last(store_tag_size);
    std::vector<std::byte> out(entry.ciphertext_len);
    CipherCtx ctx{EVP_CIPHER_CTX_new()};
    int len = 0;
    const bool setup =
        ctx && EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_size),
                            nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, as_uchar(_object_key.span()),
                           as_uchar(h->nonce)) == 1 &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, as_uchar(aad), static_cast<int>(aad.size())) ==
            1 &&
        (ct.empty() || EVP_DecryptUpdate(ctx.get(), as_uchar_mut(out), &len, as_uchar(ct),
                                         static_cast<int>(ct.size())) == 1) &&
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(store_tag_size),
                            as_uchar_mut(tag)) == 1;
    if (!setup) {
        ERR_clear_error();
        return std::unexpected(StoreError::crypto);
    }
    if (EVP_DecryptFinal_ex(ctx.get(), as_uchar_mut(std::span{out}.subspan(out.size())), &len) !=
        1) {
        ERR_clear_error();
        secure_zero(out);
        return std::unexpected(StoreError::authentication_failed);
    }
    return out;
}

auto SealedStore::get(std::string_view name)
    -> std::expected<std::optional<std::vector<std::byte>>, StoreError> {
    if (_closed) {
        return std::unexpected(StoreError::closed);
    }
    const auto it = _index.find(name);
    if (it == _index.end() || it->second.removed) {
        return std::optional<std::vector<std::byte>>{};
    }
    auto data = open_record(_active_half, _half_generation, it->second.offset, name, it->second);
    if (!data) {
        if (data.error() == StoreError::authentication_failed) {
            ++_faults;
            _index.erase(it);
        }
        return std::unexpected(data.error());
    }
    return std::optional<std::vector<std::byte>>{std::move(*data)};
}

auto SealedStore::contains(std::string_view name) const -> bool {
    const auto it = _index.find(name);
    return it != _index.end() && !it->second.removed;
}

auto SealedStore::names() const -> std::vector<std::string> {
    std::vector<std::string> out;
    for (const auto& [name, e] : _index) {
        if (!e.removed) {
            out.push_back(name);
        }
    }
    return out;
}

auto SealedStore::put(std::string_view name, std::span<const std::byte> data)
    -> std::expected<void, StoreError> {
    const StoreWrite w{.name = std::string{name},
                       .data = std::vector<std::byte>(data.begin(), data.end())};
    return commit(std::span{&w, 1});
}

auto SealedStore::remove(std::string_view name) -> std::expected<void, StoreError> {
    const StoreWrite w{.name = std::string{name}, .data = std::nullopt};
    return commit(std::span{&w, 1});
}

auto SealedStore::commit(std::span<const StoreWrite> writes) -> std::expected<void, StoreError> {
    if (_closed) {
        return std::unexpected(StoreError::closed);
    }
    std::set<std::string_view> seen;
    for (const auto& w : writes) {
        if (!valid_name(w.name) || !seen.insert(w.name).second) {
            return std::unexpected(StoreError::bad_name);
        }
    }
    auto appended = append(writes);
    if (appended || appended.error() != StoreError::no_space) {
        return appended;
    }
    return compact(writes);
}

auto SealedStore::append(std::span<const StoreWrite> writes) -> std::expected<void, StoreError> {
    std::uint64_t tail = _tail;
    Digest chain = _chain;
    std::vector<std::vector<std::byte>> records;
    std::vector<std::pair<std::string, Entry>> updates;
    for (const auto& w : writes) {
        const auto it = _index.find(w.name);
        const std::uint64_t version = it == _index.end() ? 1 : it->second.version + 1;
        const std::span<const std::byte> data =
            w.data ? std::span<const std::byte>{*w.data} : std::span<const std::byte>{};
        if (record_size(w.name.size(), data.size()) > _half_size - tail) {
            return std::unexpected(StoreError::no_space);
        }
        auto rec = seal_record(_half_generation, tail, w.name, version, !w.data, data);
        if (!rec) {
            return std::unexpected(rec.error());
        }
        if (!sha256({chain, *rec}, chain)) {
            return std::unexpected(StoreError::crypto);
        }
        updates.emplace_back(w.name,
                             Entry{.offset = tail,
                                   .version = version,
                                   .ciphertext_len = static_cast<std::uint32_t>(data.size()),
                                   .removed = !w.data});
        tail += rec->size();
        records.push_back(std::move(*rec));
    }
    std::uint64_t at = half_base(_active_half) + _tail;
    for (const auto& rec : records) {
        if (auto ok = _flash->write(at, rec); !ok) {
            return std::unexpected(flash_failed(ok.error()));
        }
        at += rec.size();
    }
    if (auto ok = _flash->sync(); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    auto done = finish_commit(_active_half, _half_generation, tail, chain);
    if (!done && done.error() != StoreError::anchor) {
        return done;
    }
    for (auto& [name, e] : updates) {
        _index[name] = e;
    }
    return done;
}

auto SealedStore::compact(std::span<const StoreWrite> writes) -> std::expected<void, StoreError> {
    const auto target = static_cast<std::uint8_t>(1 - _active_half);
    const auto generation = _half_generation + 1;
    Digest chain{};
    if (!chain_seed(generation, chain)) {
        return std::unexpected(StoreError::crypto);
    }
    // Everything live that this commit does not replace, then the commit.
    std::vector<StoreWrite> live;
    for (const auto& [name, e] : _index) {
        const bool replaced =
            std::ranges::any_of(writes, [&](const StoreWrite& w) { return w.name == name; });
        if (e.removed || replaced) {
            continue;
        }
        auto data = open_record(_active_half, _half_generation, e.offset, name, e);
        if (!data) {
            if (data.error() != StoreError::authentication_failed) {
                return std::unexpected(data.error());
            }
            ++_faults;  // dropped, as get() would have dropped it
            continue;
        }
        live.push_back({.name = name, .data = std::move(*data)});
    }
    for (const auto& w : writes) {
        if (w.data) {
            live.push_back(w);
        }
    }
    std::uint64_t tail = 0;
    for (const auto& w : live) {
        tail += record_size(w.name.size(), w.data->size());
    }
    if (tail > _half_size) {
        for (auto& w : live) {
            secure_zero(*w.data);
        }
        return std::unexpected(StoreError::no_space);
    }
    std::map<std::string, Entry, std::less<>> index;
    std::uint64_t offset = 0;
    for (auto& w : live) {
        auto rec = seal_record(generation, offset, w.name, 1, false, *w.data);
        secure_zero(*w.data);
        if (!rec) {
            return std::unexpected(rec.error());
        }
        if (!sha256({chain, *rec}, chain)) {
            return std::unexpected(StoreError::crypto);
        }
        if (auto ok = _flash->write(half_base(target) + offset, *rec); !ok) {
            return std::unexpected(flash_failed(ok.error()));
        }
        index[w.name] = Entry{.offset = offset,
                              .version = 1,
                              .ciphertext_len = static_cast<std::uint32_t>(w.data->size()),
                              .removed = false};
        offset += rec->size();
    }
    if (auto ok = _flash->sync(); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    auto done = finish_commit(target, generation, offset, chain);
    if (!done && done.error() != StoreError::anchor) {
        return done;
    }
    _index = std::move(index);
    return done;
}

auto SealedStore::finish_commit(std::uint8_t half, std::uint64_t generation, std::uint64_t tail,
                                const Digest& chain) -> std::expected<void, StoreError> {
    const Superblock sb{.active_half = half,
                        .version = _version + 1,
                        .generation = generation,
                        .tail = tail,
                        .chain = chain};
    if (auto ok = write_superblock(sb); !ok) {
        return ok;
    }
    // The commit is durable from here: the store moves to it even if the
    // counter update fails, and open() finishes that update later.
    _active_half = half;
    _half_generation = generation;
    _version = sb.version;
    _tail = tail;
    _chain = chain;
    if (auto ok = _anchor->advance(Counter::store_version, sb.version); !ok) {
        return std::unexpected(anchor_failed(ok.error()));
    }
    return {};
}

auto SealedStore::erase() -> std::expected<void, StoreError> {
    if (auto ok = _anchor->destroy_store_key(); !ok) {
        return std::unexpected(anchor_failed(ok.error()));
    }
    _closed = true;
    _index.clear();
    secure_zero(_object_key.span());
    secure_zero(_superblock_key.span());
    const std::vector<std::byte> zeros(2 * store_page_size);
    if (auto ok = _flash->write(0, zeros); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    if (auto ok = _flash->sync(); !ok) {
        return std::unexpected(flash_failed(ok.error()));
    }
    return {};
}

}  // namespace ak::helm
