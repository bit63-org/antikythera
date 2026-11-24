// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "tls/role_identity.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <cerrno>
#include <climits>
#include <ctime>
#include <fstream>
#include <iterator>
#include <utility>

#include "proto/server_identity.hpp"

namespace ak::tls {

auto to_string(IdentityError e) noexcept -> const char* {
    switch (e) {
        case IdentityError::io:
            return "io";
        case IdentityError::bad_key:
            return "bad_key";
        case IdentityError::bad_config:
            return "bad_config";
        case IdentityError::bad_certificate:
            return "bad_certificate";
        case IdentityError::wrong_key:
            return "wrong_key";
        case IdentityError::wrong_server:
            return "wrong_server";
        case IdentityError::missing_address:
            return "missing_address";
        case IdentityError::untrusted:
            return "untrusted";
    }
    return "unknown";
}

namespace {

struct BioFree {
    auto operator()(BIO* p) const noexcept -> void { BIO_free(p); }
};
struct X509Free {
    auto operator()(X509* p) const noexcept -> void { X509_free(p); }
};
struct PkeyFree {
    auto operator()(EVP_PKEY* p) const noexcept -> void { EVP_PKEY_free(p); }
};
struct ReqFree {
    auto operator()(X509_REQ* p) const noexcept -> void { X509_REQ_free(p); }
};
struct StoreFree {
    auto operator()(X509_STORE* p) const noexcept -> void { X509_STORE_free(p); }
};
struct StoreCtxFree {
    auto operator()(X509_STORE_CTX* p) const noexcept -> void { X509_STORE_CTX_free(p); }
};
struct NamesFree {
    auto operator()(GENERAL_NAMES* p) const noexcept -> void { GENERAL_NAMES_free(p); }
};
struct CertStackFree {
    auto operator()(STACK_OF(X509) * p) const noexcept -> void { sk_X509_free(p); }
};
struct ExtStackFree {
    auto operator()(STACK_OF(X509_EXTENSION) * p) const noexcept -> void {
        sk_X509_EXTENSION_pop_free(p, X509_EXTENSION_free);
    }
};

using BioPtr = std::unique_ptr<BIO, BioFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using ReqPtr = std::unique_ptr<X509_REQ, ReqFree>;
using StorePtr = std::unique_ptr<X509_STORE, StoreFree>;
using StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, StoreCtxFree>;
using NamesPtr = std::unique_ptr<GENERAL_NAMES, NamesFree>;
using CertStackPtr = std::unique_ptr<STACK_OF(X509), CertStackFree>;
using ExtStackPtr = std::unique_ptr<STACK_OF(X509_EXTENSION), ExtStackFree>;

using Chain = std::vector<X509Ptr>;

auto mem_bio(const std::string& s) -> BioPtr {
    if (s.size() > static_cast<std::size_t>(INT_MAX)) {
        return nullptr;
    }
    return BioPtr{BIO_new_mem_buf(s.data(), static_cast<int>(s.size()))};
}

auto bio_text(BIO* bio) -> std::string {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    return len > 0 ? std::string{data, static_cast<std::size_t>(len)} : std::string{};
}

auto read_text(const std::filesystem::path& path) -> std::optional<std::string> {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

// Writes `text` to `path` through a temporary file and a rename, so a
// crash leaves the old file or the new one, never half of one.
auto write_atomic(const std::filesystem::path& path, const std::string& text, mode_t mode) -> bool {
    auto tmp = path;
    tmp += ".tmp";
    static_cast<void>(::unlink(tmp.c_str()));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        return false;
    }
    std::size_t done = 0;
    bool ok = true;
    while (ok && done < text.size()) {
        const auto n = ::write(fd, text.data() + done, text.size() - done);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        ok = n > 0;
        done += ok ? static_cast<std::size_t>(n) : 0;
    }
    ok = ok && ::fsync(fd) == 0;
    ok = (::close(fd) == 0) && ok;
    ok = ok && ::rename(tmp.c_str(), path.c_str()) == 0;
    if (!ok) {
        static_cast<void>(::unlink(tmp.c_str()));
    }
    return ok;
}

auto key_pem(EVP_PKEY* key) -> std::string {
    BioPtr bio{BIO_new(BIO_s_mem())};
    if (!bio ||
        PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return {};
    }
    return bio_text(bio.get());
}

auto pem_of(const Chain& chain) -> std::string {
    BioPtr bio{BIO_new(BIO_s_mem())};
    if (!bio) {
        return {};
    }
    for (const auto& c : chain) {
        if (PEM_write_bio_X509(bio.get(), c.get()) != 1) {
            return {};
        }
    }
    return bio_text(bio.get());
}

auto load_key(const std::filesystem::path& path) -> std::expected<PkeyPtr, IdentityError> {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        if (errno != ENOENT) {
            return std::unexpected(IdentityError::io);
        }
        PkeyPtr key{EVP_EC_gen("P-256")};
        if (!key) {
            return std::unexpected(IdentityError::bad_key);
        }
        const auto pem = key_pem(key.get());
        if (pem.empty() || !write_atomic(path, pem, S_IRUSR | S_IWUSR)) {
            return std::unexpected(IdentityError::io);
        }
        return key;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return std::unexpected(IdentityError::bad_key);
    }
    const auto text = read_text(path);
    if (!text) {
        return std::unexpected(IdentityError::io);
    }
    auto bio = mem_bio(*text);
    PkeyPtr key{bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr) : nullptr};
    if (!key) {
        return std::unexpected(IdentityError::bad_key);
    }
    return key;
}

auto load_ca(const std::string& pem) -> StorePtr {
    StorePtr store{X509_STORE_new()};
    auto bio = mem_bio(pem);
    if (!store || !bio) {
        return nullptr;
    }
    int added = 0;
    for (;;) {
        X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
        if (!cert) {
            break;
        }
        if (X509_STORE_add_cert(store.get(), cert.get()) != 1) {
            return nullptr;
        }
        ++added;
    }
    return added > 0 ? std::move(store) : nullptr;
}

auto make_request(EVP_PKEY* key, const IdentityConfig& c)
    -> std::expected<std::vector<std::byte>, IdentityError> {
    ReqPtr req{X509_REQ_new()};
    if (!req || X509_REQ_set_version(req.get(), 0) != 1 ||
        X509_REQ_set_pubkey(req.get(), key) != 1) {
        return std::unexpected(IdentityError::bad_key);
    }
    X509_NAME* name = X509_REQ_get_subject_name(req.get());
    const auto& cn = c.common_name.empty() ? std::string{"storage"} : c.common_name;
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1,
                                   0) != 1) {
        return std::unexpected(IdentityError::bad_config);
    }
    std::string san = "URI:" + proto::server_uri(c.server_id);
    for (const auto& a : c.addresses) {
        san += ",IP:" + a;
    }
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str());
    ExtStackPtr exts{sk_X509_EXTENSION_new_null()};
    if (ext == nullptr || !exts || sk_X509_EXTENSION_push(exts.get(), ext) == 0) {
        X509_EXTENSION_free(ext);
        return std::unexpected(IdentityError::bad_config);
    }
    if (X509_REQ_add_extensions(req.get(), exts.get()) != 1 ||
        X509_REQ_sign(req.get(), key, EVP_sha256()) <= 0) {
        return std::unexpected(IdentityError::bad_key);
    }
    const int len = i2d_X509_REQ(req.get(), nullptr);
    if (len <= 0) {
        return std::unexpected(IdentityError::bad_key);
    }
    std::vector<std::byte> der(static_cast<std::size_t>(len));
    auto* out = reinterpret_cast<unsigned char*>(der.data());
    if (i2d_X509_REQ(req.get(), &out) != len) {
        return std::unexpected(IdentityError::bad_key);
    }
    return der;
}

auto parse_der_chain(std::span<const std::byte> der) -> std::expected<Chain, IdentityError> {
    Chain chain;
    const auto* p = reinterpret_cast<const unsigned char*>(der.data());
    const auto* const end = p + der.size();
    while (p < end) {
        const long left = end - p;
        X509Ptr cert{d2i_X509(nullptr, &p, left)};
        if (!cert) {
            return std::unexpected(IdentityError::bad_certificate);
        }
        chain.push_back(std::move(cert));
    }
    if (chain.empty()) {
        return std::unexpected(IdentityError::bad_certificate);
    }
    return chain;
}

auto parse_pem_chain(const std::string& pem) -> Chain {
    Chain chain;
    auto bio = mem_bio(pem);
    while (bio) {
        X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
        if (!cert) {
            break;
        }
        chain.push_back(std::move(cert));
    }
    return chain;
}

auto uris_of(X509* cert) -> std::vector<std::string> {
    std::vector<std::string> out;
    NamesPtr names{static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr))};
    if (!names) {
        return out;
    }
    for (int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i) {
        const GENERAL_NAME* n = sk_GENERAL_NAME_value(names.get(), i);
        if (n->type == GEN_URI) {
            const ASN1_IA5STRING* uri = n->d.uniformResourceIdentifier;
            out.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                             static_cast<std::size_t>(ASN1_STRING_length(uri)));
        }
    }
    return out;
}

auto to_time_point(const ASN1_TIME* t) -> std::optional<RoleIdentity::SystemClock::time_point> {
    std::tm tm{};
    if (t == nullptr || ASN1_TIME_to_tm(t, &tm) != 1) {
        return std::nullopt;
    }
    return RoleIdentity::SystemClock::from_time_t(timegm(&tm));
}

}  // namespace

struct IdentityImpl {
    IdentityConfig config;
    PkeyPtr key;
    StorePtr ca;
    std::string key_pem;
    std::vector<std::byte> request;
    Chain chain;  // empty until a certificate passes
    std::string chain_pem;
    std::optional<RoleIdentity::SystemClock::time_point> not_before;
    std::optional<RoleIdentity::SystemClock::time_point> not_after;

    [[nodiscard]] auto check(const Chain& c) const -> std::expected<void, IdentityError> {
        X509* leaf = c.front().get();
        if (X509_check_private_key(leaf, key.get()) != 1) {
            return std::unexpected(IdentityError::wrong_key);
        }
        const auto uris = uris_of(leaf);
        const auto id = proto::server_id_of(uris);
        if (!id || *id != config.server_id) {
            return std::unexpected(IdentityError::wrong_server);
        }
        for (const auto& a : config.addresses) {
            if (X509_check_ip_asc(leaf, a.c_str(), 0) != 1) {
                return std::unexpected(IdentityError::missing_address);
            }
        }
        CertStackPtr untrusted{sk_X509_new_null()};
        if (!untrusted) {
            return std::unexpected(IdentityError::untrusted);
        }
        for (std::size_t i = 1; i < c.size(); ++i) {
            if (sk_X509_push(untrusted.get(), c[i].get()) == 0) {
                return std::unexpected(IdentityError::untrusted);
            }
        }
        StoreCtxPtr ctx{X509_STORE_CTX_new()};
        if (!ctx || X509_STORE_CTX_init(ctx.get(), ca.get(), leaf, untrusted.get()) != 1 ||
            X509_verify_cert(ctx.get()) != 1) {
            return std::unexpected(IdentityError::untrusted);
        }
        return {};
    }

    auto adopt(Chain c) -> void {
        not_before = to_time_point(X509_get0_notBefore(c.front().get()));
        not_after = to_time_point(X509_get0_notAfter(c.front().get()));
        chain_pem = pem_of(c);
        chain = std::move(c);
    }
};

RoleIdentity::RoleIdentity(std::unique_ptr<IdentityImpl> impl) noexcept : _impl{std::move(impl)} {}
RoleIdentity::RoleIdentity(RoleIdentity&&) noexcept = default;
auto RoleIdentity::operator=(RoleIdentity&&) noexcept -> RoleIdentity& = default;
RoleIdentity::~RoleIdentity() = default;

auto RoleIdentity::open(IdentityConfig config) -> std::expected<RoleIdentity, IdentityError> {
    if (config.server_id == 0 || config.key_path.empty() || config.cert_path.empty()) {
        return std::unexpected(IdentityError::bad_config);
    }
    auto impl = std::make_unique<IdentityImpl>();
    impl->ca = load_ca(config.ca_pem);
    if (!impl->ca) {
        return std::unexpected(IdentityError::bad_config);
    }
    auto key = load_key(config.key_path);
    if (!key) {
        return std::unexpected(key.error());
    }
    impl->key = std::move(*key);
    impl->key_pem = key_pem(impl->key.get());
    auto request = make_request(impl->key.get(), config);
    if (!request) {
        return std::unexpected(request.error());
    }
    impl->request = std::move(*request);
    impl->config = std::move(config);
    if (const auto text = read_text(impl->config.cert_path)) {
        auto chain = parse_pem_chain(*text);
        if (!chain.empty() && impl->check(chain)) {
            impl->adopt(std::move(chain));
        }
    }
    return RoleIdentity{std::move(impl)};
}

auto RoleIdentity::ready() const noexcept -> bool {
    return _impl && !_impl->chain.empty();
}

auto RoleIdentity::config(Role role) const -> std::optional<Config> {
    if (!ready()) {
        return std::nullopt;
    }
    return Config{.role = role,
                  .ca_pem = _impl->config.ca_pem,
                  .cert_pem = _impl->chain_pem,
                  .key_pem = _impl->key_pem,
                  .peer_name = {}};
}

auto RoleIdentity::request(SystemClock::time_point now) const -> std::span<const std::byte> {
    if (!_impl) {
        return {};
    }
    if (ready() && _impl->not_before && _impl->not_after) {
        const auto renew_at = *_impl->not_after - ((*_impl->not_after - *_impl->not_before) / 3);
        if (now < renew_at) {
            return {};
        }
    }
    return _impl->request;
}

auto RoleIdentity::install(std::span<const std::byte> chain) -> std::expected<void, IdentityError> {
    auto parsed = parse_der_chain(chain);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (auto ok = _impl->check(*parsed); !ok) {
        return std::unexpected(ok.error());
    }
    const auto pem = pem_of(*parsed);
    if (pem.empty() ||
        !write_atomic(_impl->config.cert_path, pem, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) {
        return std::unexpected(IdentityError::io);
    }
    _impl->adopt(std::move(*parsed));
    return {};
}

auto RoleIdentity::not_after() const -> std::optional<SystemClock::time_point> {
    return ready() ? _impl->not_after : std::nullopt;
}

}  // namespace ak::tls
