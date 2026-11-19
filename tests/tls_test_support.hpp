// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Throwaway PKI for TLS tests: a CA and leaf certificates (ECDSA P-256)
// generated in memory, so no key or certificate is committed.

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace ak::test {

struct Pem {
    std::string cert;
    std::string key;
};

namespace detail {

struct PkeyFree {
    auto operator()(EVP_PKEY* p) const noexcept -> void { EVP_PKEY_free(p); }
};
struct X509Free {
    auto operator()(X509* p) const noexcept -> void { X509_free(p); }
};
struct BioFree {
    auto operator()(BIO* p) const noexcept -> void { BIO_free(p); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using BioPtr = std::unique_ptr<BIO, BioFree>;

inline auto require(bool ok, const char* what) -> void {
    if (!ok) {
        throw std::runtime_error(what);
    }
}

inline auto bio_string(BIO* bio) -> std::string {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    return {data, static_cast<std::size_t>(len)};
}

inline auto to_pem(X509* cert) -> std::string {
    BioPtr bio{BIO_new(BIO_s_mem())};
    require(PEM_write_bio_X509(bio.get(), cert) == 1, "PEM_write_bio_X509");
    return bio_string(bio.get());
}

inline auto to_pem(EVP_PKEY* key) -> std::string {
    BioPtr bio{BIO_new(BIO_s_mem())};
    require(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
            "PEM_write_bio_PrivateKey");
    return bio_string(bio.get());
}

inline auto add_ext(X509* cert, X509* issuer, int nid, const char* value) -> void {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    require(ext != nullptr, "X509V3_EXT_conf_nid");
    require(X509_add_ext(cert, ext, -1) == 1, "X509_add_ext");
    X509_EXTENSION_free(ext);
}

inline auto make_cert(const std::string& cn, EVP_PKEY* key, X509* issuer, long serial) -> X509Ptr {
    X509Ptr cert{X509_new()};
    require(cert != nullptr, "X509_new");
    require(X509_set_version(cert.get(), 2) == 1, "X509_set_version");
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    require(X509_set_pubkey(cert.get(), key) == 1, "X509_set_pubkey");
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509* signer = issuer != nullptr ? issuer : cert.get();
    require(X509_set_issuer_name(cert.get(), X509_get_subject_name(signer)) == 1,
            "X509_set_issuer_name");
    return cert;
}

}  // namespace detail

class TestCa {
public:
    explicit TestCa(const std::string& cn) {
        _key = detail::PkeyPtr{EVP_EC_gen("P-256")};
        detail::require(_key != nullptr, "EVP_EC_gen");
        _cert = detail::make_cert(cn, _key.get(), nullptr, 1);
        detail::add_ext(_cert.get(), _cert.get(), NID_basic_constraints, "critical,CA:TRUE");
        detail::add_ext(_cert.get(), _cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
        detail::add_ext(_cert.get(), _cert.get(), NID_subject_key_identifier, "hash");
        detail::require(X509_sign(_cert.get(), _key.get(), EVP_sha256()) > 0, "X509_sign");
    }

    [[nodiscard]] auto cert_pem() const -> std::string { return detail::to_pem(_cert.get()); }

    // A leaf for `cn` with subjectAltName `san` (e.g. "DNS:controller" or
    // "IP:127.0.0.1"), usable for both TLS client and server auth.
    [[nodiscard]] auto issue(const std::string& cn, const std::string& san) -> Pem {
        detail::PkeyPtr key{EVP_EC_gen("P-256")};
        detail::require(key != nullptr, "EVP_EC_gen");
        auto cert = detail::make_cert(cn, key.get(), _cert.get(), ++_serial);
        detail::add_ext(cert.get(), _cert.get(), NID_basic_constraints, "critical,CA:FALSE");
        detail::add_ext(cert.get(), _cert.get(), NID_key_usage, "critical,digitalSignature");
        detail::add_ext(cert.get(), _cert.get(), NID_ext_key_usage, "serverAuth,clientAuth");
        detail::add_ext(cert.get(), _cert.get(), NID_subject_alt_name, san.c_str());
        detail::require(X509_sign(cert.get(), _key.get(), EVP_sha256()) > 0, "X509_sign");
        return {.cert = detail::to_pem(cert.get()), .key = detail::to_pem(key.get())};
    }

private:
    detail::PkeyPtr _key;
    detail::X509Ptr _cert;
    long _serial{1};
};

}  // namespace ak::test
