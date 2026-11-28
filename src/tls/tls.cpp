// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "tls/tls.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <ctime>
#include <functional>
#include <optional>
#include <utility>

namespace ak::tls {

namespace {

struct SslCtxFree {
    auto operator()(SSL_CTX* p) const noexcept -> void { SSL_CTX_free(p); }
};
struct SslFree {
    auto operator()(SSL* p) const noexcept -> void { SSL_free(p); }
};
struct BioFree {
    auto operator()(BIO* p) const noexcept -> void { BIO_free(p); }
};
struct X509Free {
    auto operator()(X509* p) const noexcept -> void { X509_free(p); }
};
struct PkeyFree {
    auto operator()(EVP_PKEY* p) const noexcept -> void { EVP_PKEY_free(p); }
};
struct AddrinfoFree {
    auto operator()(addrinfo* p) const noexcept -> void { freeaddrinfo(p); }
};

using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxFree>;
using SslPtr = std::unique_ptr<SSL, SslFree>;
using BioPtr = std::unique_ptr<BIO, BioFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;
using AddrinfoPtr = std::unique_ptr<addrinfo, AddrinfoFree>;

auto mem_bio(const std::string& pem) -> BioPtr {
    if (pem.size() > static_cast<std::size_t>(INT_MAX)) {
        return nullptr;
    }
    return BioPtr{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
}

auto is_ip_literal(const std::string& name) -> bool {
    in6_addr v6{};
    in_addr v4{};
    return inet_pton(AF_INET6, name.c_str(), &v6) == 1 ||
           inet_pton(AF_INET, name.c_str(), &v4) == 1;
}

// Pins the peer's name in the verification parameters, so the handshake
// fails on a mismatch rather than leaving the check to the caller.
auto pin_peer_name(X509_VERIFY_PARAM* param, const std::string& name) -> bool {
    if (name.empty()) {
        return true;
    }
    if (is_ip_literal(name)) {
        return X509_VERIFY_PARAM_set1_ip_asc(param, name.c_str()) == 1;
    }
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    return X509_VERIFY_PARAM_set1_host(param, name.c_str(), name.size()) == 1;
}

auto load_ca(SSL_CTX* ctx, const std::string& pem) -> bool {
    auto bio = mem_bio(pem);
    if (!bio) {
        return false;
    }
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    int loaded = 0;
    while (X509Ptr cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)}) {
        if (X509_STORE_add_cert(store, cert.get()) != 1) {
            return false;
        }
        ++loaded;
    }
    ERR_clear_error();  // the loop ends on a "no start line" error
    return loaded > 0;
}

auto load_identity(SSL_CTX* ctx, const std::string& cert_pem, const std::string& key_pem) -> bool {
    auto cert_bio = mem_bio(cert_pem);
    auto key_bio = mem_bio(key_pem);
    if (!cert_bio || !key_bio) {
        return false;
    }
    X509Ptr leaf{PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr)};
    PkeyPtr key{PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr)};
    if (!leaf || !key || SSL_CTX_use_certificate(ctx, leaf.get()) != 1) {
        return false;
    }
    // Any intermediates follow the leaf in cert_pem.
    while (X509Ptr extra{PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr)}) {
        if (SSL_CTX_add0_chain_cert(ctx, extra.get()) != 1) {
            return false;
        }
        (void)extra.release();  // add0: the context owns it now
    }
    ERR_clear_error();
    return SSL_CTX_use_PrivateKey(ctx, key.get()) == 1 && SSL_CTX_check_private_key(ctx) == 1;
}

auto set_nonblocking(int fd) -> bool {
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

auto millis_until(Clock::time_point deadline) -> int {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
    return static_cast<int>(std::clamp<std::chrono::milliseconds::rep>(left.count(), 0, INT_MAX));
}

// Waits for `events` on fd until the deadline; false on timeout or error.
auto wait_fd(int fd, short events, Clock::time_point deadline) -> bool {
    for (;;) {
        pollfd p{.fd = fd, .events = events, .revents = 0};
        const int n = poll(&p, 1, millis_until(deadline));
        if (n > 0) {
            return true;
        }
        if (n == 0 || errno != EINTR) {
            return false;
        }
    }
}

auto close_fd(int fd) noexcept -> void {
    if (fd >= 0) {
        (void)::close(fd);
    }
}

}  // namespace

auto to_string(Error e) noexcept -> const char* {
    switch (e) {
        case Error::bad_config:
            return "bad_config";
        case Error::resolve_failed:
            return "resolve_failed";
        case Error::connect_failed:
            return "connect_failed";
        case Error::handshake_failed:
            return "handshake_failed";
        case Error::timed_out:
            return "timed_out";
        case Error::closed:
            return "closed";
        case Error::io:
            return "io";
    }
    return "unknown";
}

struct ContextImpl {
    SslCtxPtr ctx;
    Role role{Role::client};
    std::string peer_name;
    std::function<std::optional<std::int64_t>()> verification_time;
};

struct StreamImpl {
    SslPtr ssl;
    int fd{-1};

    StreamImpl() = default;
    StreamImpl(const StreamImpl&) = delete;
    auto operator=(const StreamImpl&) -> StreamImpl& = delete;
    StreamImpl(StreamImpl&&) = delete;
    auto operator=(StreamImpl&&) -> StreamImpl& = delete;
    ~StreamImpl() {
        ssl.reset();
        close_fd(fd);
    }
};

// ---- Context --------------------------------------------------------------

Context::Context(std::unique_ptr<ContextImpl> impl) noexcept : _impl{std::move(impl)} {}
Context::Context(Context&&) noexcept = default;
auto Context::operator=(Context&&) noexcept -> Context& = default;
Context::~Context() = default;

auto Context::role() const noexcept -> Role {
    return _impl->role;
}

auto Context::create(const Config& config) -> std::expected<Context, Error> {
    if (config.role == Role::client && config.peer_name.empty()) {
        return std::unexpected(Error::bad_config);
    }
    SslCtxPtr ctx{
        SSL_CTX_new(config.role == Role::client ? TLS_client_method() : TLS_server_method())};
    if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
        !load_ca(ctx.get(), config.ca_pem) ||
        !load_identity(ctx.get(), config.cert_pem, config.key_pem)) {
        ERR_clear_error();
        return std::unexpected(Error::bad_config);
    }
    // Both roles verify the peer, and a server refuses a client without a
    // certificate (mutual authentication).
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    // Partial writes let write_all resume after WANT_WRITE on a
    // non-blocking socket without re-presenting the same buffer address.
    SSL_CTX_set_mode(ctx.get(),
                     SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    // No session resumption: every connection re-authenticates both sides.
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx.get(), 0);
    if (!pin_peer_name(SSL_CTX_get0_param(ctx.get()), config.peer_name)) {
        return std::unexpected(Error::bad_config);
    }
    auto impl = std::make_unique<ContextImpl>();
    impl->ctx = std::move(ctx);
    impl->role = config.role;
    impl->peer_name = config.peer_name;
    impl->verification_time = config.verification_time;
    return Context{std::move(impl)};
}

// ---- Stream ---------------------------------------------------------------

Stream::Stream(std::unique_ptr<StreamImpl> impl) noexcept : _impl{std::move(impl)} {}
Stream::Stream(Stream&&) noexcept = default;
auto Stream::operator=(Stream&&) noexcept -> Stream& = default;
Stream::~Stream() {
    close();
}

namespace {

auto handshake(const Context& ctx, int fd, Clock::time_point deadline)
    -> std::expected<std::unique_ptr<StreamImpl>, Error> {
    auto impl = std::make_unique<StreamImpl>();
    impl->fd = fd;
    impl->ssl = SslPtr{SSL_new(ctx.impl().ctx.get())};
    if (!impl->ssl || SSL_set_fd(impl->ssl.get(), fd) != 1) {
        ERR_clear_error();
        return std::unexpected(Error::io);
    }
    if (ctx.impl().verification_time) {
        if (const auto t = ctx.impl().verification_time()) {
            X509_VERIFY_PARAM_set_time(SSL_get0_param(impl->ssl.get()), static_cast<time_t>(*t));
        }
    }
    const bool client = ctx.role() == Role::client;
    if (client && !is_ip_literal(ctx.impl().peer_name) &&
        // SSL_set_tlsext_host_name, minus the macro's C-style cast.
        SSL_ctrl(impl->ssl.get(), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                 const_cast<char*>(ctx.impl().peer_name.c_str())) != 1) {
        ERR_clear_error();
        return std::unexpected(Error::io);
    }
    for (;;) {
        const int rc = client ? SSL_connect(impl->ssl.get()) : SSL_accept(impl->ssl.get());
        if (rc == 1) {
            break;
        }
        const int err = SSL_get_error(impl->ssl.get(), rc);
        ERR_clear_error();
        short events = 0;
        if (err == SSL_ERROR_WANT_READ) {
            events = POLLIN;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            events = POLLOUT;
        } else {
            return std::unexpected(Error::handshake_failed);
        }
        if (!wait_fd(fd, events, deadline)) {
            return std::unexpected(Error::timed_out);
        }
    }
    // Belt and braces: SSL_VERIFY_PEER already failed the handshake on a
    // bad chain or name, but never proceed without a verified peer cert.
    X509Ptr peer{SSL_get1_peer_certificate(impl->ssl.get())};
    if (!peer || SSL_get_verify_result(impl->ssl.get()) != X509_V_OK) {
        return std::unexpected(Error::handshake_failed);
    }
    return impl;
}

}  // namespace

auto Stream::connect(const Context& ctx, const std::string& host, std::uint16_t port,
                     Clock::time_point deadline) -> std::expected<Stream, Error> {
    if (ctx.role() != Role::client) {
        return std::unexpected(Error::bad_config);
    }
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* raw = nullptr;
    const auto service = std::to_string(port);
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &raw) != 0) {
        return std::unexpected(Error::resolve_failed);
    }
    AddrinfoPtr list{raw};
    for (const addrinfo* ai = list.get(); ai != nullptr; ai = ai->ai_next) {
        const int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (!set_nonblocking(fd)) {
            close_fd(fd);
            continue;
        }
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            if (errno != EINPROGRESS || !wait_fd(fd, POLLOUT, deadline)) {
                close_fd(fd);
                continue;
            }
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0 || so_error != 0) {
                close_fd(fd);
                continue;
            }
        }
        const int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        auto impl = handshake(ctx, fd, deadline);  // owns fd from here
        if (!impl) {
            return std::unexpected(impl.error());
        }
        return Stream{std::move(*impl)};
    }
    return std::unexpected(Error::connect_failed);
}

auto Stream::accept(const Context& ctx, int fd, Clock::time_point deadline)
    -> std::expected<Stream, Error> {
    if (ctx.role() != Role::server || !set_nonblocking(fd)) {
        close_fd(fd);
        return std::unexpected(Error::bad_config);
    }
    auto impl = handshake(ctx, fd, deadline);
    if (!impl) {
        return std::unexpected(impl.error());
    }
    return Stream{std::move(*impl)};
}

auto Stream::fd() const noexcept -> int {
    return _impl ? _impl->fd : -1;
}

auto Stream::pending() const noexcept -> bool {
    return _impl && _impl->ssl && SSL_pending(_impl->ssl.get()) > 0;
}

auto Stream::peer_uris() const -> std::vector<std::string> {
    std::vector<std::string> out;
    if (!_impl || !_impl->ssl) {
        return out;
    }
    X509* cert = SSL_get0_peer_certificate(_impl->ssl.get());
    if (cert == nullptr) {
        return out;
    }
    auto* names =
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names == nullptr) {
        return out;
    }
    for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        const GENERAL_NAME* n = sk_GENERAL_NAME_value(names, i);
        if (n->type == GEN_URI) {
            const ASN1_IA5STRING* uri = n->d.uniformResourceIdentifier;
            out.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                             static_cast<std::size_t>(ASN1_STRING_length(uri)));
        }
    }
    GENERAL_NAMES_free(names);
    return out;
}

auto Stream::read_some(std::span<std::byte> out) -> std::expected<std::size_t, Error> {
    if (!_impl || !_impl->ssl) {
        return std::unexpected(Error::closed);
    }
    std::size_t got = 0;
    const int rc = SSL_read_ex(_impl->ssl.get(), out.data(), out.size(), &got);
    if (rc == 1) {
        return got;
    }
    const int err = SSL_get_error(_impl->ssl.get(), rc);
    ERR_clear_error();
    switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return std::size_t{0};
        case SSL_ERROR_ZERO_RETURN:
            return std::unexpected(Error::closed);
        default:
            return std::unexpected(Error::io);
    }
}

auto Stream::write_all(std::span<const std::byte> bytes, Clock::time_point deadline)
    -> std::expected<void, Error> {
    if (!_impl || !_impl->ssl) {
        return std::unexpected(Error::closed);
    }
    while (!bytes.empty()) {
        std::size_t wrote = 0;
        const int rc = SSL_write_ex(_impl->ssl.get(), bytes.data(), bytes.size(), &wrote);
        if (rc == 1) {
            bytes = bytes.subspan(wrote);
            continue;
        }
        const int err = SSL_get_error(_impl->ssl.get(), rc);
        ERR_clear_error();
        short events = 0;
        if (err == SSL_ERROR_WANT_WRITE) {
            events = POLLOUT;
        } else if (err == SSL_ERROR_WANT_READ) {
            events = POLLIN;
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return std::unexpected(Error::closed);
        } else {
            return std::unexpected(Error::io);
        }
        if (!wait_fd(_impl->fd, events, deadline)) {
            return std::unexpected(Error::timed_out);
        }
    }
    return {};
}

auto Stream::close() noexcept -> void {
    if (_impl && _impl->ssl) {
        (void)SSL_shutdown(_impl->ssl.get());  // best effort, non-blocking
        ERR_clear_error();
    }
    _impl.reset();
}

// ---- Listener -------------------------------------------------------------

Listener::Listener(Listener&& other) noexcept
    : _fd{std::exchange(other._fd, -1)}, _port{other._port} {}

auto Listener::operator=(Listener&& other) noexcept -> Listener& {
    if (this != &other) {
        close_fd(_fd);
        _fd = std::exchange(other._fd, -1);
        _port = other._port;
    }
    return *this;
}

Listener::~Listener() {
    close_fd(_fd);
}

auto Listener::bind(const std::string& host, std::uint16_t port) -> std::expected<Listener, Error> {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    addrinfo* raw = nullptr;
    const auto service = std::to_string(port);
    if (getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &raw) != 0) {
        return std::unexpected(Error::resolve_failed);
    }
    AddrinfoPtr list{raw};
    for (const addrinfo* ai = list.get(); ai != nullptr; ai = ai->ai_next) {
        const int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        const int one = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (::bind(fd, ai->ai_addr, ai->ai_addrlen) != 0 || listen(fd, SOMAXCONN) != 0 ||
            !set_nonblocking(fd)) {
            close_fd(fd);
            continue;
        }
        sockaddr_storage bound{};
        socklen_t len = sizeof(bound);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &len) != 0) {
            close_fd(fd);
            continue;
        }
        std::uint16_t actual = 0;
        if (bound.ss_family == AF_INET6) {
            actual = ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port);
        } else {
            actual = ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);
        }
        return Listener{fd, actual};
    }
    return std::unexpected(Error::connect_failed);
}

auto Listener::accept_fd(Clock::time_point deadline) -> std::expected<int, Error> {
    for (;;) {
        const int fd = ::accept4(_fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd >= 0) {
            return fd;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return std::unexpected(Error::io);
        }
        if (!wait_fd(_fd, POLLIN, deadline)) {
            return std::unexpected(Error::timed_out);
        }
    }
}

}  // namespace ak::tls
