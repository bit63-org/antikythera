// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "objstore/s3_object_store.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "objstore/http_response.hpp"

namespace ak::objstore {

namespace {

constexpr std::uint16_t http_port = 80;
constexpr std::uint16_t https_port = 443;
constexpr unsigned status_ok = 200;
constexpr unsigned status_partial = 206;
constexpr unsigned status_unauthorized = 401;
constexpr unsigned status_forbidden = 403;
constexpr unsigned status_not_found = 404;
constexpr unsigned status_range_not_satisfiable = 416;
constexpr unsigned status_too_many = 429;
constexpr unsigned status_server_error = 500;
constexpr std::size_t read_chunk = 64U * 1024U;

auto remaining_ms(ObjectStore::Clock::time_point deadline) -> int {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - ObjectStore::Clock::now());
    constexpr std::int64_t max_ms = 1'000'000;
    return static_cast<int>(std::clamp<std::int64_t>(left.count(), 0, max_ms));
}

// Waits for `events` on fd; false on timeout or error.
auto wait_fd(int fd, short events, ObjectStore::Clock::time_point deadline)
    -> std::expected<void, FetchError> {
    while (true) {
        const int ms = remaining_ms(deadline);
        if (ms == 0) {
            return std::unexpected(FetchError::timed_out);
        }
        pollfd p{.fd = fd, .events = events, .revents = 0};
        const int rc = ::poll(&p, 1, ms);
        if (rc > 0) {
            return {};
        }
        if (rc == 0) {
            return std::unexpected(FetchError::timed_out);
        }
        if (errno != EINTR) {
            return std::unexpected(FetchError::io);
        }
    }
}

auto is_ip_literal(const std::string& host) -> bool {
    std::array<unsigned char, sizeof(in6_addr)> buf{};
    return ::inet_pton(AF_INET, host.c_str(), buf.data()) == 1 ||
           ::inet_pton(AF_INET6, host.c_str(), buf.data()) == 1;
}

// Lowercase letters, digits, hyphens and dots: safe as a DNS name.
auto dns_safe(std::string_view s) -> bool {
    return !s.empty() && std::ranges::all_of(s, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
    });
}

}  // namespace

struct S3ObjectStore::TlsContext {
    SSL_CTX* ctx{nullptr};
    TlsContext() = default;
    TlsContext(const TlsContext&) = delete;
    auto operator=(const TlsContext&) -> TlsContext& = delete;
    TlsContext(TlsContext&&) = delete;
    auto operator=(TlsContext&&) -> TlsContext& = delete;
    ~TlsContext() { SSL_CTX_free(ctx); }
};

class S3ObjectStore::Connection {
public:
    Connection(int fd, SSL* ssl) noexcept : _fd{fd}, _ssl{ssl} {}
    Connection(const Connection&) = delete;
    auto operator=(const Connection&) -> Connection& = delete;
    Connection(Connection&&) = delete;
    auto operator=(Connection&&) -> Connection& = delete;
    ~Connection() {
        if (_ssl != nullptr) {
            SSL_free(_ssl);
        }
        ::close(_fd);
    }

    [[nodiscard]] auto write_all(std::string_view data, Clock::time_point deadline)
        -> std::expected<void, FetchError> {
        std::size_t done = 0;
        while (done < data.size()) {
            const auto n = send(data.substr(done));
            if (n > 0) {
                done += static_cast<std::size_t>(n);
                continue;
            }
            if (n == 0) {
                return std::unexpected(FetchError::io);
            }
            if (auto w = wait_fd(_fd, _want, deadline); !w) {
                return w;
            }
        }
        return {};
    }

    // Bytes read; 0 when the peer closed.
    [[nodiscard]] auto read_some(std::span<std::byte> out, Clock::time_point deadline)
        -> std::expected<std::size_t, FetchError> {
        while (true) {
            const auto n = recv(out);
            if (n >= 0) {
                return static_cast<std::size_t>(n);
            }
            if (n == -2) {
                return std::unexpected(FetchError::io);
            }
            if (auto w = wait_fd(_fd, _want, deadline); !w) {
                return std::unexpected(w.error());
            }
        }
    }

private:
    // > 0 bytes sent, 0 failure, -1 would block (sets _want).
    auto send(std::string_view data) -> std::int64_t {
        if (_ssl == nullptr) {
            const ssize_t n = ::send(_fd, data.data(), data.size(), MSG_NOSIGNAL);
            if (n >= 0) {
                return n;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                _want = POLLOUT;
                return -1;
            }
            return 0;
        }
        std::size_t written = 0;
        if (SSL_write_ex(_ssl, data.data(), data.size(), &written) == 1) {
            return static_cast<std::int64_t>(written);
        }
        return ssl_retry(SSL_get_error(_ssl, 0)) ? -1 : 0;
    }

    // >= 0 bytes read (0 = closed), -1 would block (sets _want), -2 failure.
    auto recv(std::span<std::byte> out) -> std::int64_t {
        if (_ssl == nullptr) {
            const ssize_t n = ::recv(_fd, out.data(), out.size(), 0);
            if (n >= 0) {
                return n;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                _want = POLLIN;
                return -1;
            }
            return -2;
        }
        std::size_t got = 0;
        if (SSL_read_ex(_ssl, out.data(), out.size(), &got) == 1) {
            return static_cast<std::int64_t>(got);
        }
        const int err = SSL_get_error(_ssl, 0);
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        return ssl_retry(err) ? -1 : -2;
    }

    auto ssl_retry(int err) -> bool {
        if (err == SSL_ERROR_WANT_READ) {
            _want = POLLIN;
            return true;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            _want = POLLOUT;
            return true;
        }
        ERR_clear_error();
        return false;
    }

    int _fd;
    SSL* _ssl;
    short _want{POLLIN};
};

auto to_string(S3ConfigError e) noexcept -> const char* {
    switch (e) {
        case S3ConfigError::no_host:
            return "no_host";
        case S3ConfigError::no_bucket:
            return "no_bucket";
        case S3ConfigError::bad_ca_file:
            return "bad_ca_file";
        case S3ConfigError::tls_failure:
            return "tls_failure";
    }
    return "unknown";
}

S3ObjectStore::S3ObjectStore(S3Config config, std::unique_ptr<TlsContext> tls)
    : _config{std::move(config)}, _tls{std::move(tls)} {
    if (_config.port == 0) {
        _config.port = _config.tls ? https_port : http_port;
    }
    if (!_config.clock) {
        _config.clock = [] { return std::chrono::system_clock::now(); };
    }
    std::string host = _config.path_style ? _config.host : _config.bucket + "." + _config.host;
    if (host.find(':') != std::string::npos) {
        host = "[" + host + "]";  // IPv6 literal
    }
    const bool default_port = _config.port == (_config.tls ? https_port : http_port);
    _host_header = default_port ? host : host + ":" + std::to_string(_config.port);
}

S3ObjectStore::~S3ObjectStore() = default;

auto S3ObjectStore::create(S3Config config)
    -> std::expected<std::unique_ptr<S3ObjectStore>, S3ConfigError> {
    if (config.host.empty()) {
        return std::unexpected(S3ConfigError::no_host);
    }
    if (config.bucket.empty() || (!config.path_style && !dns_safe(config.bucket))) {
        return std::unexpected(S3ConfigError::no_bucket);
    }
    std::unique_ptr<TlsContext> tls;
    if (config.tls) {
        tls = std::make_unique<TlsContext>();
        tls->ctx = SSL_CTX_new(TLS_client_method());
        if (tls->ctx == nullptr || SSL_CTX_set_min_proto_version(tls->ctx, TLS1_2_VERSION) != 1) {
            return std::unexpected(S3ConfigError::tls_failure);
        }
        SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER, nullptr);
        const int loaded = config.ca_file.empty() ? SSL_CTX_set_default_verify_paths(tls->ctx)
                                                  : SSL_CTX_load_verify_locations(
                                                        tls->ctx, config.ca_file.c_str(), nullptr);
        if (loaded != 1) {
            ERR_clear_error();
            return std::unexpected(S3ConfigError::bad_ca_file);
        }
    }
    return std::unique_ptr<S3ObjectStore>(new S3ObjectStore(std::move(config), std::move(tls)));
}

auto S3ObjectStore::counters() const -> S3Counters {
    const std::scoped_lock lock{_mutex};
    return _counters;
}

auto S3ObjectStore::get_range(std::string_view key, std::uint64_t offset, std::span<std::byte> out,
                              Clock::time_point deadline) -> std::expected<void, FetchError> {
    if (out.empty()) {
        return {};
    }
    return request(key, Range{.offset = offset, .length = out.size()},
                   Sink{.fixed = out, .grow = nullptr, .max = 0}, deadline);
}

auto S3ObjectStore::get(std::string_view key, std::size_t max_bytes, Clock::time_point deadline)
    -> std::expected<std::vector<std::byte>, FetchError> {
    std::vector<std::byte> out;
    if (auto r =
            request(key, std::nullopt, Sink{.fixed = {}, .grow = &out, .max = max_bytes}, deadline);
        !r) {
        return std::unexpected(r.error());
    }
    return out;
}

auto S3ObjectStore::build_request(std::string_view key, std::optional<Range> range) const
    -> std::expected<std::string, FetchError> {
    std::string path = "/";
    if (_config.path_style) {
        path.append(_config.bucket).append("/");
    }
    path.append(key);
    const std::string uri = s3_uri_encode_path(path);
    const std::string date = amz_date(_config.clock());
    std::vector<std::pair<std::string, std::string>> headers{
        {"host", _host_header},
        {"x-amz-content-sha256", std::string{empty_payload_sha256}},
        {"x-amz-date", date},
    };
    if (range) {
        headers.emplace_back("range", "bytes=" + std::to_string(range->offset) + "-" +
                                          std::to_string(range->offset + range->length - 1));
    }
    if (_config.credentials && !_config.credentials->session_token.empty()) {
        headers.emplace_back("x-amz-security-token", _config.credentials->session_token);
    }
    std::string text = "GET " + uri + " HTTP/1.1\r\n";
    for (const auto& [name, value] : headers) {
        text.append(name).append(": ").append(value).append("\r\n");
    }
    if (_config.credentials) {
        const auto auth = sigv4_authorization({.method = "GET",
                                               .canonical_uri = uri,
                                               .headers = headers,
                                               .payload_hash = empty_payload_sha256,
                                               .amz_date = date,
                                               .region = _config.region},
                                              *_config.credentials);
        if (!auth) {
            return std::unexpected(FetchError::io);
        }
        text.append("authorization: ").append(*auth).append("\r\n");
    }
    text.append("\r\n");
    return text;
}

auto S3ObjectStore::request(std::string_view key, std::optional<Range> range, Sink sink,
                            Clock::time_point deadline) -> std::expected<void, FetchError> {
    const auto text = build_request(key, range);
    if (!text) {
        return std::unexpected(text.error());
    }
    {
        const std::scoped_lock lock{_mutex};
        ++_counters.requests;
    }
    // A pooled connection may have been closed by the server while idle;
    // if it fails before any response byte, try once more on a new one.
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool pooled = false;
        auto c = take_connection(deadline, pooled);
        if (!c) {
            return std::unexpected(c.error());
        }
        bool reusable = false;
        bool got_any = false;
        auto r = exchange(**c, *text, range, sink, deadline, reusable, got_any);
        if (r || !pooled || got_any || r.error() != FetchError::io) {
            if (reusable) {
                give_back(std::move(*c));
            }
            return r;
        }
        const std::scoped_lock lock{_mutex};
        ++_counters.stale;
    }
    return std::unexpected(FetchError::io);
}

auto S3ObjectStore::exchange(Connection& c, const std::string& text, std::optional<Range> range,
                             Sink sink, Clock::time_point deadline, bool& reusable, bool& got_any)
    -> std::expected<void, FetchError> {
    if (auto w = c.write_all(text, deadline); !w) {
        return w;
    }
    std::vector<std::byte> buf(read_chunk);
    std::size_t have = 0;
    std::expected<ResponseHead, HttpError> head = std::unexpected(HttpError::incomplete);
    while (true) {
        if (have == buf.size()) {
            if (buf.size() >= max_response_head + read_chunk) {
                return std::unexpected(FetchError::bad_response);
            }
            buf.resize(buf.size() + read_chunk);
        }
        const auto n = c.read_some(std::span{buf}.subspan(have), deadline);
        if (!n) {
            return std::unexpected(n.error());
        }
        if (*n == 0) {
            return std::unexpected(got_any ? FetchError::bad_response : FetchError::io);
        }
        got_any = true;
        have += *n;
        head = parse_response_head(std::span{buf}.first(have));
        if (head || head.error() != HttpError::incomplete) {
            break;
        }
    }
    if (!head) {
        return std::unexpected(FetchError::bad_response);
    }
    const unsigned status = head->status;
    if (status == status_not_found || status == status_range_not_satisfiable) {
        return std::unexpected(FetchError::not_found);
    }
    if (status == status_unauthorized || status == status_forbidden) {
        return std::unexpected(FetchError::denied);
    }
    if (status == status_too_many || status >= status_server_error) {
        return std::unexpected(FetchError::io);
    }
    if (!head->content_length) {
        return std::unexpected(FetchError::bad_response);
    }
    const std::uint64_t length = *head->content_length;
    std::span<std::byte> target;
    if (range) {
        const bool exact_206 = status == status_partial && head->content_range &&
                               head->content_range->first == range->offset &&
                               head->content_range->last == range->offset + range->length - 1 &&
                               length == range->length;
        const bool whole_200 = status == status_ok && range->offset == 0 &&
                               length == range->length && !head->content_range;
        if (!exact_206 && !whole_200) {
            return std::unexpected(FetchError::bad_response);
        }
        target = sink.fixed;
    } else {
        if (status != status_ok || head->content_range) {
            return std::unexpected(FetchError::bad_response);
        }
        if (length > sink.max) {
            return std::unexpected(FetchError::too_large);
        }
        sink.grow->resize(length);
        target = *sink.grow;
    }
    // The body: what came with the head, then the rest.
    const std::size_t extra = have - head->head_bytes;
    if (extra > target.size()) {
        return std::unexpected(FetchError::bad_response);  // more than declared
    }
    std::copy_n(buf.begin() + static_cast<std::ptrdiff_t>(head->head_bytes), extra, target.begin());
    std::size_t done = extra;
    while (done < target.size()) {
        const auto n = c.read_some(target.subspan(done), deadline);
        if (!n) {
            return std::unexpected(n.error());
        }
        if (*n == 0) {
            return std::unexpected(FetchError::bad_response);  // short body
        }
        done += *n;
    }
    reusable = !head->close;
    return {};
}

auto S3ObjectStore::take_connection(Clock::time_point deadline, bool& pooled)
    -> std::expected<std::unique_ptr<Connection>, FetchError> {
    {
        const std::scoped_lock lock{_mutex};
        if (!_idle.empty()) {
            auto c = std::move(_idle.back());
            _idle.pop_back();
            ++_counters.reused;
            pooled = true;
            return c;
        }
        ++_counters.connections;
    }
    pooled = false;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string port = std::to_string(_config.port);
    if (::getaddrinfo(_config.host.c_str(), port.c_str(), &hints, &res) != 0 || res == nullptr) {
        return std::unexpected(FetchError::io);
    }
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addrs{res, ::freeaddrinfo};
    int fd = -1;
    FetchError last = FetchError::io;
    for (addrinfo* a = res; a != nullptr && fd < 0; a = a->ai_next) {
        fd = ::socket(a->ai_family, a->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) {
            break;
        }
        if (errno == EINPROGRESS) {
            if (auto w = wait_fd(fd, POLLOUT, deadline); w) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    break;
                }
            } else {
                last = w.error();
            }
        }
        ::close(fd);
        fd = -1;
    }
    if (fd < 0) {
        return std::unexpected(last);
    }
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (!_tls) {
        return std::make_unique<Connection>(fd, nullptr);
    }
    SSL* ssl = SSL_new(_tls->ctx);
    if (ssl == nullptr) {
        ::close(fd);
        return std::unexpected(FetchError::io);
    }
    auto conn = std::make_unique<Connection>(fd, ssl);
    const std::string& host = _config.path_style ? _config.host : _host_header;
    bool named = SSL_set_fd(ssl, fd) == 1;
    if (is_ip_literal(_config.host)) {
        named =
            named && X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), _config.host.c_str()) == 1;
    } else {
        const std::string sni = _config.path_style ? host : _config.bucket + "." + _config.host;
        // SSL_set_tlsext_host_name, without the macro's C cast.
        std::string sni_arg = sni;
        named = named &&
                SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
                         sni_arg.data()) == 1 &&
                SSL_set1_host(ssl, sni.c_str()) == 1;
    }
    if (!named) {
        ERR_clear_error();
        return std::unexpected(FetchError::io);
    }
    while (true) {
        const int rc = SSL_connect(ssl);
        if (rc == 1) {
            return conn;
        }
        const int err = SSL_get_error(ssl, rc);
        short want = 0;
        if (err == SSL_ERROR_WANT_READ) {
            want = POLLIN;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            want = POLLOUT;
        } else {
            ERR_clear_error();
            return std::unexpected(FetchError::denied);  // the server failed verification
        }
        if (auto w = wait_fd(fd, want, deadline); !w) {
            return std::unexpected(w.error());
        }
    }
}

auto S3ObjectStore::give_back(std::unique_ptr<Connection> c) -> void {
    const std::scoped_lock lock{_mutex};
    if (_idle.size() < _config.max_idle_connections) {
        _idle.push_back(std::move(c));
    }
}

}  // namespace ak::objstore
