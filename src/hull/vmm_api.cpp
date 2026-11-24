// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/vmm_api.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <optional>

#include "hull/json.hpp"

namespace ak::hull {

namespace {

auto fail(VmmApiError e, int err = 0, unsigned status = 0) -> std::unexpected<VmmApiFailure> {
    return std::unexpected(VmmApiFailure{.error = e, .http_status = status, .sys_errno = err});
}

auto as_text(std::span<const std::byte> bytes) -> std::string_view {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

auto is_tchar(char c) -> bool {
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        return true;
    }
    return std::string_view{"!#$%&'*+-.^_`|~"}.find(c) != std::string_view::npos;
}

auto iequals(std::string_view a, std::string_view b) -> bool {
    return a.size() == b.size() && std::ranges::equal(a, b, [](char x, char y) {
               auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? char(c - 'A' + 'a') : c; };
               return lower(x) == lower(y);
           });
}

auto trim_ows(std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

class Fd {
public:
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&&) = delete;
    auto operator=(Fd&&) -> Fd& = delete;
    ~Fd() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    [[nodiscard]] auto get() const noexcept -> int { return _fd; }

private:
    int _fd;
};

using Clock = std::chrono::steady_clock;

auto wait_for(int fd, short events, Clock::time_point deadline)
    -> std::expected<void, VmmApiFailure> {
    for (;;) {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
        if (left.count() <= 0) {
            return fail(VmmApiError::timed_out);
        }
        pollfd p{.fd = fd, .events = events, .revents = 0};
        const int r = ::poll(&p, 1, static_cast<int>(left.count()));
        if (r > 0) {
            return {};
        }
        if (r < 0 && errno != EINTR) {
            return fail(VmmApiError::io_failed, errno);
        }
    }
}

}  // namespace

auto to_string(VmmApiError e) noexcept -> const char* {
    switch (e) {
        case VmmApiError::connect_failed:
            return "connect_failed";
        case VmmApiError::io_failed:
            return "io_failed";
        case VmmApiError::timed_out:
            return "timed_out";
        case VmmApiError::bad_reply:
            return "bad_reply";
        case VmmApiError::refused:
            return "refused";
        case VmmApiError::bad_body:
            return "bad_body";
    }
    return "unknown";
}

auto parse_reply(std::span<const std::byte> bytes, bool peer_closed, HttpReply& out)
    -> std::expected<ReplyParse, VmmApiFailure> {
    const auto text = as_text(bytes);
    const auto head_end = text.find("\r\n\r\n");
    if (head_end == std::string_view::npos) {
        if (text.size() > max_reply_head) {
            return fail(VmmApiError::bad_reply);
        }
        if (peer_closed) {
            return fail(VmmApiError::bad_reply);
        }
        return ReplyParse::incomplete;
    }
    if (head_end + 4 > max_reply_head) {
        return fail(VmmApiError::bad_reply);
    }
    const auto head = text.substr(0, head_end + 2);  // every line ends in CRLF

    // Status line.
    auto eol = head.find("\r\n");
    const auto status_line = head.substr(0, eol);
    if (status_line.size() < 12 ||
        (status_line.substr(0, 9) != "HTTP/1.1 " && status_line.substr(0, 9) != "HTTP/1.0 ") ||
        (status_line.size() > 12 && status_line[12] != ' ')) {
        return fail(VmmApiError::bad_reply);
    }
    unsigned status = 0;
    for (std::size_t i = 9; i < 12; ++i) {
        const char c = status_line[i];
        if (c < '0' || c > '9') {
            return fail(VmmApiError::bad_reply);
        }
        status = status * 10 + static_cast<unsigned>(c - '0');
    }
    if (status < 100) {
        return fail(VmmApiError::bad_reply);
    }
    for (const char c : status_line) {
        if ((static_cast<unsigned char>(c) < 0x20 && c != '\t') || c == 0x7F) {
            return fail(VmmApiError::bad_reply);
        }
    }

    // Headers.
    std::optional<std::size_t> content_length;
    std::size_t pos = eol + 2;
    while (pos < head.size()) {
        eol = head.find("\r\n", pos);
        const auto line = head.substr(pos, eol - pos);
        pos = eol + 2;
        if (line.find('\n') != std::string_view::npos ||
            line.find('\r') != std::string_view::npos) {
            return fail(VmmApiError::bad_reply);
        }
        const auto colon = line.find(':');
        if (colon == 0 || colon == std::string_view::npos) {
            return fail(VmmApiError::bad_reply);  // includes folded lines (leading space)
        }
        const auto name = line.substr(0, colon);
        if (!std::ranges::all_of(name, is_tchar)) {
            return fail(VmmApiError::bad_reply);
        }
        const auto value = trim_ows(line.substr(colon + 1));
        for (const char c : value) {
            if ((static_cast<unsigned char>(c) < 0x20 && c != '\t') || c == 0x7F) {
                return fail(VmmApiError::bad_reply);
            }
        }
        if (iequals(name, "transfer-encoding")) {
            return fail(VmmApiError::bad_reply);
        }
        if (iequals(name, "content-length")) {
            if (value.empty() || value.size() > 7 ||
                !std::ranges::all_of(value, [](char c) { return c >= '0' && c <= '9'; })) {
                return fail(VmmApiError::bad_reply);
            }
            std::size_t n = 0;
            std::from_chars(value.data(), value.data() + value.size(), n);
            if (n > max_reply_body || (content_length && *content_length != n)) {
                return fail(VmmApiError::bad_reply);
            }
            content_length = n;
        }
    }
    if (status == 204 && content_length.value_or(0) != 0) {
        return fail(VmmApiError::bad_reply);
    }

    const std::size_t body_start = head_end + 4;
    const std::size_t want = content_length.value_or(0);
    const std::size_t have = text.size() - body_start;
    if (have < want) {
        if (peer_closed) {
            return fail(VmmApiError::bad_reply);
        }
        return ReplyParse::incomplete;
    }
    if (have > want) {
        return fail(VmmApiError::bad_reply);  // nothing may follow the body
    }
    out.status = status;
    out.body.assign(text.substr(body_start, want));
    return ReplyParse::complete;
}

auto format_request(std::string_view method, std::string_view endpoint, std::string_view body)
    -> std::string {
    std::string r;
    r.append(method).append(" /api/v1/").append(endpoint).append(" HTTP/1.1\r\n");
    r.append("Host: localhost\r\nAccept: application/json\r\n");
    if (!body.empty()) {
        r.append("Content-Type: application/json\r\nContent-Length: ")
            .append(std::to_string(body.size()))
            .append("\r\n");
    }
    r.append("\r\n").append(body);
    return r;
}

auto parse_vm_info(std::string_view body) -> std::expected<VmmInfo, VmmApiFailure> {
    const auto doc = json::parse(body);
    if (!doc) {
        return fail(VmmApiError::bad_body);
    }
    const auto* state = doc->find("state");
    if (state == nullptr || state->as_string() == nullptr) {
        return fail(VmmApiError::bad_body);
    }
    VmmInfo info;
    const auto& s = *state->as_string();
    if (s == "Created") {
        info.state = VmmState::created;
    } else if (s == "Running") {
        info.state = VmmState::running;
    } else if (s == "Paused") {
        info.state = VmmState::paused;
    } else if (s == "Shutdown") {
        info.state = VmmState::shutdown;
    } else {
        info.state = VmmState::other;
    }
    const auto* config = doc->find("config");
    if (config == nullptr || config->as_object() == nullptr) {
        return fail(VmmApiError::bad_body);
    }
    const auto* devices = config->find("devices");
    if (devices == nullptr || devices->is_null()) {
        return info;
    }
    const auto* list = devices->as_array();
    if (list == nullptr) {
        return fail(VmmApiError::bad_body);
    }
    for (const auto& d : *list) {
        const auto* id = d.find("id");
        if (id == nullptr || id->as_string() == nullptr ||
            std::ranges::find(info.device_ids, *id->as_string()) != info.device_ids.end()) {
            return fail(VmmApiError::bad_body);
        }
        info.device_ids.push_back(*id->as_string());
    }
    return info;
}

auto ChApiClient::call(std::string_view method, std::string_view endpoint, std::string_view body)
    -> std::expected<HttpReply, VmmApiFailure> {
    const auto deadline = Clock::now() + _timeout;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto& native = _socket.native();
    if (native.size() >= sizeof(addr.sun_path)) {
        return fail(VmmApiError::connect_failed, ENAMETOOLONG);
    }
    std::memcpy(addr.sun_path, native.c_str(), native.size() + 1);

    const Fd fd{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)};
    if (fd.get() < 0) {
        return fail(VmmApiError::io_failed, errno);
    }
    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) {
            return fail(VmmApiError::connect_failed, errno);
        }
        if (auto w = wait_for(fd.get(), POLLOUT, deadline); !w) {
            return std::unexpected(w.error());
        }
        int err = 0;
        socklen_t len = sizeof(err);
        ::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            return fail(VmmApiError::connect_failed, err);
        }
    }

    const auto request = format_request(method, endpoint, body);
    std::size_t sent = 0;
    while (sent < request.size()) {
        const auto n = ::send(fd.get(), request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            if (auto w = wait_for(fd.get(), POLLOUT, deadline); !w) {
                return std::unexpected(w.error());
            }
            continue;
        }
        return fail(VmmApiError::io_failed, errno);
    }

    std::vector<std::byte> in;
    std::array<std::byte, 4096> buf{};
    HttpReply reply;
    for (;;) {
        const auto n = ::recv(fd.get(), buf.data(), buf.size(), 0);
        bool closed = false;
        if (n > 0) {
            in.insert(in.end(), buf.begin(), buf.begin() + n);
            if (in.size() > max_reply_head + max_reply_body) {
                return fail(VmmApiError::bad_reply);
            }
        } else if (n == 0) {
            closed = true;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            if (auto w = wait_for(fd.get(), POLLIN, deadline); !w) {
                return std::unexpected(w.error());
            }
            continue;
        } else {
            return fail(VmmApiError::io_failed, errno);
        }
        auto parsed = parse_reply(in, closed, reply);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        if (*parsed == ReplyParse::complete) {
            break;
        }
    }
    if (reply.status != 200 && reply.status != 204) {
        return fail(VmmApiError::refused, 0, reply.status);
    }
    return reply;
}

namespace {
auto drop_body(std::expected<HttpReply, VmmApiFailure> r) -> VmmApi::Result {
    if (!r) {
        return std::unexpected(r.error());
    }
    return {};
}
}  // namespace

auto ChApiClient::create(std::string_view config_json) -> Result {
    return drop_body(call("PUT", "vm.create", config_json));
}

auto ChApiClient::boot() -> Result {
    return drop_body(call("PUT", "vm.boot", {}));
}

auto ChApiClient::add_device(std::string_view id, const std::filesystem::path& path) -> Result {
    const auto body =
        "{\"id\":" + json::quote(id) + ",\"path\":" + json::quote(path.native()) + "}";
    return drop_body(call("PUT", "vm.add-device", body));
}

auto ChApiClient::remove_device(std::string_view id) -> Result {
    const auto body = "{\"id\":" + json::quote(id) + "}";
    return drop_body(call("PUT", "vm.remove-device", body));
}

auto ChApiClient::info() -> std::expected<VmmInfo, VmmApiFailure> {
    auto r = call("GET", "vm.info", {});
    if (!r) {
        return std::unexpected(r.error());
    }
    return parse_vm_info(r->body);
}

auto ChApiClient::ping() -> Result {
    return drop_body(call("GET", "vmm.ping", {}));
}

auto ChApiClient::shutdown_vmm() -> Result {
    return drop_body(call("PUT", "vmm.shutdown", {}));
}

}  // namespace ak::hull
