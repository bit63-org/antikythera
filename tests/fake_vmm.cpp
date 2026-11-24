// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// A stand-in for cloud-hypervisor, for vmm_launcher_test
// (.kiro/specs/hull-host-agent/ task 8). It takes the command line
// JailedVmmLauncher gives the real VMM (--api-socket path=<p> --seccomp
// true), listens on that socket and answers the API calls the agent makes
// the way Cloud Hypervisor does, keeping just enough state to make vm.info
// truthful:
//
//   GET vmm.ping           200 {"version":"fake"}
//   PUT vm.create          204, or 400 if a VM exists
//   PUT vm.boot            204 (Created -> Running), else 400
//   PUT vm.add-device      200 {"id":...} (cold- or hot-plug), 400 on a duplicate id
//   PUT vm.remove-device   204 and the device is gone at once (as if the
//                          guest ejected immediately), 404 if unknown
//   GET vm.info            200 {"config":{"devices":[...]},"state":...}, 404 before create
//   PUT vmm.shutdown       204, then exit 0
//   PUT vm.power-button    204, then exit 0 (the guest "powers off")
//   PUT fake.crash         no reply, exit 3
//
// It runs inside the real jail, so it also proves the jail lets a VMM bind
// its API socket and nothing more is needed for that.

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct State {
    bool created{false};
    bool running{false};
    std::vector<std::string> devices;
};

auto reply(int fd, int status, std::string_view reason, std::string_view body) -> void {
    std::string r = "HTTP/1.1 " + std::to_string(status) + " " + std::string{reason} + "\r\n";
    r += "Server: fake-vmm\r\n";
    if (!body.empty()) {
        r += "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
             "\r\n";
    }
    r += "\r\n";
    r += body;
    (void)::send(fd, r.data(), r.size(), MSG_NOSIGNAL);
}

// The value of "key":"value" in a flat JSON object (the agent's requests
// are flat and unescaped in these tests).
auto field(std::string_view body, std::string_view key) -> std::optional<std::string> {
    const std::string needle = "\"" + std::string{key} + "\":\"";
    const auto at = body.find(needle);
    if (at == std::string_view::npos) {
        return std::nullopt;
    }
    const auto start = at + needle.size();
    const auto end = body.find('"', start);
    if (end == std::string_view::npos) {
        return std::nullopt;
    }
    return std::string{body.substr(start, end - start)};
}

// Reads one request: head, then Content-Length bytes of body.
auto read_request(int fd, std::string& method, std::string& path, std::string& body) -> bool {
    std::string in;
    std::array<char, 1024> buf{};
    std::size_t head_end = std::string::npos;
    while ((head_end = in.find("\r\n\r\n")) == std::string::npos) {
        const auto n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) {
            return false;
        }
        in.append(buf.data(), static_cast<std::size_t>(n));
    }
    const auto line_end = in.find("\r\n");
    const auto line = in.substr(0, line_end);
    const auto sp1 = line.find(' ');
    const auto sp2 = line.find(' ', sp1 + 1);
    method = line.substr(0, sp1);
    path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    std::size_t length = 0;
    const auto cl = in.find("Content-Length: ");
    if (cl != std::string::npos && cl < head_end) {
        length = std::strtoul(in.c_str() + cl + 16, nullptr, 10);
    }
    body = in.substr(head_end + 4);
    while (body.size() < length) {
        const auto n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) {
            return false;
        }
        body.append(buf.data(), static_cast<std::size_t>(n));
    }
    return true;
}

auto info_json(const State& s) -> std::string {
    std::string j = "{\"config\":{\"cpus\":{\"boot_vcpus\":1},\"devices\":[";
    for (std::size_t i = 0; i < s.devices.size(); ++i) {
        j += (i != 0 ? "," : "");
        j += "{\"path\":\"/sys/bus/pci/devices/x\",\"id\":\"" + s.devices[i] + "\"}";
    }
    j += "]},\"state\":\"";
    j += s.running ? "Running" : "Created";
    j += "\",\"memory_actual_size\":1073741824}";
    return j;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    std::string socket_path;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string_view{argv[i]} == "--api-socket") {
            const std::string_view v{argv[i + 1]};
            if (v.starts_with("path=")) {
                socket_path = std::string{v.substr(5)};
            }
        }
    }
    if (socket_path.empty()) {
        std::fputs("fake_vmm: --api-socket path=<p> required\n", stderr);
        return 2;
    }
    const int lfd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (lfd < 0 || socket_path.size() >= sizeof(addr.sun_path)) {
        return 2;
    }
    std::memcpy(addr.sun_path, socket_path.c_str(), socket_path.size() + 1);
    if (::bind(lfd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(lfd, 8) != 0) {
        std::perror("fake_vmm: bind");
        return 2;
    }

    State s;
    for (;;) {
        const int fd = ::accept4(lfd, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) {
            continue;
        }
        std::string method;
        std::string path;
        std::string body;
        if (!read_request(fd, method, path, body)) {
            ::close(fd);
            continue;
        }
        int exit_after = -1;
        if (path == "/api/v1/vmm.ping" && method == "GET") {
            reply(fd, 200, "OK", "{\"version\":\"fake\"}");
        } else if (path == "/api/v1/vm.create" && method == "PUT") {
            if (s.created || body.find("\"payload\"") == std::string::npos) {
                reply(fd, 400, "Bad Request", "");
            } else {
                s.created = true;
                reply(fd, 204, "No Content", "");
            }
        } else if (path == "/api/v1/vm.boot" && method == "PUT") {
            if (!s.created || s.running) {
                reply(fd, 400, "Bad Request", "");
            } else {
                s.running = true;
                reply(fd, 204, "No Content", "");
            }
        } else if (path == "/api/v1/vm.add-device" && method == "PUT") {
            const auto id = field(body, "id");
            if (!s.created || !id || std::ranges::find(s.devices, *id) != s.devices.end()) {
                reply(fd, 400, "Bad Request", "");
            } else {
                s.devices.push_back(*id);
                reply(fd, 200, "OK", "{\"id\":\"" + *id + "\",\"bdf\":\"0000:00:05.0\"}");
            }
        } else if (path == "/api/v1/vm.remove-device" && method == "PUT") {
            const auto id = field(body, "id");
            const auto it = id ? std::ranges::find(s.devices, *id) : s.devices.end();
            if (it == s.devices.end()) {
                reply(fd, 404, "Not Found", "");
            } else {
                s.devices.erase(it);
                reply(fd, 204, "No Content", "");
            }
        } else if (path == "/api/v1/vm.info" && method == "GET") {
            if (!s.created) {
                reply(fd, 404, "Not Found", "");
            } else {
                reply(fd, 200, "OK", info_json(s));
            }
        } else if ((path == "/api/v1/vmm.shutdown" || path == "/api/v1/vm.power-button") &&
                   method == "PUT") {
            reply(fd, 204, "No Content", "");
            exit_after = 0;
        } else if (path == "/api/v1/fake.crash") {
            exit_after = 3;
        } else {
            reply(fd, 404, "Not Found", "");
        }
        ::close(fd);
        if (exit_after >= 0) {
            ::unlink(socket_path.c_str());
            return exit_after;
        }
    }
}
