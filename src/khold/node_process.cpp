// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "khold/node_process.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <format>
#include <fstream>
#include <iterator>
#include <system_error>
#include <thread>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ak::khold {

namespace {

constexpr auto reap_step = std::chrono::milliseconds{10};

// Writes `bytes` to `path` durably: a temporary file in the same
// directory, fsync, rename.
auto write_atomic(const std::filesystem::path& path, std::span<const std::byte> bytes) -> bool {
    auto tmp = path;
    tmp += ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    const auto* p = bytes.data();
    std::size_t left = bytes.size();
    bool ok = true;
    while (left > 0) {
        const auto n = ::write(fd, p, left);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            ok = false;
            break;
        }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    ok = ok && ::fsync(fd) == 0;
    ok = (::close(fd) == 0) && ok;
    std::error_code ec;
    if (ok) {
        std::filesystem::rename(tmp, path, ec);
        ok = !ec;
    }
    if (!ok) {
        std::filesystem::remove(tmp, ec);
    }
    return ok;
}

auto read_all(const std::filesystem::path& path) -> std::optional<std::vector<std::byte>> {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::nullopt;
    }
    const std::vector<char> chars{std::istreambuf_iterator<char>{in},
                                  std::istreambuf_iterator<char>{}};
    std::vector<std::byte> out(chars.size());
    std::ranges::transform(chars, out.begin(), [](char c) { return static_cast<std::byte>(c); });
    return out;
}

}  // namespace

auto layout_file_name(std::uint64_t volume_id) -> std::string {
    return std::format("{:016x}.vlay", volume_id);
}

NodeProcess::NodeProcess(NodeProcessConfig config)
    : _config{std::move(config)}, _backoff{_config.restart_min} {
    std::error_code ec;
    std::filesystem::create_directories(_config.layout_dir, ec);
    std::filesystem::create_directories(_config.report_dir, ec);
}

NodeProcess::~NodeProcess() {
    stop();
}

auto NodeProcess::start(Clock::time_point now) -> void {
    if (_config.argv.empty()) {
        return;
    }
    std::vector<char*> args;
    args.reserve(_config.argv.size() + 1);
    for (auto& a : _config.argv) {
        args.push_back(a.data());
    }
    args.push_back(nullptr);
    const pid_t pid = ::fork();
    if (pid == 0) {
        ::execvp(args[0], args.data());
        std::_Exit(127);  // NOLINT(concurrency-mt-unsafe): only the child runs this
    }
    _started_at = now;
    if (pid < 0) {
        ++_stats.start_failures;
        _next_start = now + _backoff;
        return;
    }
    _pid = pid;
    ++_generation;
    ++_stats.starts;
}

auto NodeProcess::poll(Clock::time_point now) -> void {
    if (_pid > 0) {
        int status = 0;
        const pid_t r = ::waitpid(_pid, &status, WNOHANG);
        if (r == _pid || (r < 0 && errno == ECHILD)) {
            _pid = -1;
            ++_stats.exits;
            // A node that ran a while is restarted promptly; one that keeps
            // dying backs off.
            _backoff = (now - _started_at) >= _config.restart_max
                           ? _config.restart_min
                           : std::min(_backoff * 2, _config.restart_max);
            _next_start = now + _backoff;
        }
    }
    if (_pid <= 0 && !_stopped && now >= _next_start) {
        start(now);
    }
}

auto NodeProcess::reload() -> void {
    if (_pid > 0) {
        ::kill(_pid, SIGHUP);
    }
}

auto NodeProcess::stop() -> void {
    _stopped = true;
    if (_pid <= 0) {
        return;
    }
    ::kill(_pid, SIGTERM);
    const auto deadline = Clock::now() + _config.stop_grace;
    while (Clock::now() < deadline) {
        int status = 0;
        const pid_t r = ::waitpid(_pid, &status, WNOHANG);
        if (r == _pid || (r < 0 && errno == ECHILD)) {
            _pid = -1;
            return;
        }
        std::this_thread::sleep_for(reap_step);
    }
    ::kill(_pid, SIGKILL);
    int status = 0;
    (void)::waitpid(_pid, &status, 0);
    _pid = -1;
}

auto NodeProcess::apply_layout(std::uint64_t volume_id, std::uint64_t /*epoch*/,
                               std::span<const std::byte> frame) -> bool {
    const bool ok = write_atomic(_config.layout_dir / layout_file_name(volume_id), frame);
    ++(ok ? _stats.layouts_written : _stats.layout_write_failures);
    return ok;
}

auto NodeProcess::take_reports() -> std::vector<proto::ReportBody> {
    std::vector<std::filesystem::path> names;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator{_config.report_dir, ec}) {
        if (entry.path().extension() == ".rpt" && entry.is_regular_file(ec)) {
            names.push_back(entry.path());
        }
    }
    std::ranges::sort(names);
    if (names.size() > _config.max_reports) {
        names.resize(_config.max_reports);
    }
    std::vector<proto::ReportBody> out;
    for (const auto& name : names) {
        const auto bytes = read_all(name);
        if (!bytes) {
            continue;  // tried again next time
        }
        auto rep = proto::decode_report(*bytes);
        std::filesystem::remove(name, ec);
        if (!rep) {
            ++_stats.reports_bad;
            continue;
        }
        ++_stats.reports_read;
        out.push_back(std::move(rep->body));
    }
    return out;
}

}  // namespace ak::khold
