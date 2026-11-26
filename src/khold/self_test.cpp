// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "khold/self_test.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <random>
#include <string_view>
#include <system_error>

#include <fcntl.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace ak::khold {

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t page = 4096;
constexpr std::size_t seq_block = std::size_t{1} << 20U;
constexpr std::uint64_t mib = std::uint64_t{1} << 20U;
// Random phases stop after this many operations even inside the budget,
// so a RAM-backed "drive" cannot spin for long.
constexpr std::uint64_t max_random_ops = std::uint64_t{1} << 22U;

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
    [[nodiscard]] auto ok() const noexcept -> bool { return _fd >= 0; }

private:
    int _fd;
};

struct FreeDeleter {
    auto operator()(std::byte* p) const noexcept -> void { std::free(p); }  // NOLINT
};
using Buffer = std::unique_ptr<std::byte, FreeDeleter>;

auto aligned_buffer(std::size_t size) -> Buffer {
    void* p = std::aligned_alloc(page, size);  // NOLINT(cppcoreguidelines-no-malloc)
    if (p != nullptr) {
        std::memset(p, 0xA5, size);
    }
    return Buffer{static_cast<std::byte*>(p)};
}

// Removes the scratch file however the measurement ends.
class Scratch {
public:
    explicit Scratch(std::filesystem::path path) : _path{std::move(path)} {}
    Scratch(const Scratch&) = delete;
    auto operator=(const Scratch&) -> Scratch& = delete;
    Scratch(Scratch&&) = delete;
    auto operator=(Scratch&&) -> Scratch& = delete;
    ~Scratch() {
        std::error_code ec;
        std::filesystem::remove(_path, ec);
    }
    [[nodiscard]] auto path() const -> const std::filesystem::path& { return _path; }

private:
    std::filesystem::path _path;
};

auto elapsed_s(Clock::time_point start) -> double {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

auto rate(double amount, double seconds) -> std::uint32_t {
    if (seconds <= 0.0 || amount <= 0.0) {
        return 0;
    }
    const double r = amount / seconds;
    constexpr auto top = static_cast<double>(std::numeric_limits<std::uint32_t>::max());
    return r >= top ? std::numeric_limits<std::uint32_t>::max() : static_cast<std::uint32_t>(r);
}

auto full_pwrite(int fd, const std::byte* data, std::size_t size, off_t at) -> bool {
    while (size > 0) {
        const auto n = ::pwrite(fd, data, size, at);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        data += n;
        size -= static_cast<std::size_t>(n);
        at += n;
    }
    return true;
}

auto full_pread(int fd, std::byte* data, std::size_t size, off_t at) -> bool {
    while (size > 0) {
        const auto n = ::pread(fd, data, size, at);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        data += n;
        size -= static_cast<std::size_t>(n);
        at += n;
    }
    return true;
}

auto drop_cache(int fd, bool direct) -> void {
    if (!direct) {
        (void)::posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    }
}

}  // namespace

auto read_link_mbps(const std::filesystem::path& sys_class_net, const std::string& interface)
    -> std::uint32_t {
    // An interface name never holds a path separator; refuse one rather
    // than read some other file.
    if (interface.empty() || interface.find('/') != std::string::npos || interface == "." ||
        interface == "..") {
        return 0;
    }
    std::ifstream in{sys_class_net / interface / "speed"};
    std::string text;
    if (!in || !std::getline(in, text)) {
        return 0;
    }
    std::int64_t v = 0;
    const auto* first = text.data();
    const auto* last = text.data() + text.size();
    const auto [p, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || p == first || v <= 0 ||
        v > std::numeric_limits<std::uint32_t>::max()) {
        return 0;
    }
    return static_cast<std::uint32_t>(v);
}

auto measure_drive(const DriveSpec& drive, std::uint64_t file_bytes,
                   std::chrono::milliseconds phase_budget) -> proto::DriveCapacity {
    proto::DriveCapacity out{.drive = drive.drive, .state = proto::DriveState::failed};
    struct statvfs vfs{};
    if (::statvfs(drive.dir.c_str(), &vfs) != 0 || vfs.f_frsize == 0) {
        return out;
    }
    out.capacity_bytes = static_cast<std::uint64_t>(vfs.f_blocks) * vfs.f_frsize;

    // Whole 1 MiB blocks, at least one.
    const std::uint64_t blocks = std::max<std::uint64_t>(1, file_bytes / seq_block);
    const std::uint64_t size = blocks * seq_block;
    const Scratch scratch{drive.dir / ".khold-self-test"};
    bool direct = true;
    int raw =
        ::open(scratch.path().c_str(), O_RDWR | O_CREAT | O_TRUNC | O_DIRECT | O_CLOEXEC, 0600);
    if (raw < 0 && errno == EINVAL) {
        direct = false;  // the file system does not take O_DIRECT
        raw = ::open(scratch.path().c_str(), O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    }
    const Fd fd{raw};
    auto buf = aligned_buffer(seq_block);
    if (!fd.ok() || !buf) {
        return out;
    }

    // Sequential write, including the sync that makes it durable.
    auto start = Clock::now();
    for (std::uint64_t i = 0; i < blocks; ++i) {
        if (!full_pwrite(fd.get(), buf.get(), seq_block, static_cast<off_t>(i * seq_block))) {
            return out;
        }
    }
    if (::fdatasync(fd.get()) != 0) {
        return out;
    }
    const auto seq_w = elapsed_s(start);

    // Sequential read.
    drop_cache(fd.get(), direct);
    start = Clock::now();
    for (std::uint64_t i = 0; i < blocks; ++i) {
        if (!full_pread(fd.get(), buf.get(), seq_block, static_cast<off_t>(i * seq_block))) {
            return out;
        }
    }
    const auto seq_r = elapsed_s(start);

    std::minstd_rand rng{
        static_cast<std::minstd_rand::result_type>(Clock::now().time_since_epoch().count())};
    std::uniform_int_distribution<std::uint64_t> pick{0, (size / page) - 1};

    // Random 4 KiB writes, then the sync, inside the window.
    std::uint64_t writes = 0;
    start = Clock::now();
    const auto w_end = start + phase_budget;
    while (Clock::now() < w_end && writes < max_random_ops) {
        if (!full_pwrite(fd.get(), buf.get(), page, static_cast<off_t>(pick(rng) * page))) {
            return out;
        }
        ++writes;
    }
    if (::fdatasync(fd.get()) != 0) {
        return out;
    }
    const auto rand_w = elapsed_s(start);

    // Random 4 KiB reads.
    drop_cache(fd.get(), direct);
    std::uint64_t reads = 0;
    start = Clock::now();
    const auto r_end = start + phase_budget;
    while (Clock::now() < r_end && reads < max_random_ops) {
        if (!full_pread(fd.get(), buf.get(), page, static_cast<off_t>(pick(rng) * page))) {
            return out;
        }
        ++reads;
    }
    const auto rand_r = elapsed_s(start);

    const auto mibs = static_cast<double>(size) / static_cast<double>(mib);
    out.state = proto::DriveState::ok;
    out.write_mib_per_s = std::max<std::uint32_t>(1, rate(mibs, seq_w));
    out.read_mib_per_s = std::max<std::uint32_t>(1, rate(mibs, seq_r));
    out.write_iops = std::max<std::uint32_t>(1, rate(static_cast<double>(writes), rand_w));
    out.read_iops = std::max<std::uint32_t>(1, rate(static_cast<double>(reads), rand_r));
    return out;
}

auto run_self_test(const SelfTestConfig& config) -> proto::Capacity {
    proto::Capacity c{.slot = 0, .link_mbps = 0, .drives = {}};
    for (const auto& d : config.drives) {
        if (!c.drives.empty() && d.drive <= c.drives.back().drive) {
            continue;  // the report needs strictly increasing drives
        }
        if (c.drives.size() >= proto::max_capacity_drives) {
            break;
        }
        c.drives.push_back(measure_drive(d, config.file_bytes, config.phase_budget));
    }
    c.link_mbps = config.link_mbps != 0
                      ? config.link_mbps
                      : read_link_mbps(config.sys_class_net, config.link_interface);
    return c;
}

}  // namespace ak::khold
