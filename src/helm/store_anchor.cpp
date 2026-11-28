// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/store_anchor.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

// File layout (little-endian, 64 bytes):
//   magic u32 'AKSA' | version u16 (1) | reserved u16 | key [32] | counters [3] u64
constexpr std::uint32_t anchor_magic = 0x4153'4B41;  // "AKSA" as little-endian bytes
constexpr std::uint16_t anchor_version = 1;
constexpr std::size_t anchor_file_size = 8 + store_key_size + (counter_count * 8);
constexpr mode_t anchor_mode = 0600;
constexpr mode_t group_other_bits = 077;

class Fd {
public:
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&&) = delete;
    auto operator=(Fd&&) -> Fd& = delete;
    ~Fd() {
        if (_fd >= 0) {
            (void)::close(_fd);
        }
    }
    [[nodiscard]] auto get() const noexcept -> int { return _fd; }
    [[nodiscard]] auto valid() const noexcept -> bool { return _fd >= 0; }

private:
    int _fd;
};

auto random_key(std::span<std::byte, store_key_size> out) -> std::expected<void, AnchorError> {
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(out.size())) !=
        1) {
        ERR_clear_error();
        return std::unexpected(AnchorError::random_failure);
    }
    return {};
}

auto encode(const SoftwareStoreAnchor::State& s) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    out.reserve(anchor_file_size);
    wire::Writer w{out};
    w.le32(anchor_magic);
    w.le16(anchor_version);
    w.le16(0);
    w.bytes(s.key.span());
    for (auto c : s.counters) {
        w.le64(c);
    }
    return out;
}

auto write_all(int fd, std::span<const std::byte> bytes) -> bool {
    while (!bytes.empty()) {
        const auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
    return true;
}

auto copy_state(const SoftwareStoreAnchor::State& s) -> SoftwareStoreAnchor::State {
    SoftwareStoreAnchor::State out;
    std::ranges::copy(s.key.span(), out.key.span().begin());
    out.counters = s.counters;
    return out;
}

// Writes `bytes` to `path` atomically: a temporary file, fsync, rename,
// and an fsync of the directory so the rename itself survives power loss.
auto replace_file(const std::filesystem::path& path, std::span<const std::byte> bytes)
    -> std::expected<void, AnchorError> {
    auto tmp = path;
    tmp += ".tmp";
    (void)::unlink(tmp.c_str());
    {
        Fd fd{
            ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, anchor_mode)};
        if (!fd.valid() || !write_all(fd.get(), bytes) || ::fsync(fd.get()) != 0) {
            (void)::unlink(tmp.c_str());
            return std::unexpected(AnchorError::io);
        }
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        (void)::unlink(tmp.c_str());
        return std::unexpected(AnchorError::io);
    }
    const auto dir = path.has_parent_path() ? path.parent_path() : std::filesystem::path{"."};
    Fd dfd{::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (!dfd.valid() || ::fsync(dfd.get()) != 0) {
        return std::unexpected(AnchorError::io);
    }
    return {};
}

auto read_file(const std::filesystem::path& path)
    -> std::expected<std::optional<SoftwareStoreAnchor::State>, AnchorError> {
    Fd fd{::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
    if (!fd.valid()) {
        if (errno == ENOENT) {
            return std::optional<SoftwareStoreAnchor::State>{};
        }
        return std::unexpected(errno == ELOOP ? AnchorError::insecure : AnchorError::io);
    }
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) {
        return std::unexpected(AnchorError::io);
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & group_other_bits) != 0) {
        return std::unexpected(AnchorError::insecure);
    }
    if (st.st_size != static_cast<off_t>(anchor_file_size)) {
        return std::unexpected(AnchorError::corrupt);
    }
    std::array<std::byte, anchor_file_size> buf{};
    std::span<std::byte> rest{buf};
    while (!rest.empty()) {
        const auto n = ::read(fd.get(), rest.data(), rest.size());
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            secure_zero(buf);
            return std::unexpected(AnchorError::io);
        }
        rest = rest.subspan(static_cast<std::size_t>(n));
    }
    wire::Reader r{buf};
    const auto magic = r.le32().value_or(0);
    const auto version = r.le16().value_or(0);
    const auto reserved = r.le16().value_or(1);
    SoftwareStoreAnchor::State s;
    std::ranges::copy(r.bytes(store_key_size).value_or(std::span<const std::byte>{}),
                      s.key.span().begin());
    for (auto& c : s.counters) {
        c = r.le64().value_or(0);
    }
    secure_zero(buf);
    if (magic != anchor_magic || version != anchor_version || reserved != 0) {
        return std::unexpected(AnchorError::corrupt);
    }
    return std::optional<SoftwareStoreAnchor::State>{std::move(s)};
}

}  // namespace

auto to_string(AnchorError e) noexcept -> const char* {
    switch (e) {
        case AnchorError::io:
            return "store anchor I/O error";
        case AnchorError::insecure:
            return "store anchor file is not private";
        case AnchorError::corrupt:
            return "store anchor file is corrupt";
        case AnchorError::not_monotonic:
            return "counter would not move forward";
        case AnchorError::random_failure:
            return "random number generator failed";
    }
    return "unknown";
}

auto SoftwareStoreAnchor::open(const std::filesystem::path& path)
    -> std::expected<std::unique_ptr<SoftwareStoreAnchor>, AnchorError> {
    auto existing = read_file(path);
    if (!existing) {
        return std::unexpected(existing.error());
    }
    if (*existing) {
        return std::make_unique<SoftwareStoreAnchor>(path, std::move(**existing));
    }
    State fresh;
    if (auto ok = random_key(fresh.key.span()); !ok) {
        return std::unexpected(ok.error());
    }
    auto bytes = encode(fresh);
    auto written = replace_file(path, bytes);
    secure_zero(bytes);
    if (!written) {
        return std::unexpected(written.error());
    }
    return std::make_unique<SoftwareStoreAnchor>(path, std::move(fresh));
}

auto SoftwareStoreAnchor::ephemeral()
    -> std::expected<std::unique_ptr<SoftwareStoreAnchor>, AnchorError> {
    State fresh;
    if (auto ok = random_key(fresh.key.span()); !ok) {
        return std::unexpected(ok.error());
    }
    return std::make_unique<SoftwareStoreAnchor>(std::nullopt, std::move(fresh));
}

auto SoftwareStoreAnchor::store_key() -> std::expected<SecretBytes<store_key_size>, AnchorError> {
    SecretBytes<store_key_size> k;
    std::ranges::copy(_state.key.span(), k.span().begin());
    return k;
}

auto SoftwareStoreAnchor::counter(Counter c) -> std::expected<std::uint64_t, AnchorError> {
    return _state.counters.at(static_cast<std::size_t>(c));
}

auto SoftwareStoreAnchor::persist(const State& next) -> std::expected<void, AnchorError> {
    if (!_path) {
        return {};
    }
    auto bytes = encode(next);
    auto ok = replace_file(*_path, bytes);
    secure_zero(bytes);
    return ok;
}

auto SoftwareStoreAnchor::advance(Counter c, std::uint64_t value)
    -> std::expected<void, AnchorError> {
    const auto i = static_cast<std::size_t>(c);
    if (value <= _state.counters.at(i)) {
        return std::unexpected(AnchorError::not_monotonic);
    }
    auto next = copy_state(_state);
    next.counters.at(i) = value;
    if (auto ok = persist(next); !ok) {
        return ok;
    }
    _state = std::move(next);
    return {};
}

auto SoftwareStoreAnchor::destroy_store_key() -> std::expected<void, AnchorError> {
    auto next = copy_state(_state);
    if (auto ok = random_key(next.key.span()); !ok) {
        return ok;
    }
    if (auto ok = persist(next); !ok) {
        return ok;
    }
    _state = std::move(next);
    return {};
}

}  // namespace ak::helm
