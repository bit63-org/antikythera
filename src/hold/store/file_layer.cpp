// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hold/store/file_layer.hpp"

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <system_error>
#include <utility>

namespace ak::hold::store {

namespace {

constexpr mode_t dir_mode = 0700;
constexpr mode_t file_mode = 0600;
constexpr std::size_t sector = 512;

class Fd {
public:
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&& o) noexcept : _fd{std::exchange(o._fd, -1)} {}
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

class PosixFile final : public File {
public:
    explicit PosixFile(Fd fd) noexcept : _fd{std::move(fd)} {}

    auto pread(std::uint64_t offset, std::span<std::byte> out) -> FileResult override {
        std::size_t done = 0;
        while (done < out.size()) {
            const auto n = ::pread(_fd.get(), out.data() + done, out.size() - done,
                                   static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(errno);
            }
            if (n == 0) {
                std::ranges::fill(out.subspan(done), std::byte{0});  // past the end
                break;
            }
            done += static_cast<std::size_t>(n);
        }
        return {};
    }
    auto pwrite(std::uint64_t offset, std::span<const std::byte> in) -> FileResult override {
        std::size_t done = 0;
        while (done < in.size()) {
            const auto n = ::pwrite(_fd.get(), in.data() + done, in.size() - done,
                                    static_cast<off_t>(offset + done));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected(errno);
            }
            done += static_cast<std::size_t>(n);
        }
        return {};
    }
    auto sync() -> FileResult override {
        if (::fdatasync(_fd.get()) != 0) {
            return std::unexpected(errno);
        }
        return {};
    }
    auto truncate(std::uint64_t size) -> FileResult override {
        if (::ftruncate(_fd.get(), static_cast<off_t>(size)) != 0) {
            return std::unexpected(errno);
        }
        return {};
    }
    [[nodiscard]] auto size() const -> std::expected<std::uint64_t, int> override {
        struct stat st{};
        if (::fstat(_fd.get(), &st) != 0) {
            return std::unexpected(errno);
        }
        return static_cast<std::uint64_t>(st.st_size);
    }

private:
    Fd _fd;
};

auto key(const std::filesystem::path& p) -> std::string {
    return p.lexically_normal().string();
}

// A sector-aligned prefix of a write: what a torn write may leave.
auto torn(const MemFiles::Pending& p, std::minstd_rand& rng) -> MemFiles::Pending {
    if (p.truncate || p.bytes.size() <= sector) {
        return p;
    }
    const std::size_t sectors = (p.bytes.size() + sector - 1) / sector;
    const std::size_t keep = std::min(p.bytes.size(), (rng() % sectors) * sector);
    return {.offset = p.offset,
            .bytes = {p.bytes.begin(), p.bytes.begin() + static_cast<std::ptrdiff_t>(keep)},
            .truncate = false};
}

auto apply(std::vector<std::byte>& file, const MemFiles::Pending& p) -> void {
    if (p.truncate) {
        file.resize(p.offset);
        return;
    }
    if (file.size() < p.offset + p.bytes.size()) {
        file.resize(p.offset + p.bytes.size());
    }
    std::ranges::copy(p.bytes, file.begin() + static_cast<std::ptrdiff_t>(p.offset));
}

class MemFile final : public File {
public:
    MemFile(MemFiles& layer, std::shared_ptr<MemFiles::State> state) noexcept
        : _layer{&layer}, _state{std::move(state)} {}

    auto pread(std::uint64_t offset, std::span<std::byte> out) -> FileResult override {
        const auto& f = _state->current;
        const std::size_t have =
            offset < f.size() ? std::min<std::size_t>(out.size(), f.size() - offset) : 0;
        std::copy_n(f.begin() + static_cast<std::ptrdiff_t>(offset), have, out.begin());
        std::fill(out.begin() + static_cast<std::ptrdiff_t>(have), out.end(), std::byte{0});
        return {};
    }
    auto pwrite(std::uint64_t offset, std::span<const std::byte> in) -> FileResult override {
        if (!_layer->step()) {
            return std::unexpected(EIO);
        }
        MemFiles::Pending p{.offset = offset, .bytes = {in.begin(), in.end()}, .truncate = false};
        apply(_state->current, p);
        _state->pending.push_back(std::move(p));
        return {};
    }
    auto sync() -> FileResult override {
        if (!_layer->step()) {
            return std::unexpected(EIO);
        }
        for (const auto& p : _state->pending) {
            apply(_state->durable, p);
        }
        _state->pending.clear();
        return {};
    }
    auto truncate(std::uint64_t size) -> FileResult override {
        if (!_layer->step()) {
            return std::unexpected(EIO);
        }
        MemFiles::Pending p{.offset = size, .bytes = {}, .truncate = true};
        apply(_state->current, p);
        _state->pending.push_back(std::move(p));
        return {};
    }
    [[nodiscard]] auto size() const -> std::expected<std::uint64_t, int> override {
        return _state->current.size();
    }

private:
    MemFiles* _layer;
    std::shared_ptr<MemFiles::State> _state;
};

}  // namespace

// ---- PosixFiles ------------------------------------------------------------

auto PosixFiles::make_dir(const std::filesystem::path& dir) -> FileResult {
    if (::mkdir(dir.c_str(), dir_mode) != 0) {
        return std::unexpected(errno);
    }
    return {};
}

auto PosixFiles::exists(const std::filesystem::path& p) const -> bool {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

auto PosixFiles::open(const std::filesystem::path& p, bool create)
    -> std::expected<std::unique_ptr<File>, int> {
    const int flags = O_RDWR | O_CLOEXEC | (create ? (O_CREAT | O_EXCL) : 0);
    const int fd = ::open(p.c_str(), flags, file_mode);
    if (fd < 0) {
        return std::unexpected(errno);
    }
    return std::make_unique<PosixFile>(Fd{fd});
}

auto PosixFiles::remove_all(const std::filesystem::path& p) -> FileResult {
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
    if (ec) {
        return std::unexpected(ec.value());
    }
    return {};
}

auto PosixFiles::clone(const std::filesystem::path& from, const std::filesystem::path& to)
    -> FileResult {
    const Fd src{::open(from.c_str(), O_RDONLY | O_CLOEXEC)};
    if (src.get() < 0) {
        return std::unexpected(errno);
    }
    const Fd dst{::open(to.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, file_mode)};
    if (dst.get() < 0) {
        return std::unexpected(errno);
    }
    if (::ioctl(dst.get(), FICLONE, src.get()) != 0) {
        const int err = errno;
        ::unlink(to.c_str());
        return std::unexpected(err);
    }
    return {};
}

auto PosixFiles::sync_dir(const std::filesystem::path& dir) -> FileResult {
    const Fd fd{::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    if (fd.get() < 0) {
        return std::unexpected(errno);
    }
    if (::fsync(fd.get()) != 0) {
        return std::unexpected(errno);
    }
    return {};
}

auto PosixFiles::rename(const std::filesystem::path& from, const std::filesystem::path& to)
    -> FileResult {
    if (::rename(from.c_str(), to.c_str()) != 0) {
        return std::unexpected(errno);
    }
    return {};
}

// ---- MemFiles --------------------------------------------------------------

auto MemFiles::step() -> bool {
    if (_failed) {
        return false;
    }
    ++_ops;
    if (_fail_in != 0) {
        --_fail_in;
        if (_fail_in == 0) {
            _failed = true;
            return false;
        }
    }
    return true;
}

auto MemFiles::make_dir(const std::filesystem::path& dir) -> FileResult {
    if (!step()) {
        return std::unexpected(EIO);
    }
    if (!_dirs.insert(key(dir)).second) {
        return std::unexpected(EEXIST);
    }
    return {};
}

auto MemFiles::exists(const std::filesystem::path& p) const -> bool {
    return _dirs.contains(key(p)) || _files.contains(key(p));
}

auto MemFiles::open(const std::filesystem::path& p, bool create)
    -> std::expected<std::unique_ptr<File>, int> {
    const auto k = key(p);
    auto it = _files.find(k);
    if (create) {
        if (it != _files.end()) {
            return std::unexpected(EEXIST);
        }
        if (!step()) {
            return std::unexpected(EIO);
        }
        it = _files.emplace(k, std::make_shared<State>()).first;
    } else if (it == _files.end()) {
        return std::unexpected(ENOENT);
    }
    return std::make_unique<MemFile>(*this, it->second);
}

auto MemFiles::remove_all(const std::filesystem::path& p) -> FileResult {
    if (!step()) {
        return std::unexpected(EIO);
    }
    const auto prefix = key(p);
    std::erase_if(_files, [&](const auto& kv) {
        return kv.first == prefix || kv.first.starts_with(prefix + "/");
    });
    std::erase_if(_dirs,
                  [&](const std::string& d) { return d == prefix || d.starts_with(prefix + "/"); });
    return {};
}

auto MemFiles::clone(const std::filesystem::path& from, const std::filesystem::path& to)
    -> FileResult {
    if (!_reflink) {
        return std::unexpected(EOPNOTSUPP);
    }
    const auto src = _files.find(key(from));
    if (src == _files.end()) {
        return std::unexpected(ENOENT);
    }
    if (_files.contains(key(to))) {
        return std::unexpected(EEXIST);
    }
    if (!step()) {
        return std::unexpected(EIO);
    }
    // A reflink copies what the source holds now; both durable at once.
    auto copy = std::make_shared<State>();
    copy->current = src->second->current;
    copy->durable = src->second->current;
    _files.emplace(key(to), std::move(copy));
    return {};
}

auto MemFiles::sync_dir(const std::filesystem::path& /*dir*/) -> FileResult {
    if (!step()) {
        return std::unexpected(EIO);
    }
    return {};
}

auto MemFiles::rename(const std::filesystem::path& from, const std::filesystem::path& to)
    -> FileResult {
    const auto src = _files.find(key(from));
    if (src == _files.end()) {
        return std::unexpected(ENOENT);
    }
    if (!step()) {
        return std::unexpected(EIO);
    }
    auto state = src->second;
    _files.erase(src);
    _files.insert_or_assign(key(to), std::move(state));
    return {};
}

auto MemFiles::crash(std::uint64_t seed) -> void {
    std::minstd_rand rng{static_cast<std::minstd_rand::result_type>(seed | 1U)};
    for (auto& [name, f] : _files) {
        auto next = f->durable;
        for (const auto& p : f->pending) {
            switch (rng() % 3) {
                case 0:
                    break;  // lost
                case 1:
                    apply(next, p);
                    break;
                default:
                    apply(next, torn(p, rng));
                    break;
            }
        }
        f->durable = next;
        f->current = std::move(next);
        f->pending.clear();
    }
    _fail_in = 0;
    _failed = false;
}

auto MemFiles::contents(const std::filesystem::path& p) const -> std::vector<std::byte> {
    const auto it = _files.find(key(p));
    return it == _files.end() ? std::vector<std::byte>{} : it->second->current;
}

}  // namespace ak::hold::store
