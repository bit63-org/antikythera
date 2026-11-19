// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/file_backend.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>
#include <utility>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "common/wire.hpp"

namespace ak::oar::blk {

namespace {

namespace wire = ak::wire;

// "AKBLKVOL"
constexpr std::array<std::byte, 8> magic{std::byte{'A'}, std::byte{'K'}, std::byte{'B'},
                                         std::byte{'L'}, std::byte{'K'}, std::byte{'V'},
                                         std::byte{'O'}, std::byte{'L'}};
constexpr std::size_t digest_size = 32;  // SHA-256
// magic, version, key length, block size, volume, owner, capacity, key.
constexpr std::size_t fields_size = 8 + 2 + 2 + 4 + 8 + 8 + 8 + max_wrapped_key_size;
constexpr std::size_t digest_offset = fields_size;
constexpr std::size_t used_size = fields_size + digest_size;
static_assert(used_size <= metadata_block_size);

constexpr std::uint32_t block_512 = 512;
constexpr std::uint32_t block_4k = 4096;
// The data must end at an offset off_t can hold.
constexpr std::uint64_t max_capacity_sectors =
    (static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()) - volume_data_offset) /
    sector_size;
constexpr mode_t volume_file_mode = 0600;

using Block = std::array<std::byte, metadata_block_size>;

auto sha256(std::span<const std::byte> in, std::span<std::byte, digest_size> out) -> bool {
    unsigned int len = 0;
    return EVP_Digest(in.data(), in.size(), reinterpret_cast<unsigned char*>(out.data()), &len,
                      EVP_sha256(), nullptr) == 1 &&
           len == digest_size;
}

auto check_fields(const VolumeMetadata& m) -> std::expected<void, MetadataError> {
    if (m.volume_id == 0 || m.owner_vm == 0) {
        return std::unexpected(MetadataError::zero_id);
    }
    if (m.logical_block_size != block_512 && m.logical_block_size != block_4k) {
        return std::unexpected(MetadataError::bad_block_size);
    }
    if (m.capacity_sectors == 0 || m.capacity_sectors > max_capacity_sectors ||
        m.capacity_sectors % (m.logical_block_size / sector_size) != 0) {
        return std::unexpected(MetadataError::bad_capacity);
    }
    if (m.wrapped_key.empty() || m.wrapped_key.size() > max_wrapped_key_size) {
        return std::unexpected(MetadataError::bad_key_length);
    }
    return {};
}

auto io_failure(int err = errno) -> std::unexpected<FileFailure> {
    return std::unexpected(FileFailure{.error = FileError::io, .os_error = err});
}

auto metadata_failure(MetadataError e) -> std::unexpected<FileFailure> {
    return std::unexpected(FileFailure{.error = FileError::bad_metadata, .metadata_error = e});
}

// Opening refuses symlinks (O_NOFOLLOW) and maps the usual errors.
auto open_volume(const std::filesystem::path& path, int flags) -> std::expected<int, FileFailure> {
    const int fd = ::open(path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW, volume_file_mode);
    if (fd >= 0) {
        struct stat st{};
        if (::fstat(fd, &st) != 0) {
            const int err = errno;
            ::close(fd);
            return io_failure(err);
        }
        if (!S_ISREG(st.st_mode)) {
            ::close(fd);
            return std::unexpected(FileFailure{.error = FileError::not_regular});
        }
        return fd;
    }
    switch (errno) {
        case EEXIST:
            return std::unexpected(FileFailure{.error = FileError::exists});
        case ENOENT:
            return std::unexpected(FileFailure{.error = FileError::not_found});
        case ELOOP:
            return std::unexpected(FileFailure{.error = FileError::not_regular});
        default:
            return io_failure();
    }
}

// Whole-buffer pread/pwrite, retrying on EINTR and short transfers.
auto pread_all(int fd, std::span<std::byte> out, off_t at) -> std::expected<std::size_t, int> {
    std::size_t done = 0;
    while (done < out.size()) {
        const ssize_t n =
            ::pread(fd, out.data() + done, out.size() - done, at + static_cast<off_t>(done));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(errno);
        }
        if (n == 0) {
            break;  // end of file
        }
        done += static_cast<std::size_t>(n);
    }
    return done;
}

auto pwrite_all(int fd, std::span<const std::byte> in, off_t at) -> std::expected<void, int> {
    std::size_t done = 0;
    while (done < in.size()) {
        const ssize_t n =
            ::pwrite(fd, in.data() + done, in.size() - done, at + static_cast<off_t>(done));
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

auto sync_parent(const std::filesystem::path& path) -> std::expected<void, int> {
    const std::filesystem::path dir = path.has_parent_path() ? path.parent_path() : ".";
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(errno);
    }
    const int rc = ::fsync(fd);
    const int err = errno;
    ::close(fd);
    if (rc != 0) {
        return std::unexpected(err);
    }
    return {};
}

auto file_size(const VolumeMetadata& m) -> off_t {
    // check_fields bounds capacity so this cannot overflow.
    return static_cast<off_t>(volume_data_offset + (m.capacity_sectors * sector_size));
}

}  // namespace

auto to_string(MetadataError e) noexcept -> const char* {
    switch (e) {
        case MetadataError::wrong_size:
            return "wrong_size";
        case MetadataError::bad_magic:
            return "bad_magic";
        case MetadataError::unsupported_version:
            return "unsupported_version";
        case MetadataError::bad_digest:
            return "bad_digest";
        case MetadataError::zero_id:
            return "zero_id";
        case MetadataError::bad_block_size:
            return "bad_block_size";
        case MetadataError::bad_capacity:
            return "bad_capacity";
        case MetadataError::bad_key_length:
            return "bad_key_length";
        case MetadataError::nonzero_padding:
            return "nonzero_padding";
        case MetadataError::crypto_failure:
            return "crypto_failure";
    }
    return "unknown";
}

auto to_string(FileError e) noexcept -> const char* {
    switch (e) {
        case FileError::bad_metadata:
            return "bad_metadata";
        case FileError::exists:
            return "exists";
        case FileError::not_found:
            return "not_found";
        case FileError::not_regular:
            return "not_regular";
        case FileError::size_mismatch:
            return "size_mismatch";
        case FileError::io:
            return "io";
    }
    return "unknown";
}

auto encode_metadata(const VolumeMetadata& m) -> std::expected<Block, MetadataError> {
    if (auto ok = check_fields(m); !ok) {
        return std::unexpected(ok.error());
    }
    std::vector<std::byte> fields;
    fields.reserve(used_size);
    wire::Writer w{fields};
    w.bytes(magic);
    w.le16(metadata_version);
    w.le16(static_cast<std::uint16_t>(m.wrapped_key.size()));
    w.le32(m.logical_block_size);
    w.le64(m.volume_id);
    w.le64(m.owner_vm);
    w.le64(m.capacity_sectors);
    w.bytes(m.wrapped_key);
    fields.resize(fields_size, std::byte{0});

    Block block{};
    std::ranges::copy(fields, block.begin());
    if (!sha256(fields, std::span{block}.subspan<digest_offset, digest_size>())) {
        return std::unexpected(MetadataError::crypto_failure);
    }
    return block;
}

auto decode_metadata(std::span<const std::byte> block)
    -> std::expected<VolumeMetadata, MetadataError> {
    if (block.size() != metadata_block_size) {
        return std::unexpected(MetadataError::wrong_size);
    }
    if (!std::ranges::equal(block.first(magic.size()), magic)) {
        return std::unexpected(MetadataError::bad_magic);
    }
    wire::Reader r{block.subspan(magic.size())};
    const auto version = r.le16();
    const auto key_len = r.le16();
    const auto lbs = r.le32();
    const auto volume = r.le64();
    const auto owner = r.le64();
    const auto capacity = r.le64();
    const auto key = r.bytes(max_wrapped_key_size);
    if (!version || !key_len || !lbs || !volume || !owner || !capacity || !key) {
        return std::unexpected(MetadataError::wrong_size);  // unreachable: the block is 4 KiB
    }
    if (*version != metadata_version) {
        return std::unexpected(MetadataError::unsupported_version);
    }
    // The digest before anything else is trusted: a corrupt header is
    // reported as corrupt, not as whichever field happened to break.
    std::array<std::byte, digest_size> digest{};
    if (!sha256(block.first(fields_size), digest)) {
        return std::unexpected(MetadataError::crypto_failure);
    }
    if (!std::ranges::equal(digest, block.subspan(digest_offset, digest_size))) {
        return std::unexpected(MetadataError::bad_digest);
    }
    if (*key_len == 0 || *key_len > max_wrapped_key_size) {
        return std::unexpected(MetadataError::bad_key_length);
    }
    const auto is_zero = [](std::byte b) { return b == std::byte{0}; };
    if (!std::ranges::all_of(key->subspan(*key_len), is_zero) ||
        !std::ranges::all_of(block.subspan(used_size), is_zero)) {
        return std::unexpected(MetadataError::nonzero_padding);
    }
    VolumeMetadata m{.volume_id = *volume,
                     .owner_vm = *owner,
                     .capacity_sectors = *capacity,
                     .logical_block_size = *lbs,
                     .wrapped_key = {key->begin(), key->begin() + *key_len}};
    if (auto ok = check_fields(m); !ok) {
        return std::unexpected(ok.error());
    }
    return m;
}

auto FileBackend::create(const std::filesystem::path& path, const VolumeMetadata& m)
    -> std::expected<std::unique_ptr<FileBackend>, FileFailure> {
    const auto block = encode_metadata(m);
    if (!block) {
        return metadata_failure(block.error());
    }
    auto fd = open_volume(path, O_RDWR | O_CREAT | O_EXCL);
    if (!fd) {
        return std::unexpected(fd.error());
    }
    // From here a failure removes the half-made file.
    auto abandon = [&](int err) {
        ::close(*fd);
        ::unlink(path.c_str());
        return io_failure(err);
    };
    if (auto w = pwrite_all(*fd, *block, 0); !w) {
        return abandon(w.error());
    }
    if (::ftruncate(*fd, file_size(m)) != 0 || ::fsync(*fd) != 0) {
        return abandon(errno);
    }
    if (auto s = sync_parent(path); !s) {
        return abandon(s.error());
    }
    return std::unique_ptr<FileBackend>(new FileBackend(*fd, m));
}

auto FileBackend::open(const std::filesystem::path& path)
    -> std::expected<std::unique_ptr<FileBackend>, FileFailure> {
    auto fd = open_volume(path, O_RDWR);
    if (!fd) {
        return std::unexpected(fd.error());
    }
    auto fail = [&](std::unexpected<FileFailure> f) {
        ::close(*fd);
        return f;
    };
    Block block{};
    const auto got = pread_all(*fd, block, 0);
    if (!got) {
        return fail(io_failure(got.error()));
    }
    if (*got != block.size()) {
        return fail(metadata_failure(MetadataError::wrong_size));
    }
    auto m = decode_metadata(block);
    if (!m) {
        return fail(metadata_failure(m.error()));
    }
    struct stat st{};
    if (::fstat(*fd, &st) != 0) {
        return fail(io_failure());
    }
    if (st.st_size != file_size(*m)) {
        return fail(std::unexpected(FileFailure{.error = FileError::size_mismatch}));
    }
    return std::unique_ptr<FileBackend>(new FileBackend(*fd, std::move(*m)));
}

auto FileBackend::erase(const std::filesystem::path& path) -> std::expected<void, FileFailure> {
    auto fd = open_volume(path, O_RDWR);
    if (!fd) {
        return std::unexpected(fd.error());
    }
    const Block zeros{};
    const auto w = pwrite_all(*fd, zeros, 0);
    const int sync_rc = w ? ::fdatasync(*fd) : -1;
    const int err = !w ? w.error() : errno;
    ::close(*fd);
    if (!w || sync_rc != 0) {
        return io_failure(err);  // the file stays, so erase can be retried
    }
    if (::unlink(path.c_str()) != 0) {
        return io_failure();
    }
    if (auto s = sync_parent(path); !s) {
        return io_failure(s.error());
    }
    return {};
}

FileBackend::~FileBackend() {
    if (_fd >= 0) {
        ::close(_fd);
    }
}

auto FileBackend::rewrap(std::uint64_t owner_vm, std::span<const std::byte> wrapped_key)
    -> std::expected<void, FileFailure> {
    VolumeMetadata next = _metadata;
    next.owner_vm = owner_vm;
    next.wrapped_key.assign(wrapped_key.begin(), wrapped_key.end());
    const auto block = encode_metadata(next);
    if (!block) {
        return metadata_failure(block.error());
    }
    if (auto w = pwrite_all(_fd, *block, 0); !w) {
        return io_failure(w.error());
    }
    if (::fdatasync(_fd) != 0) {
        return io_failure();
    }
    _metadata = std::move(next);
    return {};
}

auto FileBackend::size_bytes() const noexcept -> std::uint64_t {
    return _metadata.capacity_sectors * sector_size;
}

auto FileBackend::in_range(std::uint64_t offset, std::size_t len) const noexcept -> bool {
    const std::uint64_t size = size_bytes();
    return offset <= size && len <= size - offset;
}

auto FileBackend::read(std::uint64_t offset, std::span<std::byte> out)
    -> std::expected<void, BackendError> {
    if (!in_range(offset, out.size())) {
        return std::unexpected(BackendError::out_of_range);
    }
    const auto got = pread_all(_fd, out, static_cast<off_t>(volume_data_offset + offset));
    if (!got || *got != out.size()) {
        return std::unexpected(BackendError::io);  // a short read means the file shrank
    }
    return {};
}

auto FileBackend::write(std::uint64_t offset, std::span<const std::byte> in)
    -> std::expected<void, BackendError> {
    if (!in_range(offset, in.size())) {
        return std::unexpected(BackendError::out_of_range);
    }
    if (!pwrite_all(_fd, in, static_cast<off_t>(volume_data_offset + offset))) {
        return std::unexpected(BackendError::io);
    }
    return {};
}

auto FileBackend::flush() -> std::expected<void, BackendError> {
    if (::fdatasync(_fd) != 0) {
        return std::unexpected(BackendError::io);
    }
    return {};
}

}  // namespace ak::oar::blk
