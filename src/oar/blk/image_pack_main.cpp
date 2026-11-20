// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-image-pack: turns a raw disk image into the two objects of an image
// volume (.kiro/specs/oar-blk-data-plane/ task 12, design "Image format").
//
//   ak-image-pack --out DIR [--block-size 512|4096] [--chunk-shift 16..22]
//                 [--key-file PATH --key-id HEX32] IMAGE
//
// Writes DIR/<name>/manifest and DIR/<name>/data, where <name> is the
// image name (the manifest's SHA-256, 64 hex digits), and prints the name
// on stdout. The data object is sparse: chunks of zeros are holes, never
// stored. Upload the directory as-is under the image prefix, for example
//
//   aws s3 cp --recursive DIR/<name> s3://BUCKET/PREFIX/<name>
//
// The tool only writes local files. Write credentials for the bucket stay
// with whoever publishes images; the storage role only ever holds
// read-only ones (Requirement 8.9).
//
// --key-file encrypts the image under an AES-256-XTS image key: the file
// holds exactly the 64 raw key bytes (data key, then tweak key). --key-id
// is the 16-byte ID helm knows the wrapped key by, as 32 hex digits; it
// goes into the manifest. The key is held in a locked, undumpable page
// (KeySlot) while packing.
//
// The output appears atomically: everything is written and synced in a
// temporary directory under DIR, then renamed to DIR/<name>. Packing is
// deterministic, so if DIR/<name> already exists it already holds this
// image and is left as it is.

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "oar/blk/file_io.hpp"
#include "oar/blk/image_manifest.hpp"
#include "oar/blk/image_pack.hpp"
#include "oar/blk/key_slot.hpp"
#include "oar/blk/xts_cipher.hpp"

namespace {

namespace blk = ak::oar::blk;
namespace fs = std::filesystem;

constexpr std::string_view log_name = "ak-image-pack";
constexpr std::string_view arg_out = "--out";
constexpr std::string_view arg_block_size = "--block-size";
constexpr std::string_view arg_chunk_shift = "--chunk-shift";
constexpr std::string_view arg_key_file = "--key-file";
constexpr std::string_view arg_key_id = "--key-id";
constexpr int exit_usage = 2;
constexpr int base_decimal = 10;
constexpr int hex_digit_bits = 4;
constexpr unsigned hex_letter_offset = 10;

auto usage() -> int {
    std::println(stderr, "usage: {} {} DIR [{} 512|4096] [{} 16..22] [{} PATH {} HEX32] IMAGE",
                 log_name, arg_out, arg_block_size, arg_chunk_shift, arg_key_file, arg_key_id);
    return exit_usage;
}

auto fail(std::string_view what, int err) -> int {
    std::println(stderr, "{}: {}: {}", log_name, what, std::strerror(err));
    return EXIT_FAILURE;
}

auto parse_u32(std::string_view s) -> std::optional<std::uint32_t> {
    const std::string text{s};
    char* end = nullptr;
    errno = 0;
    const unsigned long v = std::strtoul(text.c_str(), &end, base_decimal);
    if (errno != 0 || end == text.c_str() || *end != '\0' || v > UINT32_MAX) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(v);
}

auto hex_value(char c) -> std::optional<unsigned> {
    if (c >= '0' && c <= '9') {
        return static_cast<unsigned>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<unsigned>(c - 'a') + hex_letter_offset;
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<unsigned>(c - 'A') + hex_letter_offset;
    }
    return std::nullopt;
}

auto parse_key_id(std::string_view s) -> std::optional<blk::ImageKeyId> {
    blk::ImageKeyId id{};
    if (s.size() != id.size() * 2) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < id.size(); ++i) {
        const auto hi = hex_value(s[2 * i]);
        const auto lo = hex_value(s[(2 * i) + 1]);
        if (!hi || !lo) {
            return std::nullopt;
        }
        id[i] = static_cast<std::byte>((*hi << hex_digit_bits) | *lo);
    }
    return id;
}

// Owns a file descriptor.
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

// Removes the temporary directory unless it was renamed into place.
class TempDir {
public:
    explicit TempDir(fs::path path) : _path{std::move(path)} {}
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        if (!_kept) {
            std::error_code ec;
            fs::remove_all(_path, ec);
        }
    }
    [[nodiscard]] auto path() const -> const fs::path& { return _path; }
    auto keep() noexcept -> void { _kept = true; }

private:
    fs::path _path;
    bool _kept{false};
};

// Reads exactly one XTS key from `path` into `slot`.
auto load_key(const std::string& path, blk::KeySlot& slot) -> int {
    const Fd fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (!fd.ok()) {
        return fail(path, errno);
    }
    // One byte more than a key, to tell a long file from a key.
    std::array<std::byte, blk::xts_key_size + 1> buf{};
    const auto got = blk::file_io::pread_all(fd.get(), buf, 0);
    if (!got) {
        return fail(path, got.error());
    }
    int rc = EXIT_SUCCESS;
    if (*got != blk::xts_key_size) {
        std::println(stderr, "{}: {}: a key file holds exactly {} bytes", log_name, path,
                     blk::xts_key_size);
        rc = EXIT_FAILURE;
    } else if (!slot.load(std::span{buf}.first<blk::xts_key_size>())) {
        std::println(stderr, "{}: could not hold the image key", log_name);
        rc = EXIT_FAILURE;
    }
    OPENSSL_cleanse(buf.data(), buf.size());
    return rc;
}

auto write_and_sync(const fs::path& path, std::span<const std::byte> bytes) -> int {
    const Fd fd{::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644)};
    if (!fd.ok()) {
        return fail(path.string(), errno);
    }
    if (auto ok = blk::file_io::pwrite_all(fd.get(), bytes, 0); !ok) {
        return fail(path.string(), ok.error());
    }
    if (::fsync(fd.get()) != 0) {
        return fail(path.string(), errno);
    }
    return EXIT_SUCCESS;
}

struct Options {
    std::string out;
    std::string image;
    std::string key_file;
    std::optional<blk::ImageKeyId> key_id;
    blk::PackOptions pack;
};

auto parse_args(std::span<char*> args) -> std::optional<Options> {
    Options o;
    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string_view a = args[i];
        const bool has_value = i + 1 < args.size();
        if (a == arg_out && has_value) {
            o.out = args[++i];
        } else if (a == arg_block_size && has_value) {
            const auto v = parse_u32(args[++i]);
            if (!v) {
                return std::nullopt;
            }
            o.pack.logical_block_size = *v;
        } else if (a == arg_chunk_shift && has_value) {
            const auto v = parse_u32(args[++i]);
            if (!v || *v > UINT8_MAX) {
                return std::nullopt;
            }
            o.pack.chunk_shift = static_cast<std::uint8_t>(*v);
        } else if (a == arg_key_file && has_value) {
            o.key_file = args[++i];
        } else if (a == arg_key_id && has_value) {
            o.key_id = parse_key_id(args[++i]);
            if (!o.key_id) {
                return std::nullopt;
            }
        } else if (!a.starts_with("-") && o.image.empty()) {
            o.image = a;
        } else {
            return std::nullopt;
        }
    }
    if (o.out.empty() || o.image.empty() || o.key_file.empty() != !o.key_id) {
        return std::nullopt;
    }
    return o;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    auto parsed = parse_args(std::span{argv, static_cast<std::size_t>(argc)});
    if (!parsed) {
        return usage();
    }
    auto& o = *parsed;

    std::optional<blk::KeySlot> slot;
    if (!o.key_file.empty()) {
        auto s = blk::KeySlot::create();
        if (!s) {
            std::println(stderr, "{}: could not lock a page for the image key: {}", log_name,
                         blk::to_string(s.error()));
            return EXIT_FAILURE;
        }
        slot.emplace(std::move(*s));
        if (const int rc = load_key(o.key_file, *slot); rc != EXIT_SUCCESS) {
            return rc;
        }
        auto key = slot->key();
        if (!key) {
            return EXIT_FAILURE;
        }
        o.pack.image_key = *key;
        o.pack.key_id = *o.key_id;
    }

    const Fd image{::open(o.image.c_str(), O_RDONLY | O_CLOEXEC)};
    if (!image.ok()) {
        return fail(o.image, errno);
    }
    // SEEK_END gives the size of a regular file and of a block device alike.
    const off_t size = ::lseek(image.get(), 0, SEEK_END);
    if (size < 0) {
        return fail(o.image, errno);
    }

    std::string tmpl = (fs::path{o.out} / ".ak-image-pack-XXXXXX").string();
    if (::mkdtemp(tmpl.data()) == nullptr) {
        return fail(o.out, errno);
    }
    TempDir tmp{tmpl};
    const auto data_path = tmp.path() / "data";
    const Fd data{::open(data_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644)};
    if (!data.ok()) {
        return fail(data_path.string(), errno);
    }

    const auto packed =
        blk::pack_image(image.get(), static_cast<std::uint64_t>(size), data.get(), o.pack);
    if (slot) {
        o.pack.image_key.reset();
        slot->drop();
    }
    if (!packed) {
        switch (packed.error()) {
            case blk::PackError::bad_image_size:
                std::println(stderr, "{}: {}: size {} is not a non-zero multiple of {}", log_name,
                             o.image, size, o.pack.logical_block_size);
                break;
            case blk::PackError::too_many_chunks:
                std::println(stderr, "{}: {}: more than {} chunks; use a larger {}", log_name,
                             o.image, blk::max_image_chunks, arg_chunk_shift);
                break;
            default:
                std::println(stderr, "{}: {}: {}", log_name, o.image,
                             blk::to_string(packed.error()));
                break;
        }
        return EXIT_FAILURE;
    }
    if (::fsync(data.get()) != 0) {
        return fail(data_path.string(), errno);
    }
    if (const int rc = write_and_sync(tmp.path() / "manifest", packed->manifest_bytes);
        rc != EXIT_SUCCESS) {
        return rc;
    }

    const auto name = blk::image_name_hex(packed->name);
    const auto final_path = fs::path{o.out} / name;
    if (::rename(tmp.path().c_str(), final_path.c_str()) == 0) {
        tmp.keep();
    } else if (errno != EEXIST && errno != ENOTEMPTY) {
        return fail(final_path.string(), errno);
    }
    // Make the rename durable.
    if (const Fd dir{::open(o.out.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)}; dir.ok()) {
        ::fsync(dir.get());
    }

    const auto& m = packed->manifest;
    std::println(stderr, "{}: {} bytes, {} chunks of {} bytes, {} stored, {} holes{}", log_name,
                 m.image_bytes, m.chunk_count(), m.chunk_size(), packed->stored_chunks,
                 m.chunk_count() - packed->stored_chunks, m.encrypted ? ", encrypted" : "");
    std::println("{}", name);
    return EXIT_SUCCESS;
}
