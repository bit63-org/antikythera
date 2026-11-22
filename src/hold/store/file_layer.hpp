// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The files under a ReplicaStore (.kiro/specs/block-volume-service/ design
// "ReplicaStore", task 5): the few operations it needs, behind an interface
// so the same store runs on a real filesystem (PosixFiles) and on an
// in-memory layer that drops unsynced writes at a chosen step (MemFiles),
// which is how the crash-consistency tests reach every point of a write.
//
// Reads past the end of a file return zeros (files are sparse); sync() is
// fdatasync; clone() is FICLONE (a reflink copy), which fails with
// EOPNOTSUPP or EXDEV where the filesystem has none.

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace ak::hold::store {

using FileResult = std::expected<void, int>;  // errno on failure

class File {
public:
    File() = default;
    File(const File&) = delete;
    auto operator=(const File&) -> File& = delete;
    File(File&&) = delete;
    auto operator=(File&&) -> File& = delete;
    virtual ~File() = default;

    [[nodiscard]] virtual auto pread(std::uint64_t offset, std::span<std::byte> out)
        -> FileResult = 0;
    [[nodiscard]] virtual auto pwrite(std::uint64_t offset, std::span<const std::byte> in)
        -> FileResult = 0;
    [[nodiscard]] virtual auto sync() -> FileResult = 0;
    [[nodiscard]] virtual auto truncate(std::uint64_t size) -> FileResult = 0;
    [[nodiscard]] virtual auto size() const -> std::expected<std::uint64_t, int> = 0;
};

class FileLayer {
public:
    FileLayer() = default;
    FileLayer(const FileLayer&) = delete;
    auto operator=(const FileLayer&) -> FileLayer& = delete;
    FileLayer(FileLayer&&) = delete;
    auto operator=(FileLayer&&) -> FileLayer& = delete;
    virtual ~FileLayer() = default;

    // Fails with EEXIST if it is there already.
    [[nodiscard]] virtual auto make_dir(const std::filesystem::path& dir) -> FileResult = 0;
    [[nodiscard]] virtual auto exists(const std::filesystem::path& p) const -> bool = 0;
    [[nodiscard]] virtual auto open(const std::filesystem::path& p, bool create)
        -> std::expected<std::unique_ptr<File>, int> = 0;
    [[nodiscard]] virtual auto remove_all(const std::filesystem::path& p) -> FileResult = 0;
    [[nodiscard]] virtual auto clone(const std::filesystem::path& from,
                                     const std::filesystem::path& to) -> FileResult = 0;
    // Makes a directory's entries (new files, removals) durable.
    [[nodiscard]] virtual auto sync_dir(const std::filesystem::path& dir) -> FileResult = 0;
};

class PosixFiles final : public FileLayer {
public:
    auto make_dir(const std::filesystem::path& dir) -> FileResult override;
    auto exists(const std::filesystem::path& p) const -> bool override;
    auto open(const std::filesystem::path& p, bool create)
        -> std::expected<std::unique_ptr<File>, int> override;
    auto remove_all(const std::filesystem::path& p) -> FileResult override;
    auto clone(const std::filesystem::path& from, const std::filesystem::path& to)
        -> FileResult override;
    auto sync_dir(const std::filesystem::path& dir) -> FileResult override;
};

// Files in memory with a crash model. Each file keeps what is durable and
// the writes since its last sync. crash() keeps a random subset of those
// unsynced writes (each possibly torn at 512-byte sectors), drops the rest
// and makes the result the new durable state, as power loss can. With
// fail_after(n), the n-th mutating operation from now and every later one
// fail with EIO without taking effect: the moment of the crash.
class MemFiles final : public FileLayer {
public:
    explicit MemFiles(bool reflink = true) : _reflink{reflink} {}

    auto make_dir(const std::filesystem::path& dir) -> FileResult override;
    auto exists(const std::filesystem::path& p) const -> bool override;
    auto open(const std::filesystem::path& p, bool create)
        -> std::expected<std::unique_ptr<File>, int> override;
    auto remove_all(const std::filesystem::path& p) -> FileResult override;
    auto clone(const std::filesystem::path& from, const std::filesystem::path& to)
        -> FileResult override;
    auto sync_dir(const std::filesystem::path& dir) -> FileResult override;

    auto fail_after(std::uint64_t ops) -> void { _fail_in = ops; }
    // Power loss: see above. Clears fail_after. Open File handles keep
    // working on the new state, but a store should be reopened.
    auto crash(std::uint64_t seed) -> void;
    // Mutating operations so far (to enumerate crash points).
    [[nodiscard]] auto ops() const noexcept -> std::uint64_t { return _ops; }
    // Every byte that differs from zero in a file (tests).
    [[nodiscard]] auto contents(const std::filesystem::path& p) const -> std::vector<std::byte>;

    struct Pending {
        std::uint64_t offset{0};
        std::vector<std::byte> bytes;
        bool truncate{false};
    };
    struct State {
        std::vector<std::byte> durable;
        std::vector<std::byte> current;
        std::vector<Pending> pending;
    };

    // For MemFile: counts the operation; false once the crash point is hit.
    [[nodiscard]] auto step() -> bool;

private:
    bool _reflink;
    std::map<std::string, std::shared_ptr<State>> _files;
    std::set<std::string> _dirs;
    std::uint64_t _ops{0};
    std::uint64_t _fail_in{0};  // 0: never
    bool _failed{false};
};

}  // namespace ak::hold::store
