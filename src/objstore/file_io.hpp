// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Whole-buffer pread/pwrite for the image volume files (chunk cache and
// overlay), retrying on EINTR and short transfers.

#include <cerrno>
#include <cstddef>
#include <expected>
#include <span>

#include <sys/types.h>
#include <unistd.h>

namespace ak::objstore::file_io {

// Bytes read: out.size(), or fewer at end of file.
inline auto pread_all(int fd, std::span<std::byte> out, off_t at)
    -> std::expected<std::size_t, int> {
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
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    return done;
}

inline auto pwrite_all(int fd, std::span<const std::byte> in, off_t at)
    -> std::expected<void, int> {
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

}  // namespace ak::objstore::file_io
