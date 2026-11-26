// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The khold role's storage self-test (kythira .kiro/specs/khold-block-service/
// Requirement 12.1, task 17): what each drive holds and can do, and how fast
// the storage link is, measured rather than assumed (Requirement 12.3).
// The role runs it when it starts, when it takes a new certificate
// (enrollment), and whenever the controller asks (a self_test record), and
// reports the result as a proto::Capacity.
//
// Per drive, in a scratch file on the drive's directory:
//
//   capacity    statvfs: the file system's size (f_blocks x f_frsize)
//   write MiB/s sequential 1 MiB writes over `file_bytes`, then fdatasync
//   read MiB/s  sequential 1 MiB reads of the same file
//   write IOPS  random 4 KiB writes for `phase_budget`, then fdatasync
//               (the sync is inside the timed window, as khold syncs
//               before it acknowledges)
//   read IOPS   random 4 KiB reads for `phase_budget`
//
// The file is opened with O_DIRECT where the file system allows it, so
// reads come from the drive, not the page cache; where it does not
// (tmpfs, some overlay mounts), the test falls back to buffered I/O and
// drops the file's pages before each read phase, which is less exact but
// still not a cache-speed fantasy. The scratch file is removed afterwards
// whatever happens. A drive whose directory cannot be used, or whose I/O
// fails, is reported with state failed and zero measurements, so the
// controller places nothing new there.
//
// The link speed is the storage interface's /sys/class/net/IF/speed in
// Mb/s; unreadable or negative (no carrier, a virtual NIC that does not
// say) is reported as 0, unknown, unless the configuration overrides it.
//
// The defaults keep the whole test short (about a second per drive plus
// the sequential passes): it runs beside live traffic and must not take a
// drive away from it for long.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "proto/report.hpp"

namespace ak::khold {

struct DriveSpec {
    std::uint8_t drive{0};      // the drive number the khold node uses
    std::filesystem::path dir;  // a directory on that drive's file system
    friend auto operator==(const DriveSpec&, const DriveSpec&) -> bool = default;
};

struct SelfTestConfig {
    std::vector<DriveSpec> drives;  // strictly increasing drive
    // The storage segment's interface; empty: no link measured.
    std::string link_interface;
    // Non-zero: report this link speed instead of reading it.
    std::uint32_t link_mbps{0};
    std::filesystem::path sys_class_net{"/sys/class/net"};
    // Size of the sequential passes' scratch file.
    std::uint64_t file_bytes{std::uint64_t{64} << 20U};
    // How long each random phase runs.
    std::chrono::milliseconds phase_budget{std::chrono::milliseconds{250}};
};

// The link speed in Mb/s, or 0 when it cannot be read.
[[nodiscard]] auto read_link_mbps(const std::filesystem::path& sys_class_net,
                                  const std::string& interface) -> std::uint32_t;

// Measures one drive. Never throws; a failure is a failed drive.
[[nodiscard]] auto measure_drive(const DriveSpec& drive, std::uint64_t file_bytes,
                                 std::chrono::milliseconds phase_budget) -> proto::DriveCapacity;

// Runs the whole test: every drive, then the link. Slot 0 (helm stamps
// the role's slot when it relays the report).
[[nodiscard]] auto run_self_test(const SelfTestConfig& config) -> proto::Capacity;

}  // namespace ak::khold
