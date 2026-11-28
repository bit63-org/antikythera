// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 4.1 (task 4): the boot
// function's disk. GPT headers and entries with their CRCs, the FAT32 ESP
// with the UKI on the removable boot path (read back by following its
// cluster chain), the provisioning partition, determinism, and sizing.

#define BOOST_TEST_MODULE boot_function_test
#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "helm/boot_function.hpp"
#include "helm/flash.hpp"
#include "proto/provisioning.hpp"
#include "test_support.hpp"

namespace helm = ak::helm;
namespace proto = ak::proto;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::size_t sec = helm::boot_sector_size;

auto u16(std::span<const std::byte> b, std::size_t at) -> std::uint16_t {
    return static_cast<std::uint16_t>(std::to_integer<unsigned>(b[at]) |
                                      (std::to_integer<unsigned>(b[at + 1]) << 8U));
}
auto u32(std::span<const std::byte> b, std::size_t at) -> std::uint32_t {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        v |= std::to_integer<std::uint32_t>(b[at + i]) << (8 * i);
    }
    return v;
}
auto u64(std::span<const std::byte> b, std::size_t at) -> std::uint64_t {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        v |= std::to_integer<std::uint64_t>(b[at + i]) << (8 * i);
    }
    return v;
}
auto text(std::span<const std::byte> b, std::size_t at, std::size_t n) -> std::string {
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(static_cast<char>(b[at + i]));
    }
    return s;
}

auto uki_of(std::size_t n) -> std::vector<std::byte> {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = std::byte{static_cast<std::uint8_t>((i * 7) ^ (i >> 9))};
    }
    return v;
}

const proto::Provisioning prov{.server_id = 7, .boot_epoch = 3, .sequence_floor = 0x40};

auto disk_of(std::span<const std::byte> uki, helm::BootArch arch = helm::BootArch::x86_64)
    -> std::vector<std::byte> {
    helm::MemoryFlash f{helm::boot_disk_size(uki.size())};
    auto ok = helm::write_boot_disk(f, uki, prov, arch);
    BOOST_REQUIRE_MESSAGE(ok.has_value(), (ok ? "" : helm::to_string(ok.error())));
    return f.bytes();
}

struct Gpt {
    std::uint64_t esp_first{0};
    std::uint64_t esp_last{0};
    std::uint64_t prov_first{0};
    std::uint64_t prov_last{0};
};

// Checks a GPT header at `lba` and its entries; returns the partitions.
auto check_gpt(std::span<const std::byte> d, std::uint64_t lba, std::uint64_t other) -> Gpt {
    const auto h = d.subspan(static_cast<std::size_t>(lba * sec), sec);
    BOOST_TEST(text(h, 0, 8) == "EFI PART");
    BOOST_TEST(u32(h, 12) == 92U);
    std::vector<std::byte> copy(h.begin(), h.begin() + 92);
    for (std::size_t i = 16; i < 20; ++i) {
        copy[i] = std::byte{0};
    }
    BOOST_TEST(u32(h, 16) == helm::gpt_crc32(copy));
    BOOST_TEST(u64(h, 24) == lba);
    BOOST_TEST(u64(h, 32) == other);
    const auto entries_lba = u64(h, 72);
    BOOST_TEST(u32(h, 80) == 128U);
    BOOST_TEST(u32(h, 84) == 128U);
    const auto entries = d.subspan(static_cast<std::size_t>(entries_lba * sec), 128 * 128);
    BOOST_TEST(u32(h, 88) == helm::gpt_crc32(entries));
    const auto esp_type = helm::guid_bytes(helm::esp_type_guid);
    const auto prov_type = helm::guid_bytes(helm::provisioning_type_guid);
    BOOST_TEST(std::ranges::equal(entries.first(16), esp_type));
    BOOST_TEST(std::ranges::equal(entries.subspan(128, 16), prov_type));
    // The provisioning partition's name, UTF-16LE.
    std::string name;
    for (std::size_t i = 0; i < 36 && u16(entries, 128 + 56 + (2 * i)) != 0; ++i) {
        name.push_back(static_cast<char>(u16(entries, 128 + 56 + (2 * i))));
    }
    BOOST_TEST(name == helm::provisioning_partition_name);
    BOOST_TEST(
        std::ranges::all_of(entries.subspan(256), [](std::byte b) { return b == std::byte{0}; }));
    return {.esp_first = u64(entries, 32),
            .esp_last = u64(entries, 40),
            .prov_first = u64(entries, 128 + 32),
            .prov_last = u64(entries, 128 + 40)};
}

// Finds `name11` in the directory at cluster `c`; returns (cluster, size).
auto lookup(std::span<const std::byte> esp, std::uint64_t data_sec, std::uint32_t c,
            std::string_view name11) -> std::pair<std::uint32_t, std::uint32_t> {
    const auto dir = esp.subspan(static_cast<std::size_t>((data_sec + c - 2) * sec), sec);
    for (std::size_t at = 0; at < sec; at += 32) {
        if (text(dir, at, 11) == name11) {
            const auto cluster =
                static_cast<std::uint32_t>((u16(dir, at + 20) << 16U) | u16(dir, at + 26));
            return {cluster, u32(dir, at + 28)};
        }
    }
    BOOST_FAIL("no " << name11);
    return {};
}

// Reads the UKI back through the FAT, as firmware would.
auto read_uki(std::span<const std::byte> d, const Gpt& g, std::string_view boot_name)
    -> std::vector<std::byte> {
    const auto esp = d.subspan(static_cast<std::size_t>(g.esp_first * sec),
                               static_cast<std::size_t>((g.esp_last - g.esp_first + 1) * sec));
    BOOST_TEST(u16(esp, 11) == sec);
    BOOST_TEST(std::to_integer<int>(esp[13]) == 1);
    BOOST_TEST(text(esp, 82, 8) == "FAT32   ");
    BOOST_TEST(u16(esp, 510) == 0xAA55U);
    BOOST_TEST(u32(esp, 28) == g.esp_first);  // hidden sectors
    BOOST_TEST(u32(esp, 32) == g.esp_last - g.esp_first + 1);
    // The backup boot sector equals the boot sector.
    BOOST_TEST(std::ranges::equal(esp.first(sec), esp.subspan(6 * sec, sec)));
    const std::uint64_t reserved = u16(esp, 14);
    const std::uint64_t fats = std::to_integer<unsigned>(esp[16]);
    const std::uint64_t fat_sz = u32(esp, 36);
    const std::uint64_t data_sec = reserved + (fats * fat_sz);
    const auto clusters = u32(esp, 32) - data_sec;
    BOOST_TEST(clusters >= 65'525U);  // FAT32 by cluster count
    const auto fat = esp.subspan(static_cast<std::size_t>(reserved * sec),
                                 static_cast<std::size_t>(fat_sz * sec));
    // The two FATs agree.
    BOOST_TEST(
        std::ranges::equal(fat, esp.subspan(static_cast<std::size_t>((reserved + fat_sz) * sec),
                                            static_cast<std::size_t>(fat_sz * sec))));
    const auto root = u32(esp, 44);
    const auto efi = lookup(esp, data_sec, root, "EFI        ");
    const auto boot = lookup(esp, data_sec, efi.first, "BOOT       ");
    const auto file = lookup(esp, data_sec, boot.first, boot_name);
    std::vector<std::byte> out;
    for (std::uint32_t c = file.first; c < 0x0FFF'FFF8U; c = u32(fat, 4 * c) & 0x0FFF'FFFFU) {
        const auto s = esp.subspan(static_cast<std::size_t>((data_sec + c - 2) * sec), sec);
        out.insert(out.end(), s.begin(), s.end());
    }
    out.resize(file.second);
    // FSInfo's free count matches the FAT.
    std::uint32_t free = 0;
    for (std::uint32_t c = 2; c < clusters + 2; ++c) {
        free += u32(fat, 4 * c) == 0 ? 1U : 0U;
    }
    BOOST_TEST(u32(esp, sec + 488) == free);
    return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(boot_function, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(disk_boots_the_uki_and_carries_the_frame) {
    const auto uki = uki_of((3 * 1024 * 1024) + 321);
    const auto d = disk_of(uki);
    const auto last = (d.size() / sec) - 1;
    // Protective MBR.
    BOOST_TEST(std::to_integer<int>(d[446 + 4]) == 0xEE);
    BOOST_TEST(u32(d, 446 + 8) == 1U);
    BOOST_TEST(u16(d, 510) == 0xAA55U);
    const auto g = check_gpt(d, 1, last);
    const auto backup = check_gpt(d, last, 1);
    BOOST_TEST(g.esp_first == backup.esp_first);
    BOOST_TEST(g.esp_first % 2048 == 0U);
    BOOST_TEST(g.prov_first % 2048 == 0U);
    BOOST_TEST(g.prov_first == g.esp_last + 1);
    BOOST_TEST(g.prov_last < last - 33);

    BOOST_TEST((read_uki(d, g, "BOOTX64 EFI") == uki));
    const auto frame = std::span{d}.subspan(static_cast<std::size_t>(g.prov_first * sec),
                                            proto::provisioning_size);
    auto back = proto::decode_provisioning(frame);
    BOOST_REQUIRE(back.has_value());
    BOOST_TEST((*back == prov));
}

BOOST_AUTO_TEST_CASE(aarch64_uses_its_removable_path) {
    const auto uki = uki_of(5000);
    const auto d = disk_of(uki, helm::BootArch::aarch64);
    const auto g = check_gpt(d, 1, (d.size() / sec) - 1);
    BOOST_TEST((read_uki(d, g, "BOOTAA64EFI") == uki));
}

BOOST_AUTO_TEST_CASE(same_inputs_same_disk) {
    const auto uki = uki_of(70'000);
    helm::MemoryFlash f{helm::boot_disk_size(uki.size())};
    // Whatever was on the function before is overwritten.
    std::ranges::fill(f.bytes(), std::byte{0xCC});
    BOOST_REQUIRE(helm::write_boot_disk(f, uki, prov).has_value());
    BOOST_TEST((f.bytes() == disk_of(uki)));
}

BOOST_AUTO_TEST_CASE(sizes_and_refusals) {
    // A small UKI still gets a FAT32-sized ESP, aligned to 1 MiB.
    BOOST_TEST(helm::boot_disk_size(1) % (1024 * 1024) == 0U);
    BOOST_TEST(helm::boot_disk_size(1) >= 34ULL * 1024 * 1024);
    BOOST_TEST(helm::boot_disk_size(64ULL << 20) > (64ULL << 20));
    helm::MemoryFlash small{1024};
    BOOST_TEST((helm::write_boot_disk(small, uki_of(10), prov).error() ==
                helm::BootDiskError::wrong_size));
    helm::MemoryFlash any{helm::boot_disk_size(1)};
    BOOST_TEST((helm::write_boot_disk(any, {}, prov).error() == helm::BootDiskError::empty_uki));
}

BOOST_AUTO_TEST_CASE(crc_and_guid_helpers) {
    const std::string_view check = "123456789";
    BOOST_TEST(helm::gpt_crc32(std::as_bytes(std::span{check})) == 0xCBF4'3926U);
    const auto g = helm::guid_bytes(helm::esp_type_guid);
    BOOST_TEST(std::to_integer<int>(g[0]) == 0x28);  // c12a7328, little-endian
    BOOST_TEST(std::to_integer<int>(g[3]) == 0xC1);
    BOOST_TEST(std::to_integer<int>(g[8]) == 0xBA);  // the last fields stay big-endian
    BOOST_TEST(std::ranges::all_of(helm::guid_bytes("not-a-guid"),
                                   [](std::byte b) { return b == std::byte{0}; }));
}

BOOST_AUTO_TEST_SUITE_END()
