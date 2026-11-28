// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/boot_function.hpp"

#include <algorithm>
#include <charconv>
#include <vector>

#include "common/wire.hpp"

namespace ak::helm {

namespace {

constexpr std::uint64_t sector = boot_sector_size;
constexpr std::uint64_t align_sectors = 2048;  // 1 MiB
constexpr std::uint64_t gpt_entries = 128;
constexpr std::uint64_t gpt_entry_size = 128;
constexpr std::uint64_t gpt_entry_sectors = gpt_entries * gpt_entry_size / sector;  // 32
constexpr std::uint64_t first_usable = 2 + gpt_entry_sectors;                       // 34
constexpr std::uint64_t provisioning_sectors = align_sectors;
constexpr std::uint64_t tail_sectors = align_sectors;  // holds the backup GPT

constexpr std::uint64_t fat_reserved = 32;
constexpr std::uint64_t fat_count = 2;
// FAT32 needs at least 65,525 clusters or readers take it for FAT16; leave
// a margin above that.
constexpr std::uint64_t min_clusters = 66'000;
constexpr std::uint32_t fat_eoc = 0x0FFF'FFFF;
constexpr std::uint32_t root_cluster = 2;
constexpr std::uint32_t efi_cluster = 3;
constexpr std::uint32_t boot_cluster = 4;
constexpr std::uint32_t file_cluster = 5;
constexpr std::uint16_t fat_date = ((2026 - 1980) << 9) | (1 << 5) | 1;  // 2026-01-01

// Fixed so the same inputs always give the same disk.
constexpr std::string_view disk_guid = "6b0a1c4e-7d52-4f31-8a9e-61686b626f6f";
constexpr std::string_view esp_unique_guid = "6b0a1c4e-7d52-4f31-8a9e-61686b657370";
constexpr std::string_view provisioning_unique_guid = "6b0a1c4e-7d52-4f31-8a9e-61686b707276";

struct Geometry {
    std::uint64_t esp_start{align_sectors};
    std::uint64_t esp_sectors{0};
    std::uint64_t fat_sectors{0};
    std::uint64_t clusters{0};
    std::uint64_t file_clusters{0};
    std::uint64_t provisioning_start{0};
    std::uint64_t total_sectors{0};
};

[[nodiscard]] auto div_up(std::uint64_t a, std::uint64_t b) noexcept -> std::uint64_t {
    return (a + b - 1) / b;
}

[[nodiscard]] auto geometry(std::uint64_t uki_size) noexcept -> Geometry {
    Geometry g;
    g.file_clusters = div_up(uki_size, sector);
    const auto clusters = std::max(min_clusters, 3 + g.file_clusters);
    const auto fat = div_up((clusters + 2) * 4, sector);
    g.esp_sectors =
        div_up(fat_reserved + (fat_count * fat) + clusters, align_sectors) * align_sectors;
    // Rounding up added clusters; size the FAT for every cluster the
    // partition can hold (a few spare FAT sectors at most).
    g.fat_sectors = div_up((g.esp_sectors - fat_reserved + 2) * 4, sector);
    g.clusters = g.esp_sectors - fat_reserved - (fat_count * g.fat_sectors);
    g.provisioning_start = g.esp_start + g.esp_sectors;
    g.total_sectors = g.provisioning_start + provisioning_sectors + tail_sectors;
    return g;
}

const std::array<std::uint32_t, 256> crc_table = [] {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = ((c & 1U) != 0) ? (0xEDB8'8320U ^ (c >> 1U)) : (c >> 1U);
        }
        t.at(i) = c;
    }
    return t;
}();

auto put16(std::span<std::byte> b, std::size_t at, std::uint16_t v) -> void {
    b[at] = std::byte{static_cast<std::uint8_t>(v)};
    b[at + 1] = std::byte{static_cast<std::uint8_t>(v >> 8U)};
}
auto put32(std::span<std::byte> b, std::size_t at, std::uint32_t v) -> void {
    for (std::size_t i = 0; i < 4; ++i) {
        b[at + i] = std::byte{static_cast<std::uint8_t>(v >> (8 * i))};
    }
}
auto put64(std::span<std::byte> b, std::size_t at, std::uint64_t v) -> void {
    for (std::size_t i = 0; i < 8; ++i) {
        b[at + i] = std::byte{static_cast<std::uint8_t>(v >> (8 * i))};
    }
}
auto put_text(std::span<std::byte> b, std::size_t at, std::string_view s) -> void {
    for (std::size_t i = 0; i < s.size(); ++i) {
        b[at + i] = static_cast<std::byte>(s[i]);
    }
}

// An 8.3 directory entry.
auto dir_entry(std::span<std::byte> b, std::size_t at, std::string_view name11, std::uint8_t attr,
               std::uint32_t cluster, std::uint32_t size) -> void {
    put_text(b, at, name11);
    b[at + 11] = std::byte{attr};
    put16(b, at + 16, fat_date);  // created
    put16(b, at + 18, fat_date);  // accessed
    put16(b, at + 20, static_cast<std::uint16_t>(cluster >> 16U));
    put16(b, at + 24, fat_date);  // written
    put16(b, at + 26, static_cast<std::uint16_t>(cluster & 0xFFFFU));
    put32(b, at + 28, size);
}

constexpr std::uint8_t attr_volume = 0x08;
constexpr std::uint8_t attr_dir = 0x10;
constexpr std::uint8_t attr_archive = 0x20;

class Writer {
public:
    explicit Writer(Flash& f) noexcept : _f{&f} {}
    auto at(std::uint64_t lba, std::span<const std::byte> data) -> bool {
        _ok = _ok && _f->write(lba * sector, data).has_value();
        return _ok;
    }
    auto zero(std::uint64_t lba, std::uint64_t sectors) -> bool {
        static const std::vector<std::byte> zeros(align_sectors * sector);
        while (_ok && sectors > 0) {
            const auto n = std::min<std::uint64_t>(sectors, align_sectors);
            at(lba, std::span{zeros}.first(static_cast<std::size_t>(n * sector)));
            lba += n;
            sectors -= n;
        }
        return _ok;
    }
    [[nodiscard]] auto ok() const noexcept -> bool { return _ok; }

private:
    Flash* _f;
    bool _ok{true};
};

auto gpt_entry(std::span<std::byte> b, std::size_t at, std::string_view type,
               std::string_view unique, std::uint64_t first, std::uint64_t last,
               std::string_view name) -> void {
    const auto t = guid_bytes(type);
    const auto u = guid_bytes(unique);
    std::ranges::copy(t, b.begin() + static_cast<std::ptrdiff_t>(at));
    std::ranges::copy(u, b.begin() + static_cast<std::ptrdiff_t>(at + 16));
    put64(b, at + 32, first);
    put64(b, at + 40, last);
    for (std::size_t i = 0; i < name.size(); ++i) {
        put16(b, at + 56 + (2 * i), static_cast<std::uint16_t>(name[i]));
    }
}

auto gpt_header(std::uint64_t mine, std::uint64_t other, std::uint64_t entries_lba,
                std::uint64_t last_usable, std::uint32_t entries_crc) -> std::vector<std::byte> {
    std::vector<std::byte> h(sector);
    put_text(h, 0, "EFI PART");
    put32(h, 8, 0x0001'0000);
    put32(h, 12, 92);
    put64(h, 24, mine);
    put64(h, 32, other);
    put64(h, 40, first_usable);
    put64(h, 48, last_usable);
    std::ranges::copy(guid_bytes(disk_guid), h.begin() + 56);
    put64(h, 72, entries_lba);
    put32(h, 80, gpt_entries);
    put32(h, 84, gpt_entry_size);
    put32(h, 88, entries_crc);
    put32(h, 16, gpt_crc32(std::span{h}.first(92)));
    return h;
}

}  // namespace

auto removable_boot_name(BootArch arch) noexcept -> std::string_view {
    return arch == BootArch::aarch64 ? "BOOTAA64EFI" : "BOOTX64 EFI";
}

auto to_string(BootDiskError e) noexcept -> const char* {
    switch (e) {
        case BootDiskError::wrong_size:
            return "boot function is not the disk's size";
        case BootDiskError::empty_uki:
            return "no UKI";
        case BootDiskError::bad_provisioning:
            return "provisioning frame does not encode";
        case BootDiskError::flash:
            return "boot function write failed";
    }
    return "unknown";
}

auto gpt_crc32(std::span<const std::byte> data) noexcept -> std::uint32_t {
    std::uint32_t c = 0xFFFF'FFFFU;
    for (const auto b : data) {
        c = crc_table.at((c ^ std::to_integer<std::uint32_t>(b)) & 0xFFU) ^ (c >> 8U);
    }
    return c ^ 0xFFFF'FFFFU;
}

auto guid_bytes(std::string_view text) noexcept -> std::array<std::byte, 16> {
    std::array<std::byte, 16> out{};
    if (text.size() != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' ||
        text[23] != '-') {
        return {};
    }
    std::array<std::uint8_t, 16> raw{};
    std::size_t n = 0;
    for (std::size_t i = 0; i < text.size();) {
        if (text[i] == '-') {
            ++i;
            continue;
        }
        unsigned v = 0;
        const auto* first = text.data() + i;
        const auto r = std::from_chars(first, first + 2, v, 16);
        if (r.ec != std::errc{} || r.ptr != first + 2 || n >= raw.size()) {
            return {};
        }
        raw.at(n++) = static_cast<std::uint8_t>(v);
        i += 2;
    }
    // time_low, time_mid and time_hi are stored little-endian.
    constexpr std::array<std::size_t, 16> order{3, 2, 1,  0,  5,  4,  7,  6,
                                                8, 9, 10, 11, 12, 13, 14, 15};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out.at(i) = std::byte{raw.at(order.at(i))};
    }
    return out;
}

auto boot_disk_size(std::uint64_t uki_size) noexcept -> std::uint64_t {
    return geometry(uki_size).total_sectors * sector;
}

auto write_boot_disk(Flash& target, std::span<const std::byte> uki,
                     const proto::Provisioning& provisioning, BootArch arch)
    -> std::expected<void, BootDiskError> {
    if (uki.empty()) {
        return std::unexpected(BootDiskError::empty_uki);
    }
    const auto frame = proto::encode_provisioning(provisioning);
    if (!frame) {
        return std::unexpected(BootDiskError::bad_provisioning);
    }
    const auto g = geometry(uki.size());
    if (target.size() != g.total_sectors * sector) {
        return std::unexpected(BootDiskError::wrong_size);
    }
    Writer w{target};
    w.zero(0, g.total_sectors);

    // Protective MBR.
    {
        std::vector<std::byte> mbr(sector);
        mbr[446 + 2] = std::byte{0x02};
        mbr[446 + 4] = std::byte{0xEE};
        mbr[446 + 5] = std::byte{0xFF};
        mbr[446 + 6] = std::byte{0xFF};
        mbr[446 + 7] = std::byte{0xFF};
        put32(mbr, 446 + 8, 1);
        put32(
            mbr, 446 + 12,
            static_cast<std::uint32_t>(std::min<std::uint64_t>(g.total_sectors - 1, 0xFFFF'FFFF)));
        mbr[510] = std::byte{0x55};
        mbr[511] = std::byte{0xAA};
        w.at(0, mbr);
    }

    // GPT, primary and backup.
    {
        std::vector<std::byte> entries(gpt_entries * gpt_entry_size);
        gpt_entry(entries, 0, esp_type_guid, esp_unique_guid, g.esp_start,
                  g.esp_start + g.esp_sectors - 1, "EFI System");
        gpt_entry(entries, gpt_entry_size, provisioning_type_guid, provisioning_unique_guid,
                  g.provisioning_start, g.provisioning_start + provisioning_sectors - 1,
                  provisioning_partition_name);
        const auto crc = gpt_crc32(entries);
        const auto last_lba = g.total_sectors - 1;
        const auto backup_entries = last_lba - gpt_entry_sectors;
        const auto last_usable = backup_entries - 1;
        w.at(1, gpt_header(1, last_lba, 2, last_usable, crc));
        w.at(2, entries);
        w.at(backup_entries, entries);
        w.at(last_lba, gpt_header(last_lba, 1, backup_entries, last_usable, crc));
    }

    // FAT32 boot sector, FSInfo, and their backups at sectors 6 and 7.
    const auto used = 3 + g.file_clusters;
    {
        std::vector<std::byte> bs(sector);
        bs[0] = std::byte{0xEB};
        bs[1] = std::byte{0x58};
        bs[2] = std::byte{0x90};
        put_text(bs, 3, "AKHELM  ");
        put16(bs, 11, static_cast<std::uint16_t>(sector));
        bs[13] = std::byte{1};  // sectors per cluster
        put16(bs, 14, static_cast<std::uint16_t>(fat_reserved));
        bs[16] = std::byte{static_cast<std::uint8_t>(fat_count)};
        bs[21] = std::byte{0xF8};
        put16(bs, 24, 63);
        put16(bs, 26, 255);
        put32(bs, 28, static_cast<std::uint32_t>(g.esp_start));
        put32(bs, 32, static_cast<std::uint32_t>(g.esp_sectors));
        put32(bs, 36, static_cast<std::uint32_t>(g.fat_sectors));
        put32(bs, 44, root_cluster);
        put16(bs, 48, 1);  // FSInfo sector
        put16(bs, 50, 6);  // backup boot sector
        bs[64] = std::byte{0x80};
        bs[66] = std::byte{0x29};
        put32(bs, 67, 0x414B'4254);  // volume ID "TBKA"
        put_text(bs, 71, "AK-BOOT    ");
        put_text(bs, 82, "FAT32   ");
        bs[510] = std::byte{0x55};
        bs[511] = std::byte{0xAA};
        std::vector<std::byte> info(sector);
        put32(info, 0, 0x4161'5252);
        put32(info, 484, 0x6141'7272);
        put32(info, 488, static_cast<std::uint32_t>(g.clusters - used));
        put32(info, 492, static_cast<std::uint32_t>(2 + used));
        put32(info, 508, 0xAA55'0000);
        w.at(g.esp_start, bs);
        w.at(g.esp_start + 1, info);
        w.at(g.esp_start + 6, bs);
        w.at(g.esp_start + 7, info);
    }

    // Both FATs: the three directories, then the UKI's chain.
    {
        const auto entries_per_sector = sector / 4;
        const auto last_cluster = file_cluster + g.file_clusters - 1;
        const auto fat_used_sectors = div_up(last_cluster + 1, entries_per_sector);
        std::vector<std::byte> fat(static_cast<std::size_t>(fat_used_sectors * sector));
        put32(fat, 0, 0x0FFF'FFF8);
        put32(fat, 4, fat_eoc);
        put32(fat, 4 * root_cluster, fat_eoc);
        put32(fat, 4 * efi_cluster, fat_eoc);
        put32(fat, 4 * boot_cluster, fat_eoc);
        for (std::uint64_t c = file_cluster; c <= last_cluster; ++c) {
            put32(fat, static_cast<std::size_t>(4 * c),
                  c == last_cluster ? fat_eoc : static_cast<std::uint32_t>(c + 1));
        }
        for (std::uint64_t i = 0; i < fat_count; ++i) {
            w.at(g.esp_start + fat_reserved + (i * g.fat_sectors), fat);
        }
    }

    // Directories and the UKI. Cluster n is at data sector n - 2.
    const auto data_lba = g.esp_start + fat_reserved + (fat_count * g.fat_sectors);
    const auto cluster_lba = [data_lba](std::uint64_t c) { return data_lba + c - 2; };
    {
        std::vector<std::byte> root(sector);
        dir_entry(root, 0, "AK-BOOT    ", attr_volume, 0, 0);
        dir_entry(root, 32, "EFI        ", attr_dir, efi_cluster, 0);
        w.at(cluster_lba(root_cluster), root);
        std::vector<std::byte> efi(sector);
        dir_entry(efi, 0, ".          ", attr_dir, efi_cluster, 0);
        dir_entry(efi, 32, "..         ", attr_dir, 0, 0);  // the root is cluster 0 here
        dir_entry(efi, 64, "BOOT       ", attr_dir, boot_cluster, 0);
        w.at(cluster_lba(efi_cluster), efi);
        std::vector<std::byte> boot(sector);
        dir_entry(boot, 0, ".          ", attr_dir, boot_cluster, 0);
        dir_entry(boot, 32, "..         ", attr_dir, efi_cluster, 0);
        dir_entry(boot, 64, removable_boot_name(arch), attr_archive, file_cluster,
                  static_cast<std::uint32_t>(uki.size()));
        w.at(cluster_lba(boot_cluster), boot);
        w.at(cluster_lba(file_cluster), uki);
    }

    // The provisioning partition: the frame at its first byte.
    w.at(g.provisioning_start, *frame);

    if (!w.ok() || !target.sync()) {
        return std::unexpected(BootDiskError::flash);
    }
    return {};
}

}  // namespace ak::helm
