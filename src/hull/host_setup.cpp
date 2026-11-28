// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/host_setup.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <fstream>
#include <map>
#include <sstream>
#include <system_error>

namespace ak::hull {

namespace mb = helm::mailbox;
namespace fs = std::filesystem;

namespace {

auto split_ws(std::string_view line) -> std::vector<std::string_view> {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) {
            ++i;
        }
        const std::size_t start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t') {
            ++i;
        }
        if (i > start) {
            out.push_back(line.substr(start, i - start));
        }
    }
    return out;
}

auto lower_hex(char c) -> bool {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

auto hex16(std::string_view s) -> std::optional<std::uint16_t> {
    if (s.size() != 4 || !std::ranges::all_of(s, lower_hex)) {
        return std::nullopt;
    }
    std::uint16_t v = 0;
    std::from_chars(s.data(), s.data() + s.size(), v, 16);
    return v;
}

auto parse_pci_id(std::string_view s) -> std::optional<PciId> {
    if (s.size() != 9 || s[4] != ':') {
        return std::nullopt;
    }
    const auto v = hex16(s.substr(0, 4));
    const auto d = hex16(s.substr(5, 4));
    if (!v || !d) {
        return std::nullopt;
    }
    return PciId{.vendor = *v, .device = *d};
}

template<typename T> auto decimal(std::string_view s, T max) -> std::optional<T> {
    if (s.empty() || s.size() > 20 ||
        !std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; }) ||
        (s.size() > 1 && s[0] == '0')) {
        return std::nullopt;
    }
    T v{};
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size() || v > max) {
        return std::nullopt;
    }
    return v;
}

auto device_type(std::string_view s) -> std::optional<mb::DeviceType> {
    if (s == "nic_vf") {
        return mb::DeviceType::nic_vf;
    }
    if (s == "blk_fn") {
        return mb::DeviceType::blk_fn;
    }
    if (s == "gpu_whole") {
        return mb::DeviceType::gpu_whole;
    }
    if (s == "gpu_vf") {
        return mb::DeviceType::gpu_vf;
    }
    return std::nullopt;
}

// Iterates the lines of `text`, handing each (without comment and trailing
// CR-free) to `fn(line_no, words)`; refuses NUL and CR anywhere.
template<typename Fn>
auto each_line(std::string_view text, Fn fn) -> std::expected<void, ParseFailure> {
    if (text.size() > max_config_bytes) {
        return std::unexpected(ParseFailure{.line = 0, .reason = "file too large"});
    }
    std::size_t line_no = 0;
    std::size_t pos = 0;
    while (pos < text.size()) {
        ++line_no;
        auto eol = text.find('\n', pos);
        if (eol == std::string_view::npos) {
            eol = text.size();
        }
        auto line = text.substr(pos, eol - pos);
        pos = eol + 1;
        for (const char c : line) {
            const auto u = static_cast<unsigned char>(c);
            if ((u < 0x20 && c != '\t') || u >= 0x7F) {
                return std::unexpected(
                    ParseFailure{.line = line_no, .reason = "control or non-ASCII byte"});
            }
        }
        if (const auto hash = line.find('#'); hash != std::string_view::npos) {
            line = line.substr(0, hash);
        }
        const auto words = split_ws(line);
        if (words.empty()) {
            continue;
        }
        if (auto r = fn(line_no, words); !r) {
            return r;
        }
    }
    return {};
}

auto read_small(const fs::path& p) -> std::optional<std::string> {
    std::ifstream in{p};
    if (!in) {
        return std::nullopt;
    }
    std::string s;
    std::getline(in, s);
    return s;
}

auto sysfs_hex16(const fs::path& p) -> std::optional<std::uint16_t> {
    auto s = read_small(p);
    if (!s || !s->starts_with("0x")) {
        return std::nullopt;
    }
    return hex16(std::string_view{*s}.substr(2));
}

auto write_attr(const fs::path& file, std::string_view value) -> int {
    // O_TRUNC as a shell's `echo value > file` does; sysfs ignores it.
    const int fd = ::open(file.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) {
        return errno;
    }
    ssize_t n = -1;
    do {
        n = ::write(fd, value.data(), value.size());
    } while (n < 0 && errno == EINTR);
    const int err = n == static_cast<ssize_t>(value.size()) ? 0 : (n < 0 ? errno : EIO);
    ::close(fd);
    return err;
}

auto sysfs_decimal(const fs::path& p) -> std::optional<unsigned> {
    const auto s = read_small(p);
    if (!s) {
        return std::nullopt;
    }
    return decimal<unsigned>(*s, 0xFFFF);
}

// Whether the device at the real (canonical) path `real` sits below the
// port `port`: one of its ancestor directories is named after the port.
auto below_port(const fs::path& real, const std::string& port) -> bool {
    for (auto p = real.parent_path(); p.has_relative_path() && p != p.parent_path();
         p = p.parent_path()) {
        if (p.filename() == port) {
            return true;
        }
    }
    return false;
}

// The canonical PCI addresses under <sysfs>/bus/pci/devices, sorted.
auto pci_devices(const fs::path& sysfs, std::error_code& ec) -> std::vector<std::string> {
    std::vector<std::string> bdfs;
    for (const auto& e : fs::directory_iterator{sysfs / "bus" / "pci" / "devices", ec}) {
        const auto name = e.path().filename().string();
        if (valid_bdf(name)) {
            bdfs.push_back(name);
        }
    }
    std::ranges::sort(bdfs);
    return bdfs;
}

auto fail(std::string step, std::string detail, int err = 0) -> std::unexpected<SetupFailure> {
    return std::unexpected(
        SetupFailure{.step = std::move(step), .detail = std::move(detail), .sys_errno = err});
}

}  // namespace

auto to_string(mb::DeviceType t) noexcept -> const char* {
    switch (t) {
        case mb::DeviceType::nic_vf:
            return "nic_vf";
        case mb::DeviceType::blk_fn:
            return "blk_fn";
        case mb::DeviceType::gpu_whole:
            return "gpu_whole";
        case mb::DeviceType::gpu_vf:
            return "gpu_vf";
    }
    return "unknown";
}

auto valid_bdf(std::string_view bdf) noexcept -> bool {
    // dddd:bb:dd.f
    if (bdf.size() != 12 || bdf[4] != ':' || bdf[7] != ':' || bdf[10] != '.') {
        return false;
    }
    for (const std::size_t i : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
        if (!lower_hex(bdf[i])) {
            return false;
        }
    }
    // Device numbers go to 0x1f, functions to 7.
    return (bdf[8] == '0' || bdf[8] == '1') && bdf[11] >= '0' && bdf[11] <= '7';
}

auto parse_host_config(std::string_view text) -> std::expected<HostConfig, ParseFailure> {
    HostConfig cfg;
    bool have_mailbox = false;
    bool have_server_id = false;
    auto bad = [](std::size_t n, std::string why) {
        return std::expected<void, ParseFailure>{std::unexpect,
                                                 ParseFailure{.line = n, .reason = std::move(why)}};
    };
    auto r = each_line(
        text,
        [&](std::size_t n,
            const std::vector<std::string_view>& w) -> std::expected<void, ParseFailure> {
            if (w[0] == "mailbox") {
                if (w.size() != 2) {
                    return bad(n, "mailbox takes one <vendor>:<device>");
                }
                if (have_mailbox) {
                    return bad(n, "second mailbox line");
                }
                const auto id = parse_pci_id(w[1]);
                if (!id) {
                    return bad(n, "bad PCI ID");
                }
                cfg.mailbox = *id;
                have_mailbox = true;
                return {};
            }
            if (w[0] == "slot") {
                if (w.size() != 8 || w[2] != "port" || w[4] != "type" || w[6] != "id") {
                    return bad(n, "slot <n> port <bdf> type <type> id <vendor>:<device>");
                }
                const auto slot = decimal<unsigned>(w[1], 0xFE);  // 0xFF means "no slot"
                const auto type = device_type(w[5]);
                const auto id = parse_pci_id(w[7]);
                if (!slot) {
                    return bad(n, "bad slot number");
                }
                if (!valid_bdf(w[3])) {
                    return bad(n, "bad port address");
                }
                if (!type) {
                    return bad(n, "unknown function type");
                }
                if (!id) {
                    return bad(n, "bad PCI ID");
                }
                for (const auto& s : cfg.slots) {
                    if (s.slot == *slot) {
                        return bad(n, "slot listed twice");
                    }
                    if (s.port == w[3]) {
                        return bad(n, "port listed twice");
                    }
                }
                cfg.slots.push_back(SlotRule{.slot = static_cast<std::uint8_t>(*slot),
                                             .port = std::string{w[3]},
                                             .type = *type,
                                             .id = *id});
                return {};
            }
            if (w[0] == "sriov") {
                if (w.size() != 7 || w[1] != "port" || w[3] != "pf" || w[5] != "vfs") {
                    return bad(n, "sriov port <bdf> pf <vendor>:<device> vfs <n>");
                }
                const auto id = parse_pci_id(w[4]);
                const auto vfs = decimal<unsigned>(w[6], 0xFFFF);
                if (!valid_bdf(w[2])) {
                    return bad(n, "bad port address");
                }
                if (!id) {
                    return bad(n, "bad PCI ID");
                }
                if (!vfs || *vfs == 0) {
                    return bad(n, "bad VF count");
                }
                for (const auto& other : cfg.sriov) {
                    if (other.port == w[2]) {
                        return bad(n, "sriov port listed twice");
                    }
                }
                cfg.sriov.push_back(SriovRule{
                    .port = std::string{w[2]}, .pf = *id, .vfs = static_cast<std::uint16_t>(*vfs)});
                return {};
            }
            if (w[0] == "server-id") {
                if (have_server_id) {
                    return bad(n, "second server-id line");
                }
                if (w.size() == 2 && w[1] == "cmdline") {
                    cfg.server_id_source = ServerIdSource::cmdline;
                } else if (w.size() == 2 && w[1] == "partition") {
                    cfg.server_id_source = ServerIdSource::partition;
                } else if (w.size() == 3 && w[1] == "file" && w[2].starts_with('/')) {
                    const fs::path p{w[2]};
                    if (p.lexically_normal() != p) {
                        return bad(n, "server-id file path is not normal");
                    }
                    cfg.server_id_source = ServerIdSource::file;
                    cfg.server_id_file = p;
                } else {
                    return bad(n,
                               "server-id cmdline | server-id file <absolute path> | "
                               "server-id partition");
                }
                have_server_id = true;
                return {};
            }
            return bad(n, "unknown keyword");
        });
    if (!r) {
        return std::unexpected(r.error());
    }
    if (!have_mailbox) {
        return std::unexpected(ParseFailure{.line = 0, .reason = "no mailbox line"});
    }
    if (!have_server_id) {
        return std::unexpected(ParseFailure{.line = 0, .reason = "no server-id line"});
    }
    // A PF is never handed out (Requirement 5.3), so no slot below the same
    // port may claim functions with its ID.
    for (const auto& board : cfg.sriov) {
        for (const auto& s : cfg.slots) {
            if (s.port == board.port && s.id == board.pf) {
                return std::unexpected(ParseFailure{
                    .line = 0, .reason = "sriov PF ID is also a slot's ID on its port"});
            }
        }
    }
    return cfg;
}

auto server_id_from_text(std::string_view text) -> std::optional<mb::ServerId> {
    if (text.ends_with('\n')) {
        text.remove_suffix(1);
    }
    const auto v = decimal<std::uint64_t>(text, UINT64_MAX);
    if (v == mb::no_server_id) {
        return std::nullopt;
    }
    return v;
}

auto provisioning_from_file(std::span<const std::byte> bytes)
    -> std::optional<proto::Provisioning> {
    if (proto::is_provisioning_frame(bytes)) {
        auto p = proto::decode_provisioning(bytes);
        if (!p) {
            return std::nullopt;
        }
        return *p;
    }
    const auto id = server_id_from_text(
        std::string_view{reinterpret_cast<const char*>(bytes.data()), bytes.size()});
    if (!id) {
        return std::nullopt;
    }
    return proto::Provisioning{.server_id = *id, .boot_epoch = 0, .sequence_floor = 0};
}

auto server_id_from_cmdline(std::string_view cmdline) -> std::optional<mb::ServerId> {
    std::optional<std::string_view> last;
    for (const auto word :
         split_ws(cmdline.ends_with('\n') ? cmdline.substr(0, cmdline.size() - 1) : cmdline)) {
        if (word.starts_with("hull.server_id=")) {
            last = word.substr(15);
        }
    }
    if (!last) {
        return std::nullopt;
    }
    return server_id_from_text(*last);
}

auto discover(const HostConfig& config, const fs::path& sysfs)
    -> std::expected<HostDiscovery, SetupFailure> {
    const auto devices = sysfs / "bus" / "pci" / "devices";
    std::error_code ec;
    const auto bdfs = pci_devices(sysfs, ec);
    if (ec) {
        return fail("enumerate", devices.string(), ec.value());
    }

    HostDiscovery out;
    std::map<std::uint8_t, std::uint16_t> next_function;
    for (const auto& bdf : bdfs) {
        const auto dir = devices / bdf;
        const auto vendor = sysfs_hex16(dir / "vendor");
        const auto device = sysfs_hex16(dir / "device");
        if (!vendor || !device) {
            continue;
        }
        const PciId id{.vendor = *vendor, .device = *device};
        if (id == config.mailbox) {
            if (!out.mailbox_bdf.empty()) {
                return fail("mailbox", "two mailbox functions: " + out.mailbox_bdf + " and " + bdf);
            }
            out.mailbox_bdf = bdf;
            continue;
        }
        const auto real = fs::canonical(dir, ec);
        if (ec) {
            continue;
        }
        for (const auto& rule : config.slots) {
            if (id != rule.id) {
                continue;
            }
            if (!below_port(real, rule.port)) {
                continue;
            }
            const auto fn = next_function[rule.slot]++;
            out.functions.push_back(InventoryEntry{
                .ref = {.slot = rule.slot, .type = rule.type, .function = fn},
                .bdf = bdf,
                .iommu_group = 0,
                .reset = fs::is_symlink(dir / "physfn") ? ResetMethod::flr : ResetMethod::bus,
            });
            break;
        }
    }
    if (out.mailbox_bdf.empty()) {
        return fail("mailbox", "no function with the mailbox's ID");
    }
    return out;
}

auto find_sriov_pf(const SriovRule& rule, const fs::path& sysfs)
    -> std::expected<std::string, SetupFailure> {
    const auto devices = sysfs / "bus" / "pci" / "devices";
    std::error_code ec;
    const auto bdfs = pci_devices(sysfs, ec);
    if (ec) {
        return fail("enumerate", devices.string(), ec.value());
    }
    std::string found;
    for (const auto& bdf : bdfs) {
        const auto dir = devices / bdf;
        const auto vendor = sysfs_hex16(dir / "vendor");
        const auto device = sysfs_hex16(dir / "device");
        if (!vendor || !device || PciId{.vendor = *vendor, .device = *device} != rule.pf) {
            continue;
        }
        const auto real = fs::canonical(dir, ec);
        if (ec || !below_port(real, rule.port)) {
            continue;
        }
        if (!found.empty()) {
            return fail("sriov", "two PFs below " + rule.port + ": " + found + " and " + bdf);
        }
        found = bdf;
    }
    if (found.empty()) {
        return fail("sriov", "no PF with the rule's ID below " + rule.port);
    }
    return found;
}

auto create_vfs(const std::string& pf, std::uint16_t count, const fs::path& sysfs)
    -> std::expected<void, SetupFailure> {
    if (!valid_bdf(pf) || count == 0) {
        return fail("sriov", pf, EINVAL);
    }
    const auto dir = sysfs / "bus" / "pci" / "devices" / pf;
    const auto total = sysfs_decimal(dir / "sriov_totalvfs");
    if (!total) {
        return fail("sriov", pf + ": not SR-IOV capable (no sriov_totalvfs)");
    }
    if (count > *total) {
        return fail("sriov", pf + ": " + std::to_string(count) + " VFs asked, " +
                                 std::to_string(*total) + " supported");
    }
    const auto numvfs = dir / "sriov_numvfs";
    const auto current = sysfs_decimal(numvfs);
    if (!current) {
        return fail("sriov", numvfs.string() + " unreadable");
    }
    if (*current == count) {
        return {};
    }
    // vfio-pci refuses sriov_configure unless this parameter is on; it is
    // writable at run time, so the image needs no extra command-line word.
    const auto param = sysfs / "module" / "vfio_pci" / "parameters" / "enable_sriov";
    if (const int err = write_attr(param, "1"); err != 0) {
        return fail("sriov", param.string(), err);
    }
    if (*current != 0) {
        if (const int err = write_attr(numvfs, "0"); err != 0) {
            return fail("sriov", numvfs.string() + " = 0", err);
        }
    }
    if (const int err = write_attr(numvfs, std::to_string(count)); err != 0) {
        return fail("sriov", numvfs.string() + " = " + std::to_string(count), err);
    }
    if (sysfs_decimal(numvfs) != std::optional<unsigned>{count}) {
        return fail("sriov", pf + ": sriov_numvfs did not take " + std::to_string(count));
    }
    return {};
}

auto bind_to_vfio(const std::string& bdf, const fs::path& sysfs)
    -> std::expected<void, SetupFailure> {
    if (!valid_bdf(bdf)) {
        return fail("bind", bdf, EINVAL);
    }
    const auto dir = sysfs / "bus" / "pci" / "devices" / bdf;
    if (const int err = write_attr(dir / "driver_override", "vfio-pci"); err != 0) {
        return fail("bind", (dir / "driver_override").string(), err);
    }
    if (fs::is_symlink(dir / "driver") && !bound_to_vfio(bdf, sysfs)) {
        if (const int err = write_attr(dir / "driver" / "unbind", bdf); err != 0) {
            return fail("unbind", bdf, err);
        }
    }
    if (!bound_to_vfio(bdf, sysfs)) {
        if (const int err = write_attr(sysfs / "bus" / "pci" / "drivers_probe", bdf); err != 0) {
            return fail("probe", bdf, err);
        }
    }
    return {};
}

auto bound_to_vfio(const std::string& bdf, const fs::path& sysfs) -> bool {
    std::error_code ec;
    const auto target = fs::read_symlink(sysfs / "bus" / "pci" / "devices" / bdf / "driver", ec);
    return !ec && target.filename() == "vfio-pci";
}

auto isolated_group(const std::string& bdf, const fs::path& sysfs)
    -> std::expected<std::uint32_t, SetupFailure> {
    std::error_code ec;
    const auto link = fs::read_symlink(sysfs / "bus" / "pci" / "devices" / bdf / "iommu_group", ec);
    if (ec) {
        return fail("iommu", bdf + ": no IOMMU group", ec.value());
    }
    const auto name = link.filename().string();
    const auto group = decimal<std::uint32_t>(name, UINT32_MAX);
    if (!group) {
        return fail("iommu", bdf + ": bad group " + name);
    }
    std::vector<std::string> members;
    for (const auto& e :
         fs::directory_iterator{sysfs / "kernel" / "iommu_groups" / name / "devices", ec}) {
        members.push_back(e.path().filename().string());
    }
    if (ec) {
        return fail("iommu", bdf + ": group " + name + " unreadable", ec.value());
    }
    if (members != std::vector<std::string>{bdf}) {
        std::string list;
        for (const auto& m : members) {
            list += (list.empty() ? "" : " ") + m;
        }
        return fail("iommu", bdf + ": group " + name + " is shared: " + list);
    }
    return *group;
}

auto format_inventory(const std::vector<InventoryEntry>& entries) -> std::string {
    std::ostringstream out;
    for (const auto& e : entries) {
        out << unsigned{e.ref.slot} << ' ' << to_string(e.ref.type) << ' ' << e.ref.function << ' '
            << e.bdf << ' ' << e.iommu_group << ' ' << (e.reset == ResetMethod::flr ? "flr" : "bus")
            << '\n';
    }
    return out.str();
}

auto parse_inventory(std::string_view text)
    -> std::expected<std::vector<InventoryEntry>, ParseFailure> {
    std::vector<InventoryEntry> out;
    auto bad = [](std::size_t n, std::string why) {
        return std::expected<void, ParseFailure>{std::unexpect,
                                                 ParseFailure{.line = n, .reason = std::move(why)}};
    };
    auto r = each_line(
        text,
        [&](std::size_t n,
            const std::vector<std::string_view>& w) -> std::expected<void, ParseFailure> {
            if (w.size() != 6) {
                return bad(n, "<slot> <type> <function> <bdf> <group> <reset>");
            }
            const auto slot = decimal<unsigned>(w[0], 0xFE);
            const auto type = device_type(w[1]);
            const auto fn = decimal<unsigned>(w[2], 0xFFFF);
            const auto group = decimal<std::uint32_t>(w[4], UINT32_MAX);
            if (!slot || !type || !fn || !valid_bdf(w[3]) || !group ||
                (w[5] != "bus" && w[5] != "flr")) {
                return bad(n, "bad field");
            }
            InventoryEntry e{.ref = {.slot = static_cast<std::uint8_t>(*slot),
                                     .type = *type,
                                     .function = static_cast<std::uint16_t>(*fn)},
                             .bdf = std::string{w[3]},
                             .iommu_group = *group,
                             .reset = w[5] == "flr" ? ResetMethod::flr : ResetMethod::bus};
            for (const auto& x : out) {
                if (x.bdf == e.bdf || x.iommu_group == e.iommu_group ||
                    (x.ref.slot == e.ref.slot && x.ref.function == e.ref.function)) {
                    return bad(n, "function, address or group listed twice");
                }
            }
            out.push_back(std::move(e));
            return {};
        });
    if (!r) {
        return std::unexpected(r.error());
    }
    return out;
}

auto parse_controller_keys(std::string_view text)
    -> std::expected<std::vector<ControllerKey>, ParseFailure> {
    std::vector<ControllerKey> out;
    std::size_t n = 0;
    while (!text.empty()) {
        ++n;
        const auto end = text.find(';');
        const auto entry = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        const auto colon = entry.find(':');
        if (colon == std::string_view::npos) {
            return std::unexpected(ParseFailure{.line = n, .reason = "<id>:<hex key>"});
        }
        const auto id = decimal<unsigned>(entry.substr(0, colon), 0xFFFF);
        const auto hex = entry.substr(colon + 1);
        if (!id || *id == 0 || hex.size() != 2 * ed25519_public_key_size ||
            !std::ranges::all_of(hex, lower_hex)) {
            return std::unexpected(ParseFailure{.line = n, .reason = "bad key ID or key"});
        }
        ControllerKey key{.id = static_cast<KeyId>(*id), .key = {}};
        for (std::size_t i = 0; i < ed25519_public_key_size; ++i) {
            unsigned b = 0;
            std::from_chars(hex.data() + 2 * i, hex.data() + 2 * i + 2, b, 16);
            key.key[i] = static_cast<std::byte>(b);
        }
        out.push_back(key);
    }
    return out;
}

}  // namespace ak::hull
