// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// ak-guest-testdev: the guest side of harbor phase 2
// (.kiro/specs/harbor-virt-on-virt/ Requirement 5.2).
//
// Runs inside an L2 guest (or L1) on one ak-testdev function bound to
// vfio-pci, and drives it the way a tenant driver would:
//
//   MMIO   BAR0 magic, version, slot ID, scratch patterns
//   MSI-X  every vector raised through IRQ_DOORBELL arrives on its own
//          eventfd, and only there
//   DMA    the board process fills a guest buffer with a pattern, writes
//          exactly LEN bytes, and rejects a zero length
//   reset  VFIO_DEVICE_RESET reaches the board (RESET_COUNT increments and
//          SCRATCH is cleared)
//
// The L2 guest has no IOMMU of its own, so it normally uses vfio's no-IOMMU
// mode and hands the device guest-physical addresses read from
// /proc/self/pagemap; with a real or virtual IOMMU (a type1 group) it maps
// the buffer at a fixed IOVA instead. Either way the address the board
// process receives has been through L1's vIOMMU and QEMU's vfio-user
// client, which is the path phase 2 exists to prove.
//
// Prints one PASS/FAIL line per check and exits non-zero on any failure.
//
// Usage: ak-guest-testdev BDF [--slot N]

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <filesystem>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <linux/pci_regs.h>
#include <linux/vfio.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

// ak-testdev's BAR0 map (src/oar/testdev/main.cpp).
namespace reg {
constexpr std::uint64_t magic = 0x00;
constexpr std::uint64_t version = 0x04;
constexpr std::uint64_t scratch = 0x08;
constexpr std::uint64_t irq_doorbell = 0x0C;
constexpr std::uint64_t reset_count = 0x10;
constexpr std::uint64_t slot_id = 0x14;
constexpr std::uint64_t dma_addr_lo = 0x20;
constexpr std::uint64_t dma_addr_hi = 0x24;
constexpr std::uint64_t dma_len = 0x28;
constexpr std::uint64_t dma_pattern = 0x2C;
constexpr std::uint64_t dma_ctrl = 0x30;
constexpr std::uint64_t dma_status = 0x34;
}  // namespace reg

constexpr std::uint32_t magic_aktd = 0x4454'4B41;
constexpr std::uint32_t expected_version = 1;
constexpr std::uint32_t expected_msix_vectors = 4;
constexpr std::uint32_t dma_ctrl_fill = 1;
constexpr std::uint32_t dma_status_done = 1;
constexpr std::uint32_t dma_status_error = 2;
constexpr std::array<std::uint32_t, 4> scratch_patterns{0xA5A5'A5A5, 0x5A5A'5A5A, 0x0000'0000,
                                                        0xFFFF'FFFF};
constexpr std::uint32_t reset_marker = 0xC0FF'EE00;

constexpr std::size_t page_size = 0x1000;
constexpr std::size_t dma_buffer_size = page_size;
constexpr std::size_t dma_partial_len = 512;
constexpr std::uint8_t dma_full_pattern = 0x5A;
constexpr std::uint8_t dma_partial_pattern = 0xC3;
constexpr std::uint8_t dma_canary = 0xEE;
// Fixed IOVA for the DMA buffer when the group has a type1 IOMMU.
constexpr std::uint64_t type1_iova = 0x1000'0000;

constexpr int irq_timeout_ms = 2000;
constexpr int stray_irq_window_ms = 50;
constexpr unsigned half_shift = 32;
constexpr std::uint64_t low_half_mask = 0xFFFF'FFFFull;

// /proc/self/pagemap: one 64-bit entry per virtual page.
constexpr std::uint64_t pagemap_present = 1ull << 63;
constexpr std::uint64_t pagemap_pfn_mask = (1ull << 55) - 1;

constexpr const char* vfio_container_path = "/dev/vfio/vfio";
constexpr std::string_view arg_slot = "--slot";

int failures = 0;

auto pass(std::string_view bdf, std::string_view what) -> void {
    std::println("PASS  {}: {}", bdf, what);
}

auto fail(std::string_view bdf, std::string_view what) -> void {
    std::println("FAIL  {}: {}", bdf, what);
    ++failures;
}

auto errno_text(std::string_view what) -> std::string {
    return std::format("{}: {}", what, std::strerror(errno));
}

// Owns one file descriptor.
class Fd {
public:
    Fd() noexcept = default;
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&& other) noexcept : _fd{std::exchange(other._fd, -1)} {}
    auto operator=(Fd&& other) noexcept -> Fd& {
        if (this != &other) {
            reset();
            _fd = std::exchange(other._fd, -1);
        }
        return *this;
    }
    ~Fd() { reset(); }

    [[nodiscard]] auto get() const noexcept -> int { return _fd; }
    [[nodiscard]] auto valid() const noexcept -> bool { return _fd >= 0; }

private:
    auto reset() noexcept -> void {
        if (_fd >= 0) {
            ::close(_fd);
        }
        _fd = -1;
    }

    int _fd{-1};
};

// Page-aligned, locked anonymous buffer the device writes into.
class DmaBuffer {
public:
    DmaBuffer(const DmaBuffer&) = delete;
    auto operator=(const DmaBuffer&) -> DmaBuffer& = delete;
    DmaBuffer(DmaBuffer&& other) noexcept : _mem{std::exchange(other._mem, nullptr)} {}
    auto operator=(DmaBuffer&&) -> DmaBuffer& = delete;
    ~DmaBuffer() {
        if (_mem != nullptr) {
            ::munmap(_mem, dma_buffer_size);
        }
    }

    static auto create() -> std::expected<DmaBuffer, std::string> {
        void* mem = ::mmap(nullptr, dma_buffer_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_LOCKED, -1, 0);
        if (mem == MAP_FAILED) {
            return std::unexpected{errno_text("mmap DMA buffer")};
        }
        return DmaBuffer{mem};
    }

    [[nodiscard]] auto bytes() const noexcept -> std::span<std::uint8_t> {
        return {static_cast<std::uint8_t*>(_mem), dma_buffer_size};
    }
    [[nodiscard]] auto vaddr() const noexcept -> std::uint64_t {
        return reinterpret_cast<std::uint64_t>(_mem);
    }

private:
    explicit DmaBuffer(void* mem) noexcept : _mem{mem} {}
    void* _mem{nullptr};
};

// Guest-physical address of a locked page, for no-IOMMU DMA.
auto physical_address(std::uint64_t vaddr) -> std::expected<std::uint64_t, std::string> {
    Fd pagemap{::open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC)};
    if (!pagemap.valid()) {
        return std::unexpected{errno_text("open /proc/self/pagemap")};
    }
    std::uint64_t entry = 0;
    const auto offset = static_cast<off_t>((vaddr / page_size) * sizeof(entry));
    if (::pread(pagemap.get(), &entry, sizeof(entry), offset) !=
        static_cast<ssize_t>(sizeof(entry))) {
        return std::unexpected{errno_text("read /proc/self/pagemap")};
    }
    const std::uint64_t pfn = entry & pagemap_pfn_mask;
    if ((entry & pagemap_present) == 0 || pfn == 0) {
        return std::unexpected{std::string{"page not present or PFN hidden (need CAP_SYS_ADMIN)"}};
    }
    return pfn * page_size + (vaddr % page_size);
}

// One vfio-pci function: container, group and device descriptors.
class VfioDevice {
public:
    static auto open(const std::string& bdf) -> std::expected<VfioDevice, std::string>;

    [[nodiscard]] auto noiommu() const noexcept -> bool { return _noiommu; }

    [[nodiscard]] auto read32(std::uint64_t offset) const
        -> std::expected<std::uint32_t, std::string> {
        std::uint32_t value = 0;
        if (::pread(_device.get(), &value, sizeof(value), static_cast<off_t>(_bar0 + offset)) !=
            static_cast<ssize_t>(sizeof(value))) {
            return std::unexpected{errno_text(std::format("BAR0 read {:#x}", offset))};
        }
        return value;
    }

    [[nodiscard]] auto write32(std::uint64_t offset, std::uint32_t value) const
        -> std::expected<void, std::string> {
        if (::pwrite(_device.get(), &value, sizeof(value), static_cast<off_t>(_bar0 + offset)) !=
            static_cast<ssize_t>(sizeof(value))) {
            return std::unexpected{errno_text(std::format("BAR0 write {:#x}", offset))};
        }
        return {};
    }

    // Memory decoding and bus mastering; vfio-pci leaves both to the user.
    [[nodiscard]] auto enable() const -> std::expected<void, std::string> {
        std::uint16_t command = 0;
        const auto at = static_cast<off_t>(_config + PCI_COMMAND);
        if (::pread(_device.get(), &command, sizeof(command), at) !=
            static_cast<ssize_t>(sizeof(command))) {
            return std::unexpected{errno_text("read PCI_COMMAND")};
        }
        command |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
        if (::pwrite(_device.get(), &command, sizeof(command), at) !=
            static_cast<ssize_t>(sizeof(command))) {
            return std::unexpected{errno_text("write PCI_COMMAND")};
        }
        return {};
    }

    [[nodiscard]] auto msix_count() const -> std::expected<std::uint32_t, std::string> {
        vfio_irq_info info{};
        info.argsz = sizeof(info);
        info.index = VFIO_PCI_MSIX_IRQ_INDEX;
        if (::ioctl(_device.get(), VFIO_DEVICE_GET_IRQ_INFO, &info) != 0) {
            return std::unexpected{errno_text("VFIO_DEVICE_GET_IRQ_INFO")};
        }
        return info.count;
    }

    // Routes MSI-X vectors [0, fds.size()) to the given eventfds, or
    // disables MSI-X when fds is empty.
    [[nodiscard]] auto set_msix(std::span<const int> fds) const
        -> std::expected<void, std::string> {
        const std::size_t payload = fds.size() * sizeof(int);
        alignas(vfio_irq_set)
            std::array<std::byte, sizeof(vfio_irq_set) + (expected_msix_vectors * sizeof(int))>
                storage{};
        if (payload > storage.size() - sizeof(vfio_irq_set)) {
            return std::unexpected{std::string{"too many MSI-X vectors"}};
        }
        auto* set = reinterpret_cast<vfio_irq_set*>(storage.data());
        set->argsz = static_cast<std::uint32_t>(sizeof(vfio_irq_set) + payload);
        set->index = VFIO_PCI_MSIX_IRQ_INDEX;
        set->start = 0;
        set->count = static_cast<std::uint32_t>(fds.size());
        set->flags = VFIO_IRQ_SET_ACTION_TRIGGER |
                     (fds.empty() ? VFIO_IRQ_SET_DATA_NONE : VFIO_IRQ_SET_DATA_EVENTFD);
        if (!fds.empty()) {
            std::memcpy(storage.data() + sizeof(vfio_irq_set), fds.data(), payload);
        }
        if (::ioctl(_device.get(), VFIO_DEVICE_SET_IRQS, set) != 0) {
            return std::unexpected{errno_text("VFIO_DEVICE_SET_IRQS")};
        }
        return {};
    }

    // The address the device must be given for buf.
    [[nodiscard]] auto dma_address(const DmaBuffer& buf) const
        -> std::expected<std::uint64_t, std::string> {
        if (_noiommu) {
            return physical_address(buf.vaddr());
        }
        vfio_iommu_type1_dma_map map{};
        map.argsz = sizeof(map);
        map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
        map.vaddr = buf.vaddr();
        map.iova = type1_iova;
        map.size = dma_buffer_size;
        if (::ioctl(_container.get(), VFIO_IOMMU_MAP_DMA, &map) != 0) {
            return std::unexpected{errno_text("VFIO_IOMMU_MAP_DMA")};
        }
        return type1_iova;
    }

    [[nodiscard]] auto reset() const -> std::expected<void, std::string> {
        if (::ioctl(_device.get(), VFIO_DEVICE_RESET) != 0) {
            return std::unexpected{errno_text("VFIO_DEVICE_RESET")};
        }
        return {};
    }

private:
    VfioDevice() = default;

    Fd _container;
    Fd _group;
    Fd _device;
    bool _noiommu{false};
    std::uint64_t _bar0{0};
    std::uint64_t _config{0};
};

auto region_offset(int device, std::uint32_t index) -> std::expected<std::uint64_t, std::string> {
    vfio_region_info info{};
    info.argsz = sizeof(info);
    info.index = index;
    if (::ioctl(device, VFIO_DEVICE_GET_REGION_INFO, &info) != 0) {
        return std::unexpected{errno_text(std::format("VFIO_DEVICE_GET_REGION_INFO {}", index))};
    }
    return info.offset;
}

auto VfioDevice::open(const std::string& bdf) -> std::expected<VfioDevice, std::string> {
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path group_link = fs::path{"/sys/bus/pci/devices"} / bdf / "iommu_group";
    const auto group_target = fs::read_symlink(group_link, ec);
    if (ec) {
        return std::unexpected{
            std::format("{}: {} (is it bound to vfio-pci?)", group_link.string(), ec.message())};
    }
    const std::string group_id = group_target.filename().string();

    VfioDevice dev;
    const std::string noiommu_path = std::format("/dev/vfio/noiommu-{}", group_id);
    dev._noiommu = fs::exists(noiommu_path, ec);
    const std::string group_path =
        dev._noiommu ? noiommu_path : std::format("/dev/vfio/{}", group_id);

    dev._container = Fd{::open(vfio_container_path, O_RDWR | O_CLOEXEC)};
    if (!dev._container.valid()) {
        return std::unexpected{errno_text(vfio_container_path)};
    }
    if (::ioctl(dev._container.get(), VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        return std::unexpected{std::string{"unexpected VFIO API version"}};
    }
    dev._group = Fd{::open(group_path.c_str(), O_RDWR | O_CLOEXEC)};
    if (!dev._group.valid()) {
        return std::unexpected{errno_text(group_path)};
    }
    vfio_group_status status{};
    status.argsz = sizeof(status);
    if (::ioctl(dev._group.get(), VFIO_GROUP_GET_STATUS, &status) != 0) {
        return std::unexpected{errno_text("VFIO_GROUP_GET_STATUS")};
    }
    if ((status.flags & VFIO_GROUP_FLAGS_VIABLE) == 0) {
        return std::unexpected{
            std::format("group {} is not viable (bind every member to vfio-pci)", group_id)};
    }
    const int container_fd = dev._container.get();
    if (::ioctl(dev._group.get(), VFIO_GROUP_SET_CONTAINER, &container_fd) != 0) {
        return std::unexpected{errno_text("VFIO_GROUP_SET_CONTAINER")};
    }
    const unsigned long iommu_type = dev._noiommu ? VFIO_NOIOMMU_IOMMU : VFIO_TYPE1_IOMMU;
    if (::ioctl(dev._container.get(), VFIO_SET_IOMMU, iommu_type) != 0) {
        return std::unexpected{errno_text("VFIO_SET_IOMMU")};
    }
    dev._device = Fd{::ioctl(dev._group.get(), VFIO_GROUP_GET_DEVICE_FD, bdf.c_str())};
    if (!dev._device.valid()) {
        return std::unexpected{errno_text("VFIO_GROUP_GET_DEVICE_FD")};
    }
    auto bar0 = region_offset(dev._device.get(), VFIO_PCI_BAR0_REGION_INDEX);
    auto config = region_offset(dev._device.get(), VFIO_PCI_CONFIG_REGION_INDEX);
    if (!bar0) {
        return std::unexpected{bar0.error()};
    }
    if (!config) {
        return std::unexpected{config.error()};
    }
    dev._bar0 = *bar0;
    dev._config = *config;
    return dev;
}

// Reports err as a failure of `what` and returns false, or true on success.
template<typename T>
auto ok(std::string_view bdf, std::string_view what, const std::expected<T, std::string>& result)
    -> bool {
    if (result) {
        return true;
    }
    fail(bdf, std::format("{}: {}", what, result.error()));
    return false;
}

auto check_mmio(std::string_view bdf, const VfioDevice& dev, long expected_slot) -> void {
    if (auto magic = dev.read32(reg::magic); ok(bdf, "MMIO magic", magic)) {
        if (*magic == magic_aktd) {
            pass(bdf, std::format("BAR0 magic {:#010x}", *magic));
        } else {
            fail(bdf, std::format("BAR0 magic {:#010x}, want {:#010x}", *magic, magic_aktd));
        }
    }
    if (auto version = dev.read32(reg::version); ok(bdf, "MMIO version", version)) {
        if (*version == expected_version) {
            pass(bdf, std::format("version {}", *version));
        } else {
            fail(bdf, std::format("version {}, want {}", *version, expected_version));
        }
    }
    if (auto slot = dev.read32(reg::slot_id); ok(bdf, "MMIO slot ID", slot)) {
        if (expected_slot < 0 || *slot == static_cast<std::uint32_t>(expected_slot)) {
            pass(bdf, std::format("slot ID {}", *slot));
        } else {
            fail(bdf, std::format("slot ID {}, want {}", *slot, expected_slot));
        }
    }
    for (const std::uint32_t pattern : scratch_patterns) {
        if (!ok(bdf, "scratch write", dev.write32(reg::scratch, pattern))) {
            return;
        }
        auto got = dev.read32(reg::scratch);
        if (!ok(bdf, "scratch read", got)) {
            return;
        }
        if (*got != pattern) {
            fail(bdf, std::format("scratch wrote {:#010x} read {:#010x}", pattern, *got));
            return;
        }
    }
    pass(bdf, "scratch read/write");
}

// True if fd becomes readable within timeout_ms; drains it.
auto fired(int fd, int timeout_ms) -> bool {
    pollfd p{.fd = fd, .events = POLLIN, .revents = 0};
    if (::poll(&p, 1, timeout_ms) != 1) {
        return false;
    }
    std::uint64_t count = 0;
    return ::read(fd, &count, sizeof(count)) == static_cast<ssize_t>(sizeof(count)) && count > 0;
}

auto check_msix(std::string_view bdf, const VfioDevice& dev) -> void {
    auto count = dev.msix_count();
    if (!ok(bdf, "MSI-X info", count)) {
        return;
    }
    if (*count != expected_msix_vectors) {
        fail(bdf, std::format("{} MSI-X vectors, want {}", *count, expected_msix_vectors));
        return;
    }
    std::array<Fd, expected_msix_vectors> events;
    std::array<int, expected_msix_vectors> raw{};
    for (std::size_t v = 0; v < events.size(); ++v) {
        events[v] = Fd{::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)};
        if (!events[v].valid()) {
            fail(bdf, errno_text("eventfd"));
            return;
        }
        raw[v] = events[v].get();
    }
    if (!ok(bdf, "enable MSI-X", dev.set_msix(raw))) {
        return;
    }
    bool all = true;
    for (std::uint32_t v = 0; v < expected_msix_vectors; ++v) {
        if (!ok(bdf, "doorbell", dev.write32(reg::irq_doorbell, v))) {
            all = false;
            break;
        }
        if (!fired(raw[v], irq_timeout_ms)) {
            fail(bdf,
                 std::format("MSI-X vector {} did not arrive within {} ms", v, irq_timeout_ms));
            all = false;
            continue;
        }
        for (std::uint32_t other = 0; other < expected_msix_vectors; ++other) {
            if (other != v && fired(raw[other], stray_irq_window_ms)) {
                fail(bdf, std::format("doorbell {} also raised vector {}", v, other));
                all = false;
            }
        }
    }
    if (all) {
        pass(bdf,
             std::format("MSI-X: all {} vectors delivered, none stray", expected_msix_vectors));
    }
    (void)ok(bdf, "disable MSI-X", dev.set_msix({}));
}

auto run_fill(const VfioDevice& dev, std::uint64_t addr, std::uint32_t len, std::uint8_t pattern)
    -> std::expected<std::uint32_t, std::string> {
    for (const auto& [offset, value] :
         {std::pair{reg::dma_addr_lo, static_cast<std::uint32_t>(addr & low_half_mask)},
          std::pair{reg::dma_addr_hi, static_cast<std::uint32_t>(addr >> half_shift)},
          std::pair{reg::dma_len, len}, std::pair{reg::dma_pattern, std::uint32_t{pattern}},
          std::pair{reg::dma_ctrl, dma_ctrl_fill}}) {
        if (auto r = dev.write32(offset, value); !r) {
            return std::unexpected{r.error()};
        }
    }
    // The fill is synchronous in the board process: once the CTRL write
    // has completed, STATUS holds the result.
    return dev.read32(reg::dma_status);
}

auto check_dma(std::string_view bdf, const VfioDevice& dev) -> void {
    auto buf = DmaBuffer::create();
    if (!ok(bdf, "DMA buffer", buf)) {
        return;
    }
    auto addr = dev.dma_address(*buf);
    if (!ok(bdf, "DMA address", addr)) {
        return;
    }
    const auto bytes = buf->bytes();
    const std::string mode = dev.noiommu() ? "no-IOMMU, guest-physical" : "type1 IOVA";

    std::ranges::fill(bytes, dma_canary);
    auto status = run_fill(dev, *addr, dma_buffer_size, dma_full_pattern);
    if (ok(bdf, "DMA fill", status)) {
        const bool filled =
            std::ranges::all_of(bytes, [](auto b) { return b == dma_full_pattern; });
        if (*status == dma_status_done && filled) {
            pass(bdf,
                 std::format("DMA fill of {} bytes at {:#x} ({})", dma_buffer_size, *addr, mode));
        } else {
            fail(bdf, std::format("DMA fill at {:#x} ({}): status {}, buffer {}", *addr, mode,
                                  *status, filled ? "filled" : "not filled"));
        }
    }

    std::ranges::fill(bytes, dma_canary);
    status = run_fill(dev, *addr, dma_partial_len, dma_partial_pattern);
    if (ok(bdf, "DMA partial fill", status)) {
        const auto head = bytes.first(dma_partial_len);
        const auto tail = bytes.subspan(dma_partial_len);
        const bool exact =
            std::ranges::all_of(head, [](auto b) { return b == dma_partial_pattern; }) &&
            std::ranges::all_of(tail, [](auto b) { return b == dma_canary; });
        if (*status == dma_status_done && exact) {
            pass(bdf, std::format("DMA wrote exactly {} bytes", dma_partial_len));
        } else {
            fail(bdf, std::format("DMA partial fill: status {}, bounds {}", *status,
                                  exact ? "exact" : "wrong"));
        }
    }

    status = run_fill(dev, *addr, 0, dma_full_pattern);
    if (ok(bdf, "DMA zero-length fill", status)) {
        if (*status == dma_status_error) {
            pass(bdf, "DMA rejects a zero length");
        } else {
            fail(bdf,
                 std::format("DMA zero length: status {}, want {}", *status, dma_status_error));
        }
    }
}

auto check_reset(std::string_view bdf, const VfioDevice& dev) -> void {
    auto before = dev.read32(reg::reset_count);
    if (!ok(bdf, "read RESET_COUNT", before) ||
        !ok(bdf, "write scratch", dev.write32(reg::scratch, reset_marker)) ||
        !ok(bdf, "reset", dev.reset()) || !ok(bdf, "re-enable after reset", dev.enable())) {
        return;
    }
    auto after = dev.read32(reg::reset_count);
    auto scratch = dev.read32(reg::scratch);
    if (!ok(bdf, "read RESET_COUNT", after) || !ok(bdf, "read scratch", scratch)) {
        return;
    }
    if (*after > *before && *scratch == 0) {
        pass(bdf, std::format("reset reached the board (count {} -> {}, scratch cleared)", *before,
                              *after));
    } else {
        fail(bdf,
             std::format("reset: count {} -> {}, scratch {:#010x}", *before, *after, *scratch));
    }
}

auto usage() -> int {
    std::println(stderr, "usage: ak-guest-testdev BDF [{} N]", arg_slot);
    return EXIT_FAILURE;
}

}  // namespace

auto main(int argc, char** argv) -> int {
    std::string bdf;
    long expected_slot = -1;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == arg_slot && i + 1 < argc) {
            char* end = nullptr;
            expected_slot = std::strtol(argv[++i], &end, 0);
            if (end == nullptr || *end != '\0' || expected_slot < 0) {
                return usage();
            }
        } else if (bdf.empty() && !arg.starts_with("--")) {
            bdf = arg;
        } else {
            return usage();
        }
    }
    if (bdf.empty()) {
        return usage();
    }

    auto dev = VfioDevice::open(bdf);
    if (!dev) {
        fail(bdf, std::format("open: {}", dev.error()));
        return EXIT_FAILURE;
    }
    if (!ok(bdf, "enable memory and bus master", dev->enable())) {
        return EXIT_FAILURE;
    }
    pass(bdf, std::format("opened through vfio ({})", dev->noiommu() ? "no-IOMMU" : "type1"));

    check_mmio(bdf, *dev, expected_slot);
    check_msix(bdf, *dev);
    check_dma(bdf, *dev);
    check_reset(bdf, *dev);

    if (failures == 0) {
        std::println("{}: all guest checks passed", bdf);
        return EXIT_SUCCESS;
    }
    std::println("{}: {} guest check(s) failed", bdf, failures);
    return EXIT_FAILURE;
}
