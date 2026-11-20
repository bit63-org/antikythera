// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/mailbox_vfu_server.hpp"

#include <cerrno>
#include <cstring>
#include <format>
#include <mutex>
#include <print>
#include <span>
#include <utility>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "oar/vfu/libvfio_user.hpp"

namespace ak::helm {

namespace {

namespace mb = mailbox;

constexpr std::size_t bar2_size = 0x1000;
constexpr std::uint32_t msix_vectors = 1;
constexpr std::uint32_t command_vector = 0;
constexpr std::uint32_t msix_table_bar = 2;
constexpr std::uint32_t msix_table_offset = 0;
constexpr std::uint32_t msix_pba_offset = 0x800;
constexpr unsigned msix_offset_shift = 3;  // MSI-X table/PBA offsets are in 8-byte units
constexpr std::uint8_t pcie_cap_version = 2;
constexpr int pci_revision = 0;
constexpr std::uint8_t pci_class_unassigned = 0xFF;
constexpr std::uint8_t pci_subclass_none = 0x00;
constexpr std::uint8_t pci_progif_none = 0x00;
constexpr int poll_forever = -1;
constexpr std::size_t listen_fd = 0;
constexpr std::size_t stop_fd = 1;

struct CtxDeleter {
    auto operator()(vfu_ctx_t* ctx) const noexcept -> void { vfu_destroy_ctx(ctx); }
};
using CtxPtr = std::unique_ptr<vfu_ctx_t, CtxDeleter>;

auto errno_text(std::string_view what) -> std::string {
    return std::format("{}: {}", what, std::strerror(errno));
}

}  // namespace

// Lock order: _ctx_mutex, then the MailboxDevice's own lock. libvfio-user is
// not thread-safe, so every call into the context (running it, and raising
// the interrupt from post_command) holds _ctx_mutex; BAR0 callbacks run
// inside vfu_run_ctx and take only the device lock. The mutex is recursive
// so a host-slot handler may post the next command from inside the callback.
struct MailboxVfuServer::Impl {
    class Port final : public HostPort {
    public:
        explicit Port(MailboxVfuServer& server) noexcept : _server{&server} {}
        auto post_command(const mb::Slot& slot) -> bool override {
            const std::scoped_lock lock{_server->_impl->ctx_mutex};
            return _server->_device.post_command(slot);
        }

    private:
        MailboxVfuServer* _server;
    };

    explicit Impl(MailboxVfuServer& server) : port{server} {}

    Impl(const Impl&) = delete;
    auto operator=(const Impl&) -> Impl& = delete;
    Impl(Impl&&) = delete;
    auto operator=(Impl&&) -> Impl& = delete;
    ~Impl() {
        if (stop_event >= 0) {
            ::close(stop_event);
        }
    }

    std::recursive_mutex ctx_mutex;
    CtxPtr ctx;
    int stop_event{-1};
    Port port;
};

namespace {

auto server_of(vfu_ctx_t* ctx) -> MailboxDevice& {
    return *static_cast<MailboxDevice*>(vfu_get_private(ctx));
}

auto bar0_access(vfu_ctx_t* ctx, char* buf, size_t count, loff_t offset, bool is_write) -> ssize_t {
    if (offset < 0) {
        errno = EINVAL;
        return -1;
    }
    auto& device = server_of(ctx);
    const auto at = static_cast<std::size_t>(offset);
    const std::span bytes{reinterpret_cast<std::byte*>(buf), count};
    const bool ok = is_write ? device.write(at, bytes) : device.read(at, bytes);
    if (!ok) {
        errno = EINVAL;
        return -1;
    }
    return static_cast<ssize_t>(count);
}

// The client emulates the MSI-X table and PBA; reads return zero.
auto bar2_access(vfu_ctx_t* /*ctx*/, char* buf, size_t count, loff_t offset, bool is_write)
    -> ssize_t {
    if (offset < 0 || static_cast<std::size_t>(offset) > bar2_size ||
        count > bar2_size - static_cast<std::size_t>(offset)) {
        errno = EINVAL;
        return -1;
    }
    if (!is_write) {
        std::memset(buf, 0, count);
    }
    return static_cast<ssize_t>(count);
}

auto reset_cb(vfu_ctx_t* ctx, vfu_reset_type_t /*type*/) -> int {
    server_of(ctx).reset();
    return 0;
}

auto log_cb(vfu_ctx_t* /*ctx*/, int /*level*/, const char* msg) -> void {
    std::println(stderr, "helm mailbox: {}", msg);
}

auto setup(vfu_ctx_t* ctx) -> std::expected<void, std::string> {
    const auto check = [](int rc, std::string_view what) -> std::expected<void, std::string> {
        if (rc < 0) {
            return std::unexpected(errno_text(what));
        }
        return {};
    };
    pxcap px{};
    px.hdr.id = PCI_CAP_ID_EXP;
    px.pxcaps.ver = pcie_cap_version;
    px.pxdcap.flrc = 1;
    msixcap msix{};
    msix.hdr.id = PCI_CAP_ID_MSIX;
    msix.mxc.ts = msix_vectors - 1;  // table size is encoded as N-1
    msix.mtab.tbir = msix_table_bar;
    msix.mtab.to = msix_table_offset >> msix_offset_shift;
    msix.mpba.pbir = msix_table_bar;
    msix.mpba.pbao = msix_pba_offset >> msix_offset_shift;

    return check(vfu_setup_log(ctx, log_cb, LOG_INFO), "vfu_setup_log")
        .and_then([&] {
            return check(
                vfu_pci_init(ctx, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, pci_revision),
                "vfu_pci_init");
        })
        .and_then([&] {
            vfu_pci_set_id(ctx, mailbox_vendor_id, mailbox_device_id, mailbox_vendor_id,
                           mailbox_device_id);
            vfu_pci_set_class(ctx, pci_class_unassigned, pci_subclass_none, pci_progif_none);
            return check(static_cast<int>(vfu_pci_add_capability(ctx, 0, 0, &px)),
                         "add PCIe capability");
        })
        .and_then([&] {
            return check(static_cast<int>(vfu_pci_add_capability(ctx, 0, 0, &msix)),
                         "add MSI-X capability");
        })
        .and_then([&] {
            return check(
                vfu_setup_region(ctx, VFU_PCI_DEV_BAR0_REGION_IDX, mb::reg::bar0_size, bar0_access,
                                 VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0),
                "setup BAR0");
        })
        .and_then([&] {
            return check(
                vfu_setup_region(ctx, VFU_PCI_DEV_BAR2_REGION_IDX, bar2_size, bar2_access,
                                 VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MEM, nullptr, 0, -1, 0),
                "setup BAR2");
        })
        .and_then([&] {
            return check(vfu_setup_device_nr_irqs(ctx, VFU_DEV_MSIX_IRQ, msix_vectors),
                         "setup MSI-X");
        })
        .and_then(
            [&] { return check(vfu_setup_device_reset_cb(ctx, reset_cb), "setup reset callback"); })
        // No vfu_setup_device_dma(): the mailbox never touches host memory.
        .and_then([&] { return check(vfu_realize_ctx(ctx), "vfu_realize_ctx"); });
}

}  // namespace

MailboxVfuServer::MailboxVfuServer(MailboxDevice::HostSlotHandler on_host_slot)
    : _impl{std::make_unique<Impl>(*this)},
      _device{[this] {
                  // Called by post_command with _ctx_mutex held (Impl::Port).
                  return _impl->ctx && vfu_irq_trigger(_impl->ctx.get(), command_vector) == 0;
              },
              std::move(on_host_slot)} {}

MailboxVfuServer::~MailboxVfuServer() = default;

auto MailboxVfuServer::create(const std::string& socket_path,
                              MailboxDevice::HostSlotHandler on_host_slot)
    -> std::expected<std::unique_ptr<MailboxVfuServer>, std::string> {
    std::unique_ptr<MailboxVfuServer> server{new MailboxVfuServer(std::move(on_host_slot))};
    server->_impl->stop_event = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (server->_impl->stop_event < 0) {
        return std::unexpected(errno_text("eventfd"));
    }
    ::unlink(socket_path.c_str());  // a stale socket from a previous run
    server->_impl->ctx.reset(vfu_create_ctx(VFU_TRANS_SOCK, socket_path.c_str(),
                                            LIBVFIO_USER_FLAG_ATTACH_NB, &server->_device,
                                            VFU_DEV_TYPE_PCI));
    if (!server->_impl->ctx) {
        return std::unexpected(errno_text("vfu_create_ctx"));
    }
    if (auto ok = setup(server->_impl->ctx.get()); !ok) {
        return std::unexpected(ok.error());
    }
    return server;
}

auto MailboxVfuServer::host_port() noexcept -> HostPort& {
    return _impl->port;
}

auto MailboxVfuServer::stop() noexcept -> void {
    const std::uint64_t one = 1;
    // Only fails if the counter would overflow, and then serve() is woken anyway.
    [[maybe_unused]] const ssize_t n = ::write(_impl->stop_event, &one, sizeof(one));
}

auto MailboxVfuServer::serve() -> std::expected<void, std::string> {
    vfu_ctx_t* const ctx = _impl->ctx.get();
    bool attached = false;
    for (;;) {
        std::array<pollfd, 2> fds{};
        fds[listen_fd] = {.fd = vfu_get_poll_fd(ctx), .events = POLLIN, .revents = 0};
        fds[stop_fd] = {.fd = _impl->stop_event, .events = POLLIN, .revents = 0};
        if (::poll(fds.data(), fds.size(), poll_forever) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(errno_text("poll"));
        }
        if (fds[stop_fd].revents != 0) {
            return {};
        }
        if (fds[listen_fd].revents == 0) {
            continue;
        }
        const std::scoped_lock lock{_impl->ctx_mutex};
        if (!attached) {
            if (vfu_attach_ctx(ctx) < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                return std::unexpected(errno_text("vfu_attach_ctx"));
            }
            attached = true;
            continue;
        }
        if (vfu_run_ctx(ctx) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (errno != ENOTCONN) {
                return std::unexpected(errno_text("vfu_run_ctx"));
            }
            attached = false;  // the client went away; wait for the next one
            _device.reset();
        }
    }
}

}  // namespace ak::helm
