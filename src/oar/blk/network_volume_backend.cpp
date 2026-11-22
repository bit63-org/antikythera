// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/network_volume_backend.hpp"

#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "proto/hold_stream.hpp"
#include "proto/server_identity.hpp"
#include "proto/storage_net.hpp"

namespace ak::oar::blk {

namespace {

using Clock = InitiatorCore::Clock;
using Bytes = std::vector<std::byte>;

constexpr std::size_t read_chunk = 64 * 1024;

auto close_fd(int fd) noexcept -> void {
    if (fd >= 0) {
        static_cast<void>(::close(fd));
    }
}

auto signal(int fd) noexcept -> void {
    const std::uint64_t one = 1;
    static_cast<void>(::write(fd, &one, sizeof one));
}

auto drain(int fd) noexcept -> void {
    std::uint64_t n = 0;
    while (::read(fd, &n, sizeof n) == static_cast<ssize_t>(sizeof n)) {
    }
}

}  // namespace

auto to_string(NetworkVolumeError e) noexcept -> const char* {
    switch (e) {
        case NetworkVolumeError::tls:
            return "tls";
        case NetworkVolumeError::system:
            return "system";
    }
    return "unknown";
}

// The mailbox between the role thread and the I/O thread, and the I/O
// thread itself.
struct NetworkVolumeBackend::Shared {
    enum class Kind : std::uint8_t {
        connected,
        disconnected,
        frame
    };
    struct Event {
        Kind kind{Kind::frame};
        std::uint64_t session{0};
        Bytes frame;
    };

    Shared(const Shared&) = delete;
    auto operator=(const Shared&) -> Shared& = delete;
    Shared(Shared&&) = delete;
    auto operator=(Shared&&) -> Shared& = delete;
    Shared() = default;
    ~Shared() {
        close_fd(epoll);
        close_fd(inbox_fd);
        close_fd(timer_fd);
        close_fd(io_fd);
    }

    auto post(Event e) -> void {
        {
            const std::scoped_lock lock{mutex};
            inbox.push_back(std::move(e));
        }
        signal(inbox_fd);
    }
    auto run() -> void;
    auto open(const HoldTarget& t) -> std::optional<tls::Stream>;

    int epoll{-1};     // wake_fd(): inbox_fd and timer_fd
    int inbox_fd{-1};  // the I/O thread posted events
    int timer_fd{-1};  // the core's next wake
    int io_fd{-1};     // wakes the I/O thread
    tls::Config tls;
    std::chrono::milliseconds connect_timeout{0};
    std::chrono::milliseconds write_timeout{0};

    std::mutex mutex;
    // Role thread to I/O thread.
    std::optional<HoldTarget> want;
    std::uint64_t out_session{0};
    std::deque<Bytes> out;
    bool stop{false};
    // I/O thread to role thread.
    std::vector<Event> inbox;

    std::thread thread;
};

auto NetworkVolumeBackend::Shared::open(const HoldTarget& t) -> std::optional<tls::Stream> {
    const auto host = proto::endpoint_text(t.endpoint);
    if (host.empty()) {
        return std::nullopt;
    }
    auto config = tls;
    config.role = tls::Role::client;
    config.peer_name = host;  // the primary's IP SAN
    auto ctx = tls::Context::create(config);
    if (!ctx) {
        return std::nullopt;
    }
    auto s = tls::Stream::connect(*ctx, host, t.port, Clock::now() + connect_timeout);
    if (!s) {
        return std::nullopt;
    }
    // The hold is the server the route names, by its certificate.
    const auto uris = s->peer_uris();
    const auto id = proto::server_id_of(uris);
    if (!id || *id != t.server_id) {
        s->close();
        return std::nullopt;
    }
    proto::set_storage_class(s->fd());
    return std::move(*s);
}

auto NetworkVolumeBackend::Shared::run() -> void {
    std::optional<tls::Stream> stream;
    std::uint64_t session = 0;    // the session `stream` carries
    std::uint64_t attempted = 0;  // the last session a connect was tried for
    proto::FrameAssembler in;
    Bytes buf(read_chunk);
    const auto drop = [&] {
        if (stream) {
            stream->close();
            stream.reset();
            post({.kind = Kind::disconnected, .session = session, .frame = {}});
        }
    };

    for (;;) {
        std::optional<HoldTarget> target;
        std::deque<Bytes> frames;
        {
            const std::scoped_lock lock{mutex};
            if (stop) {
                break;
            }
            target = want;
            if (stream && out_session == session) {
                frames.swap(out);
            }
        }
        if (stream && (!target || target->session != session)) {
            drop();  // the core has moved on
            continue;
        }
        if (!stream && target && target->session != attempted) {
            attempted = target->session;
            if (auto s = open(*target)) {
                stream = std::move(*s);
                session = target->session;
                in = {};
                post({.kind = Kind::connected, .session = session, .frame = {}});
            } else {
                post({.kind = Kind::disconnected, .session = target->session, .frame = {}});
            }
            continue;
        }
        for (const auto& f : frames) {
            if (!stream->write_all(f, Clock::now() + write_timeout)) {
                drop();
                break;
            }
        }
        while (stream) {
            const auto got = stream->read_some(buf);
            if (!got) {
                drop();
                break;
            }
            if (*got == 0) {
                break;
            }
            in.feed(std::span{buf}.first(*got));
            for (;;) {
                auto f = in.next();
                if (!f) {
                    drop();  // not a hold frame: end the session
                    break;
                }
                if (!f->has_value()) {
                    break;
                }
                post({.kind = Kind::frame, .session = session, .frame = std::move(**f)});
            }
        }
        if (stream && stream->pending()) {
            continue;
        }
        std::array<pollfd, 2> fds{
            pollfd{.fd = io_fd, .events = POLLIN, .revents = 0},
            pollfd{.fd = stream ? stream->fd() : -1, .events = POLLIN, .revents = 0}};
        if (::poll(fds.data(), stream ? 2 : 1, -1) < 0 && errno != EINTR) {
            break;
        }
        drain(io_fd);
    }
    if (stream) {
        stream->close();
    }
}

auto NetworkVolumeBackend::create(NetworkVolumeConfig config)
    -> std::expected<std::unique_ptr<NetworkVolumeBackend>, NetworkVolumeError> {
    // The certificate and key load (the per-connection contexts only add
    // the peer's address).
    auto probe = config.tls;
    probe.role = tls::Role::client;
    probe.peer_name = "127.0.0.1";
    if (!tls::Context::create(probe)) {
        return std::unexpected(NetworkVolumeError::tls);
    }
    auto shared = std::make_unique<Shared>();
    shared->tls = config.tls;
    shared->connect_timeout = config.connect_timeout;
    shared->write_timeout = config.write_timeout;
    shared->epoll = ::epoll_create1(EPOLL_CLOEXEC);
    shared->inbox_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    shared->timer_fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    shared->io_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (shared->epoll < 0 || shared->inbox_fd < 0 || shared->timer_fd < 0 || shared->io_fd < 0) {
        return std::unexpected(NetworkVolumeError::system);
    }
    for (const int fd : {shared->inbox_fd, shared->timer_fd}) {
        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (::epoll_ctl(shared->epoll, EPOLL_CTL_ADD, fd, &ev) != 0) {
            return std::unexpected(NetworkVolumeError::system);
        }
    }
    try {
        shared->thread = std::thread{[s = shared.get()] { s->run(); }};
    } catch (const std::system_error&) {
        return std::unexpected(NetworkVolumeError::system);
    }
    return std::unique_ptr<NetworkVolumeBackend>{
        new NetworkVolumeBackend{std::move(config), std::move(shared)}};
}

NetworkVolumeBackend::NetworkVolumeBackend(NetworkVolumeConfig config,
                                           std::unique_ptr<Shared> shared) noexcept
    : _config{std::move(config)}, _core{_config.initiator}, _shared{std::move(shared)} {}

NetworkVolumeBackend::~NetworkVolumeBackend() {
    {
        const std::scoped_lock lock{_shared->mutex};
        _shared->stop = true;
    }
    signal(_shared->io_fd);
    _shared->thread.join();
}

auto NetworkVolumeBackend::set_route(const proto::ReplicaConfig& c)
    -> std::expected<void, RouteError> {
    auto r = _core.set_route(c, Clock::now());
    publish();
    return r;
}

auto NetworkVolumeBackend::routed() const noexcept -> bool {
    return _core.routed();
}

auto NetworkVolumeBackend::fenced() const noexcept -> bool {
    return _core.fenced();
}

auto NetworkVolumeBackend::session_open() const noexcept -> bool {
    return _core.session_open();
}

auto NetworkVolumeBackend::take_faults() -> std::vector<InitiatorFault> {
    return _core.take_faults();
}

auto NetworkVolumeBackend::size_bytes() const noexcept -> std::uint64_t {
    return _core.capacity_bytes();
}

auto NetworkVolumeBackend::submit_read(std::uint64_t offset, std::span<std::byte> out,
                                       BackendCompletion done) -> void {
    _core.submit_read(offset, out, std::move(done), Clock::now());
    publish();
}

auto NetworkVolumeBackend::submit_write(std::uint64_t offset, std::span<const std::byte> in,
                                        BackendCompletion done) -> void {
    _core.submit_write(offset, in, std::move(done), Clock::now());
    publish();
}

auto NetworkVolumeBackend::submit_flush(BackendCompletion done) -> void {
    _core.submit_flush(std::move(done));
}

auto NetworkVolumeBackend::poll() -> bool {
    drain(_shared->inbox_fd);
    drain(_shared->timer_fd);
    std::vector<Shared::Event> events;
    {
        const std::scoped_lock lock{_shared->mutex};
        events.swap(_shared->inbox);
    }
    for (auto& e : events) {
        const auto now = Clock::now();
        switch (e.kind) {
            case Shared::Kind::connected:
                _core.connected(e.session, now);
                break;
            case Shared::Kind::disconnected:
                _core.disconnected(e.session, now);
                break;
            case Shared::Kind::frame:
                if (const auto f = proto::decode_hold_frame(e.frame)) {
                    _core.on_frame(e.session, *f, now);
                } else {
                    _core.disconnected(e.session, now);  // a payload that does not decode
                }
                break;
        }
    }
    _core.tick(Clock::now());
    publish();
    return _core.pending() != 0;
}

auto NetworkVolumeBackend::wake_fd() const noexcept -> int {
    return _shared->epoll;
}

auto NetworkVolumeBackend::publish() -> void {
    const auto now = Clock::now();
    const auto target = _core.target(now);
    auto frames = _core.take_output();
    bool changed = !frames.empty();
    {
        const std::scoped_lock lock{_shared->mutex};
        changed = changed || _shared->want != target;
        _shared->want = target;
        if (target) {
            if (_shared->out_session != target->session) {
                _shared->out.clear();
                _shared->out_session = target->session;
            }
            for (auto& f : frames) {
                _shared->out.push_back(std::move(f));
            }
        } else {
            _shared->out.clear();
        }
    }
    if (changed) {
        signal(_shared->io_fd);
    }
    // The timer fires at the core's next wake (steady_clock is
    // CLOCK_MONOTONIC on Linux); zero disarms it.
    itimerspec spec{};
    if (const auto wake = _core.next_wake(now)) {
        const auto ns = std::max<std::int64_t>(
            1,
            std::chrono::duration_cast<std::chrono::nanoseconds>(wake->time_since_epoch()).count());
        spec.it_value.tv_sec = static_cast<time_t>(ns / 1'000'000'000);
        spec.it_value.tv_nsec = static_cast<long>(ns % 1'000'000'000);
    }
    static_cast<void>(::timerfd_settime(_shared->timer_fd, TFD_TIMER_ABSTIME, &spec, nullptr));
}

}  // namespace ak::oar::blk
