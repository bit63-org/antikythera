// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "oar/blk/hold_transport.hpp"

#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include "proto/hold_stream.hpp"
#include "proto/server_identity.hpp"
#include "proto/storage_net.hpp"

namespace ak::oar::blk {

namespace {

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

// One session's connection and its I/O thread.
struct HoldTransport::Conn {
    Conn(const Conn&) = delete;
    auto operator=(const Conn&) -> Conn& = delete;
    Conn(Conn&&) = delete;
    auto operator=(Conn&&) -> Conn& = delete;
    explicit Conn(const HoldTarget& t) : target{t} {}
    ~Conn() { close_fd(io_fd); }

    auto request_stop() -> void {
        {
            const std::scoped_lock lock{mutex};
            stop = true;
        }
        signal(io_fd);
    }

    HoldTarget target;
    int io_fd{-1};  // wakes the thread
    std::mutex mutex;
    std::deque<Bytes> out;
    bool stop{false};
    std::atomic<bool> done{false};
    std::thread thread;
};

struct HoldTransport::Shared {
    Shared(const Shared&) = delete;
    auto operator=(const Shared&) -> Shared& = delete;
    Shared(Shared&&) = delete;
    auto operator=(Shared&&) -> Shared& = delete;
    Shared() = default;
    ~Shared() {
        close_fd(epoll);
        close_fd(inbox_fd);
        close_fd(timer_fd);
    }

    auto post(Event e) -> void {
        {
            const std::scoped_lock lock{mutex};
            inbox.push_back(std::move(e));
        }
        signal(inbox_fd);
    }
    auto open(const HoldTarget& t) -> std::optional<tls::Stream>;
    auto run(Conn& c) -> void;

    int epoll{-1};     // wake_fd(): inbox_fd and timer_fd
    int inbox_fd{-1};  // the I/O threads posted events
    int timer_fd{-1};  // the core's next wake
    std::chrono::milliseconds connect_timeout{0};
    std::chrono::milliseconds write_timeout{0};
    std::uint8_t version{1};

    std::mutex mutex;  // tls and inbox
    tls::Config tls;
    std::vector<Event> inbox;

    // Role thread only.
    std::map<std::uint64_t, std::unique_ptr<Conn>> live;  // by session
    std::vector<std::unique_ptr<Conn>> dying;             // stopped, not yet joined
};

auto HoldTransport::Shared::open(const HoldTarget& t) -> std::optional<tls::Stream> {
    const auto host = proto::endpoint_text(t.endpoint);
    if (host.empty()) {
        return std::nullopt;
    }
    tls::Config config;
    {
        const std::scoped_lock lock{mutex};  // set_tls may replace it
        config = tls;
    }
    config.role = tls::Role::client;
    config.peer_name = host;  // the server's IP SAN
    auto ctx = tls::Context::create(config);
    if (!ctx) {
        return std::nullopt;
    }
    auto s = tls::Stream::connect(*ctx, host, t.port, Clock::now() + connect_timeout);
    if (!s) {
        return std::nullopt;
    }
    // The server the target names, by its certificate.
    const auto uris = s->peer_uris();
    const auto id = proto::server_id_of(uris);
    if (!id || *id != t.server_id) {
        s->close();
        return std::nullopt;
    }
    proto::set_storage_class(s->fd());
    return std::move(*s);
}

auto HoldTransport::Shared::run(Conn& c) -> void {
    const auto session = c.target.session;
    const auto stopped = [&] {
        const std::scoped_lock lock{c.mutex};
        return c.stop;
    };
    auto stream = open(c.target);
    if (stopped()) {
        if (stream) {
            stream->close();
        }
        c.done = true;
        return;
    }
    if (!stream) {
        post({.kind = EventKind::disconnected, .session = session, .frame = {}});
        c.done = true;
        return;
    }
    post({.kind = EventKind::connected, .session = session, .frame = {}});
    proto::FrameAssembler in{version};
    Bytes buf(read_chunk);
    bool lost = false;
    while (!lost) {
        std::deque<Bytes> frames;
        {
            const std::scoped_lock lock{c.mutex};
            if (c.stop) {
                break;
            }
            frames.swap(c.out);
        }
        for (const auto& f : frames) {
            if (!stream->write_all(f, Clock::now() + write_timeout)) {
                lost = true;
                break;
            }
        }
        while (!lost) {
            const auto got = stream->read_some(buf);
            if (!got) {
                lost = true;
                break;
            }
            if (*got == 0) {
                break;
            }
            in.feed(std::span{buf}.first(*got));
            for (;;) {
                auto f = in.next();
                if (!f) {
                    lost = true;  // not a hold frame of this version: end the session
                    break;
                }
                if (!f->has_value()) {
                    break;
                }
                post({.kind = EventKind::frame, .session = session, .frame = std::move(**f)});
            }
        }
        if (lost) {
            break;
        }
        if (stream->pending()) {
            continue;
        }
        std::array<pollfd, 2> fds{pollfd{.fd = c.io_fd, .events = POLLIN, .revents = 0},
                                  pollfd{.fd = stream->fd(), .events = POLLIN, .revents = 0}};
        if (::poll(fds.data(), fds.size(), -1) < 0 && errno != EINTR) {
            lost = true;
            break;
        }
        drain(c.io_fd);
    }
    stream->close();
    if (lost && !stopped()) {
        post({.kind = EventKind::disconnected, .session = session, .frame = {}});
    }
    c.done = true;
}

auto HoldTransport::create(HoldTransportConfig config)
    -> std::expected<std::unique_ptr<HoldTransport>, NetworkVolumeError> {
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
    shared->version = config.wire_version;
    shared->epoll = ::epoll_create1(EPOLL_CLOEXEC);
    shared->inbox_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    shared->timer_fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (shared->epoll < 0 || shared->inbox_fd < 0 || shared->timer_fd < 0) {
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
    return std::unique_ptr<HoldTransport>{new HoldTransport{std::move(shared)}};
}

HoldTransport::HoldTransport(std::unique_ptr<Shared> shared) noexcept
    : _shared{std::move(shared)} {}

HoldTransport::~HoldTransport() {
    for (auto& [session, c] : _shared->live) {
        c->request_stop();
        _shared->dying.push_back(std::move(c));
    }
    _shared->live.clear();
    reap(true);
}

auto HoldTransport::reap(bool all) -> void {
    std::erase_if(_shared->dying, [all](std::unique_ptr<Conn>& c) {
        if (!all && !c->done.load()) {
            return false;
        }
        if (c->thread.joinable()) {
            c->thread.join();
        }
        return true;
    });
}

auto HoldTransport::set_tls(const tls::Config& config) -> void {
    const std::scoped_lock lock{_shared->mutex};
    _shared->tls = config;
}

auto HoldTransport::sync(const std::vector<HoldTarget>& targets, std::vector<Outgoing> frames)
    -> void {
    reap(false);
    auto& live = _shared->live;
    // Sessions the core no longer names close without an event.
    for (auto it = live.begin(); it != live.end();) {
        const bool wanted = std::ranges::any_of(
            targets, [&](const HoldTarget& t) { return t.session == it->first; });
        if (wanted) {
            ++it;
            continue;
        }
        it->second->request_stop();
        _shared->dying.push_back(std::move(it->second));
        it = live.erase(it);
    }
    for (const auto& t : targets) {
        if (live.contains(t.session)) {
            continue;
        }
        auto c = std::make_unique<Conn>(t);
        c->io_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        bool started = c->io_fd >= 0;
        if (started) {
            try {
                c->thread = std::thread{[s = _shared.get(), conn = c.get()] { s->run(*conn); }};
            } catch (const std::system_error&) {
                started = false;
            }
        }
        if (!started) {
            _shared->post({.kind = EventKind::disconnected, .session = t.session, .frame = {}});
            continue;
        }
        live.emplace(t.session, std::move(c));
    }
    std::vector<Conn*> woken;
    for (auto& f : frames) {
        const auto it = live.find(f.session);
        if (it == live.end()) {
            continue;
        }
        {
            const std::scoped_lock lock{it->second->mutex};
            it->second->out.push_back(std::move(f.frame));
        }
        if (std::ranges::find(woken, it->second.get()) == woken.end()) {
            woken.push_back(it->second.get());
        }
    }
    for (auto* c : woken) {
        signal(c->io_fd);
    }
}

auto HoldTransport::take_events() -> std::vector<Event> {
    drain(_shared->inbox_fd);
    drain(_shared->timer_fd);
    std::vector<Event> events;
    {
        const std::scoped_lock lock{_shared->mutex};
        events.swap(_shared->inbox);
    }
    return events;
}

auto HoldTransport::arm(std::optional<Clock::time_point> wake) -> void {
    // steady_clock is CLOCK_MONOTONIC on Linux; zero disarms the timer.
    itimerspec spec{};
    if (wake) {
        const auto ns = std::max<std::int64_t>(
            1,
            std::chrono::duration_cast<std::chrono::nanoseconds>(wake->time_since_epoch()).count());
        spec.it_value.tv_sec = static_cast<time_t>(ns / 1'000'000'000);
        spec.it_value.tv_nsec = static_cast<long>(ns % 1'000'000'000);
    }
    static_cast<void>(::timerfd_settime(_shared->timer_fd, TFD_TIMER_ABSTIME, &spec, nullptr));
}

auto HoldTransport::wake_fd() const noexcept -> int {
    return _shared->epoll;
}

}  // namespace ak::oar::blk
