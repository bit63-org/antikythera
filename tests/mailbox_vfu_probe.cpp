// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Serves a MailboxVfuServer for harbor/mailbox_smoke.py
// (.kiro/specs/helm-control-plane/ task 8). It echoes: every event slot the
// client rings for is posted straight back as a command (from inside the
// host-slot handler, which also proves the handler may post), and the first
// response slot ends the run, printing the slot's first word.

#include <cstdlib>
#include <print>

#include "helm/mailbox_vfu_server.hpp"

auto main(int argc, char** argv) -> int {
    if (argc != 2) {
        std::println(stderr, "usage: mailbox_vfu_probe SOCKET");
        return EXIT_FAILURE;
    }
    ak::helm::MailboxVfuServer* server = nullptr;
    auto created = ak::helm::MailboxVfuServer::create(
        argv[1], [&](ak::helm::HostSlotKind kind, const ak::helm::mailbox::Slot& slot) {
            if (kind == ak::helm::HostSlotKind::event) {
                std::println(stderr, "probe: event, posted={}",
                             server->host_port().post_command(slot));
                return;
            }
            std::println(stderr, "probe: response, first byte {:#x}",
                         static_cast<unsigned>(slot[0]));
            server->stop();
        });
    if (!created) {
        std::println(stderr, "probe: {}", created.error());
        return EXIT_FAILURE;
    }
    server = created->get();
    if (auto served = server->serve(); !served) {
        std::println(stderr, "probe: {}", served.error());
        return EXIT_FAILURE;
    }
    const auto stats = server->device().stats();
    std::println(stderr, "probe: posted={} unposted={} responses={} events={} resets={}",
                 stats.commands_posted, stats.commands_unposted, stats.responses, stats.events,
                 stats.resets);
    return stats.commands_posted == 1 && stats.commands_unposted == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
