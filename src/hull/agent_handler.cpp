// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/agent_handler.hpp"

#include <variant>

namespace ak::hull {

namespace mb = helm::mailbox;

namespace {

template<class... Ts> struct Overloaded : Ts... {
    using Ts::operator()...;
};

auto just(mb::Status s) -> CommandOutcome {
    return {.status = s, .payload = {}};
}

}  // namespace

auto AgentHandler::handle(const mb::Message& /*msg*/, const mb::Body& body) -> CommandOutcome {
    return std::visit(Overloaded{
                          [&](const mb::CreateVm& c) { return just(_supervisor->create(c)); },
                          [&](const mb::DestroyVm& c) { return just(_supervisor->destroy(c)); },
                          [&](const mb::ListVms&) { return _supervisor->list(); },
                          [&](const mb::VmStatus& c) { return _supervisor->status(c); },
                          [](const mb::AttachDevice&) { return just(mb::Status::unsupported); },
                          [](const mb::DetachDevice&) { return just(mb::Status::unsupported); },
                          [](const mb::AttachVolume&) { return just(mb::Status::unsupported); },
                          [](const mb::DetachVolume&) { return just(mb::Status::unsupported); },
                          [](const mb::CreateVolume&) { return just(mb::Status::ok); },
                          [](const mb::DeleteVolume&) { return just(mb::Status::ok); },
                          [](const mb::RewrapVolume&) { return just(mb::Status::ok); },
                          [](const mb::CreateNetwork&) { return just(mb::Status::ok); },
                          [](const mb::DeleteNetwork&) { return just(mb::Status::ok); },
                          // Responses and events never reach a handler (the client only
                          // passes commands); answer defensively all the same.
                          [](const auto&) { return just(mb::Status::malformed); },
                      },
                      body);
}

}  // namespace ak::hull
