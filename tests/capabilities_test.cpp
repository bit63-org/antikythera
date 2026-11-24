// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/hull-host-agent/ Requirement 9.1: after the drop the process
// holds at most the agent's set, no inheritable or ambient capabilities,
// and no_new_privs. Runs the drop in a forked child so the test runner
// keeps its own capabilities; as root it also checks the bounding set.

#define BOOST_TEST_MODULE capabilities_test
#include <boost/test/unit_test.hpp>

#include <linux/capability.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <string>

#include "hull/capabilities.hpp"
#include "test_support.hpp"

using ak::hull::agent_capabilities;
using ak::hull::drop_capabilities_except;
using ak::test::unit_timeout_seconds;

namespace {

// The Cap*/NoNewPrivs lines of /proc/self/status.
auto status_fields() -> std::map<std::string, std::uint64_t> {
    std::map<std::string, std::uint64_t> out;
    std::ifstream in{"/proc/self/status"};
    std::string line;
    while (std::getline(in, line)) {
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const auto key = line.substr(0, colon);
        if (key.starts_with("Cap")) {
            out[key] = std::stoull(line.substr(colon + 1), nullptr, 16);
        } else if (key == "NoNewPrivs") {
            out[key] = std::stoull(line.substr(colon + 1));
        }
    }
    return out;
}

auto agent_mask() -> std::uint64_t {
    std::uint64_t m = 0;
    for (const int cap : agent_capabilities()) {
        m |= std::uint64_t{1} << cap;
    }
    return m;
}

// Runs the drop in a child; exit code 0 means every check passed, others
// name the first that failed.
auto drop_in_child() -> int {
    const pid_t pid = ::fork();
    if (pid == 0) {
        const auto before = status_fields();
        if (!drop_capabilities_except(agent_capabilities())) {
            ::_exit(10);
        }
        auto after = status_fields();
        const auto keep = agent_mask();
        if ((after["CapEff"] & ~keep) != 0 || (after["CapPrm"] & ~keep) != 0) {
            ::_exit(11);
        }
        if (after["CapEff"] != (before.at("CapEff") & keep)) {
            ::_exit(12);  // kept what it had of the agent's set
        }
        if (after["CapInh"] != 0 || after["CapAmb"] != 0) {
            ::_exit(13);
        }
        if (after["NoNewPrivs"] != 1) {
            ::_exit(14);
        }
        const bool had_setpcap = (before.at("CapEff") & (std::uint64_t{1} << CAP_SETPCAP)) != 0;
        if (had_setpcap && (after["CapBnd"] & ~keep) != 0) {
            ::_exit(15);
        }
        ::_exit(0);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(capabilities, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(the_agent_set) {
    const auto caps = agent_capabilities();
    BOOST_TEST(caps.size() == 7U);
    BOOST_TEST((std::ranges::find(caps, CAP_SYS_ADMIN) != caps.end()));
    BOOST_TEST((std::ranges::find(caps, CAP_KILL) != caps.end()));
    // Nothing that would let the agent load modules, touch raw I/O or
    // change capabilities again.
    for (const int never : {CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SETPCAP, CAP_NET_ADMIN,
                            CAP_SYS_PTRACE, CAP_DAC_OVERRIDE, CAP_MKNOD, CAP_SYS_BOOT}) {
        BOOST_TEST((std::ranges::find(caps, never) == caps.end()));
    }
}

BOOST_AUTO_TEST_CASE(drops_everything_else) {
    BOOST_TEST(drop_in_child() == 0);
}

BOOST_AUTO_TEST_SUITE_END()
