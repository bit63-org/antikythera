// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 5.3: a storage role's media
// sanitize. The NVMe admin sequence (SANICAP, crypto erase, block erase
// as the fallback, the Sanitize Status log until done), the role options,
// and the per-drive results the oar sanitize request answers with.

#define BOOST_TEST_MODULE media_sanitize_test
#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <memory>
#include <span>
#include <stop_token>
#include <thread>
#include <vector>

#include "helm/media_sanitize.hpp"

namespace {

namespace helm = ak::helm;
namespace nvme = ak::helm::nvme;
namespace oar = ak::helm::oar;
namespace proto = ak::proto;
using namespace std::chrono_literals;

// An NVMe controller: SANICAP, how each sanitize action goes, and the
// SSTAT values the log page shows after it.
struct FakeController {
    std::uint32_t caps{nvme::sanicap_crypto | nvme::sanicap_block};
    bool identify_fails{false};
    bool crypto_refused{false};  // the Sanitize command itself fails
    std::deque<std::uint16_t> crypto_log{nvme::sstat_running, nvme::sstat_done};
    std::deque<std::uint16_t> block_log{nvme::sstat_done};
    std::vector<std::uint32_t> actions;  // SANACT of each Sanitize issued
    std::uint32_t current{0};

    auto admin() -> helm::NvmeAdmin {
        return [this](nvme_passthru_cmd& cmd) -> int {
            // The kernel's command carries the buffer address as a u64.
            // NOLINTNEXTLINE(performance-no-int-to-ptr)
            const std::span<std::byte> data{reinterpret_cast<std::byte*>(cmd.addr), cmd.data_len};
            switch (cmd.opcode) {
                case nvme::opcode_identify: {
                    if (identify_fails || cmd.cdw10 != nvme::identify_controller ||
                        data.size() != nvme::identify_size) {
                        return -1;
                    }
                    for (std::size_t i = 0; i < 4; ++i) {
                        data[nvme::sanicap_offset + i] =
                            static_cast<std::byte>((caps >> (8U * i)) & 0xFFU);
                    }
                    return 0;
                }
                case nvme::opcode_sanitize:
                    actions.push_back(cmd.cdw10);
                    current = cmd.cdw10;
                    return cmd.cdw10 == nvme::sanact_crypto && crypto_refused ? 0x4002 : 0;
                case nvme::opcode_get_log_page: {
                    if ((cmd.cdw10 & 0xFFU) != nvme::log_sanitize_status ||
                        data.size() != nvme::sanitize_log_size) {
                        return -1;
                    }
                    auto& log = current == nvme::sanact_crypto ? crypto_log : block_log;
                    const auto st = log.empty() ? nvme::sstat_running : log.front();
                    if (log.size() > 1) {
                        log.pop_front();
                    }
                    data[2] = static_cast<std::byte>(st);
                    return 0;
                }
                default:
                    return -1;
            }
        };
    }
};

auto timing(int& sleeps) -> helm::NvmeSanitizeTiming {
    return {.poll = 1s, .limit = 10s, .sleep = [&sleeps](std::chrono::milliseconds) { ++sleeps; }};
}

auto serial(std::string_view s) -> proto::IdentityText {
    return proto::identity_text(s);
}

}  // namespace

BOOST_AUTO_TEST_CASE(crypto_erase_is_used_when_supported) {
    FakeController c;
    int sleeps = 0;
    BOOST_TEST((helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) ==
                proto::SanitizeResult::sanitized_crypto));
    BOOST_TEST(c.actions == std::vector<std::uint32_t>{nvme::sanact_crypto});
    BOOST_TEST(sleeps == 1);  // one "running" before done
}

BOOST_AUTO_TEST_CASE(block_erase_is_the_fallback) {
    {
        FakeController c;
        c.caps = nvme::sanicap_block;  // no crypto erase
        int sleeps = 0;
        BOOST_TEST((helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) ==
                    proto::SanitizeResult::sanitized_block));
        BOOST_TEST(c.actions == std::vector<std::uint32_t>{nvme::sanact_block});
    }
    {
        FakeController c;
        c.crypto_refused = true;
        int sleeps = 0;
        BOOST_TEST((helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) ==
                    proto::SanitizeResult::sanitized_block));
        BOOST_TEST(c.actions.size() == 2U);
    }
    {
        FakeController c;
        c.crypto_log = {nvme::sstat_running, nvme::sstat_failed};
        c.block_log = {nvme::sstat_never, nvme::sstat_done_no_deallocate};
        int sleeps = 0;
        BOOST_TEST((helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) ==
                    proto::SanitizeResult::sanitized_block));
    }
}

BOOST_AUTO_TEST_CASE(a_drive_that_cannot_be_sanitized_fails) {
    {
        FakeController c;
        c.caps = 0;
        int sleeps = 0;
        BOOST_TEST(
            (helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) == proto::SanitizeResult::failed));
        BOOST_TEST(c.actions.empty());
    }
    {
        FakeController c;
        c.identify_fails = true;
        int sleeps = 0;
        BOOST_TEST(
            (helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) == proto::SanitizeResult::failed));
    }
    {
        // Never finishes within the limit.
        FakeController c;
        c.caps = nvme::sanicap_crypto;
        c.crypto_log = {nvme::sstat_running};
        int sleeps = 0;
        BOOST_TEST(
            (helm::nvme_sanitize(c.admin(), {}, timing(sleeps)) == proto::SanitizeResult::failed));
        BOOST_TEST(sleeps == 10);
    }
    {
        // Stopped (the role is shutting down).
        FakeController c;
        std::stop_source stop;
        stop.request_stop();
        int sleeps = 0;
        BOOST_TEST((helm::nvme_sanitize(c.admin(), stop.get_token(), timing(sleeps)) ==
                    proto::SanitizeResult::failed));
    }
    // Not a device, or not NVMe.
    BOOST_TEST((helm::sanitize_device("/nonexistent/nvme9", {}) == proto::SanitizeResult::failed));
    const auto file = std::filesystem::temp_directory_path() / "ak-media-sanitize-not-nvme";
    {
        std::FILE* f = std::fopen(file.c_str(), "w");
        BOOST_REQUIRE(f != nullptr);
        (void)std::fclose(f);
    }
    BOOST_TEST((helm::sanitize_device(file, {}) == proto::SanitizeResult::failed));
    std::filesystem::remove(file);
}

BOOST_AUTO_TEST_CASE(drive_device_options) {
    std::vector<helm::SanitizeTarget> t;
    BOOST_TEST(!helm::parse_sanitize_option("--drive-serial", "x:1", t).has_value());
    BOOST_TEST(helm::parse_sanitize_option("--drive-device", "Z9:/dev/nvme1", t).value());
    BOOST_TEST(helm::parse_sanitize_option("--drive-device", "A:1:/dev/nvme0n1", t).value());
    BOOST_REQUIRE(t.size() == 2U);
    BOOST_TEST(proto::identity_text_view(t[0].serial) == "A:1");  // serial order
    BOOST_TEST(t[0].device == "/dev/nvme0n1");
    BOOST_TEST(!helm::parse_sanitize_option("--drive-device", "Z9:/dev/nvme2", t).value());
    BOOST_TEST(!helm::parse_sanitize_option("--drive-device", "Q:dev/nvme2", t).value());
    BOOST_TEST(!helm::parse_sanitize_option("--drive-device", ":/dev/nvme2", t).value());
    BOOST_TEST(!helm::parse_sanitize_option("--drive-device", std::string(33, 'x') + ":/dev/x", t)
                    .value());
    BOOST_TEST(t.size() == 2U);

    // Drives the identity names without a device are added, to be
    // reported failed.
    const oar::RoleIdentity id{.serial = serial("B"),
                               .firmware = {},
                               .drives = {{.serial = serial("A:1"), .size_bytes = 1},
                                          {.serial = serial("M"), .size_bytes = 1}}};
    const auto all = helm::sanitize_targets(id, t);
    BOOST_REQUIRE(all.size() == 3U);
    BOOST_TEST(all[0].device == "/dev/nvme0n1");
    BOOST_TEST(proto::identity_text_view(all[1].serial) == "M");
    BOOST_TEST(all[1].device.empty());
    BOOST_TEST(all[2].device == "/dev/nvme1");
}

BOOST_AUTO_TEST_CASE(the_sanitizer_answers_running_then_every_result) {
    std::atomic<bool> release{false};
    std::atomic<int> runs{0};
    helm::MediaSanitizer s{{{.serial = serial("D-1"), .device = "/dev/a"},
                            {.serial = serial("D-2"), .device = {}},
                            {.serial = serial("D-3"), .device = "/dev/c"}},
                           [&](const std::filesystem::path& device, const std::stop_token& stop) {
                               ++runs;
                               while (!release && !stop.stop_requested()) {
                                   std::this_thread::sleep_for(1ms);
                               }
                               return device == "/dev/a" ? proto::SanitizeResult::sanitized_crypto
                                                         : proto::SanitizeResult::sanitized_block;
                           }};
    BOOST_TEST((s.status().state == oar::SanitizeState::running));  // not started
    BOOST_TEST((s.start().state == oar::SanitizeState::running));
    BOOST_TEST((s.start().state == oar::SanitizeState::running));  // once only
    release = true;
    oar::SanitizeStatus st;
    for (int i = 0; i < 5000; ++i) {
        st = s.status();
        if (st.state == oar::SanitizeState::done) {
            break;
        }
        std::this_thread::sleep_for(1ms);
    }
    BOOST_REQUIRE((st.state == oar::SanitizeState::done));
    BOOST_TEST(runs == 2);  // the drive with no device is not run
    BOOST_REQUIRE(st.drives.size() == 3U);
    BOOST_TEST((st.drives[0].result == proto::SanitizeResult::sanitized_crypto));
    BOOST_TEST((st.drives[1].result == proto::SanitizeResult::failed));
    BOOST_TEST((st.drives[2].result == proto::SanitizeResult::sanitized_block));
    // The answer encodes: it is what the role sends helm.
    BOOST_TEST(oar::encode_sanitize_status(st).has_value());
}

BOOST_AUTO_TEST_CASE(a_sanitizer_stops_with_its_role) {
    std::atomic<bool> stopped{false};
    {
        helm::MediaSanitizer s{{{.serial = serial("D-1"), .device = "/dev/a"}},
                               [&](const std::filesystem::path&, const std::stop_token& stop) {
                                   while (!stop.stop_requested()) {
                                       std::this_thread::sleep_for(1ms);
                                   }
                                   stopped = true;
                                   return proto::SanitizeResult::failed;
                               }};
        (void)s.start();
    }
    BOOST_TEST(stopped.load());
}
