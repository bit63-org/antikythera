// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/server-provisioning/ Requirement 4 (task 4): hull-init finds
// the provisioning partition by name, measures the frame into PCR 15 and
// only then decodes it. The TPM is a pseudo-terminal in raw mode played by
// a thread, which checks the exact TPM2_PCR_Extend command it receives.

#define BOOST_TEST_MODULE measured_boot_test
#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "ed25519_test_support.hpp"
#include "hull/measured_boot.hpp"
#include "proto/provisioning.hpp"
#include "test_support.hpp"

namespace fs = std::filesystem;
namespace hull = ak::hull;
namespace proto = ak::proto;
using ak::test::from_hex;
using ak::test::unit_timeout_seconds;

namespace {

class TempDir {
public:
    TempDir() {
        std::string templ = (fs::temp_directory_path() / "measured-boot-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(templ.data()) != nullptr);
        _path = templ;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(_path, ec);
    }
    [[nodiscard]] auto path() const -> const fs::path& { return _path; }

private:
    fs::path _path;
};

auto write_file(const fs::path& p, std::span<const std::byte> bytes) -> void {
    fs::create_directories(p.parent_path());
    std::ofstream out{p, std::ios::binary};
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

auto write_text(const fs::path& p, const std::string& text) -> void {
    fs::create_directories(p.parent_path());
    std::ofstream{p} << text;
}

// A block device in a fake sysfs: <root>/class/block/<dev>/uevent.
auto add_block(const fs::path& sysfs, const std::string& dev, const std::string& partname) {
    std::string uevent = "MAJOR=253\nMINOR=2\nDEVNAME=" + dev + "\nDEVTYPE=partition\n";
    if (!partname.empty()) {
        uevent += "PARTN=2\nPARTNAME=" + partname + "\n";
    }
    write_text(sysfs / "class/block" / dev / "uevent", uevent);
}

// A TPM played over a raw pseudo-terminal: answers one command with
// `rc` and keeps what it received.
class FakeTpm {
public:
    explicit FakeTpm(std::uint32_t rc) : _master{::posix_openpt(O_RDWR | O_NOCTTY)} {
        BOOST_REQUIRE(_master >= 0);
        BOOST_REQUIRE(::grantpt(_master) == 0);
        BOOST_REQUIRE(::unlockpt(_master) == 0);
        _path = ::ptsname(_master);
        // Keep the slave open and raw so the settings hold for hull's open.
        _slave = ::open(_path.c_str(), O_RDWR | O_NOCTTY);
        BOOST_REQUIRE(_slave >= 0);
        termios t{};
        BOOST_REQUIRE(::tcgetattr(_slave, &t) == 0);
        ::cfmakeraw(&t);
        BOOST_REQUIRE(::tcsetattr(_slave, TCSANOW, &t) == 0);
        _thread = std::thread{[this, rc] { serve(rc); }};
    }
    FakeTpm(const FakeTpm&) = delete;
    auto operator=(const FakeTpm&) -> FakeTpm& = delete;
    FakeTpm(FakeTpm&&) = delete;
    auto operator=(FakeTpm&&) -> FakeTpm& = delete;
    ~FakeTpm() {
        if (_thread.joinable()) {
            ::close(_slave);
            _slave = -1;
            ::close(_master);
            _master = -1;
            _thread.join();
        }
        if (_slave >= 0) {
            ::close(_slave);
        }
    }
    [[nodiscard]] auto path() const -> const std::string& { return _path; }
    // Waits for the exchange and returns the command received.
    auto command() -> std::vector<std::byte> {
        _thread.join();
        return _received;
    }

private:
    auto serve(std::uint32_t rc) -> void {
        // An extend with one SHA-256 digest is 65 bytes.
        std::vector<std::byte> buf(65);
        std::size_t got = 0;
        while (got < buf.size()) {
            const auto n = ::read(_master, buf.data() + got, buf.size() - got);
            if (n <= 0) {
                return;
            }
            got += static_cast<std::size_t>(n);
        }
        _received = buf;
        // tag 0x8002 | size 19 | rc | parameterSize 0 | empty auth response
        std::vector<std::byte> resp = from_hex("800200000013");
        for (int s = 24; s >= 0; s -= 8) {
            resp.push_back(std::byte{static_cast<std::uint8_t>(rc >> static_cast<unsigned>(s))});
        }
        const auto tail = from_hex("000000000000000000");
        resp.insert(resp.end(), tail.begin(), tail.end());
        const auto sent = ::write(_master, resp.data(), resp.size());
        // Boost.Test is not thread-safe: a short write empties what
        // command() returns, which fails the test on its own thread.
        if (sent != static_cast<ssize_t>(resp.size())) {
            _received.clear();
        }
    }

    int _master;
    int _slave{-1};
    std::string _path;
    std::thread _thread;
    std::vector<std::byte> _received;
};

auto frame() -> std::vector<std::byte> {
    auto f = proto::encode_provisioning({.server_id = 77, .boot_epoch = 5, .sequence_floor = 9});
    BOOST_REQUIRE(f.has_value());
    return *f;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(measured_boot, *boost::unit_test::timeout(unit_timeout_seconds))

BOOST_AUTO_TEST_CASE(extend_command_is_pinned) {
    hull::Sha256Digest d{};
    d.fill(std::byte{0xAB});
    const auto c = hull::pcr_extend_command(15, d);
    const auto want = from_hex(
        "80020000004100000182"        // TPM_ST_SESSIONS, size 65, TPM2_CC_PCR_Extend
        "0000000f"                    // PCR 15
        "00000009400000090000000000"  // one empty password session
        "00000001000b");              // one SHA-256 digest
    BOOST_TEST(c.size() == 65U);
    BOOST_TEST(std::ranges::equal(std::span{c}.first(want.size()), want));
    BOOST_TEST(std::ranges::all_of(std::span{c}.subspan(want.size()),
                                   [](std::byte b) { return b == std::byte{0xAB}; }));
}

BOOST_AUTO_TEST_CASE(response_codes) {
    BOOST_TEST((hull::tpm_response_code(from_hex("80010000000a00000000")) == 0U));
    BOOST_TEST((hull::tpm_response_code(from_hex("80010000000a00000922")) == 0x922U));
    // Wrong stated size, or too short.
    BOOST_TEST(!hull::tpm_response_code(from_hex("80010000000b00000000")).has_value());
    BOOST_TEST(!hull::tpm_response_code(from_hex("8001000000")).has_value());
}

BOOST_AUTO_TEST_CASE(finds_exactly_one_partition) {
    TempDir dir;
    const auto sys = dir.path() / "sys";
    add_block(sys, "vda", "");
    add_block(sys, "vda1", "EFI System");
    add_block(sys, "vda2", "ak-provisioning");
    auto found = hull::find_partition(sys, "ak-provisioning");
    BOOST_REQUIRE(found.has_value());
    BOOST_TEST(*found == "vda2");
    BOOST_TEST(!hull::find_partition(sys, "other").has_value());
    // Two of them: ambiguous, so refused.
    add_block(sys, "vdb2", "ak-provisioning");
    BOOST_TEST(!hull::find_partition(sys, "ak-provisioning").has_value());
    // A DEVNAME that would leave /dev is never used.
    TempDir other;
    add_block(other.path(), "evil", "");
    write_text(other.path() / "class/block/evil/uevent",
               "DEVNAME=../etc/shadow\nPARTNAME=ak-provisioning\n");
    BOOST_TEST(!hull::find_partition(other.path(), "ak-provisioning").has_value());
}

BOOST_AUTO_TEST_CASE(measures_the_frame_before_using_it) {
    TempDir dir;
    const auto sys = dir.path() / "sys";
    add_block(sys, "vda2", "ak-provisioning");
    auto f = frame();
    // The partition is a whole MiB; only the frame at its start counts.
    auto part = f;
    part.resize(4096);
    write_file(dir.path() / "dev/vda2", part);
    FakeTpm tpm{0};
    auto p = hull::read_measured_provisioning(sys, dir.path() / "dev", tpm.path());
    BOOST_REQUIRE_MESSAGE(p.has_value(), (p ? "" : p.error().step + ": " + p.error().detail));
    BOOST_TEST(p->server_id == 77U);
    BOOST_TEST(p->boot_epoch == 5U);
    BOOST_TEST(p->sequence_floor == 9U);
    const auto digest = hull::sha256(f);
    BOOST_REQUIRE(digest.has_value());
    BOOST_TEST((tpm.command() == hull::pcr_extend_command(hull::provisioning_pcr, *digest)));
}

BOOST_AUTO_TEST_CASE(fails_closed) {
    TempDir dir;
    const auto sys = dir.path() / "sys";
    add_block(sys, "vda2", "ak-provisioning");
    write_file(dir.path() / "dev/vda2", frame());
    {
        // The TPM refuses the extend.
        FakeTpm tpm{0x922};
        const auto p = hull::read_measured_provisioning(sys, dir.path() / "dev", tpm.path());
        BOOST_REQUIRE(!p.has_value());
        BOOST_TEST(p.error().step == "measure");
    }
    {
        // No TPM at all.
        const auto p =
            hull::read_measured_provisioning(sys, dir.path() / "dev", dir.path() / "no-tpm");
        BOOST_REQUIRE(!p.has_value());
        BOOST_TEST(p.error().step == "measure");
    }
    {
        // A frame that is measured but does not decode is still refused.
        auto bad = frame();
        bad[0] = std::byte{0};
        write_file(dir.path() / "dev/vda2", bad);
        FakeTpm tpm{0};
        const auto p = hull::read_measured_provisioning(sys, dir.path() / "dev", tpm.path());
        BOOST_REQUIRE(!p.has_value());
        BOOST_TEST(p.error().step == "provisioning");
        BOOST_TEST(tpm.command().size() == 65U);  // measured first
    }
    {
        // A partition shorter than a frame.
        const auto whole = frame();
        write_file(dir.path() / "dev/vda2", std::span{whole}.first(10));
        const auto p =
            hull::read_measured_provisioning(sys, dir.path() / "dev", dir.path() / "no-tpm");
        BOOST_REQUIRE(!p.has_value());
        BOOST_TEST(p.error().step == "provisioning");
    }
}

BOOST_AUTO_TEST_SUITE_END()
