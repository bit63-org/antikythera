// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirement 9.3: the append-only,
// hash-chained audit log.

#define BOOST_TEST_MODULE audit_log_test
#include <boost/test/unit_test.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "helm/audit_log.hpp"
#include "test_support.hpp"

using ak::helm::AuditErrc;
using ak::helm::AuditEvent;
using ak::helm::AuditLog;
using ak::helm::AuditRecord;
using ak::helm::AuditTail;
using ak::helm::format_audit_line;
using ak::helm::make_function_id;
using ak::helm::verify_audit_log;
using ak::test::unit_timeout_seconds;

namespace {

constexpr std::int64_t fixed_ms = 1'763'500'000'000;
constexpr std::uint64_t some_seq = 42;
constexpr std::uint16_t create_vm_type = 0x0001;
constexpr std::uint16_t some_status = 9;
constexpr std::uint64_t some_vm = 7;
constexpr std::uint64_t some_volume = 11;
constexpr std::uint8_t some_slot = 3;
constexpr std::uint16_t some_fn = 260;
constexpr std::uint64_t some_count = 2;
constexpr mode_t loose_mode = 0644;

auto sample_records() -> std::vector<AuditRecord> {
    return {
        AuditRecord::of(AuditEvent::command_received)
            .with_seq(some_seq)
            .with_command(create_vm_type),
        AuditRecord::of(AuditEvent::vm_key_created).with_seq(some_seq).with_vm(some_vm),
        AuditRecord::of(AuditEvent::command_outcome)
            .with_seq(some_seq)
            .with_command(create_vm_type)
            .with_status(0),
        AuditRecord::of(AuditEvent::volume_key_delivered)
            .with_seq(some_seq + 1)
            .with_status(some_status)
            .with_vm(some_vm)
            .with_volume(some_volume)
            .with_function(make_function_id(some_slot, some_fn)),
        AuditRecord::of(AuditEvent::vm_key_destroyed).with_vm(some_vm).with_count(some_count),
    };
}

auto build(const std::vector<AuditRecord>& records) -> std::string {
    std::string text;
    AuditTail tail;
    for (const auto& r : records) {
        text += format_audit_line(tail, fixed_ms, r);
        auto v = verify_audit_log(text);
        BOOST_REQUIRE(v);
        tail = *v;
    }
    return text;
}

auto lines_of(const std::string& text) -> std::vector<std::string> {
    std::vector<std::string> out;
    std::istringstream in{text};
    for (std::string line; std::getline(in, line);) {
        out.push_back(line + "\n");
    }
    return out;
}

auto join(const std::vector<std::string>& lines) -> std::string {
    std::string out;
    for (const auto& l : lines) {
        out += l;
    }
    return out;
}

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string tmpl = (std::filesystem::temp_directory_path() / "ak-audit-XXXXXX").string();
        BOOST_REQUIRE(::mkdtemp(tmpl.data()) != nullptr);
        path = tmpl;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() { std::filesystem::remove_all(path); }
};

auto read_file(const std::filesystem::path& p) -> std::string {
    std::ifstream in{p, std::ios::binary};
    return {std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
}

auto options() -> AuditLog::Options {
    return {.sync = false, .clock = [] { return fixed_ms; }};
}

}  // namespace

BOOST_AUTO_TEST_CASE(lines_have_the_documented_form,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto records = sample_records();
    const auto line = format_audit_line(AuditTail{}, fixed_ms, records.at(3));
    BOOST_TEST(
        line.starts_with("n=0 t=1763500000000 ev=volume_key_delivered seq=43 status=9 "
                         "vm=7 vol=11 fn=3.260 h="));
    BOOST_TEST(line.ends_with("\n"));
    // Unset fields are not printed.
    const auto bare = format_audit_line(AuditTail{}, fixed_ms, AuditRecord{});
    BOOST_TEST(bare.starts_with("n=0 t=1763500000000 ev=command_received h="));
}

BOOST_AUTO_TEST_CASE(a_chain_verifies_and_reports_its_tail,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto text = build(sample_records());
    const auto tail = verify_audit_log(text);
    BOOST_REQUIRE(tail);
    BOOST_TEST(tail->next_index == sample_records().size());
    BOOST_TEST((verify_audit_log("") == AuditTail{}));
}

BOOST_AUTO_TEST_CASE(any_edit_breaks_the_chain, *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto lines = lines_of(build(sample_records()));

    // Change one identifier in the middle: that record's hash no longer matches.
    auto edited = lines;
    edited.at(1).replace(edited.at(1).find("vm=7"), 4, "vm=8");
    auto r = verify_audit_log(join(edited));
    BOOST_REQUIRE(!r);
    BOOST_TEST((r.error().code == AuditErrc::bad_hash));
    BOOST_TEST(r.error().line == 2U);

    // Drop a record.
    auto dropped = lines;
    dropped.erase(dropped.begin() + 1);
    r = verify_audit_log(join(dropped));
    BOOST_REQUIRE(!r);
    BOOST_TEST((r.error().code == AuditErrc::bad_index));

    // Swap two records.
    auto swapped = lines;
    std::swap(swapped.at(1), swapped.at(2));
    r = verify_audit_log(join(swapped));
    BOOST_REQUIRE(!r);
    BOOST_TEST((r.error().code == AuditErrc::bad_index));

    // Truncating from the end leaves a valid, shorter chain (append-only
    // means the file is never truncated; the tail index shows how far it got).
    auto shorter = lines;
    shorter.pop_back();
    BOOST_TEST(verify_audit_log(join(shorter))->next_index == lines.size() - 1);
}

BOOST_AUTO_TEST_CASE(non_canonical_and_torn_lines_are_refused,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    const auto lines = lines_of(build(sample_records()));
    const std::vector<std::pair<std::string, std::string>> edits{
        {"seq=42", "seq=042"},    // leading zero
        {"cmd=0x1", "cmd=0x01"},  // leading zero
        {" seq=42", "  seq=42"},  // double space
        {"ev=command_received", "ev=nope"},
        {"n=0", "n=+0"},
    };
    for (const auto& [from, to] : edits) {
        BOOST_TEST_CONTEXT(to) {
            auto bad = lines;
            const auto at = bad.at(0).find(from);
            BOOST_REQUIRE(at != std::string::npos);
            bad.at(0).replace(at, from.size(), to);
            const auto r = verify_audit_log(join(bad));
            BOOST_REQUIRE(!r);
            BOOST_TEST((r.error().code == AuditErrc::bad_line));
            BOOST_TEST(r.error().line == 1U);
        }
    }
    auto text = join(lines);
    text.pop_back();
    const auto torn = verify_audit_log(text);
    BOOST_REQUIRE(!torn);
    BOOST_TEST((torn.error().code == AuditErrc::torn_tail));
}

BOOST_AUTO_TEST_CASE(the_file_continues_its_chain_across_reopens,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = (dir.path / "audit.log").string();
    const auto records = sample_records();
    {
        auto log = AuditLog::open(path, options());
        BOOST_REQUIRE(log);
        BOOST_REQUIRE(log->append(records.at(0)));
        BOOST_REQUIRE(log->append(records.at(1)));
    }
    struct stat st{};
    BOOST_REQUIRE(::stat(path.c_str(), &st) == 0);
    BOOST_TEST((st.st_mode & 0777U) == 0600U);
    {
        auto log = AuditLog::open(path, options());
        BOOST_REQUIRE(log);
        BOOST_TEST(log->tail().next_index == 2U);
        for (std::size_t i = 2; i < records.size(); ++i) {
            BOOST_REQUIRE(log->append(records.at(i)));
        }
        BOOST_TEST(log->tail().next_index == records.size());
    }
    // The file is byte for byte what one uninterrupted writer produces.
    BOOST_TEST(read_file(path) == build(records));
}

BOOST_AUTO_TEST_CASE(unsafe_or_tampered_files_are_refused,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.path / "audit.log";
    {
        auto log = AuditLog::open(path.string(), options());
        BOOST_REQUIRE(log);
        BOOST_REQUIRE(log->append(sample_records().at(0)));
    }

    const auto link = dir.path / "link.log";
    std::filesystem::create_symlink(path, link);
    auto r = AuditLog::open(link.string(), options());
    BOOST_REQUIRE(!r);
    BOOST_TEST((r.error().code == AuditErrc::unsafe_file));

    BOOST_REQUIRE(::chmod(path.c_str(), loose_mode) == 0);
    r = AuditLog::open(path.string(), options());
    BOOST_REQUIRE(!r);
    BOOST_TEST((r.error().code == AuditErrc::unsafe_file));
    BOOST_REQUIRE(::chmod(path.c_str(), 0600) == 0);

    {
        std::ofstream out{path, std::ios::app};
        out << "garbage\n";
    }
    r = AuditLog::open(path.string(), options());
    BOOST_REQUIRE(!r);
    BOOST_TEST((r.error().code == AuditErrc::bad_line));
    BOOST_TEST(r.error().line == 2U);

    r = AuditLog::open(dir.path.string(), options());
    BOOST_REQUIRE(!r);
}
