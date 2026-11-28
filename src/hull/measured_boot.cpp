// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "hull/measured_boot.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <system_error>

#include <openssl/evp.h>

namespace ak::hull {

namespace fs = std::filesystem;

namespace {

constexpr std::uint16_t tpm_st_sessions = 0x8002;
constexpr std::uint32_t tpm_cc_pcr_extend = 0x0000'0182;
constexpr std::uint32_t tpm_rs_pw = 0x4000'0009;
constexpr std::uint16_t tpm_alg_sha256 = 0x000B;
constexpr std::size_t tpm_header_size = 10;
constexpr std::size_t max_tpm_response = 4096;

auto be16(std::vector<std::byte>& out, std::uint16_t v) -> void {
    out.push_back(std::byte{static_cast<std::uint8_t>(v >> 8U)});
    out.push_back(std::byte{static_cast<std::uint8_t>(v)});
}
auto be32(std::vector<std::byte>& out, std::uint32_t v) -> void {
    for (int s = 24; s >= 0; s -= 8) {
        out.push_back(std::byte{static_cast<std::uint8_t>(v >> static_cast<unsigned>(s))});
    }
}
auto read_be32(std::span<const std::byte> b, std::size_t at) -> std::uint32_t {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        v = (v << 8U) | std::to_integer<std::uint32_t>(b[at + i]);
    }
    return v;
}

auto failure(std::string step, std::string detail, int err = 0) -> SetupFailure {
    return SetupFailure{.step = std::move(step), .detail = std::move(detail), .sys_errno = err};
}

// The value of KEY= in a uevent file's text.
auto uevent_value(std::string_view text, std::string_view key) -> std::optional<std::string> {
    std::size_t at = 0;
    while (at < text.size()) {
        auto end = text.find('\n', at);
        if (end == std::string_view::npos) {
            end = text.size();
        }
        const auto line = text.substr(at, end - at);
        if (line.size() > key.size() && line.starts_with(key) && line[key.size()] == '=') {
            return std::string{line.substr(key.size() + 1)};
        }
        at = end + 1;
    }
    return std::nullopt;
}

class Fd {
public:
    explicit Fd(int fd) noexcept : _fd{fd} {}
    Fd(const Fd&) = delete;
    auto operator=(const Fd&) -> Fd& = delete;
    Fd(Fd&&) = delete;
    auto operator=(Fd&&) -> Fd& = delete;
    ~Fd() {
        if (_fd >= 0) {
            ::close(_fd);
        }
    }
    [[nodiscard]] auto get() const noexcept -> int { return _fd; }

private:
    int _fd;
};

}  // namespace

auto find_partition(const fs::path& sysfs, std::string_view partname)
    -> std::expected<std::string, SetupFailure> {
    std::error_code ec;
    std::vector<std::string> found;
    for (const auto& entry : fs::directory_iterator{sysfs / "class/block", ec}) {
        std::ifstream in{entry.path() / "uevent"};
        if (!in) {
            continue;
        }
        std::ostringstream text;
        text << in.rdbuf();
        const auto name = uevent_value(text.str(), "PARTNAME");
        const auto dev = uevent_value(text.str(), "DEVNAME");
        if (name && *name == partname && dev && !dev->empty() &&
            dev->find('/') == std::string::npos && *dev != "." && *dev != "..") {
            found.push_back(*dev);
        }
    }
    if (found.empty()) {
        return std::unexpected(
            failure("provisioning", "no partition named " + std::string{partname}));
    }
    if (found.size() > 1) {
        return std::unexpected(
            failure("provisioning", "more than one partition named " + std::string{partname}));
    }
    return found.front();
}

auto pcr_extend_command(std::uint32_t pcr, const Sha256Digest& digest) -> std::vector<std::byte> {
    std::vector<std::byte> c;
    be16(c, tpm_st_sessions);
    be32(c, 0);  // size, filled below
    be32(c, tpm_cc_pcr_extend);
    be32(c, pcr);  // a PCR's handle is its index
    be32(c, 9);    // authorization area: one empty password session
    be32(c, tpm_rs_pw);
    be16(c, 0);                 // nonce
    c.push_back(std::byte{0});  // session attributes
    be16(c, 0);                 // password
    be32(c, 1);                 // TPML_DIGEST_VALUES count
    be16(c, tpm_alg_sha256);
    c.insert(c.end(), digest.begin(), digest.end());
    const auto size = static_cast<std::uint32_t>(c.size());
    for (std::size_t i = 0; i < 4; ++i) {
        c[2 + i] = std::byte{static_cast<std::uint8_t>(size >> (8 * (3 - i)))};
    }
    return c;
}

auto tpm_response_code(std::span<const std::byte> r) -> std::optional<std::uint32_t> {
    if (r.size() < tpm_header_size || read_be32(r, 2) != r.size()) {
        return std::nullopt;
    }
    return read_be32(r, 6);
}

auto sha256(std::span<const std::byte> data) -> std::optional<Sha256Digest> {
    Sha256Digest d{};
    unsigned len = 0;
    if (EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char*>(d.data()), &len,
                   EVP_sha256(), nullptr) != 1 ||
        len != d.size()) {
        return std::nullopt;
    }
    return d;
}

auto extend_pcr(const fs::path& device, std::uint32_t pcr, const Sha256Digest& digest)
    -> std::expected<void, SetupFailure> {
    const Fd fd{::open(device.c_str(), O_RDWR | O_CLOEXEC | O_NOCTTY)};
    if (fd.get() < 0) {
        return std::unexpected(failure("measure", "open " + device.string(), errno));
    }
    const auto cmd = pcr_extend_command(pcr, digest);
    if (::write(fd.get(), cmd.data(), cmd.size()) != static_cast<ssize_t>(cmd.size())) {
        return std::unexpected(failure("measure", "write " + device.string(), errno));
    }
    // The kernel's TPM device returns a whole response to one read; read
    // on until its stated size arrives anyway, for transports that do not.
    std::vector<std::byte> resp(max_tpm_response);
    std::size_t got = 0;
    std::size_t want = tpm_header_size;
    while (got < want) {
        const auto n = ::read(fd.get(), resp.data() + got, resp.size() - got);
        if (n <= 0) {
            return std::unexpected(
                failure("measure", "read " + device.string(), n < 0 ? errno : 0));
        }
        got += static_cast<std::size_t>(n);
        if (got >= tpm_header_size) {
            want = read_be32(resp, 2);
            if (want < tpm_header_size || want > resp.size()) {
                return std::unexpected(failure("measure", "malformed TPM response"));
            }
        }
    }
    const auto rc = tpm_response_code(std::span{resp}.first(got));
    if (!rc) {
        return std::unexpected(failure("measure", "malformed TPM response"));
    }
    if (*rc != 0) {
        return std::unexpected(
            failure("measure", "TPM2_PCR_Extend failed with response code " + std::to_string(*rc)));
    }
    return {};
}

auto read_measured_provisioning(const fs::path& sysfs, const fs::path& dev, const fs::path& tpm)
    -> std::expected<proto::Provisioning, SetupFailure> {
    const auto name = find_partition(sysfs, provisioning_partition);
    if (!name) {
        return std::unexpected(name.error());
    }
    const auto path = dev / *name;
    std::vector<std::byte> frame(proto::provisioning_size);
    {
        std::ifstream in{path, std::ios::binary};
        in.read(reinterpret_cast<char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
        if (!in) {
            return std::unexpected(failure("provisioning", "cannot read " + path.string()));
        }
    }
    // Measure first: nothing reads the frame before the TPM has seen it.
    const auto digest = sha256(frame);
    if (!digest) {
        return std::unexpected(failure("measure", "SHA-256 failed"));
    }
    if (auto ok = extend_pcr(tpm, provisioning_pcr, *digest); !ok) {
        return std::unexpected(ok.error());
    }
    auto p = proto::decode_provisioning(frame);
    if (!p) {
        return std::unexpected(
            failure("provisioning", std::string{"bad frame: "} + proto::to_string(p.error())));
    }
    return *p;
}

}  // namespace ak::hull
