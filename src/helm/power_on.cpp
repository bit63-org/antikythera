// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#include "helm/power_on.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <random>
#include <system_error>

namespace ak::helm {

namespace {

constexpr mode_t marker_mode = 0600;

}  // namespace

auto to_string(PolicyVerdict v) noexcept -> const char* {
    switch (v) {
        case PolicyVerdict::kept:
            return "kept";
        case PolicyVerdict::none:
            return "none stored";
        case PolicyVerdict::stale:
            return "not newer than the policy held";
        case PolicyVerdict::wrong_server:
            return "names another server";
        case PolicyVerdict::bad_signature:
            return "signature does not verify";
        case PolicyVerdict::corrupt:
            return "stored policy is corrupt";
        case PolicyVerdict::store_failed:
            return "sealed store failed";
    }
    return "unknown";
}

PowerPolicyKeeper::PowerPolicyKeeper(std::uint64_t server_id, SealedStore* store,
                                     const RecordVerifier* verifier) noexcept
    : _server_id{server_id},
      _store{store},
      _verifier{verifier},
      _current{proto::default_power_policy(server_id)} {}

auto PowerPolicyKeeper::verified(const proto::PowerPolicy& p,
                                 std::span<const std::byte> frame) const -> bool {
    return _verifier != nullptr && frame.size() == proto::power_policy_size &&
           _verifier->verify(proto::power_policy_signed_bytes(frame), p.signature, p.key_id);
}

auto PowerPolicyKeeper::load() -> PolicyVerdict {
    if (_store == nullptr) {
        return PolicyVerdict::none;
    }
    if (_store->rolled_back() || _store->degraded()) {
        // Requirement 1.5: an older copy of the partition may hold an older
        // policy, so none is trusted until the controller sends one.
        if (_store->contains(power_policy_object)) {
            (void)_store->remove(power_policy_object);
        }
        return PolicyVerdict::none;
    }
    const auto data = _store->get(power_policy_object);
    if (!data) {
        return PolicyVerdict::store_failed;
    }
    if (!*data) {
        return PolicyVerdict::none;
    }
    const auto p = proto::decode_power_policy(**data);
    if (!p) {
        return PolicyVerdict::corrupt;
    }
    if (p->server_id != _server_id) {
        return PolicyVerdict::wrong_server;
    }
    // Checked again: a key retired since it was stored no longer counts.
    if (!verified(*p, **data)) {
        return PolicyVerdict::bad_signature;
    }
    _current = *p;
    _from_record = true;
    return PolicyVerdict::kept;
}

auto PowerPolicyKeeper::offer(const proto::PowerPolicy& policy, std::span<const std::byte> frame)
    -> PolicyVerdict {
    if (policy.server_id != _server_id) {
        return PolicyVerdict::wrong_server;
    }
    if (_from_record && policy.policy_version <= _current.policy_version) {
        return PolicyVerdict::stale;
    }
    if (!verified(policy, frame)) {
        return PolicyVerdict::bad_signature;
    }
    if (_store != nullptr && !_store->put(power_policy_object, frame)) {
        return PolicyVerdict::store_failed;
    }
    _current = policy;
    _from_record = true;
    return PolicyVerdict::kept;
}

auto plan_power_on(const proto::PowerPolicy& policy, bool helm_power_returned,
                   HostPowerOverride override_, std::uint32_t jitter_ms) noexcept -> PowerOnPlan {
    switch (override_) {
        case HostPowerOverride::on:
            return {};
        case HostPowerOverride::hold:
            return {.wait = std::chrono::milliseconds{0}, .hold = true};
        case HostPowerOverride::none:
            break;
    }
    if (!helm_power_returned) {
        return {};
    }
    // The decoder bounds every term (power_wait_ms <= one hour, jitter
    // <= 30 s), so this cannot overflow.
    const auto jitter = std::min<std::uint64_t>(jitter_ms, policy.max_jitter_ms);
    const auto total = std::min(proto::power_wait_ms(policy), proto::max_power_wait_ms) + jitter;
    return {.wait = std::chrono::milliseconds{static_cast<std::chrono::milliseconds::rep>(total)},
            .hold = false};
}

auto draw_jitter(std::uint16_t max_jitter_ms) -> std::uint32_t {
    if (max_jitter_ms == 0) {
        return 0;
    }
    std::random_device rd;
    std::uniform_int_distribution<std::uint32_t> dist{0, max_jitter_ms};
    return dist(rd);
}

auto helm_power_returned(const std::filesystem::path& marker) -> std::expected<bool, int> {
    std::error_code ec;
    if (marker.has_parent_path()) {
        std::filesystem::create_directories(marker.parent_path(), ec);
    }
    const int fd =
        ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, marker_mode);
    if (fd >= 0) {
        (void)::close(fd);
        return true;
    }
    if (errno == EEXIST) {
        struct stat st{};
        if (::lstat(marker.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            return false;
        }
        return std::unexpected(EEXIST);
    }
    return std::unexpected(errno);
}

}  // namespace ak::helm
