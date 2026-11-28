// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// CredentialCache: the peers' VTEP credentials a Tunnel has verified
// (.kiro/specs/fleet-scale-networking/ Requirement 3.2, design "Certified
// handshake", task 3).
//
// Keyed by public key, with a second index by VTEP address, so the
// responder finds the credential for the static key an initiation
// decrypts to and the initiator finds the key for the address it sends
// to. Each VTEP and each key appears at most once: inserting a credential
// replaces any entry with the same key or the same VTEP (a peer that
// rotated its key, or one whose credential was renewed). Least recently
// used entries go first when the cache is full, so a credential is
// verified once per cache lifetime while memory stays bounded.
//
// The cache holds only verified credentials; it checks nothing itself.
// The frame bytes are kept so that a re-sent identical credential can be
// recognised without verifying it again.
//
// Not thread-safe: it belongs to the Tunnel's data-plane thread.

#include <algorithm>
#include <array>
#include <cstddef>
#include <list>
#include <map>
#include <span>

#include "oar/net/vtep_policy.hpp"
#include "oar/net/wireguard.hpp"
#include "proto/vtep_credential.hpp"

namespace ak::oar::net {

struct CachedCredential {
    proto::VtepCredential credential;
    std::array<std::byte, proto::vtep_credential_size> frame{};
};

class CredentialCache {
public:
    explicit CredentialCache(std::size_t capacity) : _capacity{capacity == 0 ? 1 : capacity} {}

    // Finds and marks as recently used.
    [[nodiscard]] auto find(const wg::Key& key) -> const CachedCredential* {
        const auto it = _by_key.find(key);
        if (it == _by_key.end()) {
            return nullptr;
        }
        _lru.splice(_lru.begin(), _lru, it->second);
        return &*it->second;
    }
    [[nodiscard]] auto find_vtep(const Ipv6Address& vtep) -> const CachedCredential* {
        const auto it = _by_vtep.find(vtep);
        return it == _by_vtep.end() ? nullptr : find(it->second);
    }

    // Inserts a verified credential, replacing entries for its key or VTEP.
    auto insert(const proto::VtepCredential& credential, std::span<const std::byte> frame)
        -> const CachedCredential& {
        erase(credential.public_key);
        erase_vtep(credential.vtep);
        while (_lru.size() >= _capacity) {
            erase(_lru.back().credential.public_key);
        }
        CachedCredential entry{.credential = credential, .frame = {}};
        std::copy_n(frame.begin(), std::min(frame.size(), entry.frame.size()), entry.frame.begin());
        _lru.push_front(entry);
        _by_key[credential.public_key] = _lru.begin();
        _by_vtep[credential.vtep] = credential.public_key;
        return _lru.front();
    }

    auto erase(const wg::Key& key) -> bool {
        const auto it = _by_key.find(key);
        if (it == _by_key.end()) {
            return false;
        }
        _by_vtep.erase(it->second->credential.vtep);
        _lru.erase(it->second);
        _by_key.erase(it);
        return true;
    }
    auto erase_vtep(const Ipv6Address& vtep) -> bool {
        const auto it = _by_vtep.find(vtep);
        if (it == _by_vtep.end()) {
            return false;
        }
        const auto key = it->second;
        return erase(key);
    }

    [[nodiscard]] auto contains_vtep(const Ipv6Address& vtep) const -> bool {
        return _by_vtep.contains(vtep);
    }
    [[nodiscard]] auto size() const noexcept -> std::size_t { return _lru.size(); }
    [[nodiscard]] auto capacity() const noexcept -> std::size_t { return _capacity; }

private:
    std::size_t _capacity;
    std::list<CachedCredential> _lru;  // most recently used first
    std::map<wg::Key, std::list<CachedCredential>::iterator> _by_key;
    std::map<Ipv6Address, wg::Key> _by_vtep;
};

}  // namespace ak::oar::net
