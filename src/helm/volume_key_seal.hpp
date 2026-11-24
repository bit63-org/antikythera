// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The controller's side of a VolumeKey (.kiro/specs/block-volume-service/
// design "VolumeKey"): wraps a volume's data key to a helm's secure-element
// transport key with HPKE, the header as AAD and proto::volume_key_info as
// the info. kythira KMS does this in production; harbor's test controller
// and the tests use this one.

#include <cstddef>
#include <expected>
#include <span>
#include <vector>

#include "helm/hpke.hpp"
#include "proto/volume_key.hpp"

namespace ak::helm {

// Returns the encoded VolumeKey for `header`'s server, volume, attachment
// and generation (its hpke_enc and wrapped_key are ignored and filled in).
[[nodiscard]] auto seal_volume_key(const hpke::PublicKey& recipient, proto::VolumeKey header,
                                   std::span<const std::byte, proto::volume_data_key_size> key)
    -> std::expected<std::vector<std::byte>, hpke::Error>;

}  // namespace ak::helm
