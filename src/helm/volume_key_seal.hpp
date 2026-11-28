// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// The controller's side of a VolumeKey (.kiro/specs/block-volume-service/
// design "VolumeKey"): wraps a volume's data key to a helm's secure-element
// transport key with HPKE, the header as AAD and proto::volume_key_info as
// the info. kythira KMS does this in production; harbor's test controller
// and the tests use this one. seal_image_key does the same for an
// encrypted image's key (proto::ImageKey, oar-blk task 15), and
// seal_instance_secret for a standing instance's secret (cold-start
// Requirement 5.4).

#include <cstddef>
#include <expected>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "helm/hpke.hpp"
#include "proto/image_key.hpp"
#include "proto/standing_set.hpp"
#include "proto/volume_key.hpp"

namespace ak::helm {

// Returns the encoded VolumeKey for `header`'s server, volume, attachment
// and generation (its hpke_enc and wrapped_key are ignored and filled in).
[[nodiscard]] auto seal_volume_key(const hpke::PublicKey& recipient, proto::VolumeKey header,
                                   std::span<const std::byte, proto::volume_data_key_size> key)
    -> std::expected<std::vector<std::byte>, hpke::Error>;

// Returns the encoded ImageKey for `header`'s server, volume and owner
// (its hpke_enc and wrapped_key are ignored and filled in).
[[nodiscard]] auto seal_image_key(const hpke::PublicKey& recipient, proto::ImageKey header,
                                  std::span<const std::byte, proto::volume_data_key_size> key)
    -> std::expected<std::vector<std::byte>, hpke::Error>;

// Returns `name`'s secret sealed for instance `vm` on `server`: HPKE to
// `recipient`, info proto::instance_secret_info, AAD
// proto::instance_secret_aad(server, vm, name).
[[nodiscard]] auto seal_instance_secret(const hpke::PublicKey& recipient, std::uint64_t server,
                                        std::uint64_t vm, std::string_view name,
                                        std::span<const std::byte> secret)
    -> std::expected<proto::InstanceSecret, hpke::Error>;

}  // namespace ak::helm
