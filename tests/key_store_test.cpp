// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// .kiro/specs/helm-control-plane/ Requirement 4 (key hierarchy) and the
// KeyStore section of design.md: ScopedKey zeroization, the wrapped-key
// codec, the file-backed software secure element, and KeyStore's rules.

#define BOOST_TEST_MODULE key_store_test
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <sys/stat.h>

#include "helm/key_store.hpp"
#include "helm/scoped_key.hpp"
#include "helm/secure_element.hpp"
#include "helm/volume_key_seal.hpp"
#include "proto/image_key.hpp"
#include "proto/volume_key.hpp"
#include "test_support.hpp"

namespace ak::helm {

// Declared a friend of ScopedKey; the only reader outside OarLink.
struct ScopedKeyTestAccess {
    static auto bytes(const ScopedKey& k) -> std::vector<std::byte> {
        const auto b = k.bytes();
        return {b.begin(), b.end()};
    }
};

}  // namespace ak::helm

using ak::helm::KeyError;
using ak::helm::KeyKind;
using ak::helm::KeyStore;
using ak::helm::ScopedKey;
using ak::helm::ScopedKeyTestAccess;
using ak::helm::SecretBytes;
using ak::helm::SecureElement;
using ak::helm::SeError;
using ak::helm::SoftwareSecureElement;
using ak::helm::VmId;
using ak::helm::VolumeId;
using ak::helm::WrappedKey;
using ak::helm::WrappedKeyError;
using ak::helm::WrappedVolumeKey;
using ak::test::unit_timeout_seconds;

namespace {

constexpr VmId vm_one = 1;
constexpr VmId vm_two = 2;
constexpr VmId missing_vm = 99;
constexpr VolumeId vol_a = 100;
constexpr VolumeId vol_b = 101;
constexpr VolumeId missing_vol = 404;
constexpr std::size_t secret_size = 16;
constexpr auto fill_byte = std::byte{0xA5};
constexpr const char* master_key_name = "master.key";
constexpr const char* temp_template = "ak-key-store-test-XXXXXX";
constexpr mode_t group_readable = 0640;
constexpr std::size_t short_by = 1;
constexpr std::size_t flip_offset = WrappedKey::header_size + WrappedKey::nonce_size;
constexpr auto flip_mask = std::byte{0x01};

static_assert(!std::is_copy_constructible_v<ScopedKey>);
static_assert(!std::is_copy_assignable_v<ScopedKey>);
static_assert(std::is_nothrow_move_constructible_v<ScopedKey>);
static_assert(!std::is_copy_constructible_v<SecretBytes<secret_size>>);
// ScopedKey cannot be built outside SecureElement.
static_assert(!std::is_constructible_v<ScopedKey, std::span<const std::byte, 64>>);

auto key_of(const ScopedKey& k) -> std::vector<std::byte> {
    return ScopedKeyTestAccess::bytes(k);
}

auto all_zero(std::span<const std::byte> b) -> bool {
    return std::ranges::all_of(b, [](std::byte x) { return x == std::byte{0}; });
}

auto make_se() -> SoftwareSecureElement {
    auto se = SoftwareSecureElement::ephemeral();
    BOOST_REQUIRE(se.has_value());
    return std::move(*se);
}

// A private temporary directory, removed with everything in it.
struct TempDir {
    TempDir() {
        auto pattern = (std::filesystem::temp_directory_path() / temp_template).string();
        BOOST_REQUIRE(::mkdtemp(pattern.data()) != nullptr);
        path = pattern;
    }
    TempDir(const TempDir&) = delete;
    auto operator=(const TempDir&) -> TempDir& = delete;
    TempDir(TempDir&&) = delete;
    auto operator=(TempDir&&) -> TempDir& = delete;
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

// A KeyStore over an ephemeral secure element with vm_one and vm_two.
struct Fixture {
    Fixture() : se{make_se()}, store{se} {
        BOOST_REQUIRE(store.create_vm_key(vm_one).has_value());
        BOOST_REQUIRE(store.create_vm_key(vm_two).has_value());
    }
    SoftwareSecureElement se;
    KeyStore store;
};

auto flipped(const WrappedKey& k) -> WrappedKey {
    std::vector<std::byte> bytes{k.bytes().begin(), k.bytes().end()};
    bytes.at(flip_offset) ^= flip_mask;
    auto out = WrappedKey::decode(bytes);
    BOOST_REQUIRE(out.has_value());
    return std::move(*out);
}

// What kythira KMS does: wraps `key` to `recipient` for one attachment.
auto wrap_for(const ak::helm::hpke::PublicKey& recipient, std::span<const std::byte> key,
              std::uint64_t attachment = 7, std::uint32_t generation = 1)
    -> std::vector<std::byte> {
    BOOST_REQUIRE(key.size() == ak::proto::volume_data_key_size);
    auto frame = ak::helm::seal_volume_key(recipient,
                                           {.server_id = 3,
                                            .volume_id = vol_a,
                                            .attachment_id = attachment,
                                            .generation = generation,
                                            .hpke_enc = {},
                                            .wrapped_key = {}},
                                           key.first<ak::proto::volume_data_key_size>());
    BOOST_REQUIRE(frame.has_value());
    return *frame;
}

// What the controller does for an encrypted image: wraps K_img to
// `recipient` for one image volume and its owner.
auto wrap_image_for(const ak::helm::hpke::PublicKey& recipient, std::span<const std::byte> key,
                    VolumeId volume = vol_a, VmId owner = vm_one) -> std::vector<std::byte> {
    BOOST_REQUIRE(key.size() == ak::proto::volume_data_key_size);
    auto frame = ak::helm::seal_image_key(
        recipient,
        {.server_id = 3, .volume_id = volume, .owner_vm = owner, .hpke_enc = {}, .wrapped_key = {}},
        key.first<ak::proto::volume_data_key_size>());
    BOOST_REQUIRE(frame.has_value());
    return *frame;
}

auto open_frame(SecureElement& se, std::span<const std::byte> frame)
    -> std::expected<ScopedKey, SeError> {
    const auto k = ak::proto::decode_volume_key(frame);
    BOOST_REQUIRE(k.has_value());
    return se.open_volume_key(ak::proto::volume_key_aad(frame), k->hpke_enc, k->wrapped_key);
}

}  // namespace

BOOST_AUTO_TEST_SUITE(scoped_key)

BOOST_AUTO_TEST_CASE(secure_zero_wipes, *boost::unit_test::timeout(unit_timeout_seconds)) {
    std::array<std::byte, secret_size> buf{};
    buf.fill(fill_byte);
    ak::helm::secure_zero(buf);
    BOOST_TEST(all_zero(buf));
}

BOOST_AUTO_TEST_CASE(secret_bytes_move_wipes_source,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    SecretBytes<secret_size> a;
    std::ranges::fill(a.span(), fill_byte);
    SecretBytes<secret_size> b{std::move(a)};
    // Checking the wipe on the moved-from object.
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    BOOST_TEST(all_zero(a.span()));
    BOOST_TEST(std::ranges::all_of(b.span(), [](std::byte x) { return x == fill_byte; }));

    SecretBytes<secret_size> c;
    c = std::move(b);
    // Checking the wipe on the moved-from object.
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    BOOST_TEST(all_zero(b.span()));
    BOOST_TEST(std::ranges::all_of(c.span(), [](std::byte x) { return x == fill_byte; }));
}

BOOST_AUTO_TEST_CASE(moved_from_scoped_key_is_empty_and_wiped,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    auto key = f.store.unwrap_volume_key(vol_a, vm_one);
    BOOST_REQUIRE(key.has_value());
    BOOST_TEST(key->holds_key());
    const auto original = key_of(*key);
    BOOST_TEST(!all_zero(original));

    ScopedKey moved{std::move(*key)};
    BOOST_TEST(moved.holds_key());
    BOOST_TEST((key_of(moved) == original));
    // Checking the wipe on the moved-from object.
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    BOOST_TEST(!key->holds_key());
    BOOST_TEST(all_zero(key_of(*key)));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(wrapped_key_codec)

BOOST_AUTO_TEST_CASE(round_trips, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto se = make_se();
    auto vm = se.create_vm_key(vm_one);
    BOOST_REQUIRE(vm.has_value());
    BOOST_TEST(vm->key.bytes().size() == WrappedKey::encoded_size(KeyKind::vm));
    auto vol = se.create_volume_key(*vm, vol_a);
    BOOST_REQUIRE(vol.has_value());
    BOOST_TEST(vol->key.bytes().size() == WrappedKey::encoded_size(KeyKind::volume));

    for (const auto* k : {&vm->key, &vol->key}) {
        auto again = WrappedKey::decode(k->bytes());
        BOOST_REQUIRE(again.has_value());
        BOOST_TEST((*again == *k));
        BOOST_TEST((again->kind() == k->kind()));
    }
}

BOOST_AUTO_TEST_CASE(rejects_malformed, *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto se = make_se();
    auto vm = se.create_vm_key(vm_one);
    BOOST_REQUIRE(vm.has_value());
    const std::vector<std::byte> good{vm->key.bytes().begin(), vm->key.bytes().end()};

    BOOST_TEST((WrappedKey::decode({}).error() == WrappedKeyError::wrong_size));

    auto shorter = good;
    shorter.resize(good.size() - short_by);
    BOOST_TEST((WrappedKey::decode(shorter).error() == WrappedKeyError::wrong_size));

    auto longer = good;
    longer.push_back(std::byte{0});
    BOOST_TEST((WrappedKey::decode(longer).error() == WrappedKeyError::wrong_size));

    auto version = good;
    version[0] = std::byte{WrappedKey::format_version + 1};
    BOOST_TEST((WrappedKey::decode(version).error() == WrappedKeyError::unsupported_version));

    auto kind = good;
    kind[1] = std::byte{0};
    BOOST_TEST((WrappedKey::decode(kind).error() == WrappedKeyError::unknown_kind));

    auto length = good;
    length[2] = std::byte{ak::helm::volume_key_size};
    BOOST_TEST((WrappedKey::decode(length).error() == WrappedKeyError::wrong_key_length));
}

BOOST_AUTO_TEST_CASE(wrapping_hides_the_key, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    auto key = f.store.unwrap_volume_key(vol_a, vm_one);
    BOOST_REQUIRE(key.has_value());
    const auto plain = key_of(*key);
    const auto wrapped = f.store.find_volume_key(vol_a);
    BOOST_REQUIRE(wrapped.has_value());
    const auto blob = wrapped->key.bytes();
    // Neither half of the XTS key appears in the stored blob.
    const auto half = plain.size() / 2;
    BOOST_TEST(std::ranges::search(blob, std::span{plain}.first(half)).empty());
    BOOST_TEST(std::ranges::search(blob, std::span{plain}.last(half)).empty());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(software_secure_element)

BOOST_AUTO_TEST_CASE(creates_private_master_key_file,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.path / master_key_name;
    auto se = SoftwareSecureElement::open(path);
    BOOST_REQUIRE(se.has_value());
    BOOST_TEST(std::filesystem::file_size(path) == ak::helm::master_key_size);
    struct stat st{};
    BOOST_REQUIRE(::stat(path.c_str(), &st) == 0);
    BOOST_TEST((st.st_mode & 0777) == 0600);
}

BOOST_AUTO_TEST_CASE(reopened_master_key_unwraps,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.path / master_key_name;
    std::vector<std::byte> first_key;
    std::optional<ak::helm::WrappedVmKey> vm;
    std::optional<WrappedVolumeKey> vol;
    {
        auto se = SoftwareSecureElement::open(path);
        BOOST_REQUIRE(se.has_value());
        KeyStore store{*se};
        BOOST_REQUIRE(store.create_vm_key(vm_one).has_value());
        BOOST_REQUIRE(store.create_volume_key(vol_a, vm_one).has_value());
        auto key = store.unwrap_volume_key(vol_a, vm_one);
        BOOST_REQUIRE(key.has_value());
        first_key = key_of(*key);
        vm = store.find_vm_key(vm_one);
        vol = store.find_volume_key(vol_a);
    }
    BOOST_REQUIRE(vm.has_value());
    BOOST_REQUIRE(vol.has_value());

    // A restart: same master key file, keys reloaded from storage.
    auto se = SoftwareSecureElement::open(path);
    BOOST_REQUIRE(se.has_value());
    KeyStore store{*se};
    BOOST_REQUIRE(store.import_vm_key(*vm).has_value());
    BOOST_REQUIRE(store.import_volume_key(*vol).has_value());
    auto key = store.unwrap_volume_key(vol_a, vm_one);
    BOOST_REQUIRE(key.has_value());
    BOOST_TEST((key_of(*key) == first_key));

    // Another master key cannot unwrap them.
    auto other = make_se();
    KeyStore stranger{other};
    BOOST_REQUIRE(stranger.import_vm_key(*vm).has_value());
    BOOST_REQUIRE(stranger.import_volume_key(*vol).has_value());
    BOOST_TEST((stranger.unwrap_volume_key(vol_a, vm_one).error() == KeyError::corrupt_key));
}

BOOST_AUTO_TEST_CASE(refuses_group_readable_file,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.path / master_key_name;
    BOOST_REQUIRE(SoftwareSecureElement::open(path).has_value());
    BOOST_REQUIRE(::chmod(path.c_str(), group_readable) == 0);
    BOOST_TEST((SoftwareSecureElement::open(path).error() == SeError::master_key_insecure));
}

BOOST_AUTO_TEST_CASE(refuses_symlink, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto target = dir.path / master_key_name;
    const auto link = dir.path / "link.key";
    BOOST_REQUIRE(SoftwareSecureElement::open(target).has_value());
    std::filesystem::create_symlink(target, link);
    BOOST_TEST((SoftwareSecureElement::open(link).error() == SeError::master_key_insecure));
}

BOOST_AUTO_TEST_CASE(refuses_wrong_size, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.path / master_key_name;
    {
        std::ofstream out{path, std::ios::binary};
        out << "too short";
    }
    std::filesystem::permissions(
        path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    BOOST_TEST((SoftwareSecureElement::open(path).error() == SeError::master_key_wrong_size));
}

BOOST_AUTO_TEST_CASE(refuses_directory, *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    std::filesystem::permissions(dir.path, std::filesystem::perms::owner_all);
    BOOST_TEST((SoftwareSecureElement::open(dir.path).error() == SeError::master_key_insecure));
}

BOOST_AUTO_TEST_CASE(opens_volume_keys_wrapped_to_its_transport_key,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    TempDir dir;
    const auto path = dir.path / master_key_name;
    std::vector<std::byte> data_key(ak::helm::volume_key_size);
    for (std::size_t i = 0; i < data_key.size(); ++i) {
        data_key[i] = static_cast<std::byte>(i * 3);
    }
    std::vector<std::byte> frame;
    ak::helm::hpke::PublicKey pk{};
    {
        auto se = SoftwareSecureElement::open(path);
        BOOST_REQUIRE(se.has_value());
        auto got = se->transport_public_key();
        BOOST_REQUIRE(got.has_value());
        pk = *got;
        frame = wrap_for(pk, data_key);
        auto key = open_frame(*se, frame);
        BOOST_REQUIRE(key.has_value());
        BOOST_TEST((key_of(*key) == data_key));
    }
    // The transport key survives a restart: it comes from the master key.
    auto se = SoftwareSecureElement::open(path);
    BOOST_REQUIRE(se.has_value());
    BOOST_TEST((se->transport_public_key().value() == pk));
    auto key = open_frame(*se, frame);
    BOOST_REQUIRE(key.has_value());
    BOOST_TEST((key_of(*key) == data_key));

    // Another secure element has another transport key and cannot open it.
    auto other = make_se();
    BOOST_TEST((other.transport_public_key().value() != pk));
    BOOST_TEST((open_frame(other, frame).error() == SeError::authentication_failed));
}

BOOST_AUTO_TEST_CASE(a_volume_key_opens_only_for_its_own_header,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto se = make_se();
    const std::vector<std::byte> data_key(ak::helm::volume_key_size, fill_byte);
    const auto frame = wrap_for(se.transport_public_key().value(), data_key);
    // The same wrapped key moved to another attachment's header.
    auto k = ak::proto::decode_volume_key(frame).value();
    k.attachment_id = 8;
    const auto moved = ak::proto::encode_volume_key(k).value();
    BOOST_TEST((open_frame(se, moved).error() == SeError::authentication_failed));
    // A changed ciphertext.
    k = ak::proto::decode_volume_key(frame).value();
    k.wrapped_key[0] ^= flip_mask;
    BOOST_TEST((open_frame(se, ak::proto::encode_volume_key(k).value()).error() ==
                SeError::authentication_failed));
    // Wrapped under another info string (another use of the same key).
    k = ak::proto::decode_volume_key(frame).value();
    const auto sealed = ak::helm::hpke::seal(se.transport_public_key().value(), {},
                                             ak::proto::volume_key_aad(frame), data_key);
    BOOST_REQUIRE(sealed.has_value());
    std::ranges::copy(sealed->enc, k.hpke_enc.begin());
    std::ranges::copy(sealed->ciphertext, k.wrapped_key.begin());
    BOOST_TEST((open_frame(se, ak::proto::encode_volume_key(k).value()).error() ==
                SeError::authentication_failed));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(key_store)

// cold-start Requirement 5.4: an instance secret opens only for its own
// server, instance and name, and only in the secure element it was sealed
// to.
BOOST_AUTO_TEST_CASE(instance_secrets_open_only_for_their_instance,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto se = make_se();
    ak::helm::KeyStore store{se};
    const std::vector<std::byte> plain{std::byte{1}, std::byte{2}, std::byte{3}};
    const auto pk = se.transport_public_key().value();
    const auto sealed = ak::helm::seal_instance_secret(pk, 42, 0x1001, "hsm.share", plain);
    BOOST_REQUIRE(sealed.has_value());
    std::vector<std::byte> out(plain.size());
    BOOST_REQUIRE(store.open_instance_secret(42, 0x1001, *sealed, out).has_value());
    BOOST_TEST((out == plain));
    // Another instance, server or name: the AAD differs.
    BOOST_TEST(
        (store.open_instance_secret(42, 0x1002, *sealed, out).error() == KeyError::corrupt_key));
    BOOST_TEST((std::ranges::all_of(out, [](std::byte b) { return b == std::byte{0}; })));
    BOOST_TEST(
        (store.open_instance_secret(43, 0x1001, *sealed, out).error() == KeyError::corrupt_key));
    auto renamed = *sealed;
    renamed.name = "tls.key";
    BOOST_TEST(
        (store.open_instance_secret(42, 0x1001, renamed, out).error() == KeyError::corrupt_key));
    // The wrong output size.
    std::vector<std::byte> small(2);
    BOOST_TEST(
        (store.open_instance_secret(42, 0x1001, *sealed, small).error() == KeyError::corrupt_key));
    // Sealed to another secure element.
    auto other = make_se();
    const auto stray = ak::helm::seal_instance_secret(other.transport_public_key().value(), 42,
                                                      0x1001, "hsm.share", plain);
    BOOST_REQUIRE(stray.has_value());
    BOOST_TEST(
        (store.open_instance_secret(42, 0x1001, *stray, out).error() == KeyError::corrupt_key));
}

BOOST_AUTO_TEST_CASE(unwrap_is_stable_and_keys_distinct,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    BOOST_REQUIRE(f.store.create_volume_key(vol_b, vm_one).has_value());
    auto a1 = f.store.unwrap_volume_key(vol_a, vm_one);
    auto a2 = f.store.unwrap_volume_key(vol_a, vm_one);
    auto b = f.store.unwrap_volume_key(vol_b, vm_one);
    BOOST_REQUIRE(a1.has_value());
    BOOST_REQUIRE(a2.has_value());
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(key_of(*a1).size() == ak::helm::volume_key_size);
    BOOST_TEST((key_of(*a1) == key_of(*a2)));
    BOOST_TEST((key_of(*a1) != key_of(*b)));
    BOOST_TEST(f.store.volumes_of(vm_one) == (std::vector<VolumeId>{vol_a, vol_b}));
}

// An image volume's per-attachment key: full size, fresh each time, and
// not kept anywhere.
BOOST_AUTO_TEST_CASE(ephemeral_keys_are_fresh, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    auto a = f.store.create_ephemeral_key();
    auto b = f.store.create_ephemeral_key();
    BOOST_REQUIRE(a.has_value());
    BOOST_REQUIRE(b.has_value());
    BOOST_TEST(key_of(*a).size() == ak::helm::volume_key_size);
    BOOST_TEST((key_of(*a) != key_of(*b)));
    BOOST_TEST(f.store.volumes_of(vm_one).empty());
}

BOOST_AUTO_TEST_CASE(only_owner_unwraps, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    BOOST_TEST((f.store.unwrap_volume_key(vol_a, vm_two).error() == KeyError::wrong_vm));
    BOOST_TEST(
        (f.store.unwrap_volume_key(missing_vol, vm_one).error() == KeyError::unknown_volume));
}

BOOST_AUTO_TEST_CASE(rewrap_moves_ownership, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    auto before = f.store.unwrap_volume_key(vol_a, vm_one);
    BOOST_REQUIRE(before.has_value());

    BOOST_REQUIRE(f.store.rewrap(vol_a, vm_two).has_value());
    BOOST_TEST((f.store.owner(vol_a) == vm_two));
    BOOST_TEST((f.store.unwrap_volume_key(vol_a, vm_one).error() == KeyError::wrong_vm));
    auto after = f.store.unwrap_volume_key(vol_a, vm_two);
    BOOST_REQUIRE(after.has_value());
    // The data stays readable: same volume key, new wrapping.
    BOOST_TEST((key_of(*after) == key_of(*before)));

    BOOST_TEST((f.store.rewrap(vol_a, vm_two).error() == KeyError::same_vm));
    BOOST_TEST((f.store.rewrap(vol_a, missing_vm).error() == KeyError::unknown_vm));
    BOOST_TEST((f.store.rewrap(missing_vol, vm_one).error() == KeyError::unknown_volume));
}

BOOST_AUTO_TEST_CASE(destroy_volume_key, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    BOOST_REQUIRE(f.store.destroy_volume_key(vol_a).has_value());
    BOOST_TEST(!f.store.find_volume_key(vol_a).has_value());
    BOOST_TEST((f.store.unwrap_volume_key(vol_a, vm_one).error() == KeyError::unknown_volume));
    BOOST_TEST((f.store.destroy_volume_key(vol_a).error() == KeyError::unknown_volume));
    // The id is free again.
    BOOST_TEST(f.store.create_volume_key(vol_a, vm_two).has_value());
}

BOOST_AUTO_TEST_CASE(destroy_vm_key_crypto_erases_its_volumes,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    BOOST_REQUIRE(f.store.create_volume_key(vol_b, vm_two).has_value());
    const auto saved = f.store.find_volume_key(vol_a);
    BOOST_REQUIRE(saved.has_value());

    auto erased = f.store.destroy_vm_key(vm_one);
    BOOST_REQUIRE(erased.has_value());
    BOOST_TEST(*erased == std::vector<VolumeId>{vol_a});
    BOOST_TEST(!f.store.find_vm_key(vm_one).has_value());
    BOOST_TEST(f.store.volume_count() == 1U);
    BOOST_TEST(f.store.unwrap_volume_key(vol_b, vm_two).has_value());

    // The wrapped volume key left on the media is now unusable, even under
    // a new VM with the same id.
    BOOST_REQUIRE(f.store.create_vm_key(vm_one).has_value());
    BOOST_REQUIRE(f.store.import_volume_key(*saved).has_value());
    BOOST_TEST((f.store.unwrap_volume_key(vol_a, vm_one).error() == KeyError::corrupt_key));

    BOOST_TEST((f.store.destroy_vm_key(missing_vm).error() == KeyError::unknown_vm));
}

BOOST_AUTO_TEST_CASE(rejects_bad_ids_and_duplicates,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_TEST((f.store.create_vm_key(0).error() == KeyError::invalid_id));
    BOOST_TEST((f.store.create_vm_key(vm_one).error() == KeyError::duplicate_vm));
    BOOST_TEST((f.store.create_volume_key(0, vm_one).error() == KeyError::invalid_id));
    BOOST_TEST((f.store.create_volume_key(vol_a, 0).error() == KeyError::invalid_id));
    BOOST_TEST((f.store.create_volume_key(vol_a, missing_vm).error() == KeyError::unknown_vm));
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    BOOST_TEST((f.store.create_volume_key(vol_a, vm_two).error() == KeyError::duplicate_volume));
}

BOOST_AUTO_TEST_CASE(imports_are_checked, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    const auto vm = f.store.find_vm_key(vm_one);
    const auto vol = f.store.find_volume_key(vol_a);
    BOOST_REQUIRE(vm.has_value());
    BOOST_REQUIRE(vol.has_value());

    auto se = make_se();
    KeyStore store{se};
    // Owner first.
    BOOST_TEST((store.import_volume_key(*vol).error() == KeyError::unknown_vm));
    // A volume blob offered as a VM key, and vice versa.
    BOOST_TEST(
        (store.import_vm_key({.vm = vm_one, .key = vol->key}).error() == KeyError::wrong_kind));
    BOOST_REQUIRE(store.import_vm_key(*vm).has_value());
    BOOST_TEST((store.import_vm_key(*vm).error() == KeyError::duplicate_vm));
    BOOST_TEST(
        (store.import_volume_key({.volume = vol_a, .owner = vm_one, .key = vm->key}).error() ==
         KeyError::wrong_kind));
    BOOST_TEST((store.import_vm_key({.vm = 0, .key = vm->key}).error() == KeyError::invalid_id));
}

BOOST_AUTO_TEST_CASE(tampering_is_detected, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    BOOST_REQUIRE(f.store.create_volume_key(vol_a, vm_one).has_value());
    BOOST_REQUIRE(f.store.create_volume_key(vol_b, vm_one).has_value());
    const auto vm = f.store.find_vm_key(vm_one);
    const auto a = f.store.find_volume_key(vol_a);
    const auto b = f.store.find_volume_key(vol_b);
    BOOST_REQUIRE(vm.has_value());
    BOOST_REQUIRE(a.has_value());
    BOOST_REQUIRE(b.has_value());

    auto reload = [&](const WrappedVolumeKey& vol) {
        auto store = std::make_unique<KeyStore>(f.se);
        BOOST_REQUIRE(store->import_vm_key(*vm).has_value());
        BOOST_REQUIRE(store->import_volume_key(vol).has_value());
        return store;
    };

    // A flipped ciphertext bit.
    BOOST_TEST((reload({.volume = vol_a, .owner = vm_one, .key = flipped(a->key)})
                    ->unwrap_volume_key(vol_a, vm_one)
                    .error() == KeyError::corrupt_key));
    // Volume b's blob copied onto volume a: the AAD binds the volume id.
    BOOST_TEST((reload({.volume = vol_a, .owner = vm_one, .key = b->key})
                    ->unwrap_volume_key(vol_a, vm_one)
                    .error() == KeyError::corrupt_key));

    // A VM key relabelled as another VM's: the AAD binds the vm id.
    KeyStore store{f.se};
    BOOST_REQUIRE(store.import_vm_key({.vm = vm_two, .key = vm->key}).has_value());
    BOOST_REQUIRE(
        store.import_volume_key({.volume = vol_a, .owner = vm_two, .key = a->key}).has_value());
    BOOST_TEST((store.unwrap_volume_key(vol_a, vm_two).error() == KeyError::corrupt_key));
}

BOOST_AUTO_TEST_CASE(secure_element_checks_owner,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto se = make_se();
    auto one = se.create_vm_key(vm_one);
    auto two = se.create_vm_key(vm_two);
    BOOST_REQUIRE(one.has_value());
    BOOST_REQUIRE(two.has_value());
    auto vol = se.create_volume_key(*one, vol_a);
    BOOST_REQUIRE(vol.has_value());
    BOOST_TEST(vol->owner == vm_one);
    BOOST_TEST((se.unwrap_volume_key(*two, *vol).error() == SeError::wrong_vm_key));
    BOOST_TEST((se.rewrap_volume_key(*two, *one, *vol).error() == SeError::wrong_vm_key));
    // A volume key where a VM key belongs.
    const ak::helm::WrappedVmKey bogus{.vm = vm_one, .key = vol->key};
    BOOST_TEST((se.create_volume_key(bogus, vol_b).error() == SeError::wrong_kind));
}

BOOST_AUTO_TEST_CASE(keeps_network_volume_keys_per_attachment,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    auto se = make_se();
    KeyStore store{se};
    const auto pk = se.transport_public_key().value();
    const std::vector<std::byte> gen1(ak::helm::volume_key_size, std::byte{1});
    const std::vector<std::byte> gen2(ak::helm::volume_key_size, std::byte{2});
    BOOST_TEST((store.open_attachment_key(7, 1).error() == KeyError::unknown_attachment));

    BOOST_REQUIRE(store.put_attachment_key(wrap_for(pk, gen1, 7, 1)).has_value());
    BOOST_TEST(store.attachment_key(7)->volume_id == vol_a);
    // Opened again for every delivery.
    for (int i = 0; i < 2; ++i) {
        auto key = store.open_attachment_key(7, 1);
        BOOST_REQUIRE(key.has_value());
        BOOST_TEST((key_of(*key) == gen1));
    }
    // A newer generation replaces it; the older is then stale either way.
    BOOST_REQUIRE(store.put_attachment_key(wrap_for(pk, gen2, 7, 2)).has_value());
    BOOST_TEST(
        (store.put_attachment_key(wrap_for(pk, gen1, 7, 1)).error() == KeyError::stale_generation));
    BOOST_TEST((store.open_attachment_key(7, 1).error() == KeyError::stale_generation));
    BOOST_TEST((key_of(store.open_attachment_key(7, 2).value()) == gen2));
    BOOST_TEST((store.open_attachment_key(7, 3).error() == KeyError::unknown_attachment));

    // One wrapped to another secure element is refused and not kept.
    auto other = make_se();
    BOOST_TEST((
        store.put_attachment_key(wrap_for(other.transport_public_key().value(), gen1, 8)).error() ==
        KeyError::corrupt_key));
    BOOST_TEST(
        (store.put_attachment_key(std::vector<std::byte>(10)).error() == KeyError::corrupt_key));
    BOOST_TEST(!store.attachment_key(8).has_value());
    BOOST_TEST(store.attachment_key_count() == 1U);

    store.drop_attachment_key(7);
    BOOST_TEST((store.open_attachment_key(7, 2).error() == KeyError::unknown_attachment));
    BOOST_TEST(store.attachment_key_count() == 0U);
}

// oar-blk task 15: K_img arrives wrapped to the transport key and becomes
// the image volume's ordinary volume key at its CREATE_VOLUME.
BOOST_AUTO_TEST_CASE(imports_image_keys_as_volume_keys,
                     *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    const auto pk = f.se.transport_public_key().value();
    const std::vector<std::byte> k_img(ak::helm::volume_key_size, std::byte{0x5A});
    BOOST_TEST((f.store.import_image_key(vol_a, vm_one).error() == KeyError::unknown_volume));

    BOOST_REQUIRE(f.store.put_image_key(wrap_image_for(pk, k_img)).has_value());
    BOOST_TEST(f.store.image_key(vol_a)->owner_vm == vm_one);
    BOOST_TEST(f.store.image_key_count() == 1U);
    BOOST_TEST(!f.store.owner(vol_a).has_value());  // not a volume key until imported

    // Only for the owner the controller named.
    BOOST_TEST((f.store.import_image_key(vol_a, vm_two).error() == KeyError::wrong_vm));
    BOOST_REQUIRE(f.store.import_image_key(vol_a, vm_one).has_value());
    BOOST_TEST(f.store.image_key_count() == 0U);
    BOOST_TEST((f.store.owner(vol_a) == vm_one));
    BOOST_TEST((key_of(f.store.unwrap_volume_key(vol_a, vm_one).value()) == k_img));
    BOOST_TEST((f.store.unwrap_volume_key(vol_a, vm_two).error() == KeyError::wrong_vm));
    // Wrapped like any volume key: never the plaintext.
    const auto wrapped = f.store.find_volume_key(vol_a);
    BOOST_REQUIRE(wrapped.has_value());
    BOOST_TEST((wrapped->key.kind() == KeyKind::volume));
    BOOST_TEST(std::ranges::search(wrapped->key.bytes(), k_img).empty());

    // Rewrapped and destroyed like one too.
    BOOST_REQUIRE(f.store.rewrap(vol_a, vm_two).has_value());
    BOOST_TEST((key_of(f.store.unwrap_volume_key(vol_a, vm_two).value()) == k_img));
    BOOST_REQUIRE(f.store.destroy_volume_key(vol_a).has_value());
    BOOST_TEST((f.store.unwrap_volume_key(vol_a, vm_two).error() == KeyError::unknown_volume));

    // A second frame for a volume that already has its key is refused at
    // import; a frame for a volume the store already holds a key for
    // cannot replace that key.
    BOOST_REQUIRE(f.store.create_volume_key(vol_b, vm_one).has_value());
    BOOST_REQUIRE(f.store.put_image_key(wrap_image_for(pk, k_img, vol_b)).has_value());
    BOOST_TEST((f.store.import_image_key(vol_b, vm_one).error() == KeyError::duplicate_volume));
    f.store.drop_image_key(vol_b);
    BOOST_TEST(!f.store.image_key(vol_b).has_value());
}

BOOST_AUTO_TEST_CASE(refuses_bad_image_keys, *boost::unit_test::timeout(unit_timeout_seconds)) {
    Fixture f;
    const auto pk = f.se.transport_public_key().value();
    const std::vector<std::byte> k_img(ak::helm::volume_key_size, std::byte{0x5A});
    // Wrapped to another secure element, or not a frame at all.
    auto other = make_se();
    BOOST_TEST((f.store.put_image_key(wrap_image_for(other.transport_public_key().value(), k_img))
                    .error() == KeyError::corrupt_key));
    BOOST_TEST(
        (f.store.put_image_key(std::vector<std::byte>(10)).error() == KeyError::corrupt_key));
    // A network VolumeKey frame is not an image key, even to the same SE.
    BOOST_TEST((f.store.put_image_key(wrap_for(pk, k_img)).error() == KeyError::corrupt_key));
    // A header changed after sealing (here the owner) no longer opens.
    auto moved = wrap_image_for(pk, k_img);
    moved.at(0x18) = std::byte{static_cast<unsigned char>(vm_two)};
    BOOST_TEST((f.store.put_image_key(moved).error() == KeyError::corrupt_key));
    BOOST_TEST(f.store.image_key_count() == 0U);

    // A newer frame for the volume replaces the older.
    BOOST_REQUIRE(f.store.put_image_key(wrap_image_for(pk, k_img, vol_a, vm_one)).has_value());
    BOOST_REQUIRE(f.store.put_image_key(wrap_image_for(pk, k_img, vol_a, vm_two)).has_value());
    BOOST_TEST(f.store.image_key_count() == 1U);
    BOOST_TEST(f.store.image_key(vol_a)->owner_vm == vm_two);
    // An owner that has no VM key yet.
    BOOST_REQUIRE(f.store.put_image_key(wrap_image_for(pk, k_img, vol_b, missing_vm)).has_value());
    BOOST_TEST((f.store.import_image_key(vol_b, missing_vm).error() == KeyError::unknown_vm));
    // Destroying a VM drops the frames naming it.
    BOOST_REQUIRE(f.store.destroy_vm_key(vm_two).has_value());
    BOOST_TEST(!f.store.image_key(vol_a).has_value());
    BOOST_TEST(f.store.image_key(vol_b).has_value());
}

BOOST_AUTO_TEST_SUITE_END()
