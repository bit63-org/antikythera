// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Bounds-checked readers and writers for wire formats.
//
// Every byte that crosses a trust boundary (the PCIe mailbox, MCTP on the
// sideband, Geneve on the datacenter network, virtqueues in guest memory)
// is parsed through these helpers. Reads never go past the end of the
// buffer: they return std::unexpected(WireError::truncated) instead. Wire
// structs are decoded field by field -- never by casting a pointer -- so
// there is no alignment, aliasing or padding dependence.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <type_traits>
#include <vector>

namespace ak::wire {

enum class WireError : std::uint8_t {
    truncated,  // buffer ended before the field did
    overflow,   // writer ran out of room
};

enum class Order : std::uint8_t { big, little };

namespace detail {

template <std::unsigned_integral T>
constexpr T from_order(T v, Order order) noexcept {
    const bool host_is_big = std::endian::native == std::endian::big;
    const bool want_big = order == Order::big;
    if constexpr (sizeof(T) == 1) {
        return v;
    } else {
        return host_is_big == want_big ? v : std::byteswap(v);
    }
}

}  // namespace detail

// Sequential reader over an immutable byte span.
class Reader {
public:
    constexpr explicit Reader(std::span<const std::byte> bytes) noexcept : bytes_{bytes} {}

    [[nodiscard]] constexpr std::size_t remaining() const noexcept { return bytes_.size() - pos_; }
    [[nodiscard]] constexpr std::size_t position() const noexcept { return pos_; }

    template <std::unsigned_integral T>
    [[nodiscard]] std::expected<T, WireError> read(Order order) noexcept {
        if (remaining() < sizeof(T)) {
            return std::unexpected(WireError::truncated);
        }
        T v{};
        std::memcpy(&v, bytes_.data() + pos_, sizeof(T));
        pos_ += sizeof(T);
        return detail::from_order(v, order);
    }

    [[nodiscard]] std::expected<std::uint8_t, WireError> u8() noexcept { return read<std::uint8_t>(Order::big); }
    [[nodiscard]] std::expected<std::uint16_t, WireError> be16() noexcept { return read<std::uint16_t>(Order::big); }
    [[nodiscard]] std::expected<std::uint32_t, WireError> be32() noexcept { return read<std::uint32_t>(Order::big); }
    [[nodiscard]] std::expected<std::uint64_t, WireError> be64() noexcept { return read<std::uint64_t>(Order::big); }
    [[nodiscard]] std::expected<std::uint16_t, WireError> le16() noexcept { return read<std::uint16_t>(Order::little); }
    [[nodiscard]] std::expected<std::uint32_t, WireError> le32() noexcept { return read<std::uint32_t>(Order::little); }
    [[nodiscard]] std::expected<std::uint64_t, WireError> le64() noexcept { return read<std::uint64_t>(Order::little); }

    // Returns a view of the next n bytes and advances past them.
    [[nodiscard]] std::expected<std::span<const std::byte>, WireError> bytes(std::size_t n) noexcept {
        if (remaining() < n) {
            return std::unexpected(WireError::truncated);
        }
        auto out = bytes_.subspan(pos_, n);
        pos_ += n;
        return out;
    }

    [[nodiscard]] std::expected<void, WireError> skip(std::size_t n) noexcept {
        if (remaining() < n) {
            return std::unexpected(WireError::truncated);
        }
        pos_ += n;
        return {};
    }

    // Everything not yet consumed; does not advance.
    [[nodiscard]] constexpr std::span<const std::byte> rest() const noexcept { return bytes_.subspan(pos_); }

private:
    std::span<const std::byte> bytes_;
    std::size_t pos_{0};
};

// Appending writer into a growable buffer.
class Writer {
public:
    explicit Writer(std::vector<std::byte>& out) noexcept : out_{&out} {}

    template <std::unsigned_integral T>
    void write(T v, Order order) {
        const T ordered = detail::from_order(v, order);
        std::array<std::byte, sizeof(T)> raw{};
        std::memcpy(raw.data(), &ordered, sizeof(T));
        out_->insert(out_->end(), raw.begin(), raw.end());
    }

    void u8(std::uint8_t v) { write(v, Order::big); }
    void be16(std::uint16_t v) { write(v, Order::big); }
    void be32(std::uint32_t v) { write(v, Order::big); }
    void be64(std::uint64_t v) { write(v, Order::big); }
    void le16(std::uint16_t v) { write(v, Order::little); }
    void le32(std::uint32_t v) { write(v, Order::little); }
    void le64(std::uint64_t v) { write(v, Order::little); }

    void bytes(std::span<const std::byte> b) { out_->insert(out_->end(), b.begin(), b.end()); }

private:
    std::vector<std::byte>* out_;
};

// Fixed-capacity writer into a caller-provided span (for MMIO slots and other
// buffers that must not allocate). Writes past the end fail with overflow.
class SpanWriter {
public:
    constexpr explicit SpanWriter(std::span<std::byte> out) noexcept : out_{out} {}

    [[nodiscard]] constexpr std::size_t written() const noexcept { return pos_; }

    template <std::unsigned_integral T>
    [[nodiscard]] std::expected<void, WireError> write(T v, Order order) noexcept {
        if (out_.size() - pos_ < sizeof(T)) {
            return std::unexpected(WireError::overflow);
        }
        const T ordered = detail::from_order(v, order);
        std::memcpy(out_.data() + pos_, &ordered, sizeof(T));
        pos_ += sizeof(T);
        return {};
    }

    [[nodiscard]] std::expected<void, WireError> bytes(std::span<const std::byte> b) noexcept {
        if (out_.size() - pos_ < b.size()) {
            return std::unexpected(WireError::overflow);
        }
        if (!b.empty()) {
            std::memcpy(out_.data() + pos_, b.data(), b.size());
        }
        pos_ += b.size();
        return {};
    }

private:
    std::span<std::byte> out_;
    std::size_t pos_{0};
};

}  // namespace ak::wire
