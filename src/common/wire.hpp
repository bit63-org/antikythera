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

enum class Order : std::uint8_t {
    big,
    little
};

namespace detail {

template<std::unsigned_integral T> constexpr auto from_order(T v, Order order) noexcept -> T {
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
    constexpr explicit Reader(std::span<const std::byte> bytes) noexcept : _bytes{bytes} {}

    [[nodiscard]] constexpr auto remaining() const noexcept -> std::size_t {
        return _bytes.size() - _pos;
    }
    [[nodiscard]] constexpr auto position() const noexcept -> std::size_t { return _pos; }

    template<std::unsigned_integral T>
    [[nodiscard]] auto read(Order order) noexcept -> std::expected<T, WireError> {
        if (remaining() < sizeof(T)) {
            return std::unexpected(WireError::truncated);
        }
        T v{};
        std::memcpy(&v, _bytes.data() + _pos, sizeof(T));
        _pos += sizeof(T);
        return detail::from_order(v, order);
    }

    [[nodiscard]] auto u8() noexcept -> std::expected<std::uint8_t, WireError> {
        return read<std::uint8_t>(Order::big);
    }
    [[nodiscard]] auto be16() noexcept -> std::expected<std::uint16_t, WireError> {
        return read<std::uint16_t>(Order::big);
    }
    [[nodiscard]] auto be32() noexcept -> std::expected<std::uint32_t, WireError> {
        return read<std::uint32_t>(Order::big);
    }
    [[nodiscard]] auto be64() noexcept -> std::expected<std::uint64_t, WireError> {
        return read<std::uint64_t>(Order::big);
    }
    [[nodiscard]] auto le16() noexcept -> std::expected<std::uint16_t, WireError> {
        return read<std::uint16_t>(Order::little);
    }
    [[nodiscard]] auto le32() noexcept -> std::expected<std::uint32_t, WireError> {
        return read<std::uint32_t>(Order::little);
    }
    [[nodiscard]] auto le64() noexcept -> std::expected<std::uint64_t, WireError> {
        return read<std::uint64_t>(Order::little);
    }

    // Returns a view of the next n bytes and advances past them.
    [[nodiscard]] auto bytes(std::size_t n) noexcept
        -> std::expected<std::span<const std::byte>, WireError> {
        if (remaining() < n) {
            return std::unexpected(WireError::truncated);
        }
        auto out = _bytes.subspan(_pos, n);
        _pos += n;
        return out;
    }

    [[nodiscard]] auto skip(std::size_t n) noexcept -> std::expected<void, WireError> {
        if (remaining() < n) {
            return std::unexpected(WireError::truncated);
        }
        _pos += n;
        return {};
    }

    // Everything not yet consumed; does not advance.
    [[nodiscard]] constexpr auto rest() const noexcept -> std::span<const std::byte> {
        return _bytes.subspan(_pos);
    }

private:
    std::span<const std::byte> _bytes;
    std::size_t _pos{0};
};

// Appending writer into a growable buffer.
class Writer {
public:
    explicit Writer(std::vector<std::byte>& out) noexcept : _out{&out} {}

    template<std::unsigned_integral T> auto write(T v, Order order) -> void {
        const T ordered = detail::from_order(v, order);
        std::array<std::byte, sizeof(T)> raw{};
        std::memcpy(raw.data(), &ordered, sizeof(T));
        _out->insert(_out->end(), raw.begin(), raw.end());
    }

    auto u8(std::uint8_t v) -> void { write(v, Order::big); }
    auto be16(std::uint16_t v) -> void { write(v, Order::big); }
    auto be32(std::uint32_t v) -> void { write(v, Order::big); }
    auto be64(std::uint64_t v) -> void { write(v, Order::big); }
    auto le16(std::uint16_t v) -> void { write(v, Order::little); }
    auto le32(std::uint32_t v) -> void { write(v, Order::little); }
    auto le64(std::uint64_t v) -> void { write(v, Order::little); }

    auto bytes(std::span<const std::byte> b) -> void {
        _out->insert(_out->end(), b.begin(), b.end());
    }

private:
    std::vector<std::byte>* _out;
};

// Fixed-capacity writer into a caller-provided span (for MMIO slots and other
// buffers that must not allocate). Writes past the end fail with overflow.
class SpanWriter {
public:
    constexpr explicit SpanWriter(std::span<std::byte> out) noexcept : _out{out} {}

    [[nodiscard]] constexpr auto written() const noexcept -> std::size_t { return _pos; }

    template<std::unsigned_integral T>
    [[nodiscard]] auto write(T v, Order order) noexcept -> std::expected<void, WireError> {
        if (_out.size() - _pos < sizeof(T)) {
            return std::unexpected(WireError::overflow);
        }
        const T ordered = detail::from_order(v, order);
        std::memcpy(_out.data() + _pos, &ordered, sizeof(T));
        _pos += sizeof(T);
        return {};
    }

    [[nodiscard]] auto bytes(std::span<const std::byte> b) noexcept
        -> std::expected<void, WireError> {
        if (_out.size() - _pos < b.size()) {
            return std::unexpected(WireError::overflow);
        }
        if (!b.empty()) {
            std::memcpy(_out.data() + _pos, b.data(), b.size());
        }
        _pos += b.size();
        return {};
    }

private:
    std::span<std::byte> _out;
    std::size_t _pos{0};
};

}  // namespace ak::wire
