#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <type_traits>
#include <vector>

namespace sims3lab {

class SyntheticMemory {
public:
    explicit SyntheticMemory(std::size_t size) : bytes_(size, std::byte{0}) {}

    template <typename T>
    bool read(std::uint32_t offset, T& value) const {
        static_assert(std::is_trivially_copyable_v<T>);
        if (!aligned(offset, alignof(T)) || !contains(offset, sizeof(T))) {
            return false;
        }
        std::memcpy(&value, bytes_.data() + offset, sizeof(T));
        return true;
    }

    template <typename T>
    bool write(std::uint32_t offset, const T& value) {
        static_assert(std::is_trivially_copyable_v<T>);
        if (!aligned(offset, alignof(T)) || !contains(offset, sizeof(T))) {
            return false;
        }
        std::memcpy(bytes_.data() + offset, &value, sizeof(T));
        return true;
    }

    bool read_u32_le(std::uint32_t offset, std::uint32_t& value) const {
        if (!contains(offset, sizeof(value))) {
            return false;
        }
        const auto start = static_cast<std::size_t>(offset);
        value = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes_[start])) |
                (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes_[start + 1])) << 8) |
                (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes_[start + 2])) << 16) |
                (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes_[start + 3])) << 24);
        return true;
    }

    bool write_u32_le(std::uint32_t offset, std::uint32_t value) {
        if (!contains(offset, sizeof(value))) {
            return false;
        }
        const auto start = static_cast<std::size_t>(offset);
        for (unsigned int i = 0; i < sizeof(value); ++i) {
            bytes_[start + i] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
        }
        return true;
    }

    static std::optional<std::uint32_t> checked_add(std::uint32_t base,
                                                     std::uint32_t delta) {
        if (delta > std::numeric_limits<std::uint32_t>::max() - base) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(base + delta);
    }

private:
    static bool aligned(std::uint32_t offset, std::size_t alignment) {
        return alignment == 0 || offset % alignment == 0;
    }

    bool contains(std::uint32_t offset, std::size_t length) const {
        const auto start = static_cast<std::size_t>(offset);
        return start <= bytes_.size() && length <= bytes_.size() - start;
    }

    std::vector<std::byte> bytes_;
};

}  // namespace sims3lab
