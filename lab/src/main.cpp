#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#if !defined(__aarch64__) && !defined(__arm64__)
#error "Configure this research lab with an ARM64 compiler target."
#endif

static_assert(sizeof(void*) == 8, "The lab expects a 64-bit process.");

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

void require(bool condition, std::string_view label) {
    if (!condition) {
        throw std::runtime_error(std::string("check failed: ") + std::string(label));
    }
}

int main() {
    SyntheticMemory memory(32);

    const std::uint32_t original = 0x12345678;
    require(memory.write<std::uint32_t>(4, original), "aligned write");
    std::uint32_t copied = 0;
    require(memory.read<std::uint32_t>(4, copied), "aligned read");
    require(copied == original, "read after write");

    const std::uint32_t last_word = 0xAABBCCDD;
    require(memory.write<std::uint32_t>(28, last_word), "last valid word");
    copied = 0;
    require(memory.read<std::uint32_t>(28, copied) && copied == last_word,
            "last valid word round trip");
    require(!memory.write<std::uint32_t>(29, last_word), "range past final byte");
    require(!memory.write<std::uint32_t>(1, last_word), "unaligned write");
    require(!memory.read<std::uint32_t>(1, copied), "unaligned read");
    require(!memory.write<std::uint8_t>(32, 0xFF), "offset at end");

    const auto safe_sum = SyntheticMemory::checked_add(0xFFFFFFFEu, 1u);
    require(safe_sum && *safe_sum == 0xFFFFFFFFu, "largest representable sum");
    require(!SyntheticMemory::checked_add(0xFFFFFFFFu, 1u), "32-bit addition overflow");

    std::cout << "target=ARM64\n"
              << "process_bits=" << sizeof(void*) * 8 << "\n"
              << "checks=11 passed\n";
    return 0;
}
