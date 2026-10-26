#include "synthetic_memory.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

using sims3lab::SyntheticMemory;

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
    require(!memory.write<std::uint32_t>(1, last_word), "unaligned generic write");
    require(!memory.read<std::uint32_t>(1, copied), "unaligned generic read");
    require(!memory.write<std::uint8_t>(32, 0xFF), "offset at end");

    const auto safe_sum = SyntheticMemory::checked_add(0xFFFFFFFEu, 1u);
    require(safe_sum && *safe_sum == 0xFFFFFFFFu, "largest representable sum");
    require(!SyntheticMemory::checked_add(0xFFFFFFFFu, 1u), "32-bit addition overflow");

    std::cout << "marco0_checks=11 passed\n";

    SyntheticMemory little_endian(8);
    require(little_endian.write_u32_le(1, 0x12345678), "unaligned little-endian write");
    std::uint32_t little_value = 0;
    require(little_endian.read_u32_le(1, little_value), "unaligned little-endian read");
    require(little_value == 0x12345678, "little-endian round trip");
    require(!little_endian.read_u32_le(5, little_value), "little-endian read past end");
    require(!little_endian.write_u32_le(5, 0xDEADBEEF), "little-endian write past end");

    std::cout << "little_endian_checks=4 passed\n";
    return 0;
}
