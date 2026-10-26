#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace pe32_fixture {

constexpr std::uint32_t preferred_base = 0x00400000u;
constexpr std::size_t pe_offset = 0x80;
constexpr std::size_t optional_offset = 0x98;
constexpr std::size_t section_table_offset = 0x178;
constexpr std::size_t headers_size = 0x400;
constexpr std::size_t text_raw = 0x400;
constexpr std::size_t data_raw = 0x600;
constexpr std::size_t idata_raw = 0x800;
constexpr std::size_t reloc_raw = 0xE00;
constexpr std::size_t file_size = 0x1000;

inline void put16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

inline void put32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    bytes[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

inline std::uint32_t get32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

inline void write_section(std::vector<std::uint8_t>& bytes, std::size_t index,
                          std::string_view name, std::uint32_t virtual_size,
                          std::uint32_t virtual_address, std::uint32_t raw_size,
                          std::uint32_t raw_offset, std::uint32_t characteristics) {
    const auto at = section_table_offset + index * 40;
    for (std::size_t i = 0; i < name.size() && i < 8; ++i) {
        bytes[at + i] = static_cast<std::uint8_t>(name[i]);
    }
    put32(bytes, at + 8, virtual_size);
    put32(bytes, at + 12, virtual_address);
    put32(bytes, at + 16, raw_size);
    put32(bytes, at + 20, raw_offset);
    put32(bytes, at + 36, characteristics);
}

inline std::vector<std::uint8_t> make_image() {
    std::vector<std::uint8_t> bytes(file_size, 0);
    put16(bytes, 0, 0x5A4D);
    put32(bytes, 0x3C, static_cast<std::uint32_t>(pe_offset));
    bytes[pe_offset] = 'P';
    bytes[pe_offset + 1] = 'E';
    const auto coff = pe_offset + 4;
    put16(bytes, coff, 0x014C);
    put16(bytes, coff + 2, 4);
    put16(bytes, coff + 16, 224);
    put16(bytes, coff + 18, 0x0002);

    put16(bytes, optional_offset, 0x010B);
    put32(bytes, optional_offset + 16, 0x1000);
    put32(bytes, optional_offset + 28, preferred_base);
    put32(bytes, optional_offset + 32, 4096);
    put32(bytes, optional_offset + 36, 512);
    put32(bytes, optional_offset + 56, 0x5000);
    put32(bytes, optional_offset + 60, headers_size);
    put32(bytes, optional_offset + 92, 16);
    put32(bytes, optional_offset + 96 + 8, 0x3000);
    put32(bytes, optional_offset + 96 + 12, 40);
    put32(bytes, optional_offset + 96 + 5 * 8, 0x4000);
    put32(bytes, optional_offset + 96 + 5 * 8 + 4, 12);

    write_section(bytes, 0, ".text", 0x100, 0x1000, 0x200, text_raw, 0x60000020);
    write_section(bytes, 1, ".data", 0x700, 0x2000, 0x200, data_raw, 0xC0000040);
    write_section(bytes, 2, ".idata", 0x1000, 0x3000, 0x600, idata_raw, 0xC0000040);
    write_section(bytes, 3, ".reloc", 0x100, 0x4000, 0x200, reloc_raw, 0x40000040);

    bytes[text_raw] = 0xC3;  // Synthetic RET byte; the loader never executes it.
    put32(bytes, data_raw + 0x10, preferred_base + 0x1234);

    put32(bytes, idata_raw, 0x3060);      // OriginalFirstThunk
    put32(bytes, idata_raw + 12, 0x3040); // Name
    put32(bytes, idata_raw + 16, 0x3080); // FirstThunk
    const char module[] = "synthetic.dll";
    for (std::size_t i = 0; i < sizeof(module); ++i) {
        bytes[idata_raw + 0x40 + i] = static_cast<std::uint8_t>(module[i]);
    }
    put32(bytes, idata_raw + 0x60, 0x30A0);
    put32(bytes, idata_raw + 0x64, 0x80000007u);
    put32(bytes, idata_raw + 0x68, 0);
    put16(bytes, idata_raw + 0xA0, 0); // Hint
    const char import_name[] = "KnownByName";
    for (std::size_t i = 0; i < sizeof(import_name); ++i) {
        bytes[idata_raw + 0xA2 + i] = static_cast<std::uint8_t>(import_name[i]);
    }

    put32(bytes, reloc_raw, 0x2000);
    put32(bytes, reloc_raw + 4, 12);
    put16(bytes, reloc_raw + 8, 0x3010); // HIGHLOW at .data + 0x10
    put16(bytes, reloc_raw + 10, 0);     // ABSOLUTE padding
    return bytes;
}

}  // namespace pe32_fixture
