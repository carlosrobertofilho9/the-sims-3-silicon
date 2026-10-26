#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pe32_execution_fixture {

constexpr std::uint32_t preferred_base = 0x00400000u;
constexpr std::uint32_t text_rva = 0x1000u;
constexpr std::uint32_t data_rva = 0x2000u;
constexpr std::uint32_t reloc_rva = 0x3000u;
constexpr std::uint32_t stop_rva = 0x101Au;
constexpr std::uint32_t data_value_rva = 0x2010u;
constexpr std::uint32_t data_result_rva = 0x2014u;
constexpr std::size_t pe_offset = 0x80;
constexpr std::size_t optional_offset = 0x98;
constexpr std::size_t section_table_offset = 0x178;
constexpr std::size_t text_raw = 0x400;
constexpr std::size_t data_raw = 0x600;
constexpr std::size_t reloc_raw = 0x800;

inline void put16(std::vector<std::uint8_t>& bytes, std::size_t offset,
                  std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

inline void put32(std::vector<std::uint8_t>& bytes, std::size_t offset,
                  std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
    bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
    bytes[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
}

inline void write_section(std::vector<std::uint8_t>& bytes, std::size_t index,
                          const char* name, std::uint32_t virtual_address,
                          std::uint32_t characteristics) {
    const auto at = section_table_offset + index * 40;
    for (std::size_t i = 0; name[i] != '\0' && i < 8; ++i) {
        bytes[at + i] = static_cast<std::uint8_t>(name[i]);
    }
    put32(bytes, at + 8, 0x200);
    put32(bytes, at + 12, virtual_address);
    put32(bytes, at + 16, 0x200);
    put32(bytes, at + 20, text_raw + index * 0x200);
    put32(bytes, at + 36, characteristics);
}

inline std::vector<std::uint8_t> make_image() {
    std::vector<std::uint8_t> bytes(0xA00, 0);
    put16(bytes, 0, 0x5A4D);
    put32(bytes, 0x3C, static_cast<std::uint32_t>(pe_offset));
    bytes[pe_offset] = 'P';
    bytes[pe_offset + 1] = 'E';
    const auto coff = pe_offset + 4;
    put16(bytes, coff, 0x014C);
    put16(bytes, coff + 2, 3);
    put16(bytes, coff + 16, 224);
    put16(bytes, coff + 18, 0x0002);

    put16(bytes, optional_offset, 0x010B);
    put32(bytes, optional_offset + 16, text_rva);
    put32(bytes, optional_offset + 28, preferred_base);
    put32(bytes, optional_offset + 32, 4096);
    put32(bytes, optional_offset + 36, 512);
    put32(bytes, optional_offset + 56, 0x4000);
    put32(bytes, optional_offset + 60, 0x400);
    put32(bytes, optional_offset + 92, 16);
    put32(bytes, optional_offset + 96 + 5 * 8, reloc_rva);
    put32(bytes, optional_offset + 96 + 5 * 8 + 4, 12);

    write_section(bytes, 0, ".text", text_rva, 0x60000020);
    write_section(bytes, 1, ".data", data_rva, 0xC0000040);
    write_section(bytes, 2, ".reloc", reloc_rva, 0x40000040);

    // MOV EAX,[data]; ADD EAX,2; MOV [result],EAX; CMP EAX,42; JNZ fail;
    // JMP stop; fail: JMP fail. The stop address is supplied by the scenario.
    const std::uint8_t code[] = {
        0xA1, 0, 0, 0, 0,
        0x05, 2, 0, 0, 0,
        0xA3, 0, 0, 0, 0,
        0x3D, 42, 0, 0, 0,
        0x75, 0x02,
        0xEB, 0x02,
        0xEB, 0xFE,
    };
    for (std::size_t index = 0; index < sizeof(code); ++index) {
        bytes[text_raw + index] = code[index];
    }
    put32(bytes, text_raw + 1, preferred_base + data_value_rva);
    put32(bytes, text_raw + 11, preferred_base + data_result_rva);
    put32(bytes, data_raw + (data_value_rva - data_rva), 40);

    // Two HIGHLOW relocations point at the absolute moffs32 operands in .text.
    put32(bytes, reloc_raw, text_rva);
    put32(bytes, reloc_raw + 4, 12);
    put16(bytes, reloc_raw + 8, 0x3001);
    put16(bytes, reloc_raw + 10, 0x300B);
    return bytes;
}

}  // namespace pe32_execution_fixture
