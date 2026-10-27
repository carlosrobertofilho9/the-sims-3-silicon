#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace pe32_calls_fixture {

constexpr std::uint32_t preferred_base = 0x00400000u;
constexpr std::uint32_t text_rva = 0x1000u;
constexpr std::uint32_t data_rva = 0x2000u;
constexpr std::uint32_t idata_rva = 0x3000u;
constexpr std::uint32_t reloc_rva = 0x4000u;
constexpr std::uint32_t stop_rva = 0x105Au;
constexpr std::uint32_t result_rva = 0x2010u;
constexpr std::uint32_t internal_call_rva = 0x1023u;
constexpr std::uint32_t internal_call_operand_rva = 0x1024u;
constexpr std::uint32_t name_iat_operand_rva = 0x1035u;
constexpr std::uint32_t ordinal_iat_operand_rva = 0x104Bu;
constexpr std::uint32_t result_operand_rva = 0x1052u;
constexpr std::uint32_t name_iat_rva = 0x3080u;
constexpr std::uint32_t ordinal_iat_rva = 0x3084u;
constexpr std::uint32_t name_import_address = 0x76001000u;
constexpr std::uint32_t ordinal_import_address = 0x76002000u;
constexpr std::uint32_t internal_function_rva = 0x1100u;
constexpr std::size_t pe_offset = 0x80;
constexpr std::size_t optional_offset = 0x98;
constexpr std::size_t section_table_offset = 0x178;
constexpr std::size_t headers_size = 0x400;
constexpr std::size_t text_raw = 0x400;
constexpr std::size_t data_raw = 0x600;
constexpr std::size_t idata_raw = 0x800;
constexpr std::size_t reloc_raw = 0xA00;
constexpr std::size_t file_size = 0xC00;

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
    put32(bytes, optional_offset + 16, text_rva);
    put32(bytes, optional_offset + 28, preferred_base);
    put32(bytes, optional_offset + 32, 4096);
    put32(bytes, optional_offset + 36, 512);
    put32(bytes, optional_offset + 56, 0x5000);
    put32(bytes, optional_offset + 60, headers_size);
    put32(bytes, optional_offset + 92, 16);
    put32(bytes, optional_offset + 96 + 1 * 8, idata_rva);
    put32(bytes, optional_offset + 96 + 1 * 8 + 4, 40);
    put32(bytes, optional_offset + 96 + 5 * 8, reloc_rva);
    put32(bytes, optional_offset + 96 + 5 * 8 + 4, 16);

    write_section(bytes, 0, ".text", 0x1000, text_rva, 0x200, text_raw, 0x60000020);
    write_section(bytes, 1, ".data", 0x1000, data_rva, 0x200, data_raw, 0xC0000040);
    write_section(bytes, 2, ".idata", 0x1000, idata_rva, 0x200, idata_raw, 0xC0000040);
    write_section(bytes, 3, ".reloc", 0x1000, reloc_rva, 0x200, reloc_raw, 0x40000040);

    std::vector<std::uint8_t> code;
    const auto emit_u32 = [&code](std::uint32_t value) {
        for (unsigned int shift = 0; shift < 32; shift += 8) {
            code.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
        }
    };
    const auto emit_mov_reg = [&code, &emit_u32](std::uint8_t reg, std::uint32_t value) {
        code.push_back(static_cast<std::uint8_t>(0xB8u + reg));
        emit_u32(value);
    };
    const auto emit_call_iat = [&code, &emit_u32](std::uint32_t address) {
        code.push_back(0xFF);
        code.push_back(0x15);
        const auto operand_offset = code.size();
        emit_u32(address);
        return operand_offset;
    };

    // Seed nonvolatile and caller-visible registers, then call the internal
    // routine at RVA 0x1100. Its MOV/RET pair returns 40 in EAX.
    emit_mov_reg(1, 0x11111111u);  // ECX
    emit_mov_reg(2, 0x22222222u);  // EDX
    emit_mov_reg(3, 0x33333333u);  // EBX
    emit_mov_reg(5, 0x55555555u);  // EBP
    emit_mov_reg(6, 0x66666666u);  // ESI
    emit_mov_reg(7, 0x77777777u);  // EDI
    code.insert(code.end(), {0x3D, 0, 0, 0, 0});  // CMP EAX,0: set ZF
    code.push_back(0xE8);                         // CALL rel32 internal
    emit_u32(internal_function_rva - (text_rva + static_cast<std::uint32_t>(code.size()) + 4u));

    // cdecl add(40,2): push right-to-left and let the caller clean its args.
    code.insert(code.end(), {0x68, 2, 0, 0, 0, 0x50});
    code.insert(code.end(), {0x3D, 40, 0, 0, 0});   // ZF must survive CALL
    const auto name_operand_offset = emit_call_iat(preferred_base + name_iat_rva);
    const auto name_flag_check = code.size();
    code.insert(code.end(), {0x75, 0});              // JNZ fail on clobbered ZF
    code.insert(code.end(), {0x83, 0xC4, 8});        // ADD ESP,8 (cdecl cleanup)

    // stdcall add(42,0): the synthetic callee removes its two arguments.
    code.insert(code.end(), {0x3D, 42, 0, 0, 0});   // ZF must survive CALL
    code.insert(code.end(), {0x68, 0, 0, 0, 0, 0x50});
    const auto ordinal_operand_offset = emit_call_iat(preferred_base + ordinal_iat_rva);
    const auto ordinal_flag_check = code.size();
    code.insert(code.end(), {0x75, 0});

    code.insert(code.end(), {0xA3, 0, 0, 0, 0});
    const auto result_operand_offset = code.size() - 4;
    code.insert(code.end(), {0xEB, 0x02});            // Success jumps over the failure loop
    const auto fail_offset = code.size();
    code.insert(code.end(), {0xEB, 0xFE});            // Fail path: bounded by max_steps
    const auto stop_offset = code.size();
    code[name_flag_check + 1] = static_cast<std::uint8_t>(
        fail_offset - (name_flag_check + 2));
    code[ordinal_flag_check + 1] = static_cast<std::uint8_t>(
        fail_offset - (ordinal_flag_check + 2));

    for (std::size_t index = 0; index < code.size(); ++index) {
        bytes[text_raw + index] = code[index];
    }
    put32(bytes, text_raw + name_operand_offset, preferred_base + name_iat_rva);
    put32(bytes, text_raw + ordinal_operand_offset, preferred_base + ordinal_iat_rva);
    put32(bytes, text_raw + result_operand_offset, preferred_base + result_rva);
    const std::uint8_t internal_function[] = {0xB8, 40, 0, 0, 0, 0xC3};
    for (std::size_t index = 0; index < sizeof(internal_function); ++index) {
        bytes[text_raw + (internal_function_rva - text_rva) + index] = internal_function[index];
    }
    put32(bytes, optional_offset + 16, text_rva);
    put32(bytes, optional_offset + 96 + 5 * 8, reloc_rva);
    put32(bytes, optional_offset + 96 + 5 * 8 + 4, 16);
    put32(bytes, data_raw + (result_rva - data_rva), 0);

    // One import descriptor with a name thunk and an ordinal thunk.
    put32(bytes, idata_raw, 0x3060);
    put32(bytes, idata_raw + 12, 0x3040);
    put32(bytes, idata_raw + 16, 0x3080);
    const char module[] = "synthetic.dll";
    for (std::size_t i = 0; i < sizeof(module); ++i) {
        bytes[idata_raw + 0x40 + i] = static_cast<std::uint8_t>(module[i]);
    }
    put32(bytes, idata_raw + 0x60, 0x30A0);
    put32(bytes, idata_raw + 0x64, 0x80000007u);
    put32(bytes, idata_raw + 0x68, 0);
    put16(bytes, idata_raw + 0xA0, 0);
    const char import_name[] = "AddTwo";
    for (std::size_t i = 0; i < sizeof(import_name); ++i) {
        bytes[idata_raw + 0xA2 + i] = static_cast<std::uint8_t>(import_name[i]);
    }

    // Relocate both absolute IAT operands and the absolute data-store operand.
    put32(bytes, reloc_raw, text_rva);
    put32(bytes, reloc_raw + 4, 16);
    const auto name_operand_rva = text_rva + static_cast<std::uint32_t>(name_operand_offset);
    const auto ordinal_operand_rva = text_rva + static_cast<std::uint32_t>(ordinal_operand_offset);
    const auto result_operand_rva = text_rva + static_cast<std::uint32_t>(result_operand_offset);
    put16(bytes, reloc_raw + 8,
          static_cast<std::uint16_t>(0x3000u | (name_operand_rva & 0x0FFFu)));
    put16(bytes, reloc_raw + 10,
          static_cast<std::uint16_t>(0x3000u | (ordinal_operand_rva & 0x0FFFu)));
    put16(bytes, reloc_raw + 12,
          static_cast<std::uint16_t>(0x3000u | (result_operand_rva & 0x0FFFu)));
    put16(bytes, reloc_raw + 14, 0);

    return bytes;
}

}  // namespace pe32_calls_fixture
