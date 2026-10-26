#include "pe32_fixture.hpp"
#include "pe32_loader.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using sims3lab::ImportSymbol;
using sims3lab::Pe32ErrorCode;
using sims3lab::VirtualMemory32;

namespace {

int checks = 0;

void require(bool condition, std::string_view label) {
    ++checks;
    if (!condition) {
        throw std::runtime_error(std::string("check failed: ") + std::string(label));
    }
}

auto resolver() {
    return [](std::string_view module, const ImportSymbol& symbol)
        -> std::optional<std::uint32_t> {
        if (module != "synthetic.dll") return std::nullopt;
        if (!symbol.by_ordinal && symbol.name == "KnownByName") return 0x76001000u;
        if (symbol.by_ordinal && symbol.ordinal == 7) return 0x76002000u;
        return std::nullopt;
    };
}

void expect_error(const std::vector<std::uint8_t>& bytes, std::optional<std::uint32_t> base,
                  Pe32ErrorCode code, std::string_view label) {
    const auto result = sims3lab::load_pe32(bytes, base, resolver());
    require(!result, label);
    require(result.error.has_value(), "error result is structured");
    require(result.error->code == code, "structured error code matches");
}

std::uint32_t read_word(const VirtualMemory32& memory, std::uint32_t address) {
    std::uint32_t value = 0;
    if (!memory.read_u32_le(address, value)) {
        throw std::runtime_error("could not read a fixture word from simulated memory");
    }
    return value;
}

void preferred_base_and_sections() {
    const auto bytes = pe32_fixture::make_image();
    const auto result = sims3lab::load_pe32(bytes, std::nullopt, resolver());
    require(static_cast<bool>(result), "preferred-base fixture loads");
    const auto& image = *result.image;
    require(image.base == pe32_fixture::preferred_base, "default base is preferred base");
    require(image.entry_point == pe32_fixture::preferred_base + 0x1000,
            "entry point is base plus entry RVA");
    require(image.size == 0x5000, "image size retained");
    require(image.memory.regions().size() == 5, "headers and four sections are mapped");

    std::uint8_t byte = 0;
    require(image.memory.read(image.base, &byte, 1) && byte == 'M', "headers are copied");
    require(image.memory.read(image.base + 0x1000, &byte, 1) && byte == 0xC3,
            "section bytes are copied to their RVA");
    require(image.memory.read(image.base + 0x2000 + 0x300, &byte, 1) && byte == 0,
            "virtual section tail is zero-filled");
    require(read_word(image.memory, image.base + 0x2010) == pe32_fixture::preferred_base + 0x1234,
            "preferred load leaves absolute reference unchanged");

    require(image.imports.size() == 2, "name and ordinal imports are resolved");
    require(!image.imports[0].symbol.by_ordinal && image.imports[0].symbol.name == "KnownByName",
            "name import is reported");
    require(image.imports[1].symbol.by_ordinal && image.imports[1].symbol.ordinal == 7,
            "ordinal import is reported");
    require(read_word(image.memory, image.base + 0x3080) == 0x76001000u,
            "name import address is written into IAT");
    require(read_word(image.memory, image.base + 0x3084) == 0x76002000u,
            "ordinal import address is written into IAT");
}

void rebasing_up_and_down() {
    for (const std::uint32_t base : {0x00500000u, 0x00300000u}) {
        const auto result = sims3lab::load_pe32(pe32_fixture::make_image(), base, resolver());
        require(static_cast<bool>(result), "rebased fixture loads");
        require(result.image->base == base, "requested base is used");
        require(result.image->entry_point == base + 0x1000, "rebased entry point uses new base");
        require(read_word(result.image->memory, base + 0x2010) == base + 0x1234,
                "HIGHLOW reference adjusts in either delta direction");
    }
}

void memory_permissions_and_boundaries() {
    auto result = sims3lab::load_pe32(pe32_fixture::make_image(), std::nullopt, resolver());
    require(static_cast<bool>(result), "fixture loads for memory checks");
    auto& image = *result.image;
    const auto code = image.base + 0x1000;
    const auto data = image.base + 0x2000;
    const auto missing = image.base + image.size;
    std::uint8_t byte = 0;
    require(image.memory.is_readable(code, 1), "code region is readable");
    require(image.memory.is_executable(code, 1), "code region is executable");
    require(!image.memory.is_writable(code, 1), "code region is not writable");
    require(image.memory.is_readable(data, 1) && image.memory.is_writable(data, 1),
            "data region is readable and writable");
    require(!image.memory.is_executable(data, 1), "data region is not executable");
    require(image.memory.fetch_instruction(code, &byte, 1), "instruction fetch succeeds in code");
    require(!image.memory.fetch_instruction(data, &byte, 1), "instruction fetch is denied in data");
    require(!image.memory.write(code, &byte, 1), "write is denied in code");
    require(image.memory.write(data, &byte, 1), "write succeeds in data");
    require(!image.memory.read(missing, &byte, 1), "unmapped read is denied");
    require(!image.memory.is_readable(missing, 1), "unmapped range is not readable");
    require(!image.memory.is_mapped(missing, 1), "unmapped range is not mapped");
    require(image.memory.read(code + 0xFFF, &byte, 1), "last byte inside section is readable");
    require(!image.memory.read(code + 0xFFF, &byte, 2), "read cannot cross a region boundary");
    require(!image.memory.write(code + 0xFFF, &byte, 2), "write cannot cross a region boundary");
    require(!image.memory.fetch_instruction(code + 0xFFF, &byte, 2),
            "instruction fetch cannot cross a region boundary");
    require(!image.memory.write(image.base, &byte, 1), "header mapping is read-only");
    require(!image.memory.write(0xFFFFFFFEu, &byte, 4), "guest address overflow is denied");
    require(!image.memory.read(data, &byte, std::numeric_limits<std::size_t>::max()),
            "host-sized access length cannot wrap the guest address space");
    require(!image.memory.is_readable(data, std::numeric_limits<std::size_t>::max()),
            "access query rejects host-sized overflow");
}

void malformed_and_unsupported_inputs() {
    auto bytes = pe32_fixture::make_image();
    bytes.pop_back();
    expect_error(bytes, std::nullopt, Pe32ErrorCode::truncated_file, "truncated raw section is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put16(bytes, pe32_fixture::pe_offset + 4, 0x8664);
    expect_error(bytes, std::nullopt, Pe32ErrorCode::unsupported_architecture,
                 "non-x86 architecture is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put32(bytes, pe32_fixture::section_table_offset + 40 + 12, 0x1000);
    expect_error(bytes, std::nullopt, Pe32ErrorCode::overlapping_sections,
                 "overlapping virtual sections are rejected");

    expect_error(pe32_fixture::make_image(), 0xFFFFF000u, Pe32ErrorCode::address_overflow,
                 "image base range overflow is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put16(bytes, pe32_fixture::reloc_raw + 8, 0x4010);
    expect_error(bytes, 0x00500000u, Pe32ErrorCode::unsupported_relocation,
                 "unknown relocation type is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put32(bytes, pe32_fixture::optional_offset + 96 + 5 * 8, 0);
    pe32_fixture::put32(bytes, pe32_fixture::optional_offset + 96 + 5 * 8 + 4, 0);
    expect_error(bytes, 0x00500000u, Pe32ErrorCode::relocations_unavailable,
                 "rebasing without relocation directory is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put16(bytes, pe32_fixture::pe_offset + 4 + 18, 0x0003);
    expect_error(bytes, 0x00500000u, Pe32ErrorCode::relocations_unavailable,
                 "rebasing with relocations stripped is rejected");

    for (const auto directory_index : {9u, 10u, 13u}) {
        bytes = pe32_fixture::make_image();
        const auto directory = pe32_fixture::optional_offset + 96 + directory_index * 8;
        pe32_fixture::put32(bytes, directory, 0x3000);
        pe32_fixture::put32(bytes, directory + 4, 4);
        expect_error(bytes, std::nullopt, Pe32ErrorCode::unsupported_feature,
                     "TLS, delayed imports, and load config are rejected");
    }

    bytes = pe32_fixture::make_image();
    pe32_fixture::put32(bytes, pe32_fixture::optional_offset + 56, 64u * 1024u * 1024u + 4096u);
    expect_error(bytes, std::nullopt, Pe32ErrorCode::image_too_large,
                 "images above 64 MiB are rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put32(bytes, pe32_fixture::optional_offset + 16, 0x2000);
    expect_error(bytes, std::nullopt, Pe32ErrorCode::entry_not_executable,
                 "entry point outside executable section is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put32(bytes, pe32_fixture::optional_offset + 96 + 8, 0x800);
    expect_error(bytes, std::nullopt, Pe32ErrorCode::malformed_imports,
                 "import directory in an unmapped image gap is rejected");

    bytes = pe32_fixture::make_image();
    pe32_fixture::put32(bytes, pe32_fixture::optional_offset + 96 + 5 * 8, 0x800);
    expect_error(bytes, 0x00500000u, Pe32ErrorCode::malformed_relocations,
                 "relocation directory in an unmapped image gap is rejected");

    const auto missing_import = sims3lab::load_pe32(pe32_fixture::make_image(), std::nullopt,
        [](std::string_view, const ImportSymbol&) -> std::optional<std::uint32_t> {
            return std::nullopt;
        });
    require(!missing_import && missing_import.error->code == Pe32ErrorCode::import_not_found,
            "missing synthetic import produces structured error");
}

}  // namespace

int main() {
    try {
        preferred_base_and_sections();
        rebasing_up_and_down();
        memory_permissions_and_boundaries();
        malformed_and_unsupported_inputs();
        std::cout << "pe32_loader_checks=" << checks << " passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
