#include "pe32_execution_fixture.hpp"
#include "pe32_loader.hpp"
#include "x86_subset.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

int checks = 0;

void require(bool condition, std::string_view label) {
    ++checks;
    if (!condition) {
        throw std::runtime_error(std::string("check failed: ") + std::string(label));
    }
}

sims3lab::LoadedImage load(std::optional<std::uint32_t> base = std::nullopt) {
    auto result = sims3lab::load_pe32(pe32_execution_fixture::make_image(), base);
    if (!result) {
        throw std::runtime_error("execution fixture did not load: " + result.error->message);
    }
    return std::move(*result.image);
}

std::uint32_t read_word(const sims3lab::VirtualMemory32& memory, std::uint32_t address) {
    std::uint32_t value = 0;
    if (!memory.read_u32_le(address, value)) {
        throw std::runtime_error("could not read a fixture word");
    }
    return value;
}

void patch_word(sims3lab::LoadedImage& image, std::uint32_t address, std::uint32_t value) {
    const std::array<std::uint8_t, 4> bytes{
        static_cast<std::uint8_t>(value & 0xFFu),
        static_cast<std::uint8_t>((value >> 8) & 0xFFu),
        static_cast<std::uint8_t>((value >> 16) & 0xFFu),
        static_cast<std::uint8_t>((value >> 24) & 0xFFu),
    };
    require(image.memory.loader_patch(address, bytes.data(), bytes.size()),
            "test can patch fixture instruction operand");
}

void executes_at_all_bases() {
    const sims3lab::X86SubsetInterpreter interpreter;
    auto stopped_at_entry = load();
    const auto initial_state = interpreter.run_loaded_image(
        stopped_at_entry, stopped_at_entry.entry_point);
    require(initial_state.halted && initial_state.state.instruction_count == 0,
            "the explicit stop address is checked before instruction fetch");
    require(initial_state.state.instruction_pointer == stopped_at_entry.entry_point &&
                initial_state.state.registers == std::array<std::uint32_t, 8>{} &&
                !initial_state.state.zero_flag,
            "loaded execution starts at entry with zeroed registers and flags");

    for (const auto base : {pe32_execution_fixture::preferred_base,
                            0x00500000u, 0x00300000u}) {
        auto image = load(base);
        const auto data_value = base + pe32_execution_fixture::data_value_rva;
        const auto data_result = base + pe32_execution_fixture::data_result_rva;
        const auto stop = base + pe32_execution_fixture::stop_rva;
        const auto first_absolute_operand = read_word(image.memory, image.entry_point + 1);
        const auto second_absolute_operand = read_word(image.memory, image.entry_point + 11);

        require(first_absolute_operand == data_value,
                "HIGHLOW relocates the absolute load operand");
        require(second_absolute_operand == data_result,
                "HIGHLOW relocates the absolute store operand");

        const auto result = interpreter.run_loaded_image(image, stop);
        require(result.halted && result.error.empty(), "fixture reaches its explicit stop address");
        require(result.state.registers[0] == 42, "fixture calculates 42 in EAX");
        for (std::size_t index = 1; index < result.state.registers.size(); ++index) {
            require(result.state.registers[index] == 0,
                    "loaded execution starts other general registers at zero");
        }
        require(result.state.zero_flag, "CMP confirms the calculated value");
        require(result.state.instruction_pointer == stop, "EIP is the scenario stop address");
        require(result.state.instruction_count == 6, "six x86 instructions execute on success");
        require(read_word(image.memory, data_result) == 42,
                "fixture stores 42 in its writable virtual data section");
    }
}

void enforces_virtual_memory_permissions() {
    const sims3lab::X86SubsetInterpreter interpreter;

    auto image = load();
    image.entry_point = image.base + pe32_execution_fixture::data_rva;
    auto result = interpreter.run_loaded_image(image, image.entry_point + 1);
    require(!result.halted && result.error == "instruction fetch without execute permission",
            "instruction fetch requires execute permission");

    image = load();
    patch_word(image, image.entry_point + 11, image.entry_point);
    result = interpreter.run_loaded_image(image, image.base + pe32_execution_fixture::stop_rva);
    require(!result.halted && result.error == "write without write permission",
            "MOV to a read-only executable section is denied");

    image = load();
    patch_word(image, image.entry_point + 1, image.base + image.size);
    result = interpreter.run_loaded_image(image, image.base + pe32_execution_fixture::stop_rva);
    require(!result.halted && result.error == "read from unmapped memory",
            "data reads outside mapped image sections are denied");

    auto bytes = pe32_execution_fixture::make_image();
    pe32_execution_fixture::put32(bytes,
        pe32_execution_fixture::section_table_offset + 40 + 36, 0x80000040u);
    auto read_denied = sims3lab::load_pe32(bytes);
    require(static_cast<bool>(read_denied), "write-only data fixture loads");
    image = std::move(*read_denied.image);
    result = interpreter.run_loaded_image(image, image.base + pe32_execution_fixture::stop_rva);
    require(!result.halted && result.error == "read without read permission",
            "MOV from a mapped section without R permission is denied");
}

void reports_decode_and_limit_failures() {
    const sims3lab::X86SubsetInterpreter interpreter;

    auto image = load();
    const auto truncated_address = image.base + pe32_execution_fixture::text_rva + 0xFFF;
    const std::uint8_t mov_eax_imm32 = 0xB8;
    require(image.memory.loader_patch(truncated_address, &mov_eax_imm32, 1),
            "truncated instruction byte is placed at executable section boundary");
    image.entry_point = truncated_address;
    auto result = interpreter.run_loaded_image(image, truncated_address + 6);
    require(!result.halted && result.error == "truncated instruction",
            "truncated PE instruction cannot fetch bytes beyond executable code");

    image = load();
    const std::uint8_t unknown_opcode = 0x90;
    require(image.memory.loader_patch(image.entry_point, &unknown_opcode, 1),
            "unknown opcode is placed in the loaded code");
    result = interpreter.run_loaded_image(image, image.base + pe32_execution_fixture::stop_rva);
    require(!result.halted && result.error == "unsupported opcode",
            "unknown instruction remains unsupported in PE mode");

    image = load();
    require(image.memory.write_u32_le(image.base + pe32_execution_fixture::data_value_rva, 39),
            "mismatch value selects the fixture failure branch");
    result = interpreter.run_loaded_image(image, image.base + pe32_execution_fixture::stop_rva, 20);
    require(!result.halted && result.error == "execution limit exceeded",
            "comparison failure follows the fixture loop until the limit");
    require(result.state.instruction_count == 20,
            "loop execution stops at the configured instruction count");
    require(result.state.instruction_pointer == image.base + pe32_execution_fixture::text_rva + 24,
            "failure branch reaches the self-loop in virtual code");
}

}  // namespace

int main() {
    try {
        executes_at_all_bases();
        enforces_virtual_memory_permissions();
        reports_decode_and_limit_failures();
        std::cout << "pe32_execution_checks=" << checks << " passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
