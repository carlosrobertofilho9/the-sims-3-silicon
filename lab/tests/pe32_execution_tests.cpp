#include "pe32_execution_fixture.hpp"
#include "pe32_calls_fixture.hpp"
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
#include <vector>

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

sims3lab::LoadedImage load_calls(std::uint32_t base = pe32_calls_fixture::preferred_base) {
    auto result = sims3lab::load_pe32(pe32_calls_fixture::make_image(), base,
        [](std::string_view module, const sims3lab::ImportSymbol& symbol)
            -> std::optional<std::uint32_t> {
            if (module != "synthetic.dll") return std::nullopt;
            if (!symbol.by_ordinal && symbol.name == "AddTwo") {
                return pe32_calls_fixture::name_import_address;
            }
            if (symbol.by_ordinal && symbol.ordinal == 7) {
                return pe32_calls_fixture::ordinal_import_address;
            }
            return std::nullopt;
        });
    if (!result) {
        throw std::runtime_error("calls fixture did not load: " + result.error->message);
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

void patch_bytes(sims3lab::LoadedImage& image, std::uint32_t address,
                 const std::vector<std::uint8_t>& bytes) {
    require(image.memory.loader_patch(address, bytes.data(), bytes.size()),
            "test can patch fixture bytes");
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

void executes_calls_imports_and_stack_at_all_bases() {
    const sims3lab::X86SubsetInterpreter interpreter;
    for (const auto base : {pe32_calls_fixture::preferred_base, 0x00500000u, 0x00300000u}) {
        auto image = load_calls(base);
        require(image.imports.size() == 2, "calls fixture resolves a name and ordinal import");
        require(read_word(image.memory, base + pe32_calls_fixture::name_iat_rva) ==
                    pe32_calls_fixture::name_import_address,
                "name IAT contains its synthetic virtual address");
        require(read_word(image.memory, base + pe32_calls_fixture::ordinal_iat_rva) ==
                    pe32_calls_fixture::ordinal_import_address,
                "ordinal IAT contains its synthetic virtual address");
        require(read_word(image.memory, base + pe32_calls_fixture::name_iat_operand_rva) ==
                    base + pe32_calls_fixture::name_iat_rva,
                "absolute name-IAT operand is relocated");
        require(read_word(image.memory, base + pe32_calls_fixture::ordinal_iat_operand_rva) ==
                    base + pe32_calls_fixture::ordinal_iat_rva,
                "absolute ordinal-IAT operand is relocated");
        require(read_word(image.memory, base + pe32_calls_fixture::result_operand_rva) ==
                    base + pe32_calls_fixture::result_rva,
                "absolute result operand is relocated");

        std::vector<std::vector<std::uint32_t>> name_arguments;
        std::vector<std::vector<std::uint32_t>> ordinal_arguments;
        sims3lab::X86RunOptions options;
        options.enable_stack = true;
        options.imports.push_back({pe32_calls_fixture::name_import_address, 2,
            sims3lab::X86CallingConvention::cdecl,
            [&name_arguments](const std::vector<std::uint32_t>& arguments) {
                name_arguments.push_back(arguments);
                return arguments.at(0) + arguments.at(1);
            }});
        options.imports.push_back({pe32_calls_fixture::ordinal_import_address, 2,
            sims3lab::X86CallingConvention::stdcall,
            [&ordinal_arguments](const std::vector<std::uint32_t>& arguments) {
                ordinal_arguments.push_back(arguments);
                return arguments.at(0) + arguments.at(1);
            }});

        const auto result = interpreter.run_loaded_image(
            image, base + pe32_calls_fixture::stop_rva, options);
        require(result.halted && result.error.empty(), "calls fixture reaches stop address");
        require(read_word(image.memory, base + pe32_calls_fixture::result_rva) == 42,
                "calls fixture stores 42 in its data section");
        require(result.state.registers[0] == 42, "synthetic imports return 42 in EAX");
        require(result.state.registers[1] == 0x11111111u &&
                    result.state.registers[2] == 0x22222222u &&
                    result.state.registers[3] == 0x33333333u &&
                    result.state.registers[5] == 0x55555555u &&
                    result.state.registers[6] == 0x66666666u &&
                    result.state.registers[7] == 0x77777777u,
                "synthetic handlers preserve all non-EAX registers");
        require(result.state.zero_flag, "synthetic handlers preserve ZF for the fixture checks");
        require(result.state.registers[4] == 0x7FF10000u,
                "cdecl caller cleanup and stdcall callee cleanup restore ESP");
        require(result.state.instruction_pointer == base + pe32_calls_fixture::stop_rva,
                "EIP reaches the explicit stop address");
        require(result.state.instruction_count == 23,
                "each CALL, including both synthetic imports, counts once");
        require(name_arguments.size() == 1 && name_arguments[0] ==
                    std::vector<std::uint32_t>({40, 2}),
                "cdecl import receives arguments in declared order");
        require(ordinal_arguments.size() == 1 && ordinal_arguments[0] ==
                    std::vector<std::uint32_t>({42, 0}),
                "stdcall ordinal import receives arguments in declared order");
    }
}

void verifies_stack_mapping_and_guards() {
    const sims3lab::X86SubsetInterpreter interpreter;
    auto image = load_calls();
    sims3lab::X86RunOptions options;
    options.enable_stack = true;
    const auto result = interpreter.run_loaded_image(image, image.entry_point, options);
    require(result.halted && result.state.registers[4] == 0x7FF10000u,
            "stack mode initializes ESP at the top and honors the stop address");
    require(image.memory.is_mapped(0x7FF00000u, 64u * 1024u),
            "64 KiB stack is mapped at its fixed guest address");
    require(image.memory.is_readable(0x7FF00000u, 64u * 1024u) &&
                image.memory.is_writable(0x7FF00000u, 64u * 1024u),
            "stack has read and write permissions");
    require(!image.memory.is_executable(0x7FF00000u, 64u * 1024u),
            "stack does not have execute permission");
    require(!image.memory.is_mapped(0x7FEFF000u, 4096) &&
                !image.memory.is_mapped(0x7FF10000u, 4096),
            "one-page guards remain unmapped on both sides of the stack");
    std::uint8_t instruction = 0;
    require(!image.memory.fetch_instruction(0x7FF00000u, &instruction, 1),
            "instruction fetch from the stack is denied");

    auto empty_stack = load_calls();
    patch_bytes(empty_stack, empty_stack.entry_point, {0x58});  // POP EAX
    const auto empty_pop = interpreter.run_loaded_image(
        empty_stack, empty_stack.entry_point + 1, options);
    require(!empty_pop.halted && empty_pop.error == "read from unmapped memory" &&
                empty_pop.state.registers[4] == 0x7FF10000u,
            "POP from an empty stack stops at the unmapped upper guard");

    auto conflicting = load_calls(0x7FEFF000u);
    const auto conflict_result = interpreter.run_loaded_image(
        conflicting, conflicting.entry_point, options);
    require(!conflict_result.halted &&
                conflict_result.error == "stack or guard range conflicts with existing memory",
            "stack mapping rejects an image occupying a guard page");
}

void reports_call_and_stack_failures() {
    const sims3lab::X86SubsetInterpreter interpreter;
    sims3lab::X86RunOptions options;
    options.enable_stack = true;

    auto image = load_calls();
    patch_bytes(image, image.entry_point, {0x50});
    const auto legacy_result = interpreter.run_loaded_image(
        image, image.entry_point + 1);
    require(!legacy_result.halted && legacy_result.error == "write to unmapped memory" &&
                legacy_result.state.registers[4] == 0,
            "the earlier loaded-image interface still starts ESP at zero without mapping a stack");

    image = load_calls();
    const auto target = image.base + 0x6000u;
    const auto next = image.base + pe32_calls_fixture::internal_call_rva + 5u;
    patch_word(image, image.base + pe32_calls_fixture::internal_call_operand_rva,
               target - next);
    auto result = interpreter.run_loaded_image(image,
        image.base + pe32_calls_fixture::stop_rva, options);
    require(!result.halted && result.error == "instruction fetch from unmapped memory",
            "CALL to an unmapped destination is reported");
    require(result.state.instruction_count == 8,
            "a decoded direct CALL counts before its invalid target fetch");

    image = load_calls();
    result = interpreter.run_loaded_image(image,
        image.base + pe32_calls_fixture::stop_rva, options);
    require(!result.halted && result.error == "synthetic import has no handler",
            "calling a resolved import without a handler fails explicitly");

    image = load_calls();
    options.imports = {
        {pe32_calls_fixture::name_import_address, 2,
         sims3lab::X86CallingConvention::cdecl,
         [](const std::vector<std::uint32_t>&) { return 41u; }},
        {pe32_calls_fixture::ordinal_import_address, 2,
         sims3lab::X86CallingConvention::stdcall,
         [](const std::vector<std::uint32_t>&) { return 42u; }},
    };
    result = interpreter.run_loaded_image(image,
        image.base + pe32_calls_fixture::stop_rva, options, 40);
    require(!result.halted && result.error == "execution limit exceeded" &&
                result.state.instruction_pointer == image.base + pe32_calls_fixture::stop_rva - 2 &&
                result.state.instruction_count == 40,
            "fixture mismatch enters its bounded failure loop rather than the stop address");

    image = load_calls();
    patch_bytes(image, image.entry_point, {0x50, 0xEB, 0xFD});
    result = interpreter.run_loaded_image(image,
        image.base + pe32_calls_fixture::stop_rva, options, 32770);
    require(!result.halted && result.error == "write to unmapped memory",
            "repeated pushes stop at the unmapped lower stack guard");
    require(result.state.registers[4] == 0x7FF00000u,
            "a failed boundary push leaves ESP at the last valid stack address");
    require(result.state.instruction_count == 32768,
            "stack boundary failure does not retire the failing PUSH");
}

}  // namespace

int main() {
    try {
        executes_at_all_bases();
        enforces_virtual_memory_permissions();
        reports_decode_and_limit_failures();
        executes_calls_imports_and_stack_at_all_bases();
        verifies_stack_mapping_and_guards();
        reports_call_and_stack_failures();
        std::cout << "pe32_execution_checks=" << checks << " passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
