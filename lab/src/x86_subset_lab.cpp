#include "x86_subset.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#if !defined(__aarch64__) && !defined(__arm64__)
#error "Configure this research lab with an ARM64 compiler target."
#endif

static_assert(sizeof(void*) == 8, "The lab expects a 64-bit process.");

namespace {

using Program = std::vector<std::uint8_t>;

void append_imm32(Program& code, std::uint32_t value) {
    code.push_back(static_cast<std::uint8_t>(value & 0xFFu));
    code.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
    code.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
    code.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFu));
}

Program arithmetic_program() {
    Program code{0xB8};  // MOV EAX, 40
    append_imm32(code, 40);
    code.push_back(0xBB);  // MOV EBX, 0x12345678
    append_imm32(code, 0x12345678);
    code.push_back(0x05);  // ADD EAX, 2
    append_imm32(code, 2);
    code.push_back(0x3D);  // CMP EAX, 42
    append_imm32(code, 42);
    return code;
}

Program memory_program() {
    Program code{0xA1};  // MOV EAX, [1]
    append_imm32(code, 1);
    code.push_back(0xA3);  // MOV [5], EAX
    append_imm32(code, 5);
    return code;
}

Program branch_program() {
    Program code;
    code.push_back(0xB8); append_imm32(code, 0);           // EAX = 0
    code.insert(code.end(), {0x74, 0x05});                 // JZ to offset 12
    code.push_back(0xB8); append_imm32(code, 1);           // skipped
    code.push_back(0xB8); append_imm32(code, 42);          // EAX = 42
    code.push_back(0x3D); append_imm32(code, 42);          // ZF = 1
    code.insert(code.end(), {0x75, 0x05});                 // JNZ not taken
    code.push_back(0xBB); append_imm32(code, 1);           // EBX = 1
    code.insert(code.end(), {0xEB, 0x05});                 // JMP over next MOV
    code.push_back(0xBB); append_imm32(code, 0xFFFFFFFFu); // skipped
    code.push_back(0x3D); append_imm32(code, 43);          // ZF = 0
    code.insert(code.end(), {0x75, 0x05});                 // JNZ to end
    code.push_back(0xB9); append_imm32(code, 0xFFFFFFFFu); // skipped
    return code;
}

Program loop_program() {
    Program code{0xB8};  // MOV EAX, 10
    append_imm32(code, 10);
    code.push_back(0x2D);  // loop: SUB EAX, 1
    append_imm32(code, 1);
    code.insert(code.end(), {0x75, 0xF9});  // JNZ rel8 -7, back to SUB
    return code;
}

struct Scenario {
    std::string_view name;
    Program code;
    bool copies_memory = false;
};

Scenario make_scenario(std::string_view name) {
    if (name == "arithmetic") return {name, arithmetic_program(), false};
    if (name == "memory") return {name, memory_program(), true};
    if (name == "branch") return {name, branch_program(), false};
    return {"loop", loop_program(), false};
}

void print_registers(const sims3lab::X86State& state) {
    constexpr std::array<std::string_view, 8> names{
        "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"};
    std::cout << "registers=";
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i != 0) std::cout << ',';
        std::cout << names[i] << ":0x" << std::uppercase << std::hex
                  << std::setw(8) << std::setfill('0') << state.registers[i];
    }
    std::cout << std::dec << std::nouppercase << std::setfill(' ') << '\n';
}

bool run_scenario(std::string_view name, std::uint64_t max_steps) {
    auto scenario = make_scenario(name);
    sims3lab::SyntheticMemory data(32);
    if (scenario.copies_memory && !data.write_u32_le(1, 0x12345678)) {
        std::cerr << "failed to initialize synthetic data\n";
        return false;
    }

    const auto result = sims3lab::X86SubsetInterpreter{}.run(
        scenario.code, data, max_steps);
    std::cout << "program=" << scenario.name << '\n'
              << "status=" << (result.halted ? "halted" : "error") << '\n';
    if (result.halted) {
        if (scenario.copies_memory) {
            std::uint32_t copied = 0;
            if (data.read_u32_le(5, copied)) {
                std::cout << "result=memory[5]:" << copied << '\n';
            } else {
                std::cout << "result=unavailable\n";
            }
        } else {
            std::cout << "result=EAX:" << result.state.registers[0] << '\n';
        }
    } else {
        std::cout << "result=unavailable\n"
                  << "error=" << result.error << '\n';
    }
    std::cout << "steps=" << result.state.instruction_count << '\n'
              << "eip=" << result.state.instruction_pointer << '\n'
              << "zero_flag=" << std::boolalpha << result.state.zero_flag << std::noboolalpha << '\n';
    print_registers(result.state);
    return result.halted;
}

void usage(std::ostream& out) {
    out << "Usage: x86_subset_lab [--program arithmetic|memory|branch|loop|all] "
           "[--max-steps N]\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::string_view selected = "all";
    std::uint64_t max_steps = 10000;
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help" || argument == "-h") {
            usage(std::cout);
            return 0;
        }
        if (argument == "--program" && i + 1 < argc) {
            selected = argv[++i];
            continue;
        }
        if (argument == "--max-steps" && i + 1 < argc) {
            const std::string_view value(argv[++i]);
            std::uint64_t parsed = 0;
            const auto conversion = std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (conversion.ec != std::errc{} || conversion.ptr != value.data() + value.size() ||
                parsed == 0 || parsed > 10000) {
                std::cerr << "--max-steps must be between 1 and 10000\n";
                return 2;
            }
            max_steps = parsed;
            continue;
        }
        usage(std::cerr);
        return 2;
    }

    constexpr std::array<std::string_view, 4> program_names{
        "arithmetic", "memory", "branch", "loop"};
    if (selected != "all" &&
        std::find(program_names.begin(), program_names.end(), selected) == program_names.end()) {
        usage(std::cerr);
        return 2;
    }

    bool all_halted = true;
    std::cout << "target=ARM64\nprocess_bits=" << sizeof(void*) * 8 << "\n\n";
    for (const auto name : program_names) {
        if (selected == "all" || selected == name) {
            if (selected == "all" && name != program_names.front()) std::cout << '\n';
            all_halted = run_scenario(name, max_steps) && all_halted;
        }
    }
    return all_halted ? 0 : 1;
}
