#include "x86_subset.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using sims3lab::SyntheticMemory;
using sims3lab::X86RunResult;
using sims3lab::X86State;
using sims3lab::X86SubsetInterpreter;

namespace {

std::size_t checks = 0;

void require(bool condition, std::string_view label) {
    ++checks;
    if (!condition) {
        throw std::runtime_error(std::string("check failed: ") + std::string(label));
    }
}

void append_imm32(std::vector<std::uint8_t>& code, std::uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i) {
        code.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFu));
    }
}

X86RunResult run(const std::vector<std::uint8_t>& code,
                 SyntheticMemory& memory,
                 std::uint64_t max_steps = 10000,
                 X86State state = {}) {
    return X86SubsetInterpreter{}.run(code, memory, max_steps, state);
}

void expect_error(const std::vector<std::uint8_t>& code,
                  SyntheticMemory& memory,
                  std::string_view expected,
                  std::uint64_t max_steps = 10000,
                  X86State state = {}) {
    const auto result = run(code, memory, max_steps, state);
    require(!result.halted, "program should fail");
    require(result.error == expected, "expected interpreter error category");
}

}  // namespace

int main() {
    SyntheticMemory memory(32);
    X86State initial;
    constexpr std::array<std::uint32_t, 8> values{
        0x100, 0x201, 0x302, 0x403, 0x504, 0x605, 0x706, 0x807};
    std::vector<std::uint8_t> set_registers;
    for (std::uint8_t i = 0; i < values.size(); ++i) {
        set_registers.push_back(static_cast<std::uint8_t>(0xB8 + i));
        append_imm32(set_registers, values[i]);
    }
    auto result = run(set_registers, memory);
    require(result.halted && result.state.registers == values, "MOV immediate loads all eight registers");
    require(result.state.instruction_count == 8, "one step per MOV instruction");

    initial = {};
    initial.registers[1] = 0xCAFEBABE;
    initial.zero_flag = true;
    result = run({0xB8, 7, 0, 0, 0}, memory, 10000, initial);
    require(result.halted && result.state.registers[0] == 7, "MOV writes EAX");
    require(result.state.registers[1] == 0xCAFEBABE, "MOV preserves other registers");
    require(result.state.zero_flag, "MOV preserves zero flag");

    initial = {};
    initial.registers[3] = 0xAABBCCDD;
    result = run({0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0x05, 1, 0, 0, 0}, memory, 10000, initial);
    require(result.halted && result.state.registers[0] == 0, "ADD wraps modulo 2^32");
    require(result.state.zero_flag, "ADD sets zero flag from wrapped result");
    require(result.state.registers[3] == 0xAABBCCDD, "ADD preserves other registers");

    result = run({0xB8, 1, 0, 0, 0, 0x2D, 1, 0, 0, 0}, memory);
    require(result.halted && result.state.registers[0] == 0 && result.state.zero_flag,
            "SUB updates EAX and zero flag");
    result = run({0xB8, 0, 0, 0, 0, 0x2D, 1, 0, 0, 0}, memory);
    require(result.halted && result.state.registers[0] == 0xFFFFFFFFu && !result.state.zero_flag,
            "SUB wraps modulo 2^32");

    result = run({0xB8, 42, 0, 0, 0, 0x3D, 42, 0, 0, 0}, memory);
    require(result.halted && result.state.registers[0] == 42 && result.state.zero_flag,
            "CMP sets zero flag on equality without changing EAX");
    result = run({0xB8, 42, 0, 0, 0, 0x3D, 41, 0, 0, 0}, memory);
    require(result.halted && !result.state.zero_flag, "CMP clears zero flag on inequality");

    require(memory.write_u32_le(1, 0x12345678), "prepare unaligned data word");
    std::vector<std::uint8_t> memory_code{
        0xA1, 1, 0, 0, 0, 0xA3, 3, 0, 0, 0};
    const auto original_code = memory_code;
    initial = {};
    initial.zero_flag = true;
    result = run(memory_code, memory, 10000, initial);
    std::uint32_t copied = 0;
    require(result.halted && result.state.registers[0] == 0x12345678,
            "MOV EAX reads unaligned little-endian data");
    require(memory.read_u32_le(3, copied) && copied == 0x12345678,
            "MOV writes unaligned little-endian data");
    require(result.state.zero_flag, "memory MOVs preserve zero flag");
    require(memory_code == original_code, "data writes do not modify the separate code area");

    X86State branch_state;
    branch_state.zero_flag = true;
    result = run({0x74, 0x05, 0xB8, 1, 0, 0, 0, 0xB8, 42, 0, 0, 0}, memory, 10000, branch_state);
    require(result.halted && result.state.registers[0] == 42, "JZ takes a positive relative branch");
    result = run({0x75, 0x02, 0xB8, 42, 0, 0, 0}, memory, 10000, branch_state);
    require(result.halted && result.state.registers[0] == 42, "JNZ leaves a branch untaken when ZF is set");
    branch_state.zero_flag = false;
    result = run({0x74, 0x05, 0xB8, 1, 0, 0, 0, 0xB8, 42, 0, 0, 0}, memory, 10000, branch_state);
    require(result.halted && result.state.instruction_count == 3,
            "JZ leaves a positive branch untaken when ZF is clear");
    result = run({0x75, 0x05, 0xB8, 1, 0, 0, 0}, memory, 10000, branch_state);
    require(result.halted && result.state.instruction_pointer == 7 && result.state.registers[0] == 0,
            "JNZ takes a positive relative branch");
    result = run({0xEB, 0x05, 0xB8, 1, 0, 0, 0}, memory);
    require(result.halted && result.state.instruction_pointer == 7 && result.state.registers[0] == 0,
            "JMP takes a positive relative branch");
    result = run({0xEB, 0xFE}, memory, 4);
    require(!result.halted && result.error == "execution limit exceeded" &&
                result.state.instruction_count == 4,
            "negative self-loop stops at execution limit");

    expect_error({0x90}, memory, "unsupported opcode");
    expect_error({0x66, 0xB8, 1, 0, 0, 0}, memory, "unsupported prefix");
    expect_error({0xB8, 1, 0}, memory, "truncated instruction");
    expect_error({0xA1, 1, 0}, memory, "truncated instruction");
    expect_error({0xEB, 0xFC}, memory, "jump target outside program");
    expect_error({0xEB, 0x7F}, memory, "jump target outside program");
    expect_error({0xA1, 0xFF, 0xFF, 0xFF, 0xFF}, memory, "memory access out of range");
    expect_error({0xA3, 0xFF, 0xFF, 0xFF, 0xFF}, memory, "memory access out of range");
    expect_error({0xB8, 1, 0, 0, 0, 0xB8, 2, 0, 0, 0}, memory,
                 "execution limit exceeded", 1);
    expect_error({0xB8, 1, 0, 0, 0}, memory, "execution limit must be positive", 0);
    X86State invalid_ip;
    invalid_ip.instruction_pointer = 2;
    expect_error({0x90}, memory, "instruction address outside program", 10000, invalid_ip);

    result = run({0xEB, 0x00}, memory);
    require(result.halted && result.state.instruction_pointer == 2,
            "branch to exact end of program halts normally");

    std::cout << "x86_subset_checks=" << checks << " passed\n";
    return 0;
}
