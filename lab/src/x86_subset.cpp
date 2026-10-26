#include "x86_subset.hpp"

#include <cstdint>
#include <stdexcept>

namespace sims3lab {
namespace {

class DecodeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

bool is_unsupported_prefix(std::uint8_t byte) {
    switch (byte) {
        case 0x26:  // ES segment override
        case 0x2E:  // CS segment override
        case 0x36:  // SS segment override
        case 0x3E:  // DS segment override
        case 0x64:  // FS segment override
        case 0x65:  // GS segment override
        case 0x66:  // operand-size override
        case 0x67:  // address-size override
        case 0xF0:  // LOCK
        case 0xF2:  // REPNE/REPNZ
        case 0xF3:  // REP/REPE/REPZ
            return true;
        default:
            return false;
    }
}

std::uint8_t fetch_u8(const std::vector<std::uint8_t>& code, X86State& state) {
    if (state.instruction_pointer >= code.size()) {
        throw DecodeError("truncated instruction");
    }
    return code[state.instruction_pointer++];
}

std::uint32_t fetch_u32(const std::vector<std::uint8_t>& code, X86State& state) {
    if (state.instruction_pointer > code.size() || code.size() - state.instruction_pointer < 4) {
        throw DecodeError("truncated instruction");
    }
    const auto start = state.instruction_pointer;
    const std::uint32_t value = static_cast<std::uint32_t>(code[start]) |
                                (static_cast<std::uint32_t>(code[start + 1]) << 8) |
                                (static_cast<std::uint32_t>(code[start + 2]) << 16) |
                                (static_cast<std::uint32_t>(code[start + 3]) << 24);
    state.instruction_pointer += 4;
    return value;
}

std::int32_t fetch_rel8(const std::vector<std::uint8_t>& code, X86State& state) {
    const auto raw = fetch_u8(code, state);
    return raw < 0x80 ? static_cast<std::int32_t>(raw)
                      : static_cast<std::int32_t>(raw) - 0x100;
}

void apply_relative_jump(X86State& state, std::int32_t displacement, std::size_t code_size) {
    const auto target = static_cast<std::int64_t>(state.instruction_pointer) + displacement;
    if (target < 0 || static_cast<std::uint64_t>(target) > code_size) {
        throw DecodeError("jump target outside program");
    }
    state.instruction_pointer = static_cast<std::size_t>(target);
}

}  // namespace

X86RunResult X86SubsetInterpreter::run(const std::vector<std::uint8_t>& code,
                                       SyntheticMemory& data,
                                       std::uint64_t max_steps,
                                       X86State state) const {
    if (max_steps == 0) {
        return {state, false, "execution limit must be positive"};
    }

    try {
        while (true) {
            if (state.instruction_pointer == code.size()) {
                return {state, true, {}};
            }
            if (state.instruction_pointer > code.size()) {
                throw DecodeError("instruction address outside program");
            }
            if (state.instruction_count >= max_steps) {
                throw DecodeError("execution limit exceeded");
            }

            const auto opcode = fetch_u8(code, state);
            if (is_unsupported_prefix(opcode)) {
                throw DecodeError("unsupported prefix");
            }

            if (opcode >= 0xB8 && opcode <= 0xBF) {
                const auto register_index = static_cast<std::size_t>(opcode - 0xB8);
                state.registers[register_index] = fetch_u32(code, state);
            } else {
                switch (opcode) {
                    case 0xA1: {  // MOV EAX, moffs32
                        const auto address = fetch_u32(code, state);
                        if (!data.read_u32_le(address, state.registers[0])) {
                            throw DecodeError("memory access out of range");
                        }
                        break;
                    }
                    case 0xA3: {  // MOV moffs32, EAX
                        const auto address = fetch_u32(code, state);
                        if (!data.write_u32_le(address, state.registers[0])) {
                            throw DecodeError("memory access out of range");
                        }
                        break;
                    }
                    case 0x05: {  // ADD EAX, imm32
                        const auto immediate = fetch_u32(code, state);
                        state.registers[0] += immediate;  // unsigned arithmetic wraps modulo 2^32
                        state.zero_flag = state.registers[0] == 0;
                        break;
                    }
                    case 0x2D: {  // SUB EAX, imm32
                        const auto immediate = fetch_u32(code, state);
                        state.registers[0] -= immediate;
                        state.zero_flag = state.registers[0] == 0;
                        break;
                    }
                    case 0x3D: {  // CMP EAX, imm32
                        const auto immediate = fetch_u32(code, state);
                        state.zero_flag = state.registers[0] == immediate;
                        break;
                    }
                    case 0x74: {  // JZ rel8
                        const auto displacement = fetch_rel8(code, state);
                        if (state.zero_flag) {
                            apply_relative_jump(state, displacement, code.size());
                        }
                        break;
                    }
                    case 0x75: {  // JNZ rel8
                        const auto displacement = fetch_rel8(code, state);
                        if (!state.zero_flag) {
                            apply_relative_jump(state, displacement, code.size());
                        }
                        break;
                    }
                    case 0xEB: {  // JMP rel8
                        const auto displacement = fetch_rel8(code, state);
                        apply_relative_jump(state, displacement, code.size());
                        break;
                    }
                    default:
                        throw DecodeError("unsupported opcode");
                }
            }
            ++state.instruction_count;
        }
    } catch (const DecodeError& error) {
        return {state, false, error.what()};
    }
}

}  // namespace sims3lab
