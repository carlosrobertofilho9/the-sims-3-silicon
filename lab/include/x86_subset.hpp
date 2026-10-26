#pragma once

#include "synthetic_memory.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sims3lab {

struct X86State {
    // IA-32 general-purpose register order: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI.
    std::array<std::uint32_t, 8> registers{};
    std::size_t instruction_pointer = 0;
    std::uint64_t instruction_count = 0;
    bool zero_flag = false;
};

struct X86RunResult {
    X86State state;
    bool halted = false;
    std::string error;
};

class X86SubsetInterpreter {
public:
    X86RunResult run(const std::vector<std::uint8_t>& code,
                     SyntheticMemory& data,
                     std::uint64_t max_steps = 10000,
                     X86State initial_state = {}) const;
};

}  // namespace sims3lab
