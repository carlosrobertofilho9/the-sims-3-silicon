#pragma once

#include "synthetic_memory.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sims3lab {

struct LoadedImage;

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

enum class X86CallingConvention {
    cdecl,
    stdcall,
};

struct SyntheticImportHandler {
    std::uint32_t address = 0;
    std::uint32_t argument_count = 0;
    X86CallingConvention convention = X86CallingConvention::cdecl;
    std::function<std::uint32_t(const std::vector<std::uint32_t>&)> function;
};

struct X86RunOptions {
    bool enable_stack = false;
    std::vector<SyntheticImportHandler> imports;
};

class X86SubsetInterpreter {
public:
    X86RunResult run(const std::vector<std::uint8_t>& code,
                     SyntheticMemory& data,
                     std::uint64_t max_steps = 10000,
                     X86State initial_state = {}) const;

    X86RunResult run_loaded_image(LoadedImage& image,
                                  std::uint32_t stop_address,
                                  std::uint64_t max_steps = 10000) const;

    X86RunResult run_loaded_image(LoadedImage& image,
                                  std::uint32_t stop_address,
                                  const X86RunOptions& options,
                                  std::uint64_t max_steps = 10000) const;
};

}  // namespace sims3lab
