#include "pe32_execution_fixture.hpp"
#include "pe32_loader.hpp"
#include "x86_subset.hpp"

#include <charconv>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace {

bool run_scenario(std::string_view name, std::uint32_t base, std::uint64_t max_steps) {
    const auto loaded = sims3lab::load_pe32(pe32_execution_fixture::make_image(), base);
    if (!loaded) {
        std::cerr << name << ": " << sims3lab::pe32_error_name(loaded.error->code)
                  << ": " << loaded.error->message << '\n';
        return false;
    }

    auto image = *loaded.image;
    const auto stop = base + pe32_execution_fixture::stop_rva;
    const auto execution = sims3lab::X86SubsetInterpreter{}.run_loaded_image(
        image, stop, max_steps);
    std::uint32_t result_value = 0;
    const bool result_readable = image.memory.read_u32_le(
        base + pe32_execution_fixture::data_result_rva, result_value);

    std::cout << name << " base=0x" << std::hex << std::setw(8) << std::setfill('0')
              << base << " result=";
    if (result_readable) {
        std::cout << std::dec << result_value;
    } else {
        std::cout << "unavailable";
    }
    std::cout << " eax=0x" << std::hex << std::setw(8) << execution.state.registers[0]
              << " eip=0x" << std::setw(8) << execution.state.instruction_pointer
              << std::dec << " steps=" << execution.state.instruction_count
              << " reason=" << (execution.halted ? "stop-address" : execution.error) << '\n';
    return execution.halted && result_readable && result_value == 42 &&
           execution.state.registers[0] == 42;
}

bool parse_max_steps(std::string_view text, std::uint64_t& value) {
    if (text.empty()) return false;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size() && value > 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::string scenario = "all";
    std::uint64_t max_steps = 10000;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--scenario" && index + 1 < argc) {
            scenario = argv[++index];
        } else if (argument == "--max-steps" && index + 1 < argc) {
            if (!parse_max_steps(argv[++index], max_steps)) {
                std::cerr << "--max-steps must be a positive integer\n";
                return 2;
            }
        } else {
            std::cerr << "usage: pe32_execution_lab [--scenario preferred|rebased|all] "
                         "[--max-steps N]\n";
            return 2;
        }
    }

    if (scenario == "preferred") {
        return run_scenario("preferred", pe32_execution_fixture::preferred_base, max_steps) ? 0 : 1;
    }
    if (scenario == "rebased") {
        const bool upward = run_scenario("rebased-up", 0x00500000u, max_steps);
        const bool downward = run_scenario("rebased-down", 0x00300000u, max_steps);
        return upward && downward ? 0 : 1;
    }
    if (scenario == "all") {
        const bool preferred = run_scenario("preferred",
                                            pe32_execution_fixture::preferred_base, max_steps);
        const bool upward = run_scenario("rebased-up", 0x00500000u, max_steps);
        const bool downward = run_scenario("rebased-down", 0x00300000u, max_steps);
        return preferred && upward && downward ? 0 : 1;
    }
    std::cerr << "unknown scenario: " << scenario << '\n';
    return 2;
}
