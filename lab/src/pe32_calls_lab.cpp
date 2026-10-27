#include "pe32_calls_fixture.hpp"
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
#include <vector>

namespace {

sims3lab::ImportResolver synthetic_registry() {
    return [](std::string_view module, const sims3lab::ImportSymbol& symbol)
        -> std::optional<std::uint32_t> {
        if (module != "synthetic.dll") return std::nullopt;
        if (!symbol.by_ordinal && symbol.name == "AddTwo") {
            return pe32_calls_fixture::name_import_address;
        }
        if (symbol.by_ordinal && symbol.ordinal == 7) {
            return pe32_calls_fixture::ordinal_import_address;
        }
        return std::nullopt;
    };
}

bool run_scenario(std::string_view name, std::uint32_t base, std::uint64_t max_steps) {
    const auto loaded = sims3lab::load_pe32(
        pe32_calls_fixture::make_image(), base, synthetic_registry());
    if (!loaded) {
        std::cerr << name << ": " << sims3lab::pe32_error_name(loaded.error->code)
                  << ": " << loaded.error->message << '\n';
        return false;
    }

    auto image = *loaded.image;
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

    const auto execution = sims3lab::X86SubsetInterpreter{}.run_loaded_image(
        image, base + pe32_calls_fixture::stop_rva, options, max_steps);
    std::uint32_t result_value = 0;
    const bool result_readable = image.memory.read_u32_le(
        base + pe32_calls_fixture::result_rva, result_value);
    const bool imports_ok = name_arguments.size() == 1 &&
        name_arguments[0] == std::vector<std::uint32_t>({40, 2}) &&
        ordinal_arguments.size() == 1 &&
        ordinal_arguments[0] == std::vector<std::uint32_t>({42, 0});
    const bool registers_ok = execution.state.registers[1] == 0x11111111u &&
        execution.state.registers[2] == 0x22222222u &&
        execution.state.registers[3] == 0x33333333u &&
        execution.state.registers[5] == 0x55555555u &&
        execution.state.registers[6] == 0x66666666u &&
        execution.state.registers[7] == 0x77777777u && execution.state.zero_flag;

    std::cout << name << " base=0x" << std::hex << std::setw(8) << std::setfill('0')
              << base << " result=";
    if (result_readable) std::cout << std::dec << result_value;
    else std::cout << "unavailable";
    std::cout << " eax=0x" << std::hex << std::setw(8) << execution.state.registers[0]
              << " esp=0x" << std::setw(8) << execution.state.registers[4]
              << " eip=0x" << std::setw(8) << execution.state.instruction_pointer
              << std::dec << " steps=" << execution.state.instruction_count
              << " imports=" << (name_arguments.size() + ordinal_arguments.size())
              << " args=" << (imports_ok ? "40,2;42,0" : "invalid")
              << " registers=" << (registers_ok ? "preserved" : "changed")
              << " reason=" << (execution.halted ? "stop-address" : execution.error) << '\n';

    return execution.halted && result_readable && result_value == 42 &&
           execution.state.registers[0] == 42 && execution.state.registers[4] == 0x7FF10000u &&
           execution.state.instruction_pointer == base + pe32_calls_fixture::stop_rva &&
           execution.state.instruction_count == 23 && imports_ok && registers_ok;
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
            std::cerr << "usage: pe32_calls_lab [--scenario preferred|rebased|all] "
                         "[--max-steps N]\n";
            return 2;
        }
    }

    if (scenario == "preferred") {
        return run_scenario("preferred", pe32_calls_fixture::preferred_base, max_steps) ? 0 : 1;
    }
    if (scenario == "rebased") {
        const bool upward = run_scenario("rebased-up", 0x00500000u, max_steps);
        const bool downward = run_scenario("rebased-down", 0x00300000u, max_steps);
        return upward && downward ? 0 : 1;
    }
    if (scenario == "all") {
        const bool preferred = run_scenario(
            "preferred", pe32_calls_fixture::preferred_base, max_steps);
        const bool upward = run_scenario("rebased-up", 0x00500000u, max_steps);
        const bool downward = run_scenario("rebased-down", 0x00300000u, max_steps);
        return preferred && upward && downward ? 0 : 1;
    }
    std::cerr << "unknown scenario: " << scenario << '\n';
    return 2;
}
