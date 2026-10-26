#include "pe32_fixture.hpp"
#include "pe32_loader.hpp"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

sims3lab::ImportResolver synthetic_registry() {
    return [](std::string_view module, const sims3lab::ImportSymbol& symbol)
        -> std::optional<std::uint32_t> {
        if (module != "synthetic.dll") return std::nullopt;
        if (!symbol.by_ordinal && symbol.name == "KnownByName") return 0x76001000u;
        if (symbol.by_ordinal && symbol.ordinal == 7) return 0x76002000u;
        return std::nullopt;
    };
}

bool run_scenario(std::string_view name, std::optional<std::uint32_t> base) {
    const auto result = sims3lab::load_pe32(pe32_fixture::make_image(), base, synthetic_registry());
    if (!result) {
        std::cerr << name << ": " << sims3lab::pe32_error_name(result.error->code)
                  << ": " << result.error->message << '\n';
        return false;
    }
    const auto& image = *result.image;
    std::uint32_t relocated = 0;
    if (!image.memory.read_u32_le(image.base + 0x2010, relocated)) {
        std::cerr << name << ": could not read relocation target\n";
        return false;
    }
    std::cout << name << " base=0x" << std::hex << std::setw(8) << std::setfill('0')
              << image.base << " entry=0x" << std::setw(8) << image.entry_point
              << " relocated=0x" << std::setw(8) << relocated << std::dec
              << " regions=" << image.memory.regions().size()
              << " imports=" << image.imports.size() << " executed=false\n";
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string scenario = "all";
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--scenario" && index + 1 < argc) {
            scenario = argv[++index];
        } else {
            std::cerr << "usage: pe32_loader_lab [--scenario preferred|rebased|all]\n";
            return 2;
        }
    }

    if (scenario == "preferred") {
        return run_scenario("preferred", std::nullopt) ? 0 : 1;
    }
    if (scenario == "rebased") {
        const bool upward = run_scenario("rebased-up", 0x00500000u);
        const bool downward = run_scenario("rebased-down", 0x00300000u);
        return upward && downward ? 0 : 1;
    }
    if (scenario == "all") {
        const bool preferred = run_scenario("preferred", std::nullopt);
        const bool upward = run_scenario("rebased-up", 0x00500000u);
        const bool downward = run_scenario("rebased-down", 0x00300000u);
        return preferred && upward && downward ? 0 : 1;
    }
    std::cerr << "unknown scenario: " << scenario << '\n';
    return 2;
}
