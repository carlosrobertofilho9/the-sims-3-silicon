#include "x86_subset.hpp"

#include "pe32_loader.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

namespace sims3lab {
namespace {

constexpr std::uint32_t kStackBase = 0x7FF00000u;
constexpr std::uint32_t kStackSize = 64u * 1024u;
constexpr std::uint32_t kGuardSize = 4096u;
constexpr std::size_t kEsp = 4;

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

class VectorMemoryAdapter {
public:
    VectorMemoryAdapter(const std::vector<std::uint8_t>& code, SyntheticMemory& data)
        : code_(code), data_(data) {}

    bool reached_stop(const X86State& state) const {
        return state.instruction_pointer == code_.size();
    }

    void validate_instruction_pointer(const X86State& state) const {
        if (state.instruction_pointer > code_.size()) {
            throw DecodeError("instruction address outside program");
        }
    }

    void begin_instruction() const {}
    void finish_instruction() const {}

    std::uint8_t fetch_u8(X86State& state) const {
        std::uint8_t value = 0;
        fetch(state, &value, sizeof(value));
        return value;
    }

    std::uint32_t fetch_u32(X86State& state) const {
        std::array<std::uint8_t, 4> bytes{};
        fetch(state, bytes.data(), bytes.size());
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8) |
               (static_cast<std::uint32_t>(bytes[2]) << 16) |
               (static_cast<std::uint32_t>(bytes[3]) << 24);
    }

    bool read_u32(std::uint32_t address, std::uint32_t& value) const {
        return data_.read_u32_le(address, value);
    }

    bool write_u32(std::uint32_t address, std::uint32_t value) {
        return data_.write_u32_le(address, value);
    }

    bool is_import_address(std::uint32_t) const { return false; }

    void apply_relative_jump(X86State& state, std::int32_t displacement) const {
        const auto target = static_cast<std::int64_t>(state.instruction_pointer) + displacement;
        if (target < 0 || static_cast<std::uint64_t>(target) > code_.size()) {
            throw DecodeError("jump target outside program");
        }
        state.instruction_pointer = static_cast<std::size_t>(target);
    }

private:
    void fetch(X86State& state, void* destination, std::size_t length) const {
        if (state.instruction_pointer > code_.size() ||
            length > code_.size() - state.instruction_pointer) {
            throw DecodeError("truncated instruction");
        }
        const auto start = state.instruction_pointer;
        for (std::size_t index = 0; index < length; ++index) {
            static_cast<std::uint8_t*>(destination)[index] = code_[start + index];
        }
        state.instruction_pointer += length;
    }

    const std::vector<std::uint8_t>& code_;
    SyntheticMemory& data_;
};

class LoadedImageMemoryAdapter {
public:
    LoadedImageMemoryAdapter(LoadedImage& image, std::uint32_t stop_address)
        : image_(image), stop_address_(stop_address) {}

    bool reached_stop(const X86State& state) const {
        return state.instruction_pointer == stop_address_;
    }

    void validate_instruction_pointer(const X86State& state) const {
        if (state.instruction_pointer > UINT32_MAX) {
            throw DecodeError("instruction address outside 32-bit address space");
        }
    }

    void begin_instruction() const { instruction_byte_fetched_ = false; }
    void finish_instruction() const { instruction_byte_fetched_ = false; }

    std::uint8_t fetch_u8(X86State& state) const {
        std::uint8_t value = 0;
        fetch(state, &value, sizeof(value));
        return value;
    }

    std::uint32_t fetch_u32(X86State& state) const {
        std::array<std::uint8_t, 4> bytes{};
        fetch(state, bytes.data(), bytes.size());
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8) |
               (static_cast<std::uint32_t>(bytes[2]) << 16) |
               (static_cast<std::uint32_t>(bytes[3]) << 24);
    }

    bool read_u32(std::uint32_t address, std::uint32_t& value) const {
        if (image_.memory.read_u32_le(address, value)) return true;
        if (!image_.memory.is_mapped(address, sizeof(value))) {
            throw DecodeError("read from unmapped memory");
        }
        if (!image_.memory.is_readable(address, sizeof(value))) {
            throw DecodeError("read without read permission");
        }
        throw DecodeError("memory read failed");
    }

    bool write_u32(std::uint32_t address, std::uint32_t value) {
        if (image_.memory.write_u32_le(address, value)) return true;
        if (!image_.memory.is_mapped(address, sizeof(value))) {
            throw DecodeError("write to unmapped memory");
        }
        if (!image_.memory.is_writable(address, sizeof(value))) {
            throw DecodeError("write without write permission");
        }
        throw DecodeError("memory write failed");
    }

    bool is_import_address(std::uint32_t address) const {
        return std::any_of(image_.imports.begin(), image_.imports.end(),
            [address](const ResolvedImport& import) {
                return import.resolved_address == address;
            });
    }

    void apply_relative_jump(X86State& state, std::int32_t displacement) const {
        const auto next = static_cast<std::uint32_t>(state.instruction_pointer);
        state.instruction_pointer = static_cast<std::uint32_t>(
            next + static_cast<std::uint32_t>(displacement));
    }

private:
    void fetch(X86State& state, void* destination, std::size_t length) const {
        validate_instruction_pointer(state);
        const auto address = static_cast<std::uint32_t>(state.instruction_pointer);
        if (!image_.memory.fetch_instruction(address, destination, length)) {
            if (instruction_byte_fetched_) {
                throw DecodeError("truncated instruction");
            }
            if (!image_.memory.is_mapped(address, length)) {
                throw DecodeError("instruction fetch from unmapped memory");
            }
            if (!image_.memory.is_executable(address, length)) {
                throw DecodeError("instruction fetch without execute permission");
            }
            throw DecodeError("instruction fetch failed");
        }
        instruction_byte_fetched_ = true;
        state.instruction_pointer = static_cast<std::uint32_t>(address + length);
    }

    LoadedImage& image_;
    std::uint32_t stop_address_;
    mutable bool instruction_byte_fetched_ = false;
};

template <typename MemoryAdapter>
void push_u32(MemoryAdapter& memory, X86State& state, std::uint32_t value) {
    const auto address = state.registers[kEsp] - 4u;
    if (!memory.write_u32(address, value)) {
        throw DecodeError("memory access out of range");
    }
    state.registers[kEsp] = address;
}

template <typename MemoryAdapter>
std::uint32_t pop_u32(MemoryAdapter& memory, X86State& state) {
    std::uint32_t value = 0;
    if (!memory.read_u32(state.registers[kEsp], value)) {
        throw DecodeError("memory access out of range");
    }
    state.registers[kEsp] += 4u;
    return value;
}

std::int32_t signed_rel32(std::uint32_t raw) {
    const auto value = raw < 0x80000000u
        ? static_cast<std::int64_t>(raw)
        : static_cast<std::int64_t>(raw) - 0x100000000ll;
    return static_cast<std::int32_t>(value);
}

const SyntheticImportHandler* find_handler(
    const std::vector<SyntheticImportHandler>& handlers, std::uint32_t address) {
    const auto found = std::find_if(handlers.begin(), handlers.end(),
        [address](const SyntheticImportHandler& handler) {
            return handler.address == address;
        });
    return found == handlers.end() ? nullptr : &*found;
}

template <typename MemoryAdapter>
std::uint32_t execute_import(MemoryAdapter& memory, X86State& state,
                             const SyntheticImportHandler& handler) {
    std::vector<std::uint32_t> arguments;
    arguments.reserve(handler.argument_count);
    for (std::uint32_t index = 0; index < handler.argument_count; ++index) {
        const auto argument_address = static_cast<std::uint64_t>(state.registers[kEsp]) +
                                      4u + static_cast<std::uint64_t>(index) * 4u;
        if (argument_address > std::numeric_limits<std::uint32_t>::max()) {
            throw DecodeError("synthetic import arguments exceed 32-bit address space");
        }
        std::uint32_t argument = 0;
        if (!memory.read_u32(static_cast<std::uint32_t>(argument_address), argument)) {
            throw DecodeError("memory access out of range");
        }
        arguments.push_back(argument);
    }

    std::uint32_t result = 0;
    try {
        result = handler.function(arguments);
    } catch (const std::exception&) {
        throw DecodeError("synthetic import handler failed");
    } catch (...) {
        throw DecodeError("synthetic import handler failed");
    }

    const auto return_address = pop_u32(memory, state);
    state.instruction_pointer = return_address;
    if (handler.convention == X86CallingConvention::stdcall) {
        state.registers[kEsp] += handler.argument_count * 4u;
    }
    // Synthetic handlers receive values only. They cannot alter host or guest
    // registers; EAX is the sole register updated by the return value.
    state.registers[0] = result;
    return result;
}

template <typename MemoryAdapter>
X86RunResult execute(MemoryAdapter& memory, X86State state,
                     const std::vector<SyntheticImportHandler>& imports,
                     std::uint64_t max_steps) {
    if (max_steps == 0) {
        return {state, false, "execution limit must be positive"};
    }

    try {
        while (true) {
            if (memory.reached_stop(state)) {
                return {state, true, {}};
            }
            memory.validate_instruction_pointer(state);
            if (state.instruction_count >= max_steps) {
                throw DecodeError("execution limit exceeded");
            }

            memory.begin_instruction();
            const auto opcode = memory.fetch_u8(state);
            if (is_unsupported_prefix(opcode)) {
                throw DecodeError("unsupported prefix");
            }

            if (opcode >= 0xB8 && opcode <= 0xBF) {
                const auto register_index = static_cast<std::size_t>(opcode - 0xB8);
                state.registers[register_index] = memory.fetch_u32(state);
            } else if (opcode >= 0x50 && opcode <= 0x57) {
                const auto register_index = static_cast<std::size_t>(opcode - 0x50);
                const auto value = state.registers[register_index];
                push_u32(memory, state, value);
            } else if (opcode >= 0x58 && opcode <= 0x5F) {
                const auto register_index = static_cast<std::size_t>(opcode - 0x58);
                const auto value = pop_u32(memory, state);
                state.registers[register_index] = value;
            } else {
                switch (opcode) {
                    case 0x68: {  // PUSH imm32
                        push_u32(memory, state, memory.fetch_u32(state));
                        break;
                    }
                    case 0xA1: {  // MOV EAX, moffs32
                        const auto address = memory.fetch_u32(state);
                        if (!memory.read_u32(address, state.registers[0])) {
                            throw DecodeError("memory access out of range");
                        }
                        break;
                    }
                    case 0xA3: {  // MOV moffs32, EAX
                        const auto address = memory.fetch_u32(state);
                        if (!memory.write_u32(address, state.registers[0])) {
                            throw DecodeError("memory access out of range");
                        }
                        break;
                    }
                    case 0x05: {  // ADD EAX, imm32
                        const auto immediate = memory.fetch_u32(state);
                        state.registers[0] += immediate;
                        state.zero_flag = state.registers[0] == 0;
                        break;
                    }
                    case 0x2D: {  // SUB EAX, imm32
                        const auto immediate = memory.fetch_u32(state);
                        state.registers[0] -= immediate;
                        state.zero_flag = state.registers[0] == 0;
                        break;
                    }
                    case 0x3D: {  // CMP EAX, imm32
                        const auto immediate = memory.fetch_u32(state);
                        state.zero_flag = state.registers[0] == immediate;
                        break;
                    }
                    case 0x74: {  // JZ rel8
                        const auto raw = memory.fetch_u8(state);
                        const auto displacement = raw < 0x80
                            ? static_cast<std::int32_t>(raw)
                            : static_cast<std::int32_t>(raw) - 0x100;
                        if (state.zero_flag) {
                            memory.apply_relative_jump(state, displacement);
                        }
                        break;
                    }
                    case 0x75: {  // JNZ rel8
                        const auto raw = memory.fetch_u8(state);
                        const auto displacement = raw < 0x80
                            ? static_cast<std::int32_t>(raw)
                            : static_cast<std::int32_t>(raw) - 0x100;
                        if (!state.zero_flag) {
                            memory.apply_relative_jump(state, displacement);
                        }
                        break;
                    }
                    case 0x83: {  // ADD ESP, imm8 (only ModRM 11 000 100)
                        const auto modrm = memory.fetch_u8(state);
                        if (modrm != 0xC4) {
                            throw DecodeError("unsupported opcode");
                        }
                        const auto raw = memory.fetch_u8(state);
                        const auto signed_immediate = raw < 0x80
                            ? static_cast<std::int32_t>(raw)
                            : static_cast<std::int32_t>(raw) - 0x100;
                        state.registers[kEsp] += static_cast<std::uint32_t>(signed_immediate);
                        state.zero_flag = state.registers[kEsp] == 0;
                        break;
                    }
                    case 0xC2: {  // RET imm16
                        const auto amount = static_cast<std::uint16_t>(memory.fetch_u8(state)) |
                            static_cast<std::uint16_t>(memory.fetch_u8(state) << 8);
                        const auto target = pop_u32(memory, state);
                        state.registers[kEsp] += amount;
                        state.instruction_pointer = target;
                        break;
                    }
                    case 0xC3: {  // RET
                        state.instruction_pointer = pop_u32(memory, state);
                        break;
                    }
                    case 0xE8: {  // CALL rel32
                        const auto displacement = signed_rel32(memory.fetch_u32(state));
                        const auto return_address = static_cast<std::uint32_t>(state.instruction_pointer);
                        push_u32(memory, state, return_address);
                        memory.apply_relative_jump(state, displacement);
                        break;
                    }
                    case 0xEB: {  // JMP rel8
                        const auto raw = memory.fetch_u8(state);
                        const auto displacement = raw < 0x80
                            ? static_cast<std::int32_t>(raw)
                            : static_cast<std::int32_t>(raw) - 0x100;
                        memory.apply_relative_jump(state, displacement);
                        break;
                    }
                    case 0xFf: {  // FF /2 with absolute disp32: CALL [address]
                        const auto modrm = memory.fetch_u8(state);
                        if (modrm != 0x15) {
                            throw DecodeError("unsupported opcode");
                        }
                        const auto iat_address = memory.fetch_u32(state);
                        std::uint32_t target = 0;
                        if (!memory.read_u32(iat_address, target)) {
                            throw DecodeError("memory access out of range");
                        }

                        const auto return_address = static_cast<std::uint32_t>(state.instruction_pointer);
                        push_u32(memory, state, return_address);
                        if (const auto* handler = find_handler(imports, target)) {
                            execute_import(memory, state, *handler);
                        } else if (memory.is_import_address(target)) {
                            throw DecodeError("synthetic import has no handler");
                        } else {
                            state.instruction_pointer = target;
                        }
                        break;
                    }
                    default:
                        throw DecodeError("unsupported opcode");
                }
            }
            memory.finish_instruction();
            ++state.instruction_count;
        }
    } catch (const DecodeError& error) {
        return {state, false, error.what()};
    }
}

bool valid_import_registry(const std::vector<SyntheticImportHandler>& imports,
                           std::string& error) {
    for (std::size_t index = 0; index < imports.size(); ++index) {
        const auto& import = imports[index];
        if (!import.function) {
            error = "synthetic import handler is empty";
            return false;
        }
        if (import.argument_count > (kStackSize / 4u) - 1u) {
            error = "synthetic import argument count exceeds stack capacity";
            return false;
        }
        if (import.convention != X86CallingConvention::cdecl &&
            import.convention != X86CallingConvention::stdcall) {
            error = "unsupported synthetic import calling convention";
            return false;
        }
        for (std::size_t earlier = 0; earlier < index; ++earlier) {
            if (imports[earlier].address == import.address) {
                error = "duplicate synthetic import address";
                return false;
            }
        }
    }
    return true;
}

bool stack_range_conflicts(const LoadedImage& image) {
    const auto reserved_start = static_cast<std::uint64_t>(kStackBase) - kGuardSize;
    const auto reserved_end = static_cast<std::uint64_t>(kStackBase) + kStackSize + kGuardSize;
    for (const auto& region : image.memory.regions()) {
        const auto region_start = static_cast<std::uint64_t>(region.address);
        const auto region_end = region_start + region.size;
        if (region_start < reserved_end && reserved_start < region_end) {
            return true;
        }
    }
    return false;
}

}  // namespace

X86RunResult X86SubsetInterpreter::run(const std::vector<std::uint8_t>& code,
                                       SyntheticMemory& data,
                                       std::uint64_t max_steps,
                                       X86State initial_state) const {
    VectorMemoryAdapter memory(code, data);
    return execute(memory, initial_state, {}, max_steps);
}

X86RunResult X86SubsetInterpreter::run_loaded_image(LoadedImage& image,
                                                    std::uint32_t stop_address,
                                                    std::uint64_t max_steps) const {
    X86RunOptions options;
    return run_loaded_image(image, stop_address, options, max_steps);
}

X86RunResult X86SubsetInterpreter::run_loaded_image(LoadedImage& image,
                                                    std::uint32_t stop_address,
                                                    const X86RunOptions& options,
                                                    std::uint64_t max_steps) const {
    X86State state{};
    state.instruction_pointer = image.entry_point;
    if (max_steps == 0) {
        return {state, false, "execution limit must be positive"};
    }
    std::string error;
    if (!valid_import_registry(options.imports, error)) {
        return {state, false, std::move(error)};
    }
    if (options.enable_stack) {
        if (stack_range_conflicts(image)) {
            return {state, false, "stack or guard range conflicts with existing memory"};
        }
        if (!image.memory.map_region(kStackBase, kStackSize,
                                     MemoryPermissions{true, true, false}, "synthetic stack")) {
            return {state, false, "could not map synthetic stack"};
        }
        state.registers[kEsp] = kStackBase + kStackSize;
    }
    LoadedImageMemoryAdapter memory(image, stop_address);
    return execute(memory, state, options.imports, max_steps);
}

}  // namespace sims3lab
