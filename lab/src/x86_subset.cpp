#include "x86_subset.hpp"

#include "pe32_loader.hpp"

#include <array>
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
X86RunResult execute(MemoryAdapter& memory, X86State state, std::uint64_t max_steps) {
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
            } else {
                switch (opcode) {
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
                    case 0xEB: {  // JMP rel8
                        const auto raw = memory.fetch_u8(state);
                        const auto displacement = raw < 0x80
                            ? static_cast<std::int32_t>(raw)
                            : static_cast<std::int32_t>(raw) - 0x100;
                        memory.apply_relative_jump(state, displacement);
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

}  // namespace

X86RunResult X86SubsetInterpreter::run(const std::vector<std::uint8_t>& code,
                                       SyntheticMemory& data,
                                       std::uint64_t max_steps,
                                       X86State initial_state) const {
    VectorMemoryAdapter memory(code, data);
    return execute(memory, initial_state, max_steps);
}

X86RunResult X86SubsetInterpreter::run_loaded_image(LoadedImage& image,
                                                    std::uint32_t stop_address,
                                                    std::uint64_t max_steps) const {
    X86State state{};
    state.instruction_pointer = image.entry_point;
    LoadedImageMemoryAdapter memory(image, stop_address);
    return execute(memory, state, max_steps);
}

}  // namespace sims3lab
