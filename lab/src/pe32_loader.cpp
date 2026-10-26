#include "pe32_loader.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace sims3lab {
namespace {

constexpr std::uint64_t kAddressSpaceEnd = 0x100000000ull;
constexpr std::uint32_t kPageSize = 4096;
constexpr std::uint32_t kMaximumImageSize = 64u * 1024u * 1024u;
constexpr std::uint16_t kMachineI386 = 0x014Cu;
constexpr std::uint16_t kPe32Magic = 0x010Bu;
constexpr std::uint16_t kRelocationsStripped = 0x0001u;
constexpr std::uint32_t kSectionExecute = 0x20000000u;
constexpr std::uint32_t kSectionRead = 0x40000000u;
constexpr std::uint32_t kSectionWrite = 0x80000000u;

struct Failure {
    Pe32ErrorCode code;
    std::string message;
};

[[noreturn]] void fail(Pe32ErrorCode code, std::string message) {
    throw Failure{code, std::move(message)};
}

bool file_range(const std::vector<std::uint8_t>& bytes, std::uint64_t offset,
                std::uint64_t length) {
    return offset <= bytes.size() && length <= bytes.size() - offset;
}

bool address_range_end(std::uint32_t address, std::size_t length, std::uint64_t& end) {
    const std::uint64_t start = address;
    if (length > kAddressSpaceEnd - start) {
        return false;
    }
    end = start + length;
    return true;
}

std::uint16_t file_u16(const std::vector<std::uint8_t>& bytes, std::uint64_t offset) {
    if (!file_range(bytes, offset, 2)) {
        fail(Pe32ErrorCode::truncated_file, "truncated PE field");
    }
    return static_cast<std::uint16_t>(bytes[static_cast<std::size_t>(offset)]) |
           static_cast<std::uint16_t>(bytes[static_cast<std::size_t>(offset + 1)] << 8);
}

std::uint32_t file_u32(const std::vector<std::uint8_t>& bytes, std::uint64_t offset) {
    if (!file_range(bytes, offset, 4)) {
        fail(Pe32ErrorCode::truncated_file, "truncated PE field");
    }
    const auto at = static_cast<std::size_t>(offset);
    return static_cast<std::uint32_t>(bytes[at]) |
           (static_cast<std::uint32_t>(bytes[at + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[at + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[at + 3]) << 24);
}

std::uint64_t align_up(std::uint64_t value, std::uint32_t alignment) {
    if (alignment == 0) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    const auto remainder = value % alignment;
    if (remainder == 0) {
        return value;
    }
    const auto increment = alignment - remainder;
    if (value > std::numeric_limits<std::uint64_t>::max() - increment) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return value + increment;
}

struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct Section {
    std::string name;
    std::uint32_t virtual_size = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t mapped_size = 0;
    std::uint32_t characteristics = 0;
};

struct ParsedImage {
    std::uint32_t preferred_base = 0;
    std::uint32_t entry_rva = 0;
    std::uint32_t size_image = 0;
    std::uint32_t size_headers = 0;
    std::uint16_t file_characteristics = 0;
    std::array<DataDirectory, 16> directories{};
    std::vector<Section> sections;
};

ParsedImage parse_headers(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 64) {
        fail(Pe32ErrorCode::truncated_file, "file is too short for an MS-DOS header");
    }
    if (file_u16(bytes, 0) != 0x5A4Du) {
        fail(Pe32ErrorCode::invalid_signature, "missing MZ signature");
    }
    const std::uint32_t pe_offset = file_u32(bytes, 0x3Cu);
    if (!file_range(bytes, pe_offset, 24)) {
        fail(Pe32ErrorCode::truncated_file, "PE and COFF headers are truncated");
    }
    if (bytes[pe_offset] != 'P' || bytes[pe_offset + 1] != 'E' ||
        bytes[pe_offset + 2] != 0 || bytes[pe_offset + 3] != 0) {
        fail(Pe32ErrorCode::invalid_signature, "missing PE signature");
    }

    const std::uint64_t coff = static_cast<std::uint64_t>(pe_offset) + 4;
    if (file_u16(bytes, coff) != kMachineI386) {
        fail(Pe32ErrorCode::unsupported_architecture, "only PE32 x86 (I386) is supported");
    }
    const auto section_count = file_u16(bytes, coff + 2);
    const auto optional_size = file_u16(bytes, coff + 16);
    ParsedImage parsed;
    parsed.file_characteristics = file_u16(bytes, coff + 18);
    if (section_count == 0 || section_count > 96) {
        fail(Pe32ErrorCode::malformed_headers, "section count must be between 1 and 96");
    }
    const std::uint64_t optional = coff + 20;
    if (optional_size < 96 || !file_range(bytes, optional, optional_size)) {
        fail(Pe32ErrorCode::truncated_file, "PE32 optional header is truncated");
    }
    if (file_u16(bytes, optional) != kPe32Magic) {
        fail(Pe32ErrorCode::unsupported_format, "only the PE32 optional header is supported");
    }

    parsed.entry_rva = file_u32(bytes, optional + 16);
    parsed.preferred_base = file_u32(bytes, optional + 28);
    const auto section_alignment = file_u32(bytes, optional + 32);
    const auto file_alignment = file_u32(bytes, optional + 36);
    parsed.size_image = file_u32(bytes, optional + 56);
    parsed.size_headers = file_u32(bytes, optional + 60);
    if (section_alignment != kPageSize || file_alignment < 512 ||
        file_alignment > kPageSize || (file_alignment & (file_alignment - 1u)) != 0) {
        fail(Pe32ErrorCode::invalid_alignment,
             "this profile requires 4096-byte sections and a power-of-two file alignment from 512 to 4096");
    }
    if (parsed.preferred_base % 65536u != 0) {
        fail(Pe32ErrorCode::invalid_alignment, "preferred image base is not 64 KiB aligned");
    }
    if (parsed.size_image == 0 || parsed.size_image > kMaximumImageSize) {
        fail(Pe32ErrorCode::image_too_large, "image size must be between 1 byte and 64 MiB");
    }
    if (parsed.size_image % section_alignment != 0 || parsed.size_headers == 0 ||
        parsed.size_headers > parsed.size_image || parsed.size_headers > bytes.size() ||
        parsed.size_headers % file_alignment != 0) {
        fail(Pe32ErrorCode::malformed_headers, "invalid SizeOfImage or SizeOfHeaders");
    }

    const auto directory_count = file_u32(bytes, optional + 92);
    const std::uint64_t directory_bytes = optional_size - 96u;
    if (directory_count > directory_bytes / 8u) {
        fail(Pe32ErrorCode::malformed_headers,
             "data-directory count exceeds the optional header bounds");
    }
    const auto parsed_directory_count = std::min<std::uint32_t>(directory_count, 16u);
    for (std::uint32_t index = 0; index < parsed_directory_count; ++index) {
        parsed.directories[index].rva = file_u32(bytes, optional + 96u + index * 8u);
        parsed.directories[index].size = file_u32(bytes, optional + 100u + index * 8u);
    }

    const std::uint64_t section_table = optional + optional_size;
    const std::uint64_t section_table_size = static_cast<std::uint64_t>(section_count) * 40u;
    if (!file_range(bytes, section_table, section_table_size)) {
        fail(Pe32ErrorCode::truncated_file, "section table is truncated");
    }
    const std::uint64_t section_table_end = section_table + section_table_size;
    if (section_table_end > parsed.size_headers) {
        fail(Pe32ErrorCode::malformed_headers, "SizeOfHeaders does not cover the section table");
    }

    parsed.sections.reserve(section_count);
    for (std::uint16_t index = 0; index < section_count; ++index) {
        const auto at = section_table + static_cast<std::uint64_t>(index) * 40u;
        Section section;
        for (std::size_t char_index = 0; char_index < 8; ++char_index) {
            const auto value = bytes[static_cast<std::size_t>(at + char_index)];
            if (value == 0) {
                break;
            }
            section.name.push_back(static_cast<char>(value));
        }
        section.virtual_size = file_u32(bytes, at + 8);
        section.virtual_address = file_u32(bytes, at + 12);
        section.raw_size = file_u32(bytes, at + 16);
        section.raw_offset = file_u32(bytes, at + 20);
        section.characteristics = file_u32(bytes, at + 36);
        const auto content_size = std::max(section.virtual_size, section.raw_size);
        const auto mapped_size = align_up(content_size, section_alignment);
        if (section.name.empty() || section.virtual_address == 0 ||
            section.virtual_address % section_alignment != 0 ||
            content_size == 0 ||
            mapped_size == std::numeric_limits<std::uint64_t>::max() ||
            mapped_size > std::numeric_limits<std::uint32_t>::max()) {
            fail(Pe32ErrorCode::invalid_section, "invalid section name, RVA, or virtual size");
        }
        section.mapped_size = static_cast<std::uint32_t>(mapped_size);
        const std::uint64_t virtual_end = static_cast<std::uint64_t>(section.virtual_address) +
                                          section.mapped_size;
        if (virtual_end > parsed.size_image ||
            section.virtual_address < align_up(parsed.size_headers, section_alignment)) {
            fail(Pe32ErrorCode::invalid_section, "section lies outside the declared image");
        }
        if (section.raw_size != 0) {
            if (section.raw_offset % file_alignment != 0 || section.raw_size % file_alignment != 0 ||
                section.raw_offset < parsed.size_headers) {
                fail(Pe32ErrorCode::invalid_section, "section raw data has an invalid file range");
            }
            if (!file_range(bytes, section.raw_offset, section.raw_size)) {
                fail(Pe32ErrorCode::truncated_file, "section raw data is truncated");
            }
        }
        parsed.sections.push_back(std::move(section));
    }

    for (std::size_t left = 0; left < parsed.sections.size(); ++left) {
        const auto& a = parsed.sections[left];
        const std::uint64_t a_virtual_end = static_cast<std::uint64_t>(a.virtual_address) + a.mapped_size;
        const std::uint64_t a_raw_end = static_cast<std::uint64_t>(a.raw_offset) + a.raw_size;
        for (std::size_t right = left + 1; right < parsed.sections.size(); ++right) {
            const auto& b = parsed.sections[right];
            const std::uint64_t b_virtual_end = static_cast<std::uint64_t>(b.virtual_address) + b.mapped_size;
            const std::uint64_t b_raw_end = static_cast<std::uint64_t>(b.raw_offset) + b.raw_size;
            const bool virtual_overlap = a.virtual_address < b_virtual_end && b.virtual_address < a_virtual_end;
            const bool raw_overlap = a.raw_size != 0 && b.raw_size != 0 &&
                                     a.raw_offset < b_raw_end && b.raw_offset < a_raw_end;
            if (virtual_overlap || raw_overlap) {
                fail(Pe32ErrorCode::overlapping_sections,
                     virtual_overlap ? "virtual section ranges overlap" : "raw section ranges overlap");
            }
        }
    }

    const auto& imports = parsed.directories[1];
    const auto& relocations = parsed.directories[5];
    const auto& tls = parsed.directories[9];
    const auto& load_config = parsed.directories[10];
    const auto& delay_imports = parsed.directories[13];
    if (tls.rva != 0 || tls.size != 0) {
        fail(Pe32ErrorCode::unsupported_feature, "TLS is not supported by this loader profile");
    }
    if (delay_imports.rva != 0 || delay_imports.size != 0) {
        fail(Pe32ErrorCode::unsupported_feature,
             "delayed imports are not supported by this loader profile");
    }
    if (load_config.rva != 0 || load_config.size != 0) {
        fail(Pe32ErrorCode::unsupported_feature,
             "load config is not supported by this loader profile");
    }
    if ((imports.rva == 0) != (imports.size == 0) ||
        (relocations.rva == 0) != (relocations.size == 0)) {
        fail(Pe32ErrorCode::malformed_headers, "data-directory RVA and size must both be zero or nonzero");
    }

    return parsed;
}

std::optional<std::uint32_t> rva_to_address(std::uint32_t base, std::uint32_t rva) {
    const auto address = static_cast<std::uint64_t>(base) + rva;
    if (address > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(address);
}

bool is_zero_descriptor(const std::array<std::uint32_t, 5>& fields) {
    return std::all_of(fields.begin(), fields.end(), [](std::uint32_t value) { return value == 0; });
}

}  // namespace

bool VirtualMemory32::map_region(std::uint32_t address, std::uint32_t size,
                                 MemoryPermissions permissions, std::string name) {
    if (size == 0) {
        return false;
    }
    const std::uint64_t start = address;
    const std::uint64_t end = start + size;
    if (end > kAddressSpaceEnd) {
        return false;
    }
    for (const auto& existing : storage_) {
        const std::uint64_t existing_start = existing.info.address;
        const std::uint64_t existing_end = existing_start + existing.info.size;
        if (start < existing_end && existing_start < end) {
            return false;
        }
    }
    MemoryRegionInfo info{address, size, permissions, std::move(name)};
    Region region;
    region.info = info;
    region.bytes.assign(size, 0);
    storage_.push_back(std::move(region));
    region_info_.push_back(std::move(info));
    return true;
}

bool VirtualMemory32::read(std::uint32_t address, void* destination, std::size_t length) const {
    if (length != 0 && destination == nullptr) {
        return false;
    }
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) {
        return false;
    }
    for (const auto& region : storage_) {
        const std::uint64_t region_start = region.info.address;
        const std::uint64_t region_end = region_start + region.info.size;
        if (start >= region_start && end <= region_end && region.info.permissions.read) {
            const auto offset = static_cast<std::size_t>(start - region_start);
            if (length != 0) {
                std::memcpy(destination, region.bytes.data() + offset, length);
            }
            return true;
        }
    }
    return false;
}

bool VirtualMemory32::write(std::uint32_t address, const void* source, std::size_t length) {
    if (length != 0 && source == nullptr) {
        return false;
    }
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) {
        return false;
    }
    for (auto& region : storage_) {
        const std::uint64_t region_start = region.info.address;
        const std::uint64_t region_end = region_start + region.info.size;
        if (start >= region_start && end <= region_end && region.info.permissions.write) {
            const auto offset = static_cast<std::size_t>(start - region_start);
            if (length != 0) {
                std::memcpy(region.bytes.data() + offset, source, length);
            }
            return true;
        }
    }
    return false;
}

bool VirtualMemory32::fetch_instruction(std::uint32_t address, void* destination,
                                        std::size_t length) const {
    if (length != 0 && destination == nullptr) {
        return false;
    }
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) {
        return false;
    }
    for (const auto& region : storage_) {
        const std::uint64_t region_start = region.info.address;
        const std::uint64_t region_end = region_start + region.info.size;
        if (start >= region_start && end <= region_end && region.info.permissions.execute) {
            const auto offset = static_cast<std::size_t>(start - region_start);
            if (length != 0) {
                std::memcpy(destination, region.bytes.data() + offset, length);
            }
            return true;
        }
    }
    return false;
}

bool VirtualMemory32::read_u16_le(std::uint32_t address, std::uint16_t& value) const {
    std::uint8_t bytes[2]{};
    if (!read(address, bytes, sizeof(bytes))) {
        return false;
    }
    value = static_cast<std::uint16_t>(bytes[0]) |
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8);
    return true;
}

bool VirtualMemory32::read_u32_le(std::uint32_t address, std::uint32_t& value) const {
    std::uint8_t bytes[4]{};
    if (!read(address, bytes, sizeof(bytes))) {
        return false;
    }
    value = static_cast<std::uint32_t>(bytes[0]) |
            (static_cast<std::uint32_t>(bytes[1]) << 8) |
            (static_cast<std::uint32_t>(bytes[2]) << 16) |
            (static_cast<std::uint32_t>(bytes[3]) << 24);
    return true;
}

bool VirtualMemory32::write_u32_le(std::uint32_t address, std::uint32_t value) {
    std::uint8_t bytes[4] = {
        static_cast<std::uint8_t>(value & 0xFFu),
        static_cast<std::uint8_t>((value >> 8) & 0xFFu),
        static_cast<std::uint8_t>((value >> 16) & 0xFFu),
        static_cast<std::uint8_t>((value >> 24) & 0xFFu),
    };
    return write(address, bytes, sizeof(bytes));
}

bool VirtualMemory32::is_readable(std::uint32_t address, std::size_t length) const {
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) return false;
    return std::any_of(storage_.begin(), storage_.end(), [start, end](const Region& region) {
        const auto region_start = static_cast<std::uint64_t>(region.info.address);
        const auto region_end = region_start + region.info.size;
        return start >= region_start && end <= region_end && region.info.permissions.read;
    });
}

bool VirtualMemory32::is_writable(std::uint32_t address, std::size_t length) const {
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) return false;
    return std::any_of(storage_.begin(), storage_.end(), [start, end](const Region& region) {
        const auto region_start = static_cast<std::uint64_t>(region.info.address);
        const auto region_end = region_start + region.info.size;
        return start >= region_start && end <= region_end && region.info.permissions.write;
    });
}

bool VirtualMemory32::is_executable(std::uint32_t address, std::size_t length) const {
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) return false;
    return std::any_of(storage_.begin(), storage_.end(), [start, end](const Region& region) {
        const auto region_start = static_cast<std::uint64_t>(region.info.address);
        const auto region_end = region_start + region.info.size;
        return start >= region_start && end <= region_end && region.info.permissions.execute;
    });
}

bool VirtualMemory32::is_mapped(std::uint32_t address, std::size_t length) const {
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) return false;
    return std::any_of(storage_.begin(), storage_.end(), [start, end](const Region& region) {
        const auto region_start = static_cast<std::uint64_t>(region.info.address);
        const auto region_end = region_start + region.info.size;
        return start >= region_start && end <= region_end;
    });
}

const std::vector<MemoryRegionInfo>& VirtualMemory32::regions() const noexcept {
    return region_info_;
}

bool VirtualMemory32::loader_read(std::uint32_t address, void* destination, std::size_t length) const {
    if (length != 0 && destination == nullptr) return false;
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) return false;
    for (const auto& region : storage_) {
        const auto region_start = static_cast<std::uint64_t>(region.info.address);
        const auto region_end = region_start + region.info.size;
        if (start >= region_start && end <= region_end) {
            if (length != 0) {
                std::memcpy(destination, region.bytes.data() + static_cast<std::size_t>(start - region_start), length);
            }
            return true;
        }
    }
    return false;
}

bool VirtualMemory32::patch(std::uint32_t address, const void* source, std::size_t length) {
    if (length != 0 && source == nullptr) return false;
    const std::uint64_t start = address;
    std::uint64_t end = 0;
    if (!address_range_end(address, length, end)) return false;
    for (auto& region : storage_) {
        const auto region_start = static_cast<std::uint64_t>(region.info.address);
        const auto region_end = region_start + region.info.size;
        if (start >= region_start && end <= region_end) {
            if (length != 0) {
                std::memcpy(region.bytes.data() + static_cast<std::size_t>(start - region_start), source, length);
            }
            return true;
        }
    }
    return false;
}

bool VirtualMemory32::loader_patch(std::uint32_t address, const void* source, std::size_t length) {
    return patch(address, source, length);
}

class Pe32Loader {
public:
    static Pe32LoadResult load(const std::vector<std::uint8_t>& bytes,
                               std::optional<std::uint32_t> requested_base,
                               const ImportResolver& resolver) {
        try {
            const auto parsed = parse_headers(bytes);
            const auto base = requested_base.value_or(parsed.preferred_base);
            if (static_cast<std::uint64_t>(base) + parsed.size_image > kAddressSpaceEnd) {
                fail(Pe32ErrorCode::address_overflow, "image range exceeds the 32-bit address space");
            }
            if (parsed.entry_rva >= parsed.size_image) {
                fail(Pe32ErrorCode::entry_not_executable, "entry point lies outside the image");
            }
            const auto entry = rva_to_address(base, parsed.entry_rva);
            if (!entry) {
                fail(Pe32ErrorCode::address_overflow, "entry-point address overflows 32 bits");
            }

            LoadedImage image;
            image.base = base;
            image.preferred_base = parsed.preferred_base;
            image.entry_point = *entry;
            image.size = parsed.size_image;
            if (!image.memory.map_region(base, parsed.size_headers,
                                         MemoryPermissions{true, false, false}, "headers")) {
                fail(Pe32ErrorCode::memory_error, "could not map image headers");
            }
            if (!image.memory.loader_patch(base, bytes.data(), parsed.size_headers)) {
                fail(Pe32ErrorCode::memory_error, "could not copy image headers");
            }
            for (const auto& section : parsed.sections) {
                MemoryPermissions permissions{
                    (section.characteristics & kSectionRead) != 0,
                    (section.characteristics & kSectionWrite) != 0,
                    (section.characteristics & kSectionExecute) != 0,
                };
                const auto address = rva_to_address(base, section.virtual_address);
                if (!address || !image.memory.map_region(*address, section.mapped_size,
                                                          permissions, section.name)) {
                    fail(Pe32ErrorCode::memory_error, "could not map section " + section.name);
                }
                if (section.raw_size != 0 &&
                    !image.memory.loader_patch(*address, bytes.data() + section.raw_offset,
                                               section.raw_size)) {
                    fail(Pe32ErrorCode::memory_error, "could not copy section " + section.name);
                }
            }

            const bool rebased = base != parsed.preferred_base;
            const auto& relocation_directory = parsed.directories[5];
            if (rebased) {
                if ((parsed.file_characteristics & kRelocationsStripped) != 0 ||
                    relocation_directory.rva == 0 || relocation_directory.size == 0) {
                    fail(Pe32ErrorCode::relocations_unavailable,
                         "image cannot move from its preferred base without base relocations");
                }
                apply_relocations(image, relocation_directory);
            }
            resolve_imports(image, parsed.directories[1], resolver);

            bool executable_entry = false;
            for (const auto& region : image.memory.regions()) {
                const std::uint64_t start = region.address;
                const std::uint64_t end = start + region.size;
                if (image.entry_point >= start && static_cast<std::uint64_t>(image.entry_point) < end &&
                    region.permissions.execute) {
                    executable_entry = true;
                    break;
                }
            }
            if (!executable_entry) {
                fail(Pe32ErrorCode::entry_not_executable,
                     "entry point is not inside an executable section");
            }
            return Pe32LoadResult{std::move(image), std::nullopt};
        } catch (const Failure& failure) {
            return Pe32LoadResult{std::nullopt, Pe32Error{failure.code, failure.message}};
        } catch (const std::bad_alloc&) {
            return Pe32LoadResult{std::nullopt,
                                  Pe32Error{Pe32ErrorCode::image_too_large, "memory allocation failed"}};
        }
    }

private:
    static std::uint32_t loader_u32(const VirtualMemory32& memory, std::uint32_t address,
                                    Pe32ErrorCode error_code, const char* message) {
        std::uint8_t bytes[4]{};
        if (!memory.loader_read(address, bytes, sizeof(bytes))) {
            fail(error_code, message);
        }
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8) |
               (static_cast<std::uint32_t>(bytes[2]) << 16) |
               (static_cast<std::uint32_t>(bytes[3]) << 24);
    }

    static void apply_relocations(LoadedImage& image, const DataDirectory& directory) {
        const auto directory_address = rva_to_address(image.base, directory.rva);
        if (!directory_address || directory.rva >= image.size ||
            static_cast<std::uint64_t>(directory.rva) + directory.size > image.size) {
            fail(Pe32ErrorCode::malformed_relocations, "relocation directory lies outside the image");
        }
        if (!image.memory.is_mapped(*directory_address, directory.size)) {
            fail(Pe32ErrorCode::malformed_relocations, "relocation directory is not in a mapped region");
        }
        std::uint32_t cursor = 0;
        const std::uint32_t delta = image.base - image.preferred_base;
        while (cursor < directory.size) {
            if (directory.size - cursor < 8) {
                fail(Pe32ErrorCode::malformed_relocations, "truncated relocation block header");
            }
            const auto block_address64 = static_cast<std::uint64_t>(*directory_address) + cursor;
            if (block_address64 > std::numeric_limits<std::uint32_t>::max()) {
                fail(Pe32ErrorCode::malformed_relocations, "relocation block address overflows");
            }
            const auto block_address = static_cast<std::uint32_t>(block_address64);
            const auto page_rva = loader_u32(image.memory, block_address,
                                             Pe32ErrorCode::malformed_relocations,
                                             "relocation block is unmapped");
            const auto block_size_address64 = block_address64 + 4;
            if (block_size_address64 > std::numeric_limits<std::uint32_t>::max()) {
                fail(Pe32ErrorCode::malformed_relocations, "relocation block header overflows");
            }
            const auto block_size = loader_u32(image.memory, static_cast<std::uint32_t>(block_size_address64),
                                               Pe32ErrorCode::malformed_relocations,
                                               "relocation block is truncated");
            if (page_rva % kPageSize != 0 || block_size < 8 || (block_size & 1u) != 0 ||
                block_size > directory.size - cursor) {
                fail(Pe32ErrorCode::malformed_relocations, "invalid relocation block size or page RVA");
            }
            const std::uint32_t entry_count = (block_size - 8) / 2;
            for (std::uint32_t index = 0; index < entry_count; ++index) {
                const auto entry_address64 = static_cast<std::uint64_t>(*directory_address) +
                                             cursor + 8u + index * 2u;
                if (entry_address64 > std::numeric_limits<std::uint32_t>::max()) {
                    fail(Pe32ErrorCode::malformed_relocations, "relocation entry address overflows");
                }
                std::uint8_t raw_entry[2]{};
                if (!image.memory.loader_read(static_cast<std::uint32_t>(entry_address64), raw_entry, 2)) {
                    fail(Pe32ErrorCode::malformed_relocations, "relocation entry is unmapped");
                }
                const std::uint16_t item = static_cast<std::uint16_t>(raw_entry[0]) |
                    static_cast<std::uint16_t>(static_cast<std::uint16_t>(raw_entry[1]) << 8);
                const std::uint16_t type = item >> 12;
                const std::uint16_t offset = item & 0x0FFFu;
                if (type == 0) {
                    continue;
                }
                if (type != 3) {
                    fail(Pe32ErrorCode::unsupported_relocation,
                         "only ABSOLUTE and HIGHLOW relocations are supported");
                }
                const std::uint64_t target_rva64 = static_cast<std::uint64_t>(page_rva) + offset;
                if (target_rva64 + 4 > image.size) {
                    fail(Pe32ErrorCode::malformed_relocations, "HIGHLOW target lies outside the image");
                }
                const auto target = rva_to_address(image.base, static_cast<std::uint32_t>(target_rva64));
                if (!target) {
                    fail(Pe32ErrorCode::address_overflow, "HIGHLOW target address overflows");
                }
                const auto value = loader_u32(image.memory, *target,
                                              Pe32ErrorCode::malformed_relocations,
                                              "HIGHLOW target is not mapped");
                const auto adjusted = static_cast<std::uint32_t>(value + delta);
                const std::uint8_t patched[4] = {
                    static_cast<std::uint8_t>(adjusted & 0xFFu),
                    static_cast<std::uint8_t>((adjusted >> 8) & 0xFFu),
                    static_cast<std::uint8_t>((adjusted >> 16) & 0xFFu),
                    static_cast<std::uint8_t>((adjusted >> 24) & 0xFFu),
                };
                if (!image.memory.loader_patch(*target, patched, sizeof(patched))) {
                    fail(Pe32ErrorCode::malformed_relocations, "could not patch HIGHLOW target");
                }
            }
            cursor += block_size;
        }
    }

    static std::string loader_string(const VirtualMemory32& memory, std::uint32_t address,
                                     Pe32ErrorCode code, const char* message) {
        std::string result;
        result.reserve(32);
        for (std::uint32_t index = 0; index < 4096; ++index) {
            const auto current64 = static_cast<std::uint64_t>(address) + index;
            if (current64 > std::numeric_limits<std::uint32_t>::max()) {
                fail(code, message);
            }
            std::uint8_t character = 0;
            if (!memory.loader_read(static_cast<std::uint32_t>(current64), &character, 1)) {
                fail(code, message);
            }
            if (character == 0) {
                return result;
            }
            result.push_back(static_cast<char>(character));
        }
        fail(code, "PE string is not NUL-terminated within 4096 bytes");
    }

    static void resolve_imports(LoadedImage& image, const DataDirectory& directory,
                                const ImportResolver& resolver) {
        if (directory.rva == 0) {
            return;
        }
        if (directory.size < 20 || directory.size % 20 != 0 ||
            static_cast<std::uint64_t>(directory.rva) + directory.size > image.size) {
            fail(Pe32ErrorCode::malformed_imports, "import directory has an invalid size or range");
        }
        const auto directory_address = rva_to_address(image.base, directory.rva);
        if (!directory_address) {
            fail(Pe32ErrorCode::address_overflow, "import directory address overflows");
        }
        if (!image.memory.is_mapped(*directory_address, directory.size)) {
            fail(Pe32ErrorCode::malformed_imports, "import directory is not in a mapped region");
        }
        bool terminated = false;
        const std::uint32_t descriptor_count = directory.size / 20;
        for (std::uint32_t descriptor_index = 0; descriptor_index < descriptor_count; ++descriptor_index) {
            const auto descriptor_address64 = static_cast<std::uint64_t>(*directory_address) +
                                              descriptor_index * 20u;
            if (descriptor_address64 > std::numeric_limits<std::uint32_t>::max()) {
                fail(Pe32ErrorCode::malformed_imports, "import descriptor address overflows");
            }
            const auto descriptor_address = static_cast<std::uint32_t>(descriptor_address64);
            std::array<std::uint32_t, 5> fields{};
            for (std::size_t field = 0; field < fields.size(); ++field) {
                const auto field_address64 = descriptor_address64 + field * 4u;
                if (field_address64 > std::numeric_limits<std::uint32_t>::max()) {
                    fail(Pe32ErrorCode::malformed_imports, "import descriptor field address overflows");
                }
                fields[field] = loader_u32(image.memory, static_cast<std::uint32_t>(field_address64),
                                           Pe32ErrorCode::malformed_imports,
                                           "import descriptor is truncated or unmapped");
            }
            if (is_zero_descriptor(fields)) {
                terminated = true;
                break;
            }
            const auto lookup_rva = fields[0] == 0 ? fields[4] : fields[0];
            if (lookup_rva == 0 || fields[3] == 0 || fields[4] == 0) {
                fail(Pe32ErrorCode::malformed_imports, "import descriptor has a missing table or module name");
            }
            const auto module_address = rva_to_address(image.base, fields[3]);
            if (!module_address) {
                fail(Pe32ErrorCode::malformed_imports, "module name RVA overflows");
            }
            const auto module = loader_string(image.memory, *module_address,
                                              Pe32ErrorCode::malformed_imports,
                                              "import module name is unmapped or unterminated");
            if (module.empty()) {
                fail(Pe32ErrorCode::malformed_imports, "import module name is empty");
            }

            bool thunk_terminated = false;
            for (std::uint32_t thunk_index = 0; thunk_index < 65536; ++thunk_index) {
                const std::uint64_t lookup_entry_rva64 = static_cast<std::uint64_t>(lookup_rva) + thunk_index * 4u;
                const std::uint64_t iat_entry_rva64 = static_cast<std::uint64_t>(fields[4]) + thunk_index * 4u;
                if (lookup_entry_rva64 > std::numeric_limits<std::uint32_t>::max() ||
                    iat_entry_rva64 > std::numeric_limits<std::uint32_t>::max()) {
                    fail(Pe32ErrorCode::malformed_imports, "import thunk table overflows");
                }
                const auto lookup_entry = rva_to_address(image.base, static_cast<std::uint32_t>(lookup_entry_rva64));
                const auto iat_entry = rva_to_address(image.base, static_cast<std::uint32_t>(iat_entry_rva64));
                if (!lookup_entry || !iat_entry) {
                    fail(Pe32ErrorCode::malformed_imports, "import thunk address overflows");
                }
                const auto thunk = loader_u32(image.memory, *lookup_entry,
                                              Pe32ErrorCode::malformed_imports,
                                              "import lookup table is truncated or unmapped");
                if (thunk == 0) {
                    thunk_terminated = true;
                    break;
                }

                ImportSymbol symbol;
                if ((thunk & 0x80000000u) != 0) {
                    if ((thunk & 0x7FFF0000u) != 0) {
                        fail(Pe32ErrorCode::malformed_imports, "ordinal import has reserved bits set");
                    }
                    symbol.by_ordinal = true;
                    symbol.ordinal = static_cast<std::uint16_t>(thunk & 0xFFFFu);
                } else {
                    const auto name_address = rva_to_address(image.base, thunk);
                    if (!name_address) {
                        fail(Pe32ErrorCode::malformed_imports, "import-by-name RVA overflows");
                    }
                    std::uint8_t hint[2]{};
                    if (!image.memory.loader_read(*name_address, hint, sizeof(hint))) {
                        fail(Pe32ErrorCode::malformed_imports, "import-by-name hint is unmapped");
                    }
                    const auto import_name_rva = static_cast<std::uint64_t>(thunk) + 2u;
                    if (import_name_rva > std::numeric_limits<std::uint32_t>::max()) {
                        fail(Pe32ErrorCode::malformed_imports, "import-by-name string RVA overflows");
                    }
                    const auto import_name_address = rva_to_address(image.base,
                                                                   static_cast<std::uint32_t>(import_name_rva));
                    if (!import_name_address) {
                        fail(Pe32ErrorCode::malformed_imports, "import-by-name address overflows");
                    }
                    symbol.name = loader_string(image.memory, *import_name_address,
                                                Pe32ErrorCode::malformed_imports,
                                                "import-by-name string is unmapped or unterminated");
                    if (symbol.name.empty()) {
                        fail(Pe32ErrorCode::malformed_imports, "import-by-name string is empty");
                    }
                }

                if (!resolver) {
                    fail(Pe32ErrorCode::import_not_found, "no synthetic import resolver was provided");
                }
                std::optional<std::uint32_t> address;
                try {
                    address = resolver(module, symbol);
                } catch (...) {
                    fail(Pe32ErrorCode::import_not_found,
                         "synthetic import resolver raised an exception");
                }
                if (!address) {
                    const auto requested = symbol.by_ordinal
                        ? std::string("ordinal ") + std::to_string(symbol.ordinal)
                        : symbol.name;
                    fail(Pe32ErrorCode::import_not_found,
                         "synthetic resolver has no address for " + module + "!" + requested);
                }
                const std::uint8_t resolved_bytes[4] = {
                    static_cast<std::uint8_t>(*address & 0xFFu),
                    static_cast<std::uint8_t>((*address >> 8) & 0xFFu),
                    static_cast<std::uint8_t>((*address >> 16) & 0xFFu),
                    static_cast<std::uint8_t>((*address >> 24) & 0xFFu),
                };
                if (!image.memory.loader_patch(*iat_entry, resolved_bytes, sizeof(resolved_bytes))) {
                    fail(Pe32ErrorCode::malformed_imports, "IAT entry is unmapped");
                }
                image.imports.push_back(ResolvedImport{module, symbol, *iat_entry, *address});
            }
            if (!thunk_terminated) {
                fail(Pe32ErrorCode::malformed_imports, "import lookup table has no terminator");
            }
        }
        if (!terminated) {
            fail(Pe32ErrorCode::malformed_imports, "import descriptor table has no terminator");
        }
    }
};

Pe32LoadResult load_pe32(const std::vector<std::uint8_t>& bytes,
                         std::optional<std::uint32_t> base,
                         ImportResolver resolver) {
    return Pe32Loader::load(bytes, base, resolver);
}

const char* pe32_error_name(Pe32ErrorCode code) noexcept {
    switch (code) {
        case Pe32ErrorCode::truncated_file: return "truncated_file";
        case Pe32ErrorCode::invalid_signature: return "invalid_signature";
        case Pe32ErrorCode::unsupported_architecture: return "unsupported_architecture";
        case Pe32ErrorCode::unsupported_format: return "unsupported_format";
        case Pe32ErrorCode::invalid_alignment: return "invalid_alignment";
        case Pe32ErrorCode::malformed_headers: return "malformed_headers";
        case Pe32ErrorCode::image_too_large: return "image_too_large";
        case Pe32ErrorCode::address_overflow: return "address_overflow";
        case Pe32ErrorCode::invalid_section: return "invalid_section";
        case Pe32ErrorCode::overlapping_sections: return "overlapping_sections";
        case Pe32ErrorCode::entry_not_executable: return "entry_not_executable";
        case Pe32ErrorCode::unsupported_feature: return "unsupported_feature";
        case Pe32ErrorCode::relocations_unavailable: return "relocations_unavailable";
        case Pe32ErrorCode::malformed_relocations: return "malformed_relocations";
        case Pe32ErrorCode::unsupported_relocation: return "unsupported_relocation";
        case Pe32ErrorCode::malformed_imports: return "malformed_imports";
        case Pe32ErrorCode::import_not_found: return "import_not_found";
        case Pe32ErrorCode::memory_error: return "memory_error";
    }
    return "unknown";
}

}  // namespace sims3lab
