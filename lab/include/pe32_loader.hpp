#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sims3lab {

struct MemoryPermissions {
    bool read = false;
    bool write = false;
    bool execute = false;
};

struct MemoryRegionInfo {
    std::uint32_t address = 0;
    std::uint32_t size = 0;
    MemoryPermissions permissions;
    std::string name;
};

class VirtualMemory32 {
public:
    bool read(std::uint32_t address, void* destination, std::size_t length) const;
    bool write(std::uint32_t address, const void* source, std::size_t length);
    bool fetch_instruction(std::uint32_t address, void* destination,
                           std::size_t length) const;
    bool read_u16_le(std::uint32_t address, std::uint16_t& value) const;
    bool read_u32_le(std::uint32_t address, std::uint32_t& value) const;
    bool write_u32_le(std::uint32_t address, std::uint32_t value);
    bool is_readable(std::uint32_t address, std::size_t length) const;
    bool is_writable(std::uint32_t address, std::size_t length) const;
    bool is_executable(std::uint32_t address, std::size_t length) const;
    bool is_mapped(std::uint32_t address, std::size_t length) const;
    const std::vector<MemoryRegionInfo>& regions() const noexcept;

    // Used by the loader while constructing the image, independent of guest permissions.
    bool loader_read(std::uint32_t address, void* destination, std::size_t length) const;
    // Used only while constructing a loaded image, before final permissions apply.
    bool loader_patch(std::uint32_t address, const void* source, std::size_t length);

private:
    struct Region {
        MemoryRegionInfo info;
        std::vector<std::uint8_t> bytes;
    };

    bool map_region(std::uint32_t address, std::uint32_t size,
                    MemoryPermissions permissions, std::string name);
    bool patch(std::uint32_t address, const void* source, std::size_t length);

    std::vector<Region> storage_;
    std::vector<MemoryRegionInfo> region_info_;

    friend struct Pe32LoadResult;
    friend class Pe32Loader;
};

struct ImportSymbol {
    bool by_ordinal = false;
    std::string name;
    std::uint16_t ordinal = 0;
};

using ImportResolver = std::function<std::optional<std::uint32_t>(
    std::string_view module, const ImportSymbol& symbol)>;

struct ResolvedImport {
    std::string module;
    ImportSymbol symbol;
    std::uint32_t iat_address = 0;
    std::uint32_t resolved_address = 0;
};

struct LoadedImage {
    std::uint32_t base = 0;
    std::uint32_t preferred_base = 0;
    std::uint32_t entry_point = 0;
    std::uint32_t size = 0;
    std::vector<ResolvedImport> imports;
    VirtualMemory32 memory;
};

enum class Pe32ErrorCode {
    truncated_file,
    invalid_signature,
    unsupported_architecture,
    unsupported_format,
    invalid_alignment,
    malformed_headers,
    image_too_large,
    address_overflow,
    invalid_section,
    overlapping_sections,
    entry_not_executable,
    unsupported_feature,
    relocations_unavailable,
    malformed_relocations,
    unsupported_relocation,
    malformed_imports,
    import_not_found,
    memory_error,
};

struct Pe32Error {
    Pe32ErrorCode code = Pe32ErrorCode::malformed_headers;
    std::string message;
};

struct Pe32LoadResult {
    std::optional<LoadedImage> image;
    std::optional<Pe32Error> error;
    explicit operator bool() const noexcept { return image.has_value(); }
};

// No guest code is executed. A missing base selects the PE's preferred base.
Pe32LoadResult load_pe32(const std::vector<std::uint8_t>& bytes,
                         std::optional<std::uint32_t> base = std::nullopt,
                         ImportResolver resolver = {});

const char* pe32_error_name(Pe32ErrorCode code) noexcept;

}  // namespace sims3lab
