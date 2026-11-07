#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

#pragma pack(push, 1)
struct RawAttrDefEntry {
    wchar_t name[64];
    uint32_t type_code;
    uint32_t display_rule;
    uint32_t collation_rule;
    uint32_t flags;
    uint64_t min_size;
    uint64_t max_size;
};
#pragma pack(pop)

static_assert(sizeof(RawAttrDefEntry) == 160, "RawAttrDefEntry must be exactly 160 bytes");

struct AttrDefEntryInfo {
    std::wstring name;
    uint32_t type_code{0};
    uint32_t display_rule{0};
    uint32_t collation_rule{0};
    std::wstring collation_name;
    uint32_t flags{0};
    bool is_indexable{false};
    bool allows_multiple{false};
    bool not_resident{false};
    uint64_t min_size{0};
    uint64_t max_size{0};
    bool is_custom{false};
};

struct AttrDefReport {
    bool valid{false};
    wchar_t volume_letter{L'C'};
    uint64_t record_frn{4};
    size_t total_definitions{0};
    size_t standard_types_count{0};
    size_t custom_types_count{0};
    size_t indexable_count{0};
    size_t multiple_count{0};
    std::vector<AttrDefEntryInfo> entries;
};

class AttrDefAnalyzer {
public:
    static AttrDefReport parse_from_buffer(const uint8_t* data, size_t size, wchar_t drive_letter = L'C');
    static Result<AttrDefReport> inspect(VolumeReader& volume);

    static std::wstring collation_rule_to_string(uint32_t rule);
    static std::wstring flags_to_string(uint32_t flags);
    static bool is_standard_type(uint32_t type_code);
    static void print_report(const AttrDefReport& report);
};

} // namespace mftscan
