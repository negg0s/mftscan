#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct ExtendedAttributeItem {
    std::string name;
    uint8_t flags{0};
    uint16_t value_length{0};
    bool is_need_ea{false};
    bool is_wsl_attribute{false};
    std::string value_preview;
};

struct FileEaReport {
    uint64_t frn{0};
    std::wstring path;
    uint32_t packed_ea_size{0};
    uint16_t need_ea_count{0};
    bool has_wsl_metadata{false};
    std::vector<ExtendedAttributeItem> attributes;
};

class ExtendedAttributesAnalyzer {
public:
    static Result<FileEaReport> parse_ea_stream(
        const uint8_t* ea_data,
        size_t ea_data_size,
        uint64_t frn,
        const std::wstring& path = {}
    );
};

} // namespace mftscan
