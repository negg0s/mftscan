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

struct AttributeListEntryInfo {
    uint32_t attribute_type{0};
    std::wstring type_name;
    std::wstring attribute_name;
    uint64_t lowest_vcn{0};
    uint64_t child_record_frn{0};
    uint16_t child_sequence_number{0};
    uint16_t attribute_id{0};
    uint16_t entry_length{0};
};

class AttrListDecoder {
public:
    static std::vector<AttributeListEntryInfo> decode(
        const uint8_t* data,
        size_t size
    );

    static std::wstring format_entry(const AttributeListEntryInfo& entry);
};

} // namespace mftscan
