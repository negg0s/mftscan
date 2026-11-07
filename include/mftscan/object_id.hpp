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

struct ObjectIdInfo {
    uint64_t frn{0};
    std::wstring path;
    std::wstring object_id_str;
    std::wstring birth_volume_id_str;
    std::wstring birth_object_id_str;
    std::wstring birth_domain_id_str;
    bool has_birth_data{false};
    bool is_migrated{false};
};

class ObjectIdAnalyzer {
public:
    static std::wstring format_guid(const uint8_t* guid_bytes);

    static Result<ObjectIdInfo> parse_attribute(
        const uint8_t* payload,
        size_t payload_size,
        uint64_t frn,
        const std::wstring& path = {}
    );
};

} // namespace mftscan
