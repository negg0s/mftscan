#include "mftscan/object_id.hpp"

#include <cstdio>
#include <cstring>

namespace mftscan {

std::wstring ObjectIdAnalyzer::format_guid(const uint8_t* b) {
    if (!b) {
        return L"";
    }

    const auto* g = reinterpret_cast<const GUID*>(b);
    wchar_t buf[42] = {0};
    swprintf_s(buf, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g->Data1, g->Data2, g->Data3,
        g->Data4[0], g->Data4[1],
        g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    return buf;
}

Result<ObjectIdInfo> ObjectIdAnalyzer::parse_attribute(
    const uint8_t* payload,
    size_t payload_size,
    uint64_t frn,
    const std::wstring& path
) {
    if (!payload || payload_size < 16) {
        return Error(ERROR_INVALID_PARAMETER, L"Payload smaller than 16 bytes for Object ID");
    }

    ObjectIdInfo info;
    info.frn = frn;
    info.path = path;
    info.object_id_str = format_guid(payload);

    auto is_zero = [](const uint8_t* ptr) -> bool {
        for (int i = 0; i < 16; ++i) {
            if (ptr[i] != 0) return false;
        }
        return true;
    };

    if (payload_size >= 48) {
        info.has_birth_data = true;
        info.birth_volume_id_str = format_guid(payload + 16);
        info.birth_object_id_str = format_guid(payload + 32);

        if (payload_size >= 64) {
            info.birth_domain_id_str = format_guid(payload + 48);
        }

        const bool birth_obj_present = !is_zero(payload + 32);
        if (birth_obj_present && memcmp(payload, payload + 32, 16) != 0) {
            info.is_migrated = true;
        }
    }

    return info;
}

} // namespace mftscan
