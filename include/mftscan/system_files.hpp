#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct SystemFileInfo {
    uint64_t frn{0};
    std::wstring standard_name;
    std::wstring purpose;
    uint64_t size_bytes{0};
    uint64_t allocated_bytes{0};
    uint32_t fragment_count{0};
    bool is_resident{false};
    bool is_present{false};
    std::vector<std::wstring> attribute_types;
    std::wstring extra_info;
};

struct SystemAuditReport {
    wchar_t volume_letter{L'C'};
    uint8_t ntfs_major_version{0};
    uint8_t ntfs_minor_version{0};
    uint16_t volume_flags{0};
    bool is_dirty{false};
    uint64_t bad_clusters_count{0};
    std::vector<SystemFileInfo> files;
};

class SystemFilesInspector {
public:
    static Result<SystemAuditReport> inspect(VolumeReader& volume);

    static const wchar_t* get_standard_system_name(uint64_t frn) noexcept;
    static const wchar_t* get_standard_system_purpose(uint64_t frn) noexcept;
};

} // namespace mftscan
