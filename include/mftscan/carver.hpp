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

struct CarveResult {
    uint64_t frn{0};
    std::wstring stream_name;
    std::wstring output_path;
    uint64_t bytes_written{0};
    uint64_t clusters_read{0};
    bool is_resident{false};
    bool is_deleted_record{false};
    bool success{false};
    std::wstring error_message;
};

struct BatchCarveStats {
    uint64_t attempted{0};
    uint64_t succeeded{0};
    uint64_t failed{0};
    uint64_t total_bytes{0};
};

class FileCarver {
public:
    static Result<CarveResult> carve_record(
        VolumeReader& volume,
        uint64_t frn,
        const std::wstring& output_path,
        const std::wstring& stream_name = L"",
        bool include_slack = false
    );

    static Result<CarveResult> carve_from_buffer(
        HANDLE volume_handle,
        const VolumeGeometry& geometry,
        const uint8_t* record_buffer,
        uint32_t record_size,
        uint64_t frn,
        const std::wstring& output_path,
        const std::wstring& stream_name = L"",
        bool include_slack = false
    );

    static BatchCarveStats carve_deleted_files(
        VolumeReader& volume,
        const std::vector<RecordInfo>& records,
        const std::wstring& output_dir,
        const std::wstring& ext_filter = L"",
        bool include_slack = false
    );

    static std::wstring sanitize_filename(const std::wstring& name);
    static bool ensure_directory_exists(const std::wstring& dir_path);
};

} // namespace mftscan
