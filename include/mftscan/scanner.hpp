#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/path_builder.hpp"
#include "mftscan/query.hpp"
#include "mftscan/volume.hpp"

#include <functional>
#include <vector>

namespace mftscan {

class VolumeScanner {
public:
    explicit VolumeScanner(wchar_t drive_letter);

    using ProgressCallback = std::function<void(uint64_t records_scanned, uint64_t total_estimate)>;

    Result<std::vector<RecordInfo>> scan(
        const QueryFilter& filter,
        ProgressCallback on_progress = nullptr
    );

    Result<std::vector<RecordInfo>> scan_fallback_win32(
        const std::wstring& root_path,
        const QueryFilter& filter
    );

    const ScanStats& stats() const noexcept { return stats_; }
    const VolumeGeometry& geometry() const noexcept { return reader_.geometry(); }

private:
    wchar_t drive_letter_{L'C'};
    VolumeReader reader_;
    PathBuilder path_builder_;
    ScanStats stats_;
};

} // namespace mftscan