#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <string>
#include <vector>

namespace mftscan {

struct ExtensionStat {
    std::wstring extension;
    uint64_t count{0};
    uint64_t total_bytes{0};
};

struct DirectoryUsage {
    std::wstring path;
    uint64_t file_count{0};
    uint64_t total_bytes{0};
};

class DiskUsageAnalyzer {
public:
    static std::vector<RecordInfo> top_largest_files(
        const std::vector<RecordInfo>& records,
        size_t limit = 20
    );

    static std::vector<ExtensionStat> compute_extension_histogram(
        const std::vector<RecordInfo>& records,
        size_t limit = 20
    );

    static std::vector<DirectoryUsage> compute_top_directories(
        const std::vector<RecordInfo>& records,
        size_t limit = 20
    );
};

} // namespace mftscan