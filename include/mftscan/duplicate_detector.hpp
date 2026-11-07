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

struct DuplicateGroup {
    uint64_t file_size{0};
    uint64_t wasted_bytes{0};
    std::vector<std::wstring> paths;
};

struct DuplicateReport {
    uint64_t total_duplicate_files{0};
    uint64_t total_wasted_bytes{0};
    std::vector<DuplicateGroup> groups;
};

class DuplicateDetector {
public:
    static DuplicateReport find_duplicates(
        const std::vector<RecordInfo>& records,
        uint64_t min_file_size = 1024,
        size_t max_groups = 50
    );

private:
    static uint64_t compute_file_partial_hash(const std::wstring& path) noexcept;
    static uint64_t compute_file_full_hash(const std::wstring& path) noexcept;
};

} // namespace mftscan