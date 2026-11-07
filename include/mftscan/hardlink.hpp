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

struct HardLinkGroup {
    uint64_t frn{0};
    uint16_t hard_link_count{0};
    uint64_t size_bytes{0};
    uint64_t allocated_bytes{0};
    uint64_t saved_bytes{0};
    std::wstring primary_path;
    std::vector<std::wstring> names;
};

struct HardLinkReport {
    uint64_t total_multi_link_files{0};
    uint64_t total_link_references{0};
    uint64_t total_space_saved_bytes{0};
    std::vector<HardLinkGroup> groups;
};

class HardLinkTracker {
public:
    static HardLinkReport analyze(const std::vector<RecordInfo>& records);
};

} // namespace mftscan
