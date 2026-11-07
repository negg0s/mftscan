#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <vector>

namespace mftscan {

struct FragmentationReport {
    uint64_t total_fragmented_files{0};
    uint64_t total_excess_fragments{0};
    uint32_t highest_fragment_count{0};
    std::vector<RecordInfo> most_fragmented_files;
};

class FragmentationAnalyzer {
public:
    static FragmentationReport analyze(
        const std::vector<RecordInfo>& records,
        uint32_t min_fragments = 1,
        size_t limit = 25
    );
};

} // namespace mftscan