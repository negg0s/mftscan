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

struct SizeBucket {
    std::wstring label;
    uint64_t count{0};
    uint64_t total_bytes{0};
};

struct DensityReport {
    uint64_t total_records{0};
    uint64_t active_files{0};
    uint64_t active_directories{0};
    uint64_t resident_files{0};
    uint64_t non_resident_files{0};
    uint64_t zero_byte_files{0};

    uint64_t total_logical_bytes{0};
    uint64_t total_allocated_bytes{0};
    uint64_t total_slack_bytes{0};
    uint64_t total_resident_bytes{0};

    uint64_t cluster_slack_saved_bytes{0};
    double resident_file_percentage{0.0};
    double space_efficiency_ratio{0.0};
    double average_file_slack_bytes{0.0};

    std::vector<SizeBucket> buckets;
};

class DensityAnalyzer {
public:
    static DensityReport analyze(
        const std::vector<RecordInfo>& records,
        uint32_t cluster_size = 4096
    );

    static void print_report(const DensityReport& report);
};

} // namespace mftscan
