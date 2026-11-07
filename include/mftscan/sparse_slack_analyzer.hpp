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

struct SlackSpaceReport {
    uint64_t total_slack_bytes{0};
    uint64_t total_files_with_slack{0};
    std::vector<RecordInfo> top_slack_files;
};

struct CompressionReport {
    uint64_t compressed_file_count{0};
    uint64_t compressed_logical_bytes{0};
    uint64_t compressed_allocated_bytes{0};
    uint64_t compressed_saved_bytes{0};

    uint64_t sparse_file_count{0};
    uint64_t sparse_logical_bytes{0};
    uint64_t sparse_allocated_bytes{0};
    uint64_t sparse_saved_bytes{0};

    std::vector<RecordInfo> top_compressed_files;
    std::vector<RecordInfo> top_sparse_files;
};

class SparseSlackAnalyzer {
public:
    static SlackSpaceReport analyze_slack(
        const std::vector<RecordInfo>& records,
        size_t limit = 20
    );

    static CompressionReport analyze_compression(
        const std::vector<RecordInfo>& records,
        size_t limit = 20
    );
};

} // namespace mftscan