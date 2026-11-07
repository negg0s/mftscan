#pragma once

#include "mftscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct InliningCandidate {
    uint64_t frn{0};
    std::wstring name;
    std::wstring full_path;
    uint64_t size_bytes{0};
    uint64_t wasted_bytes{0};
    double overhead_percentage{0.0};
};

struct InliningReport {
    size_t total_files_analyzed{0};
    size_t already_resident_count{0};
    uint64_t already_resident_payload_bytes{0};
    size_t inlining_candidates_count{0};
    uint64_t reclaimable_bytes{0};
    uint32_t cluster_size{4096};
    double current_resident_ratio{0.0};
    double potential_resident_ratio{0.0};

    std::vector<InliningCandidate> candidates;
};

class InliningAdvisor {
public:
    static InliningReport analyze(
        const std::vector<RecordInfo>& records,
        uint32_t cluster_size = 4096,
        size_t top_limit = 25
    );

    static void print_report(const InliningReport& report);
};

} // namespace mftscan
