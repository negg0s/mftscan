#include "mftscan/fragmentation_analyzer.hpp"

#include <algorithm>

namespace mftscan {

FragmentationReport FragmentationAnalyzer::analyze(
    const std::vector<RecordInfo>& records,
    uint32_t min_fragments,
    size_t limit
) {
    FragmentationReport report;
    std::vector<RecordInfo> candidates;

    for (const auto& r : records) {
        if (!r.is_directory && !r.is_deleted && r.fragment_count >= min_fragments) {
            report.total_fragmented_files++;
            report.total_excess_fragments += r.fragment_count;
            if (r.fragment_count > report.highest_fragment_count) {
                report.highest_fragment_count = r.fragment_count;
            }
            candidates.push_back(r);
        }
    }

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const RecordInfo& a, const RecordInfo& b) {
            return a.fragment_count > b.fragment_count;
        }
    );

    if (candidates.size() > limit) {
        candidates.resize(limit);
    }

    report.most_fragmented_files = std::move(candidates);
    return report;
}

} // namespace mftscan