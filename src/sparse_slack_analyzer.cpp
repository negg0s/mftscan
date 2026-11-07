#include "mftscan/sparse_slack_analyzer.hpp"

#include <algorithm>

namespace mftscan {

SlackSpaceReport SparseSlackAnalyzer::analyze_slack(
    const std::vector<RecordInfo>& records,
    size_t limit
) {
    SlackSpaceReport report;
    std::vector<RecordInfo> slack_candidates;

    for (const auto& r : records) {
        if (!r.is_directory && !r.is_deleted && r.slack_bytes > 0) {
            report.total_slack_bytes += r.slack_bytes;
            report.total_files_with_slack++;
            slack_candidates.push_back(r);
        }
    }

    std::sort(
        slack_candidates.begin(),
        slack_candidates.end(),
        [](const RecordInfo& a, const RecordInfo& b) {
            return a.slack_bytes > b.slack_bytes;
        }
    );

    if (slack_candidates.size() > limit) {
        slack_candidates.resize(limit);
    }

    report.top_slack_files = std::move(slack_candidates);
    return report;
}

CompressionReport SparseSlackAnalyzer::analyze_compression(
    const std::vector<RecordInfo>& records,
    size_t limit
) {
    CompressionReport report;
    std::vector<RecordInfo> comp_candidates;
    std::vector<RecordInfo> sparse_candidates;

    for (const auto& r : records) {
        if (r.is_directory || r.is_deleted) {
            continue;
        }

        if (r.is_compressed) {
            report.compressed_file_count++;
            report.compressed_logical_bytes += r.size_bytes;
            report.compressed_allocated_bytes += r.allocated_bytes;
            if (r.size_bytes > r.allocated_bytes) {
                report.compressed_saved_bytes += (r.size_bytes - r.allocated_bytes);
            }
            comp_candidates.push_back(r);
        }

        if (r.is_sparse) {
            report.sparse_file_count++;
            report.sparse_logical_bytes += r.size_bytes;
            report.sparse_allocated_bytes += r.allocated_bytes;
            if (r.size_bytes > r.allocated_bytes) {
                report.sparse_saved_bytes += (r.size_bytes - r.allocated_bytes);
            }
            sparse_candidates.push_back(r);
        }
    }

    std::sort(
        comp_candidates.begin(),
        comp_candidates.end(),
        [](const RecordInfo& a, const RecordInfo& b) {
            return a.size_bytes > b.size_bytes;
        }
    );
    if (comp_candidates.size() > limit) {
        comp_candidates.resize(limit);
    }
    report.top_compressed_files = std::move(comp_candidates);

    std::sort(
        sparse_candidates.begin(),
        sparse_candidates.end(),
        [](const RecordInfo& a, const RecordInfo& b) {
            return a.size_bytes > b.size_bytes;
        }
    );
    if (sparse_candidates.size() > limit) {
        sparse_candidates.resize(limit);
    }
    report.top_sparse_files = std::move(sparse_candidates);

    return report;
}

} // namespace mftscan