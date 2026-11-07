#include "mftscan/inlining.hpp"
#include "mftscan/formatter.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

InliningReport InliningAdvisor::analyze(
    const std::vector<RecordInfo>& records,
    uint32_t cluster_size,
    size_t top_limit
) {
    InliningReport report{};
    report.cluster_size = cluster_size;

    std::vector<const RecordInfo*> candidate_ptrs;

    for (const auto& rec : records) {
        if (rec.is_deleted || rec.is_directory || rec.record_index < 16) {
            continue;
        }

        ++report.total_files_analyzed;

        if (rec.is_resident) {
            ++report.already_resident_count;
            report.already_resident_payload_bytes += rec.size_bytes;
        } else {
            // Non-resident file: check if size could fit residently in MFT record (<= 700 bytes)
            if (rec.size_bytes > 0 && rec.size_bytes <= 700 && !rec.is_compressed && !rec.is_sparse) {
                candidate_ptrs.push_back(&rec);
            }
        }
    }

    report.inlining_candidates_count = candidate_ptrs.size();
    report.reclaimable_bytes = static_cast<uint64_t>(report.inlining_candidates_count) * cluster_size;

    if (report.total_files_analyzed > 0) {
        report.current_resident_ratio = (static_cast<double>(report.already_resident_count) /
                                         static_cast<double>(report.total_files_analyzed)) * 100.0;
        report.potential_resident_ratio = (static_cast<double>(report.already_resident_count + report.inlining_candidates_count) /
                                           static_cast<double>(report.total_files_analyzed)) * 100.0;
    }

    // Sort candidates by size ascending (smallest files waste the highest percentage)
    std::sort(candidate_ptrs.begin(), candidate_ptrs.end(), [](const RecordInfo* a, const RecordInfo* b) {
        return a->size_bytes < b->size_bytes;
    });

    const size_t take_count = std::min(top_limit, candidate_ptrs.size());
    report.candidates.reserve(take_count);

    for (size_t i = 0; i < take_count; ++i) {
        const auto* rec = candidate_ptrs[i];
        InliningCandidate cand{};
        cand.frn = rec->record_index;
        cand.name = rec->name;
        cand.full_path = rec->full_path.empty() ? rec->name : rec->full_path;
        cand.size_bytes = rec->size_bytes;
        cand.wasted_bytes = (cluster_size > rec->size_bytes) ? (cluster_size - rec->size_bytes) : 0;
        if (rec->size_bytes > 0) {
            cand.overhead_percentage = (static_cast<double>(cand.wasted_bytes) / static_cast<double>(cluster_size)) * 100.0;
        }
        report.candidates.push_back(std::move(cand));
    }

    return report;
}

void InliningAdvisor::print_report(const InliningReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS RESIDENT STREAM INLINING AND STORAGE COMPACTNESS AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Files Evaluated      : " << report.total_files_analyzed << L"\n";
    std::wcout << L"  Already Resident     : " << report.already_resident_count << L" files (" << Formatter::format_bytes(report.already_resident_payload_bytes) << L" inlined in MFT)\n";
    std::wcout << L"  Current Inlining Rate: " << std::fixed << std::setprecision(2) << report.current_resident_ratio << L"%\n";
    std::wcout << L"  Inlining Candidates  : " << report.inlining_candidates_count << L" non-resident files (size <= 700 bytes)\n";
    std::wcout << L"  Reclaimable Space    : " << Formatter::format_bytes(report.reclaimable_bytes) << L" (" << report.inlining_candidates_count << L" disk clusters)\n";
    std::wcout << L"  Potential Inlining   : " << std::fixed << std::setprecision(2) << report.potential_resident_ratio << L"%\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.candidates.empty()) {
        std::wcout << L"  Zero inlining candidates found. All small files are already resident in MFT records.\n";
    } else {
        std::wcout << L" TOP SMALL NON-RESIDENT FILES WASTING DISK CLUSTERS (<= 700 BYTES)\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::right
                   << std::setw(10) << L"Size"
                   << std::setw(12) << L"Cluster"
                   << std::setw(12) << L"Wasted"
                   << std::setw(10) << L"Overhead"
                   << L"  "
                   << std::left
                   << L"Path\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        for (const auto& c : report.candidates) {
            std::wcout << std::left
                       << std::setw(12) << c.frn
                       << std::right
                       << std::setw(10) << (std::to_wstring(c.size_bytes) + L" B")
                       << std::setw(12) << (std::to_wstring(report.cluster_size) + L" B")
                       << std::setw(12) << (std::to_wstring(c.wasted_bytes) + L" B")
                       << std::setw(9) << std::fixed << std::setprecision(1) << c.overhead_percentage << L"%"
                       << L"  "
                       << std::left
                       << c.full_path << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
