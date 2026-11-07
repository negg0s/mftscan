#include "mftscan/unallocated_analyzer.hpp"
#include "mftscan/formatter.hpp"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

static std::wstring extract_ext(const std::wstring& name) {
    size_t dot_pos = name.rfind(L'.');
    if (dot_pos == std::wstring::npos || dot_pos == 0 || dot_pos == name.size() - 1) {
        return L"(no ext)";
    }
    std::wstring ext = name.substr(dot_pos + 1);
    for (auto& c : ext) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return ext;
}

UnallocatedReport UnallocatedAnalyzer::analyze(
    const std::vector<RecordInfo>& records,
    size_t top_limit
) {
    UnallocatedReport report{};
    report.total_records = records.size();

    std::vector<DeletedFileCandidate> candidates;
    std::vector<DeletedSpan> all_spans;

    bool in_deleted_span = false;
    uint64_t current_span_start = 0;
    uint64_t current_span_count = 0;

    for (const auto& rec : records) {
        if (rec.is_deleted) {
            ++report.unallocated_records;

            if (!in_deleted_span) {
                in_deleted_span = true;
                current_span_start = rec.record_index;
                current_span_count = 1;
            } else {
                ++current_span_count;
            }

            if (!rec.name.empty()) {
                ++report.recoverable_with_name;

                std::wstring ext = extract_ext(rec.name);
                report.extension_breakdown[ext]++;

                if (rec.size_bytes > 0) {
                    report.recoverable_payload_bytes += rec.size_bytes;
                    if (rec.is_resident) {
                        ++report.recoverable_resident;
                    } else {
                        ++report.recoverable_non_resident;
                    }

                    DeletedFileCandidate cand{};
                    cand.frn = rec.record_index;
                    cand.name = rec.name;
                    cand.extension = ext;
                    cand.size_bytes = rec.size_bytes;
                    cand.allocated_bytes = rec.allocated_bytes;
                    cand.is_resident = rec.is_resident;
                    cand.creation_time = rec.creation_time;
                    cand.modification_time = rec.modification_time;
                    cand.sequence_number = rec.sequence_number;
                    candidates.push_back(std::move(cand));
                }
            }
        } else {
            ++report.allocated_records;
            if (in_deleted_span) {
                in_deleted_span = false;
                DeletedSpan span{};
                span.start_frn = current_span_start;
                span.end_frn = current_span_start + current_span_count - 1;
                span.record_count = current_span_count;
                all_spans.push_back(span);
                if (current_span_count > report.max_contiguous_deleted_records) {
                    report.max_contiguous_deleted_records = current_span_count;
                }
            }
        }
    }

    if (in_deleted_span) {
        DeletedSpan span{};
        span.start_frn = current_span_start;
        span.end_frn = current_span_start + current_span_count - 1;
        span.record_count = current_span_count;
        all_spans.push_back(span);
        if (current_span_count > report.max_contiguous_deleted_records) {
            report.max_contiguous_deleted_records = current_span_count;
        }
    }

    report.contiguous_deleted_spans_count = all_spans.size();

    if (report.total_records > 0) {
        report.unallocated_percentage = (static_cast<double>(report.unallocated_records) /
                                         static_cast<double>(report.total_records)) * 100.0;
    }

    // Sort spans by record count descending
    std::sort(all_spans.begin(), all_spans.end(), [](const DeletedSpan& a, const DeletedSpan& b) {
        return a.record_count > b.record_count;
    });

    const size_t span_take = std::min(size_t{5}, all_spans.size());
    report.top_deleted_spans.assign(all_spans.begin(), all_spans.begin() + span_take);

    // Sort candidate files by size descending
    std::sort(candidates.begin(), candidates.end(), [](const DeletedFileCandidate& a, const DeletedFileCandidate& b) {
        return a.size_bytes > b.size_bytes;
    });

    const size_t file_take = std::min(top_limit, candidates.size());
    report.top_recoverable_files.assign(candidates.begin(), candidates.begin() + file_take);

    return report;
}

void UnallocatedAnalyzer::print_report(const UnallocatedReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS UNALLOCATED MFT RECORDS AND DELETED CARVING TARGET AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Total MFT Records    : " << report.total_records << L"\n";
    std::wcout << L"  Allocated Records    : " << report.allocated_records << L"\n";
    std::wcout << L"  Unallocated Records  : " << report.unallocated_records << L" (" << std::fixed << std::setprecision(2) << report.unallocated_percentage << L"% of MFT)\n";
    std::wcout << L"  Deleted Spans Count  : " << report.contiguous_deleted_spans_count << L" contiguous regions\n";
    std::wcout << L"  Max Contiguous Span  : " << report.max_contiguous_deleted_records << L" records\n";
    std::wcout << L"  Preserved Filenames  : " << report.recoverable_with_name << L" deleted records\n";
    std::wcout << L"  Resident in MFT      : " << report.recoverable_resident << L" files (immune to cluster overwrite)\n";
    std::wcout << L"  Non-Resident Extents : " << report.recoverable_non_resident << L" files\n";
    std::wcout << L"  Recoverable Payload  : " << Formatter::format_bytes(report.recoverable_payload_bytes) << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (!report.top_deleted_spans.empty()) {
        std::wcout << L" LARGEST CONTIGUOUS UNALLOCATED RECORD SPANS (CARVING ZONES)\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
        std::wcout << std::left
                   << std::setw(16) << L"Start FRN"
                   << std::setw(16) << L"End FRN"
                   << std::right
                   << std::setw(16) << L"Record Count"
                   << L"  "
                   << std::left
                   << L"Span Range\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        for (const auto& s : report.top_deleted_spans) {
            std::wcout << std::left
                       << std::setw(16) << s.start_frn
                       << std::setw(16) << s.end_frn
                       << std::right
                       << std::setw(16) << s.record_count
                       << L"  "
                       << std::left
                       << L"[" << s.start_frn << L" .. " << s.end_frn << L"]\n";
        }
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    }

    if (!report.extension_breakdown.empty()) {
        std::wcout << L" DELETED FILES BREAKDOWN BY EXTENSION (TOP RECENTLY REMOVED)\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        std::vector<std::pair<std::wstring, size_t>> sorted_exts(
            report.extension_breakdown.begin(),
            report.extension_breakdown.end()
        );
        std::sort(sorted_exts.begin(), sorted_exts.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });

        const size_t ext_take = std::min(size_t{10}, sorted_exts.size());
        for (size_t i = 0; i < ext_take; ++i) {
            std::wcout << L"  ." << std::left << std::setw(12) << sorted_exts[i].first
                       << L": " << std::right << std::setw(8) << sorted_exts[i].second << L" files\n";
        }
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    }

    if (report.top_recoverable_files.empty()) {
        std::wcout << L"  Zero recoverable unallocated records with intact file streams found.\n";
    } else {
        std::wcout << L" TOP RECOVERABLE DELETED FILES BY PAYLOAD SIZE\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::setw(6)  << L"Seq"
                   << std::right
                   << std::setw(14) << L"Size"
                   << std::setw(12) << L"Storage"
                   << L"  "
                   << std::left
                   << std::setw(22) << L"Modified"
                   << L"Name\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        for (const auto& f : report.top_recoverable_files) {
            std::wcout << std::left
                       << std::setw(12) << f.frn
                       << std::setw(6)  << f.sequence_number
                       << std::right
                       << std::setw(14) << Formatter::format_bytes(f.size_bytes)
                       << std::setw(12) << (f.is_resident ? L"Resident" : L"Clusters")
                       << L"  "
                       << std::left
                       << std::setw(22) << Formatter::format_filetime(f.modification_time)
                       << f.name << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
