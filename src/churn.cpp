#include "mftscan/churn.hpp"
#include "mftscan/formatter.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>

namespace mftscan {

ChurnReport ChurnAnalyzer::analyze(const std::vector<RecordInfo>& records, size_t top_limit) {
    ChurnReport report{};
    report.total_records_evaluated = records.size();

    if (records.empty()) {
        report.min_sequence = 0;
        return report;
    }

    uint64_t sum_sequence = 0;
    size_t valid_records_count = 0;

    std::vector<const RecordInfo*> sorted_ptrs;
    sorted_ptrs.reserve(records.size());

    for (const auto& rec : records) {
        if (rec.is_deleted) {
            ++report.deleted_records;
        } else {
            ++report.active_records;
        }

        const uint16_t seq = rec.sequence_number;
        if (seq == 0) {
            continue;
        }

        ++valid_records_count;
        sum_sequence += seq;

        if (seq < report.min_sequence) {
            report.min_sequence = seq;
        }
        if (seq > report.max_sequence) {
            report.max_sequence = seq;
        }

        if (seq >= 60000) {
            ++report.rollover_risk_count;
        }

        if (seq <= 5) {
            ++report.tier_1_to_5;
        } else if (seq <= 20) {
            ++report.tier_6_to_20;
        } else if (seq <= 50) {
            ++report.tier_21_to_50;
        } else if (seq <= 100) {
            ++report.tier_51_to_100;
        } else if (seq <= 500) {
            ++report.tier_101_to_500;
        } else {
            ++report.tier_above_500;
        }

        sorted_ptrs.push_back(&rec);
    }

    if (valid_records_count > 0) {
        report.avg_sequence = static_cast<double>(sum_sequence) / static_cast<double>(valid_records_count);
    } else {
        report.min_sequence = 0;
    }

    std::sort(sorted_ptrs.begin(), sorted_ptrs.end(), [](const RecordInfo* a, const RecordInfo* b) {
        return a->sequence_number > b->sequence_number;
    });

    const size_t take_count = std::min(top_limit, sorted_ptrs.size());
    report.top_churn_records.reserve(take_count);

    for (size_t i = 0; i < take_count; ++i) {
        const auto* rec = sorted_ptrs[i];
        ChurnEntry entry{};
        entry.frn = rec->record_index;
        entry.sequence_number = rec->sequence_number;
        entry.path = rec->full_path.empty() ? rec->name : rec->full_path;
        entry.file_size = rec->size_bytes;
        entry.is_directory = rec->is_directory;
        entry.is_deleted = rec->is_deleted;
        report.top_churn_records.push_back(std::move(entry));
    }

    return report;
}

void ChurnAnalyzer::print_report(const ChurnReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS RECORD SEQUENCE NUMBER AND CHURN AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Records Evaluated    : " << report.total_records_evaluated << L"\n";
    std::wcout << L"  Active Records       : " << report.active_records << L"\n";
    std::wcout << L"  Deleted Records      : " << report.deleted_records << L"\n";
    std::wcout << L"  Min Sequence Number  : " << report.min_sequence << L"\n";
    std::wcout << L"  Max Sequence Number  : " << report.max_sequence << L"\n";
    std::wcout << L"  Avg Sequence Number  : " << std::fixed << std::setprecision(2) << report.avg_sequence << L"\n";
    std::wcout << L"  Rollover Risk Files  : " << report.rollover_risk_count << L" (sequence >= 60000)\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << L" SEQUENCE DISTRIBUTION HISTOGRAM\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << L"  Tier 1-5   (Long-lived / Initial) : " << report.tier_1_to_5 << L"\n";
    std::wcout << L"  Tier 6-20  (Moderate Churn)       : " << report.tier_6_to_20 << L"\n";
    std::wcout << L"  Tier 21-50 (Elevated Churn)       : " << report.tier_21_to_50 << L"\n";
    std::wcout << L"  Tier 51-100(High Churn)           : " << report.tier_51_to_100 << L"\n";
    std::wcout << L"  Tier 101-500 (Severe Churn)       : " << report.tier_101_to_500 << L"\n";
    std::wcout << L"  Tier >500  (Hyper Churn Hotspots) : " << report.tier_above_500 << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << L" TOP HIGHEST CHURN RECORDS (REUSED FILE SLOTS)\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(12) << L"FRN"
               << std::setw(12) << L"Sequence"
               << std::setw(10) << L"Type"
               << std::right
               << std::setw(14) << L"Size"
               << L"  "
               << std::left
               << L"Path\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& entry : report.top_churn_records) {
        std::wstring type_str;
        if (entry.is_deleted) {
            type_str = L"DELETED";
        } else if (entry.is_directory) {
            type_str = L"DIR";
        } else {
            type_str = L"FILE";
        }

        std::wcout << std::left
                   << std::setw(12) << entry.frn
                   << std::setw(12) << entry.sequence_number
                   << std::setw(10) << type_str
                   << std::right
                   << std::setw(14) << Formatter::format_bytes(entry.file_size)
                   << L"  "
                   << std::left
                   << entry.path << L"\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
