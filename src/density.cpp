#include "mftscan/density.hpp"
#include "mftscan/formatter.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>

namespace mftscan {

DensityReport DensityAnalyzer::analyze(
    const std::vector<RecordInfo>& records,
    uint32_t cluster_size
) {
    DensityReport rep;
    rep.total_records = records.size();

    // Initialize 9 standard size buckets
    rep.buckets = {
        { L"0 B (Empty)", 0, 0 },
        { L"1 B - 512 B", 0, 0 },
        { L"513 B - 1 KB", 0, 0 },
        { L"1 KB - 4 KB", 0, 0 },
        { L"4 KB - 64 KB", 0, 0 },
        { L"64 KB - 1 MB", 0, 0 },
        { L"1 MB - 16 MB", 0, 0 },
        { L"16 MB - 256 MB", 0, 0 },
        { L"> 256 MB", 0, 0 }
    };

    auto get_bucket_index = [](uint64_t size) -> size_t {
        if (size == 0) return 0;
        if (size <= 512) return 1;
        if (size <= 1024) return 2;
        if (size <= 4096) return 3;
        if (size <= 65536) return 4;
        if (size <= 1048576) return 5;
        if (size <= 16777216) return 6;
        if (size <= 268435456) return 7;
        return 8;
    };

    for (const auto& rec : records) {
        if (rec.is_deleted) {
            continue;
        }

        if (rec.is_directory) {
            ++rep.active_directories;
            continue;
        }

        ++rep.active_files;
        rep.total_logical_bytes += rec.size_bytes;
        rep.total_allocated_bytes += rec.allocated_bytes;
        rep.total_slack_bytes += rec.slack_bytes;

        const size_t b_idx = get_bucket_index(rec.size_bytes);
        rep.buckets[b_idx].count++;
        rep.buckets[b_idx].total_bytes += rec.size_bytes;

        if (rec.size_bytes == 0) {
            ++rep.zero_byte_files;
        }

        if (rec.is_resident) {
            ++rep.resident_files;
            rep.total_resident_bytes += rec.size_bytes;
            rep.cluster_slack_saved_bytes += cluster_size;
        } else {
            ++rep.non_resident_files;
        }
    }

    const uint64_t total_files = rep.resident_files + rep.non_resident_files;
    if (total_files > 0) {
        rep.resident_file_percentage = (static_cast<double>(rep.resident_files) / static_cast<double>(total_files)) * 100.0;
    }

    if (rep.total_allocated_bytes > 0) {
        rep.space_efficiency_ratio = (static_cast<double>(rep.total_logical_bytes) / static_cast<double>(rep.total_allocated_bytes)) * 100.0;
    }

    if (rep.active_files > 0) {
        rep.average_file_slack_bytes = static_cast<double>(rep.total_slack_bytes) / static_cast<double>(rep.active_files);
    }

    return rep;
}

void DensityAnalyzer::print_report(const DensityReport& report) {
    std::wcout << L"============================================================\n";
    std::wcout << L" NTFS STORAGE DENSITY AND ALLOCATION EFFICIENCY AUDIT\n";
    std::wcout << L"============================================================\n";
    std::wcout << L"  Analyzed Records     : " << report.total_records << L"\n";
    std::wcout << L"  Active Files         : " << report.active_files << L"\n";
    std::wcout << L"  Active Directories   : " << report.active_directories << L"\n";
    std::wcout << L"  Resident Files (MFT) : " << report.resident_files
               << L" (" << std::fixed << std::setprecision(2) << report.resident_file_percentage << L"% of files)\n";
    std::wcout << L"  Non-Resident Files   : " << report.non_resident_files << L"\n";
    std::wcout << L"  Zero-Byte Files      : " << report.zero_byte_files << L"\n";
    std::wcout << L"------------------------------------------------------------\n";
    std::wcout << L"  Total Logical Size   : " << Formatter::format_bytes(report.total_logical_bytes) << L"\n";
    std::wcout << L"  Total Allocated Size : " << Formatter::format_bytes(report.total_allocated_bytes) << L"\n";
    std::wcout << L"  Total Cluster Slack  : " << Formatter::format_bytes(report.total_slack_bytes) << L"\n";
    std::wcout << L"  MFT Resident Payload : " << Formatter::format_bytes(report.total_resident_bytes) << L"\n";
    std::wcout << L"  Cluster Space Saved  : " << Formatter::format_bytes(report.cluster_slack_saved_bytes)
               << L" (via resident MFT inlining)\n";
    std::wcout << L"  Payload Efficiency   : " << std::fixed << std::setprecision(2) << report.space_efficiency_ratio << L"%\n";
    std::wcout << L"  Avg Slack / File     : " << Formatter::format_bytes(static_cast<uint64_t>(report.average_file_slack_bytes)) << L"\n";
    std::wcout << L"------------------------------------------------------------\n";
    std::wcout << L" File Size Distribution Histogram:\n";
    std::wcout << L"  " << std::left << std::setw(18) << L"Size Bucket"
               << std::right << std::setw(12) << L"Files"
               << std::setw(16) << L"Total Size"
               << std::setw(12) << L"Share\n";
    std::wcout << L"  ----------------------------------------------------------\n";

    for (const auto& b : report.buckets) {
        double share = 0.0;
        if (report.active_files > 0) {
            share = (static_cast<double>(b.count) / static_cast<double>(report.active_files)) * 100.0;
        }

        std::wcout << L"  " << std::left << std::setw(18) << b.label
                   << std::right << std::setw(12) << b.count
                   << std::setw(16) << Formatter::format_bytes(b.total_bytes)
                   << std::setw(11) << std::fixed << std::setprecision(1) << share << L"%\n";
    }
    std::wcout << L"============================================================\n";
}

} // namespace mftscan
