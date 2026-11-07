#include "mftscan/quota.hpp"
#include "mftscan/formatter.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

namespace mftscan {

QuotaReport QuotaAnalyzer::analyze(const std::vector<RecordInfo>& records) {
    QuotaReport report;

    struct OwnerAccumulator {
        uint64_t file_count{0};
        uint64_t total_logical{0};
        uint64_t total_charged{0};
    };

    std::map<uint32_t, OwnerAccumulator> map_owners;

    for (const auto& r : records) {
        if (r.is_deleted || r.is_directory) {
            continue;
        }

        report.total_files_analyzed++;
        report.total_quota_charged_bytes += r.quota_charged;

        if (r.quota_charged == 0 && r.size_bytes > 0) {
            report.uncharged_files_count++;
        }

        auto& acc = map_owners[r.owner_id];
        acc.file_count++;
        acc.total_logical += r.size_bytes;
        acc.total_charged += r.quota_charged;
    }

    auto get_owner_description = [](uint32_t id) -> std::wstring {
        switch (id) {
            case 0: return L"System / Default (Unassigned)";
            case 1: return L"Administrators Group";
            case 2: return L"Local Users / Authenticated";
            default: {
                std::wostringstream oss;
                oss << L"Account Security ID 0x" << std::hex << std::uppercase << id;
                return oss.str();
            }
        }
    };

    for (const auto& [id, acc] : map_owners) {
        OwnerQuotaUsage usage;
        usage.owner_id = id;
        usage.file_count = acc.file_count;
        usage.total_logical_bytes = acc.total_logical;
        usage.total_quota_charged = acc.total_charged;
        usage.description = get_owner_description(id);
        report.owners.push_back(std::move(usage));
    }

    std::sort(report.owners.begin(), report.owners.end(), [](const OwnerQuotaUsage& a, const OwnerQuotaUsage& b) {
        if (a.total_quota_charged != b.total_quota_charged) {
            return a.total_quota_charged > b.total_quota_charged;
        }
        return a.total_logical_bytes > b.total_logical_bytes;
    });

    return report;
}

void QuotaAnalyzer::print_report(const QuotaReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS DISK QUOTA CONSUMPTION AND OWNER ALLOCATION AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Analyzed Files       : " << report.total_files_analyzed << L"\n";
    std::wcout << L"  Total Quota Charged  : " << Formatter::format_bytes(report.total_quota_charged_bytes) << L"\n";
    std::wcout << L"  Uncharged Files      : " << report.uncharged_files_count << L" (records with 0 quota charged)\n";
    std::wcout << L"  Distinct Owners      : " << report.owners.size() << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(12) << L"Owner ID"
               << std::setw(32) << L"Account / Role"
               << std::right
               << std::setw(12) << L"Files"
               << std::setw(16) << L"Quota Charged"
               << std::setw(16) << L"Logical Size"
               << std::setw(10) << L"Share\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& o : report.owners) {
        double share = 0.0;
        if (report.total_quota_charged_bytes > 0) {
            share = (static_cast<double>(o.total_quota_charged) / static_cast<double>(report.total_quota_charged_bytes)) * 100.0;
        }

        std::wcout << std::left
                   << L"0x" << std::hex << std::setw(10) << std::uppercase << o.owner_id << std::dec
                   << std::setw(32) << o.description
                   << std::right
                   << std::setw(12) << o.file_count
                   << std::setw(16) << Formatter::format_bytes(o.total_quota_charged)
                   << std::setw(16) << Formatter::format_bytes(o.total_logical_bytes)
                   << std::setw(9) << std::fixed << std::setprecision(1) << share << L"%\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
