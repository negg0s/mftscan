#include "mftscan/extend.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/index_parser.hpp"
#include "mftscan/ntfs_defs.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

std::wstring ExtendAnalyzer::get_subsystem_purpose(const std::wstring& name) {
    if (name == L"$Quota" || name.find(L"Quota") != std::wstring::npos) {
        return L"User and group disk quota enforcement ($Q index)";
    }
    if (name == L"$ObjId" || name.find(L"ObjId") != std::wstring::npos) {
        return L"Distributed Link Tracking and object identifiers ($O index)";
    }
    if (name == L"$UsnJrnl" || name.find(L"UsnJrnl") != std::wstring::npos) {
        return L"Update Sequence Number change journal ($J and $MAX streams)";
    }
    if (name == L"$Reparse" || name.find(L"Reparse") != std::wstring::npos) {
        return L"Reparse points and symbolic links lookup index ($R index)";
    }
    if (name == L"$RmMetadata" || name.find(L"RmMetadata") != std::wstring::npos) {
        return L"Transactional NTFS (TxF) resource manager logs";
    }
    if (name == L"$Tops" || name.find(L"Tops") != std::wstring::npos) {
        return L"Transactional operation tracking";
    }
    if (name == L"$TxfLog" || name.find(L"TxfLog") != std::wstring::npos) {
        return L"Common Log File System (CLFS) transaction log";
    }
    return L"Supplementary NTFS metadata extension";
}

ExtendReport ExtendAnalyzer::analyze(
    const std::vector<RecordInfo>& records,
    wchar_t drive_letter
) {
    ExtendReport report{};
    report.volume_letter = drive_letter;
    report.extend_frn = 11;
    report.valid = true;

    for (const auto& rec : records) {
        // Find records whose parent is 11 ($Extend) or record 11 itself
        if (rec.parent_record_index == 11 && rec.record_index != 11) {
            ExtendSubEntry entry{};
            entry.frn = rec.record_index;
            entry.name = rec.name;
            entry.size_bytes = rec.size_bytes;
            entry.allocated_bytes = rec.allocated_bytes;
            entry.is_directory = rec.is_directory;
            entry.purpose = get_subsystem_purpose(rec.name);
            entry.stream_names = rec.ads_names;

            report.total_metadata_bytes += rec.size_bytes;
            report.total_allocated_bytes += rec.allocated_bytes;
            report.subsystems.push_back(std::move(entry));
        }
    }

    report.total_subsystems = report.subsystems.size();
    return report;
}

Result<ExtendReport> ExtendAnalyzer::inspect(
    VolumeReader& volume,
    const std::vector<RecordInfo>& records
) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    auto report = analyze(records, volume.drive_letter());

    // If no records passed, parse $Extend directory index directly via IndexParser
    if (report.subsystems.empty()) {
        auto idx_res = IndexParser::parse_directory_index(volume, 11);
        if (idx_res) {
            for (const auto& item : idx_res.value().entries) {
                ExtendSubEntry entry{};
                entry.frn = item.record_index;
                entry.name = item.name;
                entry.size_bytes = item.real_size;
                entry.allocated_bytes = item.allocated_size;
                entry.is_directory = item.is_directory;
                entry.purpose = get_subsystem_purpose(item.name);

                report.total_metadata_bytes += item.real_size;
                report.total_allocated_bytes += item.allocated_size;
                report.subsystems.push_back(std::move(entry));
            }
            report.total_subsystems = report.subsystems.size();
        }
    }

    return report;
}

void ExtendAnalyzer::print_report(const ExtendReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS EXTENSION DIRECTORY ($Extend) SUBSYSTEM AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Volume Letter        : " << report.volume_letter << L":\n";
    std::wcout << L"  Directory Record     : 11 ($Extend)\n";
    std::wcout << L"  Subsystems Found     : " << report.total_subsystems << L"\n";
    std::wcout << L"  Total Logical Bytes  : " << Formatter::format_bytes(report.total_metadata_bytes) << L"\n";
    std::wcout << L"  Total Allocated Disk : " << Formatter::format_bytes(report.total_allocated_bytes) << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(10) << L"FRN"
               << std::setw(16) << L"Subsystem"
               << std::setw(10) << L"Type"
               << std::right
               << std::setw(14) << L"Size"
               << std::setw(14) << L"Allocated"
               << L"  "
               << std::left
               << L"Description\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& sub : report.subsystems) {
        std::wcout << std::left
                   << std::setw(10) << sub.frn
                   << std::setw(16) << sub.name
                   << std::setw(10) << (sub.is_directory ? L"DIR" : L"FILE")
                   << std::right
                   << std::setw(14) << Formatter::format_bytes(sub.size_bytes)
                   << std::setw(14) << Formatter::format_bytes(sub.allocated_bytes)
                   << L"  "
                   << std::left
                   << sub.purpose << L"\n";

        if (!sub.stream_names.empty()) {
            std::wcout << L"             Streams: ";
            for (size_t s = 0; s < sub.stream_names.size(); ++s) {
                std::wcout << sub.stream_names[s] << (s + 1 < sub.stream_names.size() ? L", " : L"");
            }
            std::wcout << L"\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
