#include "mftscan/formatter.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

namespace mftscan {

std::wstring Formatter::format_bytes(uint64_t bytes) {
    static const wchar_t* const kUnits[] = { L"B", L"KB", L"MB", L"GB", L"TB", L"PB" };
    int unit_idx = 0;
    double d_bytes = static_cast<double>(bytes);

    while (d_bytes >= 1024.0 && unit_idx < 5) {
        d_bytes /= 1024.0;
        unit_idx++;
    }

    std::wostringstream oss;
    oss << std::fixed << std::setprecision((unit_idx == 0) ? 0 : 2) << d_bytes << L" " << kUnits[unit_idx];
    return oss.str();
}

std::wstring Formatter::format_filetime(uint64_t ft) {
    if (ft == 0) {
        return L"-";
    }

    FILETIME win_ft;
    win_ft.dwLowDateTime = static_cast<DWORD>(ft & 0xFFFFFFFF);
    win_ft.dwHighDateTime = static_cast<DWORD>((ft >> 32) & 0xFFFFFFFF);

    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&win_ft, &st)) {
        return L"-";
    }

    wchar_t buf[64] = { 0 };
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::wstring(buf);
}

void Formatter::print_banner() {
    std::wcout << L"===============================================================\n";
    std::wcout << L" mftscan: Fast NTFS Master File Table Scanner & Disk Analyzer\n";
    std::wcout << L"===============================================================\n\n";
}

void Formatter::print_scan_summary(const ScanStats& stats, const VolumeGeometry& geom) {
    std::wcout << L"[Volume " << geom.volume_letter << L": Summary]\n";
    std::wcout << L"  Total Records Scanned : " << stats.total_records_read << L"\n";
    std::wcout << L"  Active Files          : " << stats.active_files << L"\n";
    std::wcout << L"  Active Directories    : " << stats.active_directories << L"\n";
    std::wcout << L"  Deleted Records Found : " << stats.deleted_records_found << L"\n";
    std::wcout << L"  Matches Found         : " << stats.matched_records << L"\n";
    std::wcout << L"  Total Matched Size    : " << format_bytes(stats.total_bytes_matched) << L"\n";
    std::wcout << L"  Scan Duration         : " << std::fixed << std::setprecision(2) << stats.scan_duration_ms << L" ms\n";
    if (stats.read_throughput_mbs > 0.0) {
        std::wcout << L"  Throughput            : " << std::fixed << std::setprecision(1) << stats.read_throughput_mbs << L" MB/s\n";
    }
    std::wcout << L"\n";
}

void Formatter::print_results_table(const std::vector<RecordInfo>& records, size_t max_display) {
    if (records.empty()) {
        std::wcout << L"No matching files or directories found.\n";
        return;
    }

    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(12) << L"Record"
               << std::setw(8)  << L"Type"
               << std::setw(14) << L"Size"
               << std::setw(22) << L"Modified"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    const size_t to_print = (std::min)(records.size(), max_display);
    for (size_t i = 0; i < to_print; ++i) {
        const auto& r = records[i];
        std::wstring type_str;
        if (r.is_deleted) {
            type_str = L"[DEL]";
        } else if (r.is_directory) {
            type_str = L"<DIR>";
        } else {
            type_str = L"FILE";
        }

        std::wcout << std::left
                   << std::setw(12) << r.record_index
                   << std::setw(8)  << type_str
                   << std::setw(14) << (r.is_directory ? L"-" : format_bytes(r.size_bytes))
                   << std::setw(22) << format_filetime(r.modification_time)
                   << r.full_path << L"\n";
    }

    if (records.size() > max_display) {
        std::wcout << L"... and " << (records.size() - max_display) << L" more entries (use --limit to adjust).\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_top_files_table(const std::vector<RecordInfo>& records) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Top Largest Files\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(6)  << L"#"
               << std::setw(16) << L"Size"
               << std::setw(22) << L"Modified"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (size_t i = 0; i < records.size(); ++i) {
        const auto& r = records[i];
        std::wcout << std::left
                   << std::setw(6)  << (i + 1)
                   << std::setw(16) << format_bytes(r.size_bytes)
                   << std::setw(22) << format_filetime(r.modification_time)
                   << r.full_path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_top_directories_table(const std::vector<DirectoryUsage>& dirs) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Directory Space Consumption\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(6)  << L"#"
               << std::setw(16) << L"Total Size"
               << std::setw(12) << L"Files"
               << L"Directory\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (size_t i = 0; i < dirs.size(); ++i) {
        const auto& d = dirs[i];
        std::wcout << std::left
                   << std::setw(6)  << (i + 1)
                   << std::setw(16) << format_bytes(d.total_bytes)
                   << std::setw(12) << d.file_count
                   << d.path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_extension_histogram_table(const std::vector<ExtensionStat>& stats) {
    std::wcout << L"------------------------------------------------------------------------\n";
    std::wcout << L" File Type Breakdown\n";
    std::wcout << L"------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(14) << L"Extension"
               << std::setw(12) << L"File Count"
               << L"Total Size\n";
    std::wcout << L"------------------------------------------------------------------------\n";

    for (const auto& s : stats) {
        std::wcout << std::left
                   << std::setw(14) << s.extension
                   << std::setw(12) << s.count
                   << format_bytes(s.total_bytes) << L"\n";
    }
    std::wcout << L"------------------------------------------------------------------------\n\n";
}

void Formatter::print_duplicates_table(const DuplicateReport& report) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Duplicate Files Report | Found: " << report.total_duplicate_files
               << L" files | Reclaimable Space: " << format_bytes(report.total_wasted_bytes) << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    if (report.groups.empty()) {
        std::wcout << L"No duplicate files detected with current threshold.\n\n";
        return;
    }

    for (size_t i = 0; i < report.groups.size(); ++i) {
        const auto& g = report.groups[i];
        std::wcout << L"Group #" << (i + 1) << L" (" << g.paths.size() << L" copies, "
                   << format_bytes(g.file_size) << L" each, Wasted: " << format_bytes(g.wasted_bytes) << L"):\n";
        for (const auto& p : g.paths) {
            std::wcout << L"  " << p << L"\n";
        }
        std::wcout << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_usn_change(const UsnChangeRecord& change) {
    std::wcout << L"[" << format_filetime(change.timestamp) << L"] "
               << std::left << std::setw(20) << change.reason_string
               << L" " << change.file_name << L" (USN: " << change.usn << L")\n";
}

static std::string escape_json_string(const std::wstring& ws) {
    std::ostringstream oss;
    for (wchar_t wc : ws) {
        if (wc == L'"') oss << "\\\"";
        else if (wc == L'\\') oss << "\\\\";
        else if (wc == L'\b') oss << "\\b";
        else if (wc == L'\f') oss << "\\f";
        else if (wc == L'\n') oss << "\\n";
        else if (wc == L'\r') oss << "\\r";
        else if (wc == L'\t') oss << "\\t";
        else if (wc >= 32 && wc <= 126) oss << static_cast<char>(wc);
        else {
            oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(wc);
        }
    }
    return oss.str();
}

std::string Formatter::to_json(
    const std::vector<RecordInfo>& records,
    const ScanStats& stats,
    const VolumeGeometry& geom
) {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"volume\": \"" << static_cast<char>(geom.volume_letter) << ":\",\n";
    oss << "  \"stats\": {\n";
    oss << "    \"total_records_scanned\": " << stats.total_records_read << ",\n";
    oss << "    \"active_files\": " << stats.active_files << ",\n";
    oss << "    \"active_directories\": " << stats.active_directories << ",\n";
    oss << "    \"deleted_records\": " << stats.deleted_records_found << ",\n";
    oss << "    \"matches\": " << stats.matched_records << ",\n";
    oss << "    \"total_bytes_matched\": " << stats.total_bytes_matched << ",\n";
    oss << "    \"duration_ms\": " << std::fixed << std::setprecision(2) << stats.scan_duration_ms << "\n";
    oss << "  },\n";
    oss << "  \"records\": [\n";

    for (size_t i = 0; i < records.size(); ++i) {
        const auto& r = records[i];
        oss << "    {\n";
        oss << "      \"record_index\": " << r.record_index << ",\n";
        oss << "      \"name\": \"" << escape_json_string(r.name) << "\",\n";
        oss << "      \"path\": \"" << escape_json_string(r.full_path) << "\",\n";
        oss << "      \"size_bytes\": " << r.size_bytes << ",\n";
        oss << "      \"is_directory\": " << (r.is_directory ? "true" : "false") << ",\n";
        oss << "      \"is_deleted\": " << (r.is_deleted ? "true" : "false") << ",\n";
        oss << "      \"has_ads\": " << (r.has_ads ? "true" : "false") << ",\n";
        oss << "      \"modified_filetime\": " << r.modification_time << "\n";
        oss << "    }" << (i + 1 < records.size() ? "," : "") << "\n";
    }

    oss << "  ]\n";
    oss << "}\n";
    return oss.str();
}

std::string Formatter::to_csv(const std::vector<RecordInfo>& records) {
    std::ostringstream oss;
    oss << "RecordIndex,Type,SizeBytes,ModifiedFileTime,Path\n";

    for (const auto& r : records) {
        oss << r.record_index << ",";
        if (r.is_deleted) oss << "DELETED,";
        else if (r.is_directory) oss << "DIRECTORY,";
        else oss << "FILE,";

        oss << r.size_bytes << "," << r.modification_time << ",";

        std::string path_utf8;
        for (wchar_t wc : r.full_path) {
            if (wc >= 32 && wc <= 126) path_utf8.push_back(static_cast<char>(wc));
            else path_utf8.push_back('?');
        }

        oss << "\"" << path_utf8 << "\"\n";
    }

    return oss.str();
}

} // namespace mftscan