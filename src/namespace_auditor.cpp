#include "mftscan/namespace_auditor.hpp"
#include "mftscan/formatter.hpp"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

std::wstring NamespaceAuditor::namespace_to_string(uint8_t ns) {
    switch (ns) {
    case 0:  return L"POSIX";
    case 1:  return L"Win32";
    case 2:  return L"DOS";
    case 3:  return L"Win32&DOS";
    default: return L"Unknown(" + std::to_wstring(ns) + L")";
    }
}

bool NamespaceAuditor::is_dos_device_name(const std::wstring& filename) {
    if (filename.empty()) {
        return false;
    }

    // Extract base name before first dot or extension
    size_t dot_pos = filename.find(L'.');
    std::wstring base = (dot_pos == std::wstring::npos) ? filename : filename.substr(0, dot_pos);

    // Convert to uppercase
    for (auto& c : base) {
        c = static_cast<wchar_t>(towupper(c));
    }

    if (base == L"CON" || base == L"PRN" || base == L"AUX" || base == L"NUL") {
        return true;
    }

    if (base.size() == 4) {
        if ((base.rfind(L"COM", 0) == 0 || base.rfind(L"LPT", 0) == 0) &&
            base[3] >= L'1' && base[3] <= L'9') {
            return true;
        }
    }

    return false;
}

bool NamespaceAuditor::has_illegal_win32_chars(const std::wstring& filename) {
    for (wchar_t ch : filename) {
        if (ch == L':' || ch == L'*' || ch == L'?' || ch == L'\"' ||
            ch == L'<' || ch == L'>' || ch == L'|' || static_cast<uint32_t>(ch) < 32) {
            return true;
        }
    }
    return false;
}

NamespaceReport NamespaceAuditor::analyze(const std::vector<RecordInfo>& records) {
    NamespaceReport report{};
    report.total_files_analyzed = records.size();

    for (const auto& rec : records) {
        if (rec.name.empty() || rec.record_index < 16) {
            continue; // Skip root and system metadata files
        }

        bool has_anomaly = false;
        NamespaceAnomalyEntry entry{};
        entry.frn = rec.record_index;
        entry.name = rec.name;
        entry.full_path = rec.full_path.empty() ? rec.name : rec.full_path;
        entry.file_name_namespace = rec.file_name_namespace;
        entry.namespace_name = namespace_to_string(rec.file_name_namespace);
        entry.is_directory = rec.is_directory;
        entry.is_deleted = rec.is_deleted;

        std::wstring desc;

        // 1. POSIX-only namespace check
        if (rec.file_name_namespace == 0 || rec.has_posix_namespace) {
            entry.is_posix_only = true;
            has_anomaly = true;
            ++report.posix_files_count;
            desc += L"POSIX_NAMESPACE ";
        }

        // 2. Trailing dot check
        if (!rec.name.empty() && rec.name.back() == L'.') {
            entry.has_trailing_dot = true;
            has_anomaly = true;
            ++report.trailing_dot_count;
            desc += L"TRAILING_DOT ";
        }

        // 3. Trailing space check
        if (!rec.name.empty() && rec.name.back() == L' ') {
            entry.has_trailing_space = true;
            has_anomaly = true;
            ++report.trailing_space_count;
            desc += L"TRAILING_SPACE ";
        }

        // 4. DOS reserved device names
        if (is_dos_device_name(rec.name)) {
            entry.is_dos_device_name = true;
            has_anomaly = true;
            ++report.dos_device_name_count;
            desc += L"DOS_DEVICE_NAME ";
        }

        // 5. Illegal Win32 characters
        if (has_illegal_win32_chars(rec.name)) {
            entry.has_illegal_chars = true;
            has_anomaly = true;
            ++report.illegal_chars_count;
            desc += L"ILLEGAL_CHARS ";
        }

        if (has_anomaly) {
            if (!desc.empty() && desc.back() == L' ') {
                desc.pop_back();
            }
            entry.anomaly_description = std::move(desc);
            report.anomalies.push_back(std::move(entry));
        }
    }

    report.total_anomalies = report.anomalies.size();
    return report;
}

void NamespaceAuditor::print_report(const NamespaceReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS FILE NAME NAMESPACE AND PATH ANOMALY AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Files Analyzed       : " << report.total_files_analyzed << L"\n";
    std::wcout << L"  Total Anomalies Found: " << report.total_anomalies << L"\n";
    std::wcout << L"  POSIX-Only Files     : " << report.posix_files_count << L" (bypasses Win32 naming rules)\n";
    std::wcout << L"  Trailing Dot Files   : " << report.trailing_dot_count << L" (inaccessible via standard Explorer)\n";
    std::wcout << L"  Trailing Space Files : " << report.trailing_space_count << L" (inaccessible via standard Explorer)\n";
    std::wcout << L"  DOS Device Names     : " << report.dos_device_name_count << L" (CON, NUL, AUX, PRN reserved devices)\n";
    std::wcout << L"  Illegal Win32 Chars  : " << report.illegal_chars_count << L" (contains :, *, ?, <, >, |, or control chars)\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero namespace anomalies detected. All filenames comply with Win32 standards.\n";
    } else {
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::setw(12) << L"Namespace"
                   << std::setw(32) << L"Anomaly Flags"
                   << L"Path\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        const size_t show_count = std::min<size_t>(report.anomalies.size(), 30);
        for (size_t i = 0; i < show_count; ++i) {
            const auto& a = report.anomalies[i];
            std::wcout << std::left
                       << std::setw(12) << a.frn
                       << std::setw(12) << a.namespace_name
                       << std::setw(32) << a.anomaly_description
                       << a.full_path << L"\n";
        }

        if (report.anomalies.size() > show_count) {
            std::wcout << L"  ... and " << (report.anomalies.size() - show_count) << L" more namespace anomaly records.\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
