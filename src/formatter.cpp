#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"

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

void Formatter::print_fragmentation_table(const FragmentationReport& report) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" File Fragmentation Report | Fragmented Files: " << report.total_fragmented_files
               << L" | Excess Fragments: " << report.total_excess_fragments
               << L" | Max Fragments: " << report.highest_fragment_count << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    if (report.most_fragmented_files.empty()) {
        std::wcout << L"No fragmented files found matching criteria.\n\n";
        return;
    }

    std::wcout << std::left
               << std::setw(12) << L"Fragments"
               << std::setw(14) << L"Size"
               << std::setw(16) << L"Allocated"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& r : report.most_fragmented_files) {
        std::wcout << std::left
                   << std::setw(12) << r.fragment_count
                   << std::setw(14) << format_bytes(r.size_bytes)
                   << std::setw(16) << format_bytes(r.allocated_bytes)
                   << r.full_path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_slack_table(const SlackSpaceReport& report) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Cluster Slack Space Report | Files with Slack: " << report.total_files_with_slack
               << L" | Wasted Slack Space: " << format_bytes(report.total_slack_bytes) << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    if (report.top_slack_files.empty()) {
        std::wcout << L"No cluster slack space found.\n\n";
        return;
    }

    std::wcout << std::left
               << std::setw(14) << L"Slack Wasted"
               << std::setw(14) << L"Logical Size"
               << std::setw(16) << L"Allocated"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& r : report.top_slack_files) {
        std::wcout << std::left
                   << std::setw(14) << format_bytes(r.slack_bytes)
                   << std::setw(14) << format_bytes(r.size_bytes)
                   << std::setw(16) << format_bytes(r.allocated_bytes)
                   << r.full_path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_compression_table(const CompressionReport& report) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" NTFS Compression & Sparse Allocation Report\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L"  Compressed Files      : " << report.compressed_file_count << L"\n";
    std::wcout << L"  Compressed Logical    : " << format_bytes(report.compressed_logical_bytes) << L"\n";
    std::wcout << L"  Compressed Physical   : " << format_bytes(report.compressed_allocated_bytes) << L"\n";
    std::wcout << L"  Compressed Savings    : " << format_bytes(report.compressed_saved_bytes) << L"\n\n";

    std::wcout << L"  Sparse Files          : " << report.sparse_file_count << L"\n";
    std::wcout << L"  Sparse Logical        : " << format_bytes(report.sparse_logical_bytes) << L"\n";
    std::wcout << L"  Sparse Physical       : " << format_bytes(report.sparse_allocated_bytes) << L"\n";
    std::wcout << L"  Sparse Savings        : " << format_bytes(report.sparse_saved_bytes) << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_timestomp_table(const TimestompReport& report) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" Timestomp & Timestamp Anomaly Analysis Report\n";
    std::wcout << L" Total Files Scanned: " << report.total_scanned
               << L" | Suspect Records Detected: " << report.anomalies_detected << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    if (report.entries.empty()) {
        std::wcout << L"No timestamp anomalies detected on volume.\n\n";
        return;
    }

    std::wcout << std::left
               << std::setw(10) << L"FRN"
               << std::setw(30) << L"Detected Anomaly"
               << std::setw(22) << L"SI Creation"
               << std::setw(22) << L"FN Creation"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& entry : report.entries) {
        std::wstring anomaly_desc;
        for (size_t i = 0; i < entry.anomalies.size(); ++i) {
            if (i > 0) anomaly_desc += L", ";
            anomaly_desc += TimestompDetector::anomaly_to_string(entry.anomalies[i]);
        }

        std::wstring disp_path = entry.full_path.empty() ? entry.name : entry.full_path;
        std::wcout << std::left
                   << std::setw(10) << entry.record_index
                   << std::setw(30) << (anomaly_desc.size() > 28 ? anomaly_desc.substr(0, 28) : anomaly_desc)
                   << std::setw(22) << format_filetime(entry.si_creation_time)
                   << std::setw(22) << format_filetime(entry.fn_creation_time)
                   << disp_path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_signature_report(const SignatureReport& report) {
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << L" File Signature & Extension Spoofing Report\n";
    std::wcout << L" Total Files Inspected: " << report.total_inspected
               << L" | Mismatches: " << report.mismatches_detected
               << L" | Masquerading Executables: " << report.critical_executables_detected << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    if (report.entries.empty()) {
        std::wcout << L"No extension mismatches or spoofed signatures detected.\n\n";
        return;
    }

    std::wcout << std::left
               << std::setw(10) << L"FRN"
               << std::setw(10) << L"Ext"
               << std::setw(26) << L"Detected Signature"
               << std::setw(14) << L"Size"
               << std::setw(14) << L"Risk"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& e : report.entries) {
        std::wstring risk_str = e.is_executable_masquerading ? L"[CRITICAL PE]" : L"[MISMATCH]";
        std::wstring disp_path = e.full_path.empty() ? e.name : e.full_path;

        std::wcout << std::left
                   << std::setw(10) << e.record_index
                   << std::setw(10) << e.declared_extension
                   << std::setw(26) << e.detected_type_name
                   << std::setw(14) << format_bytes(e.size_bytes)
                   << std::setw(14) << risk_str
                   << disp_path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_security_report(const std::vector<SecurityAuditResult>& results) {
    size_t crit_count = 0;
    size_t high_count = 0;
    size_t med_count = 0;
    size_t low_count = 0;

    for (const auto& r : results) {
        if (r.risk_level == SecurityRiskLevel::Critical) crit_count++;
        else if (r.risk_level == SecurityRiskLevel::High) high_count++;
        else if (r.risk_level == SecurityRiskLevel::Medium) med_count++;
        else if (r.risk_level == SecurityRiskLevel::Low) low_count++;
    }

    std::wcout << L"NTFS Security Descriptor Audit Report\n";
    std::wcout << L"Total audited: " << results.size()
               << L" | Critical: " << crit_count
               << L" | High: " << high_count
               << L" | Medium: " << med_count
               << L" | Low: " << low_count << L"\n\n";

    if (results.empty()) {
        std::wcout << L"No matching files found for security audit.\n\n";
        return;
    }

    std::wcout << std::left
               << std::setw(10) << L"FRN"
               << std::setw(12) << L"Risk"
               << std::setw(24) << L"Owner"
               << std::setw(38) << L"Findings"
               << L"Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& r : results) {
        if (r.risk_level == SecurityRiskLevel::None) {
            continue;
        }

        std::wstring findings_str;
        for (size_t i = 0; i < r.findings.size(); ++i) {
            if (i > 0) findings_str += L"; ";
            findings_str += r.findings[i];
        }
        if (findings_str.size() > 36) {
            findings_str = findings_str.substr(0, 33) + L"...";
        }

        std::wstring owner_str = r.owner;
        if (owner_str.size() > 22) {
            owner_str = owner_str.substr(0, 19) + L"...";
        }

        std::wcout << std::left
                   << std::setw(10) << r.frn
                   << std::setw(12) << SecurityAuditor::risk_to_string(r.risk_level)
                   << std::setw(24) << owner_str
                   << std::setw(38) << findings_str
                   << r.path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_carve_summary(const BatchCarveStats& stats, const std::wstring& out_dir) {
    std::wcout << L"File Carve Summary\n";
    std::wcout << L"------------------------------------------------------------\n";
    std::wcout << L"Output directory: " << out_dir << L"\n";
    std::wcout << L"Attempted:        " << stats.attempted << L"\n";
    std::wcout << L"Succeeded:        " << stats.succeeded << L"\n";
    std::wcout << L"Failed:           " << stats.failed << L"\n";
    std::wcout << L"Total recovered:  " << format_bytes(stats.total_bytes) << L"\n";
    std::wcout << L"------------------------------------------------------------\n\n";
}

void Formatter::print_system_audit_report(const SystemAuditReport& report) {
    std::wcout << L"NTFS System Metadata Files & Volume Integrity Report (Volume " << report.volume_letter << L":)\n";
    std::wcout << L"NTFS Version: v" << static_cast<int>(report.ntfs_major_version) << L"." << static_cast<int>(report.ntfs_minor_version)
               << L" | Volume State: " << (report.is_dirty ? L"[DIRTY / RECOVERY NEEDED]" : L"Clean")
               << L" | Bad Clusters: " << report.bad_clusters_count << L"\n\n";

    std::wcout << std::left
               << std::setw(6)  << L"FRN"
               << std::setw(12) << L"Name"
               << std::setw(12) << L"Size"
               << std::setw(14) << L"Allocated"
               << std::setw(8)  << L"Frags"
               << std::setw(36) << L"Purpose"
               << L"Extra Info\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& f : report.files) {
        std::wstring size_str = f.is_resident ? (format_bytes(f.size_bytes) + L" (R)") : format_bytes(f.size_bytes);
        std::wstring alloc_str = format_bytes(f.allocated_bytes);

        std::wcout << std::left
                   << std::setw(6)  << f.frn
                   << std::setw(12) << f.standard_name
                   << std::setw(12) << size_str
                   << std::setw(14) << alloc_str
                   << std::setw(8)  << f.fragment_count
                   << std::setw(36) << f.purpose
                   << f.extra_info << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_bitmap_report(const BitmapReport& report) {
    std::wcout << L"NTFS Volume Cluster Allocation & Free Space Report (Volume " << report.volume_letter << L":)\n";
    std::wcout << L"--------------------------------------------------------------------------------\n";
    std::wcout << L"Total Clusters:                  " << report.total_clusters
               << L" (" << format_bytes(report.total_clusters * report.bytes_per_cluster) << L")\n";
    std::wcout << L"Used Clusters:                   " << report.used_clusters
               << L" (" << format_bytes(report.used_clusters * report.bytes_per_cluster) << L")\n";
    std::wcout << L"Free Clusters:                   " << report.free_clusters
               << L" (" << format_bytes(report.free_clusters * report.bytes_per_cluster) << L", "
               << std::fixed << std::setprecision(2) << report.free_percent << L"%)\n";
    std::wcout << L"Free Extents (Contiguous runs):  " << report.free_extents_count << L"\n";
    std::wcout << L"Largest Free Contiguous Block:   " << report.largest_free_extent_clusters
               << L" clusters (" << format_bytes(report.largest_free_extent_clusters * report.bytes_per_cluster) << L")\n";
    std::wcout << L"Average Free Block Size:         " << static_cast<uint64_t>(report.avg_free_extent_clusters)
               << L" clusters (" << format_bytes(static_cast<uint64_t>(report.avg_free_extent_clusters * report.bytes_per_cluster)) << L")\n";
    std::wcout << L"Smallest Free Block Size:        " << report.smallest_free_extent_clusters
               << L" clusters (" << format_bytes(report.smallest_free_extent_clusters * report.bytes_per_cluster) << L")\n";
    std::wcout << L"Free Space Fragmentation Index:  " << std::fixed << std::setprecision(2)
               << report.free_space_fragmentation_index << L"%\n";
    std::wcout << L"\nCluster Allocation Map (Width: " << (report.ascii_map.size() >= 2 ? report.ascii_map.size() - 2 : 0) << L" blocks):\n";
    std::wcout << L"  [ # = full (>=99%), + = heavy (>=50%), - = sparse (>0%), . = free (0%) ]\n";
    std::string s = report.ascii_map;
    std::wstring ws(s.begin(), s.end());
    std::wcout << L"  " << ws << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------\n\n";
}

void Formatter::print_logfile_report(const LogFileReport& report) {
    std::wcout << L"NTFS Transaction Journal ($LogFile) Restart Area Report (Volume " << report.volume_letter << L":)\n";
    std::wcout << L"--------------------------------------------------------------------------------\n";
    std::wcout << L"Header Magic:          " << (report.magic == kLogFileMagicRstr ? L"RSTR (Valid Restart Page)" : L"Invalid") << L"\n";
    std::wcout << L"Log Version:           v" << report.major_version << L"." << report.minor_version << L"\n";
    std::wcout << L"System / Log Page:     " << report.system_page_size << L" bytes / " << report.log_page_size << L" bytes\n";
    std::wcout << L"Current LSN:           0x" << std::hex << std::uppercase << report.current_lsn << std::dec << L" (" << report.current_lsn << L")\n";
    std::wcout << L"Active Clients:        " << report.log_clients << L"\n";
    std::wcout << L"Journal File Size:     " << format_bytes(report.file_size) << L" (" << report.file_size << L" bytes)\n";
    std::wcout << L"Log Open Count:        " << report.restart_open_log_count << L"\n";
    std::wcout << L"Shutdown State:        " << (report.is_clean_shutdown ? L"Clean Unmount (0x0002)" : L"Dirty / Pending Recovery") << L"\n";
    std::wcout << L"Status Note:           " << report.extra_notes << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------\n\n";
}

void Formatter::print_boot_sector_report(const BootSectorComparison& comp) {
    const auto& p = comp.primary;
    std::wcout << L"NTFS Boot Sector & BIOS Parameter Block (BPB) Report (Volume " << p.volume_letter << L":)\n";
    std::wcout << L"--------------------------------------------------------------------------------\n";
    std::wcout << L"OEM Identifier:            " << std::wstring(p.oem_id.begin(), p.oem_id.end()) << L"\n";
    std::wcout << L"Signature (0xAA55):        " << (p.signature_valid ? L"Valid (0xAA55)" : L"Invalid") << L"\n";
    std::wcout << L"Bytes per Sector:          " << p.bytes_per_sector << L"\n";
    std::wcout << L"Sectors per Cluster:       " << static_cast<int>(p.sectors_per_cluster) << L" (" << p.bytes_per_cluster << L" bytes/cluster)\n";
    std::wcout << L"Total Sectors:             " << p.total_sectors << L" (" << format_bytes(p.volume_size_bytes) << L")\n";
    std::wcout << L"MFT Cluster (LCN):         " << p.mft_start_lcn << L"\n";
    std::wcout << L"MFTMirr Cluster (LCN):     " << p.mft_mirr_start_lcn << L"\n";
    std::wcout << L"Bytes per MFT Record:      " << p.bytes_per_record << L"\n";
    std::wcout << L"Bytes per Index Block:     " << p.bytes_per_index_block << L"\n";
    std::wcout << L"Volume Serial Number:      " << p.serial_number_formatted << L" (0x" << std::hex << std::uppercase << p.serial_number << std::dec << L")\n";
    std::wcout << L"Backup Boot Sector:        " << (comp.has_backup ? (comp.sectors_match ? L"Present (Exact match with primary)" : L"Present (Diverges from primary)") : L"Not found") << L"\n";
    std::wcout << L"Integrity Note:            " << comp.notes << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------\n\n";
}

void Formatter::print_reparse_report(const std::vector<ReparseInfo>& list) {
    std::wcout << L"NTFS Reparse Points, Junctions & Symbolic Links (" << list.size() << L" found)\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(8)  << L"FRN"
               << std::setw(32) << L"Tag / Type"
               << std::setw(10) << L"State"
               << std::setw(34) << L"Target"
               << L"Source Path\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& r : list) {
        std::wstring state_str = r.is_broken ? L"[BROKEN]" : L"OK";
        std::wstring tgt_str = r.target_path;
        if (tgt_str.size() > 32) {
            tgt_str = tgt_str.substr(0, 29) + L"...";
        }

        std::wcout << std::left
                   << std::setw(8)  << r.frn
                   << std::setw(32) << r.tag_name
                   << std::setw(10) << state_str
                   << std::setw(34) << tgt_str
                   << r.source_path << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_mft_slack_report(const MftSlackReport& report) {
    std::wcout << L"MFT Record Slack Space Forensics (FRN " << report.frn << L")\n";
    std::wcout << L"--------------------------------------------------------------------------------\n";
    std::wcout << L"Bytes Used:               " << report.bytes_used << L" / " << report.bytes_allocated << L" bytes\n";
    std::wcout << L"Record Slack Size:        " << report.slack_size << L" bytes\n";
    std::wcout << L"Slack State:              " << (report.has_non_zero_slack ? L"Residual data detected" : L"Zero-filled (Clean)") << L"\n";
    std::wcout << L"Non-Zero Slack Bytes:     " << report.non_zero_bytes_count << L" bytes\n";

    if (!report.residual_attributes.empty()) {
        std::wcout << L"\nResidual Attributes Found (" << report.residual_attributes.size() << L"):\n";
        for (const auto& ra : report.residual_attributes) {
            std::wcout << L"  * Offset +0x" << std::hex << ra.offset << std::dec
                       << L": " << ra.type_name << L" (Length: " << ra.length << L" bytes)\n";
        }
    }

    if (!report.residual_strings.empty()) {
        std::wcout << L"\nResidual Strings Found (" << report.residual_strings.size() << L"):\n";
        for (const auto& rs : report.residual_strings) {
            std::wcout << L"  * [+" << rs.offset << L", " << (rs.is_utf16 ? L"UTF-16" : L"ASCII") << L"]: \""
                       << rs.text << L"\"\n";
        }
    }

    if (!report.hex_dump.empty()) {
        std::wcout << L"\nSlack Payload Hex Dump:\n";
        std::istringstream stream(report.hex_dump);
        std::string line;
        while (std::getline(stream, line)) {
            std::wcout << L"  " << std::wstring(line.begin(), line.end()) << L"\n";
        }
    }
    std::wcout << L"--------------------------------------------------------------------------------\n\n";
}

void Formatter::print_density_report(const DensityReport& report) {
    DensityAnalyzer::print_report(report);
}

void Formatter::print_object_id_report(const std::vector<ObjectIdInfo>& list) {
    std::wcout << L"NTFS Object Identifiers & Provenance Tracking (" << list.size() << L" files found)\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(8)  << L"FRN"
               << std::setw(40) << L"Object ID GUID"
               << std::setw(12) << L"Status"
               << L"Path / Birth Object ID\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& item : list) {
        std::wcout << std::left
                   << std::setw(8)  << item.frn
                   << std::setw(40) << item.object_id_str
                   << std::setw(12) << (item.is_migrated ? L"[MIGRATED]" : (item.has_birth_data ? L"Origin" : L"Basic"))
                   << item.path << L"\n";
        if (item.is_migrated && !item.birth_object_id_str.empty()) {
            std::wcout << L"         \\-> Birth Object ID : " << item.birth_object_id_str << L"\n";
            if (!item.birth_volume_id_str.empty()) {
                std::wcout << L"         \\-> Birth Volume ID : " << item.birth_volume_id_str << L"\n";
            }
        }
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_ea_report(const std::vector<FileEaReport>& list) {
    std::wcout << L"NTFS Extended Attributes & Subsystem Metadata (" << list.size() << L" files found)\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    for (const auto& r : list) {
        std::wcout << L"  FRN " << r.frn << L" (" << (r.has_wsl_metadata ? L"WSL Linux Metadata" : L"Extended Attributes")
                   << L", " << r.packed_ea_size << L" bytes packed, " << r.attributes.size() << L" entries): " << r.path << L"\n";
        for (const auto& a : r.attributes) {
            std::wcout << L"    * [" << std::wstring(a.name.begin(), a.name.end()) << L"] "
                       << (a.is_wsl_attribute ? L"(WSL) " : L"")
                       << L"Size: " << a.value_length << L" bytes";
            if (!a.value_preview.empty()) {
                std::wcout << L" -> " << std::wstring(a.value_preview.begin(), a.value_preview.end());
            }
            std::wcout << L"\n";
        }
        std::wcout << L"\n";
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_hardlink_report(const HardLinkReport& report) {
    std::wcout << L"NTFS Hard Link Forensics & Space Savings (" << report.total_multi_link_files << L" multi-link files, "
               << report.total_link_references << L" link references)\n";
    std::wcout << L"Total Disk Allocation Saved: " << format_bytes(report.total_space_saved_bytes) << L"\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(8)  << L"FRN"
               << std::setw(8)  << L"Links"
               << std::setw(14) << L"File Size"
               << std::setw(14) << L"Space Saved"
               << L"Primary Path / Sibling Names\n";
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

    for (const auto& g : report.groups) {
        std::wcout << std::left
                   << std::setw(8)  << g.frn
                   << std::setw(8)  << g.hard_link_count
                   << std::setw(14) << format_bytes(g.size_bytes)
                   << std::setw(14) << format_bytes(g.saved_bytes)
                   << g.primary_path << L"\n";
        for (const auto& n : g.names) {
            if (n != g.primary_path) {
                std::wcout << L"         \\-> Link alias: " << n << L"\n";
            }
        }
    }
    std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n\n";
}

void Formatter::print_usn_stats(const UsnJournalStats& stats) {
    UsnJournalAnalyzer::print_stats_report(stats);
}

void Formatter::print_usn_history(const UsnHistoryReport& report) {
    UsnJournalAnalyzer::print_history_report(report);
}

void Formatter::print_badclus_report(const BadClusterReport& report) {
    BadClusterAnalyzer::print_report(report);
}

void Formatter::print_quota_report(const QuotaReport& report) {
    QuotaAnalyzer::print_report(report);
}

void Formatter::print_attrdef_report(const AttrDefReport& report) {
    AttrDefAnalyzer::print_report(report);
}

void Formatter::print_churn_report(const ChurnReport& report) {
    ChurnAnalyzer::print_report(report);
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