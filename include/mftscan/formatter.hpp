#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/bitmap.hpp"
#include "mftscan/boot_sector.hpp"
#include "mftscan/carver.hpp"
#include "mftscan/common.hpp"
#include "mftscan/density.hpp"
#include "mftscan/disk_usage.hpp"
#include "mftscan/duplicate_detector.hpp"
#include "mftscan/extended_attributes.hpp"
#include "mftscan/fragmentation_analyzer.hpp"
#include "mftscan/logfile.hpp"
#include "mftscan/mft_slack.hpp"
#include "mftscan/object_id.hpp"
#include "mftscan/reparse.hpp"
#include "mftscan/security_auditor.hpp"
#include "mftscan/signature_verifier.hpp"
#include "mftscan/sparse_slack_analyzer.hpp"
#include "mftscan/system_files.hpp"
#include "mftscan/timestomp.hpp"
#include "mftscan/usn_monitor.hpp"

#include <string>
#include <vector>

namespace mftscan {

class Formatter {
public:
    static std::wstring format_bytes(uint64_t bytes);
    static std::wstring format_filetime(uint64_t ft);

    static void print_banner();
    static void print_scan_summary(const ScanStats& stats, const VolumeGeometry& geom);
    static void print_results_table(const std::vector<RecordInfo>& records, size_t max_display = 100);
    static void print_top_files_table(const std::vector<RecordInfo>& records);
    static void print_top_directories_table(const std::vector<DirectoryUsage>& dirs);
    static void print_extension_histogram_table(const std::vector<ExtensionStat>& stats);
    static void print_duplicates_table(const DuplicateReport& report);
    static void print_usn_change(const UsnChangeRecord& change);
    static void print_fragmentation_table(const FragmentationReport& report);
    static void print_slack_table(const SlackSpaceReport& report);
    static void print_compression_table(const CompressionReport& report);
    static void print_timestomp_table(const TimestompReport& report);
    static void print_signature_report(const SignatureReport& report);
    static void print_security_report(const std::vector<SecurityAuditResult>& results);
    static void print_carve_summary(const BatchCarveStats& stats, const std::wstring& out_dir);
    static void print_system_audit_report(const SystemAuditReport& report);
    static void print_bitmap_report(const BitmapReport& report);
    static void print_logfile_report(const LogFileReport& report);
    static void print_boot_sector_report(const BootSectorComparison& comp);
    static void print_reparse_report(const std::vector<ReparseInfo>& list);
    static void print_mft_slack_report(const MftSlackReport& report);
    static void print_density_report(const DensityReport& report);
    static void print_object_id_report(const std::vector<ObjectIdInfo>& list);
    static void print_ea_report(const std::vector<FileEaReport>& list);

    static std::string to_json(
        const std::vector<RecordInfo>& records,
        const ScanStats& stats,
        const VolumeGeometry& geom
    );

    static std::string to_csv(const std::vector<RecordInfo>& records);
};

} // namespace mftscan