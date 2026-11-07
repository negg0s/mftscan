#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/disk_usage.hpp"

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

    static std::string to_json(
        const std::vector<RecordInfo>& records,
        const ScanStats& stats,
        const VolumeGeometry& geom
    );

    static std::string to_csv(const std::vector<RecordInfo>& records);
};

} // namespace mftscan