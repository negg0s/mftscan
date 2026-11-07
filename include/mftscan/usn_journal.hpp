#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct UsnJournalStats {
    uint64_t journal_id{0};
    uint64_t lowest_valid_usn{0};
    uint64_t first_usn{0};
    uint64_t next_usn{0};
    uint64_t maximum_size{0};
    uint64_t allocation_delta{0};
    uint64_t max_usn{0};
    uint64_t approximate_event_count{0};
    double estimated_active_size_mb{0.0};
    double utilization_percentage{0.0};
    double rollover_percentage{0.0};
};

struct UsnHistoryEntry {
    uint64_t usn{0};
    uint64_t timestamp{0};
    uint64_t frn{0};
    uint64_t parent_frn{0};
    uint32_t reason{0};
    std::wstring reason_string;
    std::wstring file_name;
};

struct UsnHistoryReport {
    uint64_t target_frn{0};
    std::vector<UsnHistoryEntry> entries;
};

struct UsnDumpFilter {
    uint32_t reason_mask{0};
    size_t limit{100};
    uint64_t start_usn{0};
};

struct UsnDumpReport {
    uint64_t journal_id{0};
    uint64_t lowest_usn{0};
    uint64_t next_usn{0};
    uint32_t applied_reason_mask{0};
    std::wstring reason_filter_name;
    std::vector<UsnHistoryEntry> entries;
};

class UsnJournalAnalyzer {
public:
    static Result<UsnJournalStats> query_stats(VolumeReader& volume);

    static Result<UsnHistoryReport> extract_history(
        VolumeReader& volume,
        uint64_t target_frn,
        size_t max_events = 50
    );

    static Result<UsnDumpReport> dump_journal(
        VolumeReader& volume,
        const UsnDumpFilter& filter
    );

    static uint32_t parse_reason_string(const std::wstring& reason_str);

    static void print_stats_report(const UsnJournalStats& stats);
    static void print_history_report(const UsnHistoryReport& report);
    static void print_dump_report(const UsnDumpReport& report);
};

} // namespace mftscan
