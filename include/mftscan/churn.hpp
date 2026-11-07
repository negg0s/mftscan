#pragma once

#include "mftscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct ChurnEntry {
    uint64_t frn{0};
    uint16_t sequence_number{0};
    std::wstring path;
    uint64_t file_size{0};
    bool is_directory{false};
    bool is_deleted{false};
};

struct ChurnReport {
    size_t total_records_evaluated{0};
    size_t active_records{0};
    size_t deleted_records{0};
    uint16_t min_sequence{0xFFFF};
    uint16_t max_sequence{0};
    double avg_sequence{0.0};

    size_t tier_1_to_5{0};
    size_t tier_6_to_20{0};
    size_t tier_21_to_50{0};
    size_t tier_51_to_100{0};
    size_t tier_101_to_500{0};
    size_t tier_above_500{0};

    size_t rollover_risk_count{0};
    std::vector<ChurnEntry> top_churn_records;
};

class ChurnAnalyzer {
public:
    static ChurnReport analyze(const std::vector<RecordInfo>& records, size_t top_limit = 20);
    static void print_report(const ChurnReport& report);
};

} // namespace mftscan
