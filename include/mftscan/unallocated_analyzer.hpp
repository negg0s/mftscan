#pragma once

#include "mftscan/common.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace mftscan {

struct DeletedSpan {
    uint64_t start_frn{0};
    uint64_t end_frn{0};
    uint64_t record_count{0};
};

struct DeletedFileCandidate {
    uint64_t frn{0};
    std::wstring name;
    std::wstring extension;
    uint64_t size_bytes{0};
    uint64_t allocated_bytes{0};
    bool is_resident{false};
    uint64_t creation_time{0};
    uint64_t modification_time{0};
    uint16_t sequence_number{0};
};

struct UnallocatedReport {
    size_t total_records{0};
    size_t allocated_records{0};
    size_t unallocated_records{0};
    double unallocated_percentage{0.0};

    size_t recoverable_with_name{0};
    size_t recoverable_resident{0};
    size_t recoverable_non_resident{0};
    uint64_t recoverable_payload_bytes{0};

    uint64_t max_contiguous_deleted_records{0};
    size_t contiguous_deleted_spans_count{0};
    std::vector<DeletedSpan> top_deleted_spans;

    std::map<std::wstring, size_t> extension_breakdown;
    std::vector<DeletedFileCandidate> top_recoverable_files;
};

class UnallocatedAnalyzer {
public:
    static UnallocatedReport analyze(
        const std::vector<RecordInfo>& records,
        size_t top_limit = 25
    );

    static void print_report(const UnallocatedReport& report);
};

} // namespace mftscan
