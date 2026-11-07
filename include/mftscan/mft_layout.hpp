#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace mftscan {

struct MftCapacityWarning {
    uint64_t frn{0};
    std::wstring path;
    uint32_t bytes_used{0};
    uint32_t bytes_allocated{0};
    uint32_t free_slack{0};
    size_t attribute_count{0};
};

struct MftLayoutReport {
    size_t total_records_evaluated{0};
    size_t allocated_records{0};
    size_t unallocated_records{0};
    uint32_t bytes_per_record{1024};

    uint64_t total_allocated_record_bytes{0};
    uint64_t total_used_record_bytes{0};
    uint64_t total_internal_slack_bytes{0};
    double average_bytes_used{0.0};
    double average_internal_slack{0.0};
    double overall_mft_packing_density{0.0};

    size_t records_near_capacity_count{0}; // used >= 900 bytes
    size_t records_compact_count{0};       // used <= 350 bytes
    size_t records_with_attr_list{0};
    size_t records_with_multiple_names{0};

    std::map<uint32_t, size_t> attribute_frequency;
    std::vector<MftCapacityWarning> top_congested_records;
};

class MftLayoutAuditor {
public:
    static std::wstring attribute_type_to_string(uint32_t type_code);

    static MftLayoutReport analyze(
        VolumeReader& volume,
        const std::vector<RecordInfo>& records,
        size_t top_limit = 20
    );

    static void print_report(const MftLayoutReport& report);
};

} // namespace mftscan
