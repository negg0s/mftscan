#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <cstdint>
#include <vector>

namespace mftscan {

struct DataRunExtent {
    uint64_t starting_vcn{0};
    int64_t  starting_lcn{0}; // Negative or zero indicates sparse / unallocated
    uint64_t cluster_count{0};
    bool     is_sparse{false};
};

class DataRunDecoder {
public:
    static std::vector<DataRunExtent> decode_mapping_pairs(
        const uint8_t* run_data,
        size_t max_bytes,
        uint64_t initial_vcn = 0
    );

    static uint64_t calculate_total_clusters(const std::vector<DataRunExtent>& extents) noexcept;
};

} // namespace mftscan