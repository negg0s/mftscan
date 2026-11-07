#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct BadClusterExtent {
    uint64_t start_lcn{0};
    uint64_t cluster_count{0};
    uint64_t byte_length{0};
};

struct BadClusterReport {
    uint64_t total_volume_clusters{0};
    uint64_t bad_cluster_count{0};
    uint64_t bad_bytes_count{0};
    bool is_healthy{true};
    std::vector<BadClusterExtent> extents;
};

class BadClusterAnalyzer {
public:
    static Result<BadClusterReport> analyze(VolumeReader& volume);
    static void print_report(const BadClusterReport& report);
};

} // namespace mftscan
