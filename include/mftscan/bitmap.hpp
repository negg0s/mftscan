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

struct FreeExtentInfo {
    uint64_t starting_cluster{0};
    uint64_t cluster_count{0};
};

struct BitmapReport {
    wchar_t volume_letter{L'C'};
    uint64_t total_clusters{0};
    uint64_t used_clusters{0};
    uint64_t free_clusters{0};
    uint32_t bytes_per_cluster{4096};
    double free_percent{0.0};
    uint64_t free_extents_count{0};
    uint64_t largest_free_extent_clusters{0};
    uint64_t smallest_free_extent_clusters{0};
    double avg_free_extent_clusters{0.0};
    double free_space_fragmentation_index{0.0};
    std::string ascii_map;
};

class BitmapAnalyzer {
public:
    static Result<BitmapReport> analyze(VolumeReader& volume, size_t map_width = 64);

    static Result<BitmapReport> analyze_from_buffer(
        const uint8_t* bitmap_bytes,
        uint64_t total_clusters,
        uint32_t cluster_size,
        wchar_t volume_letter = L'C',
        size_t map_width = 64
    );
};

} // namespace mftscan
