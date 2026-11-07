#include "mftscan/bitmap.hpp"

#include <algorithm>
#include <vector>

namespace mftscan {

Result<BitmapReport> BitmapAnalyzer::analyze_from_buffer(
    const uint8_t* bitmap_bytes,
    uint64_t total_clusters,
    uint32_t cluster_size,
    wchar_t volume_letter,
    size_t map_width
) {
    if (!bitmap_bytes || total_clusters == 0) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid bitmap buffer or zero clusters");
    }

    BitmapReport report{};
    report.volume_letter = volume_letter;
    report.total_clusters = total_clusters;
    report.bytes_per_cluster = cluster_size;

    uint64_t current_free_run = 0;
    uint64_t smallest_free = UINT64_MAX;

    for (uint64_t i = 0; i < total_clusters; ++i) {
        const bool is_used = (bitmap_bytes[i / 8] & (1 << (i % 8))) != 0;
        if (is_used) {
            report.used_clusters++;
            if (current_free_run > 0) {
                report.free_extents_count++;
                if (current_free_run > report.largest_free_extent_clusters) {
                    report.largest_free_extent_clusters = current_free_run;
                }
                if (current_free_run < smallest_free) {
                    smallest_free = current_free_run;
                }
                current_free_run = 0;
            }
        } else {
            report.free_clusters++;
            current_free_run++;
        }
    }

    if (current_free_run > 0) {
        report.free_extents_count++;
        if (current_free_run > report.largest_free_extent_clusters) {
            report.largest_free_extent_clusters = current_free_run;
        }
        if (current_free_run < smallest_free) {
            smallest_free = current_free_run;
        }
    }

    report.smallest_free_extent_clusters = (report.free_extents_count > 0) ? smallest_free : 0;
    report.free_percent = (total_clusters > 0)
        ? (100.0 * static_cast<double>(report.free_clusters) / static_cast<double>(total_clusters))
        : 0.0;

    report.avg_free_extent_clusters = (report.free_extents_count > 0)
        ? (static_cast<double>(report.free_clusters) / static_cast<double>(report.free_extents_count))
        : 0.0;

    if (report.free_clusters == 0 || report.free_extents_count <= 1) {
        report.free_space_fragmentation_index = 0.0;
    } else {
        report.free_space_fragmentation_index =
            (1.0 - (static_cast<double>(report.largest_free_extent_clusters) / static_cast<double>(report.free_clusters))) * 100.0;
        if (report.free_space_fragmentation_index < 0.0) report.free_space_fragmentation_index = 0.0;
        if (report.free_space_fragmentation_index > 100.0) report.free_space_fragmentation_index = 100.0;
    }

    // Build ASCII cluster map
    if (map_width == 0) map_width = 64;
    report.ascii_map.reserve(map_width + 2);
    report.ascii_map.push_back('[');

    for (size_t b = 0; b < map_width; ++b) {
        const uint64_t start_c = (b * total_clusters) / map_width;
        const uint64_t end_c = ((b + 1) * total_clusters) / map_width;
        const uint64_t span = (end_c > start_c) ? (end_c - start_c) : 1;

        uint64_t used_in_block = 0;
        for (uint64_t c = start_c; c < end_c; ++c) {
            if ((bitmap_bytes[c / 8] & (1 << (c % 8))) != 0) {
                used_in_block++;
            }
        }

        const double ratio = static_cast<double>(used_in_block) / static_cast<double>(span);
        if (ratio >= 0.99) {
            report.ascii_map.push_back('#');
        } else if (ratio >= 0.50) {
            report.ascii_map.push_back('+');
        } else if (ratio > 0.01) {
            report.ascii_map.push_back('-');
        } else {
            report.ascii_map.push_back('.');
        }
    }
    report.ascii_map.push_back(']');

    return report;
}

Result<BitmapReport> BitmapAnalyzer::analyze(VolumeReader& volume, size_t map_width) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint64_t total_clusters = volume.geometry().total_clusters;
    if (total_clusters == 0) {
        return Error(ERROR_INVALID_DATA, L"Volume reported 0 total clusters");
    }

    // Allocate bitmap buffer chunk (e.g. 8 MB chunks)
    constexpr DWORD kChunkBytes = 8 * 1024 * 1024;
    std::vector<uint8_t> out_buf(sizeof(VOLUME_BITMAP_BUFFER) + kChunkBytes);

    STARTING_LCN_INPUT_BUFFER in_buf{};
    in_buf.StartingLcn.QuadPart = 0;

    BitmapReport report{};
    report.volume_letter = volume.drive_letter();
    report.total_clusters = total_clusters;
    report.bytes_per_cluster = volume.geometry().bytes_per_cluster;

    uint64_t current_free_run = 0;
    uint64_t smallest_free = UINT64_MAX;

    // For ASCII map buckets
    if (map_width == 0) map_width = 64;
    std::vector<uint64_t> used_per_bucket(map_width, 0);

    while (static_cast<uint64_t>(in_buf.StartingLcn.QuadPart) < total_clusters) {
        DWORD bytes_returned = 0;
        const BOOL success = DeviceIoControl(
            volume.native_handle(),
            FSCTL_GET_VOLUME_BITMAP,
            &in_buf,
            sizeof(in_buf),
            out_buf.data(),
            static_cast<DWORD>(out_buf.size()),
            &bytes_returned,
            nullptr
        );

        if (!success) {
            const DWORD err = GetLastError();
            if (err != ERROR_MORE_DATA) {
                return Error(err, L"FSCTL_GET_VOLUME_BITMAP failed");
            }
        }

        const auto* bmp_header = reinterpret_cast<const VOLUME_BITMAP_BUFFER*>(out_buf.data());
        const uint64_t start_lcn = static_cast<uint64_t>(bmp_header->StartingLcn.QuadPart);
        const uint64_t num_clusters = static_cast<uint64_t>(bmp_header->BitmapSize.QuadPart);
        const uint8_t* bits = bmp_header->Buffer;

        for (uint64_t i = 0; i < num_clusters; ++i) {
            const uint64_t cluster_idx = start_lcn + i;
            if (cluster_idx >= total_clusters) {
                break;
            }

            const bool is_used = (bits[i / 8] & (1 << (i % 8))) != 0;
            if (is_used) {
                report.used_clusters++;
                const size_t bucket = static_cast<size_t>((cluster_idx * map_width) / total_clusters);
                if (bucket < map_width) {
                    used_per_bucket[bucket]++;
                }

                if (current_free_run > 0) {
                    report.free_extents_count++;
                    if (current_free_run > report.largest_free_extent_clusters) {
                        report.largest_free_extent_clusters = current_free_run;
                    }
                    if (current_free_run < smallest_free) {
                        smallest_free = current_free_run;
                    }
                    current_free_run = 0;
                }
            } else {
                report.free_clusters++;
                current_free_run++;
            }
        }

        if (num_clusters == 0) {
            break;
        }
        in_buf.StartingLcn.QuadPart = static_cast<LONGLONG>(start_lcn + num_clusters);
    }

    if (current_free_run > 0) {
        report.free_extents_count++;
        if (current_free_run > report.largest_free_extent_clusters) {
            report.largest_free_extent_clusters = current_free_run;
        }
        if (current_free_run < smallest_free) {
            smallest_free = current_free_run;
        }
    }

    report.smallest_free_extent_clusters = (report.free_extents_count > 0) ? smallest_free : 0;
    report.free_percent = (total_clusters > 0)
        ? (100.0 * static_cast<double>(report.free_clusters) / static_cast<double>(total_clusters))
        : 0.0;

    report.avg_free_extent_clusters = (report.free_extents_count > 0)
        ? (static_cast<double>(report.free_clusters) / static_cast<double>(report.free_extents_count))
        : 0.0;

    if (report.free_clusters == 0 || report.free_extents_count <= 1) {
        report.free_space_fragmentation_index = 0.0;
    } else {
        report.free_space_fragmentation_index =
            (1.0 - (static_cast<double>(report.largest_free_extent_clusters) / static_cast<double>(report.free_clusters))) * 100.0;
        if (report.free_space_fragmentation_index < 0.0) report.free_space_fragmentation_index = 0.0;
        if (report.free_space_fragmentation_index > 100.0) report.free_space_fragmentation_index = 100.0;
    }

    // Build ASCII map string
    report.ascii_map.reserve(map_width + 2);
    report.ascii_map.push_back('[');
    for (size_t b = 0; b < map_width; ++b) {
        const uint64_t start_c = (b * total_clusters) / map_width;
        const uint64_t end_c = ((b + 1) * total_clusters) / map_width;
        const uint64_t span = (end_c > start_c) ? (end_c - start_c) : 1;

        const double ratio = static_cast<double>(used_per_bucket[b]) / static_cast<double>(span);
        if (ratio >= 0.99) {
            report.ascii_map.push_back('#');
        } else if (ratio >= 0.50) {
            report.ascii_map.push_back('+');
        } else if (ratio > 0.01) {
            report.ascii_map.push_back('-');
        } else {
            report.ascii_map.push_back('.');
        }
    }
    report.ascii_map.push_back(']');

    return report;
}

} // namespace mftscan
