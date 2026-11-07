#include "mftscan/data_run.hpp"

namespace mftscan {

std::vector<DataRunExtent> DataRunDecoder::decode_mapping_pairs(
    const uint8_t* run_data,
    size_t max_bytes,
    uint64_t initial_vcn
) {
    std::vector<DataRunExtent> extents;
    if (!run_data || max_bytes == 0) {
        return extents;
    }

    size_t index = 0;
    uint64_t current_vcn = initial_vcn;
    int64_t current_lcn = 0;

    while (index < max_bytes) {
        const uint8_t header = run_data[index++];
        if (header == 0) {
            // End of data runs marker
            break;
        }

        const uint8_t length_bytes = header & 0x0F;
        const uint8_t offset_bytes = (header >> 4) & 0x0F;

        if (length_bytes == 0 || length_bytes > 8 || offset_bytes > 8) {
            // Corrupt run header
            break;
        }
        if (index + length_bytes + offset_bytes > max_bytes) {
            // Truncated buffer
            break;
        }

        // 1. Read cluster length (unsigned)
        uint64_t run_length = 0;
        for (uint8_t i = 0; i < length_bytes; ++i) {
            run_length |= (static_cast<uint64_t>(run_data[index++]) << (i * 8));
        }

        // 2. Read LCN delta (signed, sign-extended)
        DataRunExtent extent;
        extent.starting_vcn = current_vcn;
        extent.cluster_count = run_length;

        if (offset_bytes == 0) {
            // Sparse cluster run
            extent.starting_lcn = 0;
            extent.is_sparse = true;
        } else {
            int64_t lcn_delta = 0;
            for (uint8_t i = 0; i < offset_bytes; ++i) {
                lcn_delta |= (static_cast<int64_t>(run_data[index++]) << (i * 8));
            }

            // Sign-extend if top bit of highest read byte is 1
            const uint8_t top_byte = run_data[index - 1];
            if ((top_byte & 0x80) != 0) {
                for (uint8_t i = offset_bytes; i < 8; ++i) {
                    lcn_delta |= (static_cast<int64_t>(0xFF) << (i * 8));
                }
            }

            current_lcn += lcn_delta;
            extent.starting_lcn = current_lcn;
            extent.is_sparse = false;
        }

        extents.push_back(extent);
        current_vcn += run_length;
    }

    return extents;
}

uint64_t DataRunDecoder::calculate_total_clusters(const std::vector<DataRunExtent>& extents) noexcept {
    uint64_t total = 0;
    for (const auto& ext : extents) {
        total += ext.cluster_count;
    }
    return total;
}

} // namespace mftscan