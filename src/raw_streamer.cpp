#include "mftscan/raw_streamer.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <vector>

namespace mftscan {

RawMftStreamer::RawMftStreamer(VolumeReader& volume)
    : volume_(volume) {
}

Result<std::vector<DataRunExtent>> RawMftStreamer::query_mft_extents() {
    if (!volume_.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume is not open");
    }

    const uint32_t rec_size = volume_.geometry().bytes_per_record;
    std::vector<uint8_t> rec0_data(rec_size);

    auto read_res = volume_.read_file_record(0, rec0_data.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    if (!RecordParser::apply_fixup(rec0_data.data(), rec_size, volume_.geometry().bytes_per_sector)) {
        return Error(ERROR_INVALID_DATA, L"Fixup failed on Record 0 ($MFT)");
    }

    const auto* hdr = reinterpret_cast<const MftRecordHeader*>(rec0_data.data());
    uint32_t offset = hdr->first_attribute_offset;

    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec0_data.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }

        if (attr->type_code == kAttrData && attr->name_length == 0) {
            if (attr->non_resident_flag != 0) {
                const uint32_t runs_offset = attr->non_resident.data_runs_offset;
                if (runs_offset < attr->record_length) {
                    const uint8_t* run_ptr = rec0_data.data() + offset + runs_offset;
                    const size_t max_run_len = attr->record_length - runs_offset;

                    extents_ = DataRunDecoder::decode_mapping_pairs(run_ptr, max_run_len, attr->non_resident.starting_vcn);
                    return extents_;
                }
            }
            break;
        }

        offset += attr->record_length;
    }

    return Error(ERROR_NOT_FOUND, L"Could not locate non-resident $DATA attribute in Record 0");
}

Result<bool> RawMftStreamer::read_aligned_bytes(int64_t byte_offset, uint8_t* buffer, DWORD bytes_to_read) {
    HANDLE hVolume = volume_.native_handle();
    if (hVolume == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Volume handle is invalid");
    }

    LARGE_INTEGER li_offset;
    li_offset.QuadPart = byte_offset;

    if (!SetFilePointerEx(hVolume, li_offset, nullptr, FILE_BEGIN)) {
        return Error(GetLastError(), L"SetFilePointerEx failed on raw volume seek");
    }

    DWORD bytes_read = 0;
    if (!ReadFile(hVolume, buffer, bytes_to_read, &bytes_read, nullptr)) {
        return Error(GetLastError(), L"ReadFile failed on raw volume block read");
    }

    return (bytes_read == bytes_to_read);
}

Result<uint64_t> RawMftStreamer::stream_all_records(
    uint32_t block_size_bytes,
    BlockCallback on_block
) {
    if (extents_.empty()) {
        auto ext_res = query_mft_extents();
        if (!ext_res) {
            return ext_res.error();
        }
    }

    const auto& geom = volume_.geometry();
    const uint32_t bytes_per_cluster = geom.bytes_per_cluster;
    const uint32_t bytes_per_record = geom.bytes_per_record;

    if (bytes_per_record == 0 || bytes_per_cluster == 0) {
        return Error(ERROR_INVALID_DATA, L"Invalid volume cluster or record geometry");
    }

    // Align block size to cluster boundaries
    const uint32_t aligned_block_size = ((block_size_bytes + bytes_per_cluster - 1) / bytes_per_cluster) * bytes_per_cluster;
    std::vector<uint8_t> block_buffer(aligned_block_size);

    uint64_t current_record_index = 0;
    uint64_t total_streamed_records = 0;

    for (const auto& ext : extents_) {
        const uint64_t extent_bytes = ext.cluster_count * bytes_per_cluster;
        uint64_t bytes_processed_in_ext = 0;

        if (ext.is_sparse || ext.starting_lcn <= 0) {
            // Handle sparse gap
            while (bytes_processed_in_ext < extent_bytes) {
                const uint32_t chunk_bytes = static_cast<uint32_t>(
                    (std::min<uint64_t>)(aligned_block_size, extent_bytes - bytes_processed_in_ext)
                );
                memset(block_buffer.data(), 0, chunk_bytes);

                const uint32_t rec_count = chunk_bytes / bytes_per_record;
                if (!on_block(current_record_index, block_buffer.data(), rec_count)) {
                    return total_streamed_records;
                }

                current_record_index += rec_count;
                total_streamed_records += rec_count;
                bytes_processed_in_ext += chunk_bytes;
            }
        } else {
            // Read physical extents
            const int64_t base_offset = ext.starting_lcn * bytes_per_cluster;

            while (bytes_processed_in_ext < extent_bytes) {
                const uint32_t chunk_bytes = static_cast<uint32_t>(
                    (std::min<uint64_t>)(aligned_block_size, extent_bytes - bytes_processed_in_ext)
                );

                const int64_t read_offset = base_offset + bytes_processed_in_ext;
                auto read_res = read_aligned_bytes(read_offset, block_buffer.data(), chunk_bytes);
                if (!read_res) {
                    return read_res.error();
                }

                const uint32_t rec_count = chunk_bytes / bytes_per_record;
                if (!on_block(current_record_index, block_buffer.data(), rec_count)) {
                    return total_streamed_records;
                }

                current_record_index += rec_count;
                total_streamed_records += rec_count;
                bytes_processed_in_ext += chunk_bytes;
            }
        }
    }

    return total_streamed_records;
}

} // namespace mftscan