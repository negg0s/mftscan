#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/volume.hpp"

#include <functional>
#include <vector>

namespace mftscan {

class RawMftStreamer {
public:
    explicit RawMftStreamer(VolumeReader& volume);

    Result<std::vector<DataRunExtent>> query_mft_extents();

    using BlockCallback = std::function<bool(uint64_t start_record_index, const uint8_t* block_data, uint32_t record_count)>;

    Result<uint64_t> stream_all_records(
        uint32_t block_size_bytes,
        BlockCallback on_block
    );

private:
    VolumeReader& volume_;
    std::vector<DataRunExtent> extents_;

    Result<bool> read_aligned_bytes(int64_t byte_offset, uint8_t* buffer, DWORD bytes_to_read);
};

} // namespace mftscan