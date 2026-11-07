#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/ntfs_defs.hpp"

#include <optional>
#include <vector>

namespace mftscan {

class RecordParser {
public:
    static bool apply_fixup(uint8_t* record_buffer, uint32_t record_size, uint32_t sector_size = 512) noexcept;

    static std::optional<RecordInfo> parse_record(
        const uint8_t* raw_record,
        uint32_t record_size,
        uint64_t fallback_record_index = 0,
        uint32_t sector_size = 512
    );

    static std::vector<RecordInfo> parse_batch(
        const uint8_t* records_data,
        uint32_t record_count,
        uint32_t record_size,
        uint64_t start_index,
        uint32_t sector_size = 512
    );
};

} // namespace mftscan