#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/attr_list.hpp"
#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct AttributeDetail {
    uint32_t type_code{0};
    std::wstring type_name;
    uint32_t record_length{0};
    bool is_non_resident{false};
    std::wstring stream_name;
    uint64_t content_size{0};
    uint64_t allocated_size{0};
    std::string hex_preview;
    std::vector<AttributeListEntryInfo> attr_list_entries;
};

struct RecordDumpReport {
    uint64_t record_number{0};
    uint16_t sequence_number{0};
    bool is_allocated{false};
    bool is_directory{false};
    bool fixup_valid{false};
    uint32_t bytes_used{0};
    uint32_t bytes_allocated{0};
    uint64_t base_record_ref{0};
    std::vector<AttributeDetail> attributes;
};

class RecordInspector {
public:
    static Result<RecordDumpReport> inspect(VolumeReader& volume, uint64_t record_number);
    static void print_report(const RecordDumpReport& report);

    static std::wstring attribute_type_to_string(uint32_t type_code);
    static std::string format_hex_dump(const uint8_t* data, size_t size, size_t max_bytes = 64);
};

} // namespace mftscan