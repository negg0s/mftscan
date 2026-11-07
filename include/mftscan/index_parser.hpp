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
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

#pragma pack(push, 1)

struct IndexRootHeader {
    uint32_t attribute_type;
    uint32_t collation_rule;
    uint32_t index_record_size;
    uint8_t  clusters_per_index_record;
    uint8_t  reserved[3];
};

struct IndexNodeHeader {
    uint32_t first_entry_offset;
    uint32_t total_index_size;
    uint32_t allocated_index_size;
    uint8_t  flags;
    uint8_t  reserved[3];
};

struct IndexEntryHeader {
    uint64_t file_reference;
    uint16_t length;
    uint16_t key_length;
    uint16_t flags;
    uint16_t reserved;
};

#pragma pack(pop)

struct IndexEntryInfo {
    uint64_t record_index{0};
    uint16_t sequence_number{0};
    std::wstring name;
    uint64_t real_size{0};
    uint64_t allocated_size{0};
    uint64_t creation_time{0};
    uint64_t modification_time{0};
    bool is_directory{false};
    bool is_carved_from_slack{false};
};

struct DirectoryIndexReport {
    uint64_t directory_frn{0};
    bool has_sub_nodes{false};
    uint32_t allocated_index_size{0};
    uint32_t total_index_size{0};
    std::vector<IndexEntryInfo> entries;
    std::vector<IndexEntryInfo> slack_carved_entries;
};

class IndexParser {
public:
    static Result<DirectoryIndexReport> parse_directory_index(VolumeReader& volume, uint64_t directory_frn);
    static void print_index_report(const DirectoryIndexReport& report);
};

} // namespace mftscan
