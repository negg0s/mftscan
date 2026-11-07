#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

#pragma pack(push, 1)
struct SdsEntryHeader {
    uint32_t hash;
    uint32_t security_id;
    uint64_t offset;
    uint32_t length;
};

struct RawSecurityDescriptorRelative {
    uint8_t revision;
    uint8_t sbz1;
    uint16_t control;
    uint32_t owner_offset;
    uint32_t group_offset;
    uint32_t sacl_offset;
    uint32_t dacl_offset;
};

struct RawAclHeader {
    uint8_t acl_revision;
    uint8_t sbz1;
    uint16_t acl_size;
    uint16_t ace_count;
    uint16_t sbz2;
};

struct RawAceHeader {
    uint8_t ace_type;
    uint8_t ace_flags;
    uint16_t ace_size;
};
#pragma pack(pop)

static_assert(sizeof(SdsEntryHeader) == 20, "SdsEntryHeader must be 20 bytes");
static_assert(sizeof(RawSecurityDescriptorRelative) == 20, "RawSecurityDescriptorRelative must be 20 bytes");

struct SdsDescriptorInfo {
    uint32_t security_id{0};
    uint32_t hash{0};
    uint64_t offset{0};
    uint32_t length{0};
    uint16_t control_flags{0};
    std::wstring owner_sid_str;
    std::wstring group_sid_str;
    bool has_dacl{false};
    bool is_dacl_null{false};
    bool is_dacl_empty{false};
    bool is_world_writable{false};
    uint16_t ace_count{0};
    size_t referenced_file_count{0};
    bool is_orphaned{false};
};

struct SecureDatabaseReport {
    bool valid{false};
    wchar_t volume_letter{L'C'};
    size_t total_sds_entries{0};
    size_t active_referenced_entries{0};
    size_t orphaned_entries{0};
    size_t unreferenced_security_ids_count{0};
    uint64_t total_sds_stream_bytes{0};
    double deduplication_ratio{0.0};
    size_t world_writable_descriptors{0};
    size_t null_dacl_descriptors{0};

    std::vector<SdsDescriptorInfo> descriptors;
};

class SecureAnalyzer {
public:
    static SecureDatabaseReport parse_sds_buffer(
        const uint8_t* sds_data,
        size_t sds_size,
        const std::vector<RecordInfo>& records = {},
        wchar_t drive_letter = L'C'
    );

    static Result<SecureDatabaseReport> inspect(
        VolumeReader& volume,
        const std::vector<RecordInfo>& records
    );

    static std::wstring sid_to_string(const uint8_t* sid_bytes, size_t max_bytes);
    static void print_report(const SecureDatabaseReport& report);
};

} // namespace mftscan
