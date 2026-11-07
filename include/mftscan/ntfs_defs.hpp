#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>

namespace mftscan {

#pragma pack(push, 1)

// NTFS Magic identifiers
constexpr uint32_t kMftMagicFile = 0x454C4946; // 'FILE'
constexpr uint32_t kMftMagicBaad = 0x44414142; // 'BAAD'

// Standard MFT record flags
constexpr uint16_t kRecordInUse      = 0x0001;
constexpr uint16_t kRecordDirectory  = 0x0002;
constexpr uint16_t kRecordExtension  = 0x0004;
constexpr uint16_t kRecordSpecialIdx = 0x0008;

// NTFS Attribute type codes
constexpr uint32_t kAttrStandardInformation = 0x10;
constexpr uint32_t kAttrAttributeList       = 0x20;
constexpr uint32_t kAttrFileName            = 0x30;
constexpr uint32_t kAttrObjectId            = 0x40;
constexpr uint32_t kAttrSecurityDescriptor  = 0x50;
constexpr uint32_t kAttrVolumeName          = 0x60;
constexpr uint32_t kAttrVolumeInformation   = 0x70;
constexpr uint32_t kAttrData                = 0x80;
constexpr uint32_t kAttrIndexRoot           = 0x90;
constexpr uint32_t kAttrIndexAllocation     = 0xA0;
constexpr uint32_t kAttrBitmap              = 0xB0;
constexpr uint32_t kAttrReparsePoint        = 0xC0;
constexpr uint32_t kAttrEaInformation       = 0xD0;
constexpr uint32_t kAttrEa                  = 0xE0;
constexpr uint32_t kAttrPropertySet         = 0xF0;
constexpr uint32_t kAttrLoggedUtilityStream = 0x100;
constexpr uint32_t kAttrEnd                 = 0xFFFFFFFF;

// Well-known MFT record numbers
constexpr uint64_t kRecordMft       = 0;
constexpr uint64_t kRecordMftMirr   = 1;
constexpr uint64_t kRecordLogFile   = 2;
constexpr uint64_t kRecordVolume    = 3;
constexpr uint64_t kRecordAttrDef   = 4;
constexpr uint64_t kRecordRootDir   = 5;
constexpr uint64_t kRecordBitmap    = 6;
constexpr uint64_t kRecordBoot      = 7;
constexpr uint64_t kRecordBadClus   = 8;
constexpr uint64_t kRecordSecure    = 9;
constexpr uint64_t kRecordUpCase    = 10;
constexpr uint64_t kRecordExtend    = 11;

// MFT Record Header (NTFS File Record Segment)
struct MftRecordHeader {
    uint32_t magic;                    // 'FILE'
    uint16_t update_sequence_offset;   // Offset to update sequence array
    uint16_t update_sequence_size;     // Size of update sequence in words (1 + N sectors)
    uint64_t logfile_sequence_number;  // LSN
    uint16_t sequence_number;          // Sequence number
    uint16_t hard_link_count;          // Number of directory links
    uint16_t first_attribute_offset;   // Offset to first attribute
    uint16_t flags;                    // kRecordInUse, kRecordDirectory
    uint32_t bytes_used;               // Used bytes of record
    uint32_t bytes_allocated;          // Allocated size of record (1024 bytes)
    uint64_t base_file_record;         // 0 if base record, else parent file reference
    uint16_t next_attribute_instance;  // Next attribute ID
    uint16_t reserved;                 // Alignment
    uint32_t record_number;            // MFT record number (Windows XP+)
};

// Attribute Record Header
struct AttributeRecordHeader {
    uint32_t type_code;                // Attribute type code (e.g. 0x10, 0x30, 0x80)
    uint32_t record_length;            // Total length including header
    uint8_t  non_resident_flag;        // 0 = Resident, 1 = Non-Resident
    uint8_t  name_length;              // Length of attribute name in chars
    uint16_t name_offset;              // Offset to attribute name from header start
    uint16_t flags;                    // 0x0001 = Compressed, 0x4000 = Encrypted, 0x8000 = Sparse
    uint16_t attribute_id;             // Instance tag

    union {
        // Resident Attribute Header
        struct {
            uint32_t value_length;     // Byte length of attribute content
            uint16_t value_offset;     // Offset to content from attribute header start
            uint8_t  resident_flags;   // 0x01 = Indexed
            uint8_t  reserved;
        } resident;

        // Non-Resident Attribute Header
        struct {
            uint64_t starting_vcn;     // Starting Virtual Cluster Number
            uint64_t last_vcn;         // Last Virtual Cluster Number
            uint16_t data_runs_offset; // Offset to mapping pairs (data runs)
            uint16_t compression_unit; // Compression unit size (log2 clusters)
            uint32_t padding;
            uint64_t allocated_size;   // Allocated byte size
            uint64_t real_size;        // Actual byte content size
            uint64_t valid_data_length;// Initialized content length
        } non_resident;
    };
};

// $STANDARD_INFORMATION attribute payload (0x10)
struct StandardInformation {
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_change_time;
    uint64_t last_access_time;
    uint32_t file_attributes;          // Standard DOS attributes (FILE_ATTRIBUTE_*)
    uint32_t max_versions;
    uint32_t version_number;
    uint32_t class_id;
    uint32_t owner_id;
    uint32_t security_id;
    uint64_t quota_charged;
    uint64_t usn;
};

// $FILE_NAME attribute payload (0x30)
struct FileNamePayloadHeader {
    uint64_t parent_directory_ref;     // 48 bits: MFT record number, 16 bits: sequence number
    uint64_t creation_time;
    uint64_t modification_time;
    uint64_t mft_change_time;
    uint64_t last_access_time;
    uint64_t allocated_size;
    uint64_t real_size;
    uint32_t file_attributes;
    uint32_t reparse_tag_or_eas;
    uint8_t  file_name_length;         // In UTF-16 code points
    uint8_t  file_name_namespace;      // 0 = POSIX, 1 = Win32, 2 = DOS, 3 = Win32 & DOS
};

// $VOLUME_INFORMATION attribute payload (0x70)
struct VolumeInformationPayload {
    uint64_t reserved;
    uint8_t  major_version;
    uint8_t  minor_version;
    uint16_t volume_flags;
};

constexpr uint16_t kVolumeDirty             = 0x0001;
constexpr uint16_t kVolumeResizeLogFile     = 0x0002;
constexpr uint16_t kVolumeUpgradeOnMount    = 0x0004;
constexpr uint16_t kVolumeMountedDirty      = 0x0008;
constexpr uint16_t kVolumeDeleteUsnUnderway = 0x0010;
constexpr uint16_t kVolumeRepairObjectIds   = 0x0020;
constexpr uint16_t kVolumeModifiedByChkntfs = 0x8000;

// $ATTRIBUTE_LIST entry header (0x20)
struct AttributeListEntryHeader {
    uint32_t attribute_type;          // Type code (e.g. 0x30, 0x80)
    uint16_t record_length;           // Byte length of this entry
    uint8_t  name_length;             // Name length in characters
    uint8_t  name_offset;             // Offset to name from entry start
    uint64_t lowest_vcn;              // Lowest VCN for non-resident split
    uint64_t file_reference_number;   // MFT record segment where attribute is stored
    uint16_t attribute_id;            // Attribute instance tag
};

// $LogFile page and restart area headers
constexpr uint32_t kLogFileMagicRstr = 0x52545352; // 'RSTR'
constexpr uint32_t kLogFileMagicRcrd = 0x44524352; // 'RCRD'
constexpr uint16_t kLogFileCleanShutdown = 0x0002;

struct LogFileRestartPageHeader {
    uint32_t magic;                    // 'RSTR'
    uint16_t update_sequence_offset;
    uint16_t update_sequence_size;
    uint64_t chksum_or_file_offset;
    uint32_t system_page_size;
    uint32_t log_page_size;
    uint16_t restart_area_offset;
    int16_t  minor_version;
    int16_t  major_version;
};

struct LogFileRestartArea {
    uint64_t current_lsn;              // Current Log Sequence Number
    uint16_t log_clients;              // Number of active clients
    uint16_t client_free_list;         // First free client index
    uint16_t client_in_use_list;       // First in-use client index
    uint16_t flags;                    // 0x0002 = Volume was cleanly unmounted
    uint32_t seq_number_bits;
    uint16_t restart_area_length;
    uint16_t client_array_offset;
    uint64_t file_size;
    uint32_t last_lsn_data_length;
    uint16_t record_header_length;
    uint16_t log_page_data_offset;
    uint32_t restart_open_log_count;
    uint32_t reserved;
};

#pragma pack(pop)

// File Reference extraction helper
inline uint64_t extract_record_number(uint64_t file_ref) {
    return file_ref & 0x0000FFFFFFFFFFFFULL;
}

inline uint16_t extract_sequence_number(uint64_t file_ref) {
    return static_cast<uint16_t>((file_ref >> 48) & 0xFFFF);
}

} // namespace mftscan