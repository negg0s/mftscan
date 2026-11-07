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

namespace mftscan {

#pragma pack(push, 1)

struct NtfsBootSector {
    uint8_t  jump[3];
    char     oem_id[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t  fats;
    uint16_t root_entries;
    uint16_t small_sectors;
    uint8_t  media_type;
    uint16_t sectors_per_fat;
    uint16_t sectors_per_track;
    uint16_t heads;
    uint32_t hidden_sectors;
    uint32_t large_sectors;
    uint8_t  physical_drive_number;
    uint8_t  current_head;
    uint8_t  extended_boot_signature;
    uint8_t  reserved1;
    uint64_t total_sectors;
    uint64_t mft_lcn;
    uint64_t mft_mirr_lcn;
    int8_t   clusters_per_record_code;
    uint8_t  reserved2[3];
    int8_t   clusters_per_index_code;
    uint8_t  reserved3[3];
    uint64_t volume_serial_number;
    uint32_t checksum;
    uint8_t  bootstrap_code[426];
    uint16_t boot_signature;
};

#pragma pack(pop)

constexpr uint16_t kBootSectorSignature = 0xAA55;

struct BootSectorReport {
    wchar_t volume_letter{L'C'};
    bool is_valid_ntfs{false};
    std::string oem_id;
    uint16_t bytes_per_sector{0};
    uint8_t sectors_per_cluster{0};
    uint32_t bytes_per_cluster{0};
    uint64_t total_sectors{0};
    uint64_t volume_size_bytes{0};
    uint64_t mft_start_lcn{0};
    uint64_t mft_mirr_start_lcn{0};
    uint32_t bytes_per_record{0};
    uint32_t bytes_per_index_block{0};
    uint64_t serial_number{0};
    std::wstring serial_number_formatted;
    bool signature_valid{false};
};

struct BootSectorComparison {
    BootSectorReport primary;
    BootSectorReport backup;
    bool has_backup{false};
    bool sectors_match{false};
    std::wstring notes;
};

class BootSectorParser {
public:
    static Result<BootSectorReport> parse_buffer(
        const uint8_t* buffer,
        size_t size,
        wchar_t volume_letter = L'C'
    );

    static Result<BootSectorComparison> inspect_volume(VolumeReader& volume);

    static std::wstring format_serial(uint64_t serial) noexcept;
    static uint32_t decode_size_code(int8_t code, uint32_t bytes_per_cluster) noexcept;
};

} // namespace mftscan
