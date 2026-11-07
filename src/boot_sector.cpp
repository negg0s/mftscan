#include "mftscan/boot_sector.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

namespace mftscan {

uint32_t BootSectorParser::decode_size_code(int8_t code, uint32_t bytes_per_cluster) noexcept {
    if (code < 0) {
        const int shift = -code;
        if (shift >= 0 && shift < 31) {
            return 1U << shift;
        }
        return 1024;
    }
    return static_cast<uint32_t>(code) * bytes_per_cluster;
}

std::wstring BootSectorParser::format_serial(uint64_t serial) noexcept {
    const uint32_t low = static_cast<uint32_t>(serial & 0xFFFFFFFF);
    const uint32_t high_part = (low >> 16) & 0xFFFF;
    const uint32_t low_part = low & 0xFFFF;

    std::wostringstream oss;
    oss << std::hex << std::uppercase << std::setfill(L'0')
        << std::setw(4) << high_part << L"-"
        << std::setw(4) << low_part;
    return oss.str();
}

Result<BootSectorReport> BootSectorParser::parse_buffer(
    const uint8_t* buffer,
    size_t size,
    wchar_t volume_letter
) {
    if (!buffer || size < sizeof(NtfsBootSector)) {
        return Error(ERROR_INVALID_PARAMETER, L"Buffer too small for NTFS boot sector");
    }

    const auto* bs = reinterpret_cast<const NtfsBootSector*>(buffer);

    BootSectorReport report{};
    report.volume_letter = volume_letter;
    report.signature_valid = (bs->boot_signature == kBootSectorSignature);
    report.oem_id = std::string(bs->oem_id, 8);
    report.is_valid_ntfs = (report.signature_valid && report.oem_id == "NTFS    ");

    report.bytes_per_sector = bs->bytes_per_sector;
    report.sectors_per_cluster = bs->sectors_per_cluster;
    report.bytes_per_cluster = bs->bytes_per_sector * bs->sectors_per_cluster;
    report.total_sectors = bs->total_sectors;
    report.volume_size_bytes = bs->total_sectors * bs->bytes_per_sector;

    report.mft_start_lcn = bs->mft_lcn;
    report.mft_mirr_start_lcn = bs->mft_mirr_lcn;
    report.bytes_per_record = decode_size_code(bs->clusters_per_record_code, report.bytes_per_cluster);
    report.bytes_per_index_block = decode_size_code(bs->clusters_per_index_code, report.bytes_per_cluster);

    report.serial_number = bs->volume_serial_number;
    report.serial_number_formatted = format_serial(bs->volume_serial_number);

    return report;
}

Result<BootSectorComparison> BootSectorParser::inspect_volume(VolumeReader& volume) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    HANDLE handle = volume.native_handle();
    std::vector<uint8_t> prim_buf(512, 0);

    LARGE_INTEGER seek_prim{};
    seek_prim.QuadPart = 0;
    if (!SetFilePointerEx(handle, seek_prim, nullptr, FILE_BEGIN)) {
        return Error(GetLastError(), L"Failed to seek to primary boot sector (LBA 0)");
    }

    DWORD bytes_read = 0;
    if (!ReadFile(handle, prim_buf.data(), 512, &bytes_read, nullptr) || bytes_read < 512) {
        return Error(GetLastError(), L"Failed to read primary boot sector");
    }

    auto prim_res = parse_buffer(prim_buf.data(), prim_buf.size(), volume.drive_letter());
    if (!prim_res) {
        return prim_res.error();
    }

    BootSectorComparison comp{};
    comp.primary = prim_res.value();

    if (comp.primary.total_sectors > 0 && comp.primary.bytes_per_sector > 0) {
        LARGE_INTEGER seek_backup{};
        seek_backup.QuadPart = static_cast<LONGLONG>(
            (comp.primary.total_sectors - 1) * comp.primary.bytes_per_sector
        );

        std::vector<uint8_t> backup_buf(512, 0);
        if (SetFilePointerEx(handle, seek_backup, nullptr, FILE_BEGIN)) {
            DWORD backup_read = 0;
            if (ReadFile(handle, backup_buf.data(), 512, &backup_read, nullptr) && backup_read == 512) {
                auto backup_res = parse_buffer(backup_buf.data(), backup_buf.size(), volume.drive_letter());
                if (backup_res) {
                    comp.backup = backup_res.value();
                    comp.has_backup = true;
                    comp.sectors_match = (std::memcmp(prim_buf.data(), backup_buf.data(), 512) == 0);

                    if (comp.sectors_match) {
                        comp.notes = L"Primary and backup boot sectors are identical and verified";
                    } else {
                        comp.notes = L"Warning: Primary and backup boot sectors diverge";
                    }
                    return comp;
                }
            }
        }
    }

    comp.has_backup = false;
    comp.notes = L"Primary boot sector verified; backup sector unreadable or out of bounds";
    return comp;
}

} // namespace mftscan
