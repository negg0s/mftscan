#include "mftscan/logfile.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <vector>

namespace mftscan {

Result<LogFileReport> LogFileAnalyzer::analyze_from_page(
    const uint8_t* page_buffer,
    size_t page_size,
    wchar_t volume_letter
) {
    if (!page_buffer || page_size < sizeof(LogFileRestartPageHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Page buffer too small for $LogFile restart header");
    }

    const auto* raw_header = reinterpret_cast<const LogFileRestartPageHeader*>(page_buffer);
    if (raw_header->magic != kLogFileMagicRstr) {
        return Error(ERROR_INVALID_DATA, L"Page buffer does not begin with RSTR magic");
    }

    std::vector<uint8_t> page_copy(page_buffer, page_buffer + page_size);

    // Apply USA fixup for the 512-byte sectors of the page
    if (raw_header->update_sequence_offset > 0 && raw_header->update_sequence_size > 1) {
        const uint16_t usa_offset = raw_header->update_sequence_offset;
        const uint16_t usa_count = raw_header->update_sequence_size;

        if (usa_offset + usa_count * sizeof(uint16_t) <= page_size) {
            const auto* usa = reinterpret_cast<const uint16_t*>(page_copy.data() + usa_offset);
            const uint16_t tag = usa[0];
            const uint16_t num_sectors = usa_count - 1;

            for (uint16_t s = 0; s < num_sectors; ++s) {
                const size_t sector_end_pos = (static_cast<size_t>(s) + 1) * 512 - 2;
                if (sector_end_pos + sizeof(uint16_t) <= page_size) {
                    auto* sector_end = reinterpret_cast<uint16_t*>(page_copy.data() + sector_end_pos);
                    if (*sector_end == tag) {
                        *sector_end = usa[s + 1];
                    }
                }
            }
        }
    }

    const auto* header = reinterpret_cast<const LogFileRestartPageHeader*>(page_copy.data());
    if (header->restart_area_offset + sizeof(LogFileRestartArea) > page_size) {
        return Error(ERROR_INVALID_DATA, L"Restart area offset exceeds page boundaries");
    }

    const auto* area = reinterpret_cast<const LogFileRestartArea*>(
        page_copy.data() + header->restart_area_offset
    );

    LogFileReport report{};
    report.volume_letter = volume_letter;
    report.is_valid_rstr = true;
    report.magic = header->magic;
    report.major_version = header->major_version;
    report.minor_version = header->minor_version;
    report.system_page_size = header->system_page_size;
    report.log_page_size = header->log_page_size;

    report.current_lsn = area->current_lsn;
    report.log_clients = area->log_clients;
    report.restart_flags = area->flags;
    report.is_clean_shutdown = (area->flags & kLogFileCleanShutdown) != 0;
    report.file_size = area->file_size;
    report.restart_open_log_count = area->restart_open_log_count;

    if (report.is_clean_shutdown) {
        report.extra_notes = L"Clean filesystem state (no redo/undo replay pending)";
    } else {
        report.extra_notes = L"Active or dirty unmount state (replay pending)";
    }

    return report;
}

Result<LogFileReport> LogFileAnalyzer::analyze(VolumeReader& volume) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> buffer(rec_size);

    auto res = volume.read_file_record(kRecordLogFile, buffer.data(), rec_size);
    if (!res) {
        return res.error();
    }

    RecordParser::apply_fixup(buffer.data(), rec_size, volume.geometry().bytes_per_sector);

    const auto* mft_hdr = reinterpret_cast<const MftRecordHeader*>(buffer.data());
    if (mft_hdr->magic != kMftMagicFile && mft_hdr->magic != kMftMagicBaad) {
        return Error(ERROR_INVALID_DATA, L"Record 2 ($LogFile) magic is not FILE");
    }

    uint32_t offset = mft_hdr->first_attribute_offset;
    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(buffer.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > rec_size) {
            break;
        }

        if (attr->type_code == kAttrData && attr->name_length == 0) {
            if (attr->non_resident_flag == 0) {
                // Resident (unlikely for $LogFile, but handled)
                const uint16_t val_off = attr->resident.value_offset;
                const uint32_t val_len = attr->resident.value_length;
                if (val_off + val_len <= attr->record_length) {
                    return analyze_from_page(buffer.data() + offset + val_off, val_len, volume.drive_letter());
                }
            } else {
                // Non-resident
                const uint16_t runs_off = attr->non_resident.data_runs_offset;
                if (runs_off < attr->record_length) {
                    const uint8_t* run_ptr = buffer.data() + offset + runs_off;
                    const size_t max_run_bytes = attr->record_length - runs_off;
                    auto extents = DataRunDecoder::decode_mapping_pairs(
                        run_ptr,
                        max_run_bytes,
                        attr->non_resident.starting_vcn
                    );

                    for (const auto& ext : extents) {
                        if (!ext.is_sparse && ext.starting_lcn > 0) {
                            LARGE_INTEGER seek_pos{};
                            seek_pos.QuadPart = static_cast<LONGLONG>(
                                ext.starting_lcn * volume.geometry().bytes_per_cluster
                            );

                            if (SetFilePointerEx(volume.native_handle(), seek_pos, nullptr, FILE_BEGIN)) {
                                std::vector<uint8_t> page_buf(4096);
                                DWORD bytes_read = 0;
                                if (ReadFile(volume.native_handle(), page_buf.data(), 4096, &bytes_read, nullptr) && bytes_read >= 512) {
                                    return analyze_from_page(page_buf.data(), bytes_read, volume.drive_letter());
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }

        offset += attr->record_length;
    }

    return Error(ERROR_NOT_FOUND, L"Failed to locate or read $DATA stream in $LogFile record");
}

} // namespace mftscan
