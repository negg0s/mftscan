#include "mftscan/volume_info.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

VolumeInfoReport VolumeInfoAnalyzer::parse_record_buffer(
    const uint8_t* record_data,
    uint32_t record_size,
    uint32_t sector_size,
    wchar_t drive_letter
) {
    VolumeInfoReport report{};
    report.volume_letter = drive_letter;

    if (!record_data || record_size < sizeof(MftRecordHeader)) {
        return report;
    }

    std::vector<uint8_t> rec_copy(record_data, record_data + record_size);
    if (!RecordParser::apply_fixup(rec_copy.data(), record_size, sector_size)) {
        return report;
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(rec_copy.data());
    if (header->magic != kMftMagicFile) {
        return report;
    }

    report.valid = true;

    uint32_t offset = header->first_attribute_offset;
    while (offset + sizeof(AttributeRecordHeader) <= record_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_copy.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > record_size) {
            break;
        }

        // 1. $STANDARD_INFORMATION (0x10)
        if (attr->type_code == kAttrStandardInformation && attr->non_resident_flag == 0) {
            const uint32_t val_len = attr->resident.value_length;
            const uint16_t val_off = attr->resident.value_offset;
            if (val_off + sizeof(StandardInformation) <= attr->record_length && val_len >= sizeof(StandardInformation)) {
                const auto* si = reinterpret_cast<const StandardInformation*>(rec_copy.data() + offset + val_off);
                report.volume_creation_time = si->creation_time;
                report.volume_modification_time = si->modification_time;
                report.creation_time_str = Formatter::format_filetime(si->creation_time);
                report.modification_time_str = Formatter::format_filetime(si->modification_time);
            }
        }
        // 2. $VOLUME_NAME (0x60)
        else if (attr->type_code == kAttrVolumeName && attr->non_resident_flag == 0) {
            const uint32_t val_len = attr->resident.value_length;
            const uint16_t val_off = attr->resident.value_offset;
            if (val_off + val_len <= attr->record_length && val_len > 0) {
                const auto* name_chars = reinterpret_cast<const wchar_t*>(rec_copy.data() + offset + val_off);
                const size_t char_count = val_len / sizeof(wchar_t);
                report.volume_label = std::wstring(name_chars, char_count);
            }
        }
        // 3. $VOLUME_INFORMATION (0x70)
        else if (attr->type_code == kAttrVolumeInformation && attr->non_resident_flag == 0) {
            const uint32_t val_len = attr->resident.value_length;
            const uint16_t val_off = attr->resident.value_offset;
            if (val_off + sizeof(RawVolumeInformationAttr) <= attr->record_length && val_len >= sizeof(RawVolumeInformationAttr)) {
                const auto* vi = reinterpret_cast<const RawVolumeInformationAttr*>(rec_copy.data() + offset + val_off);
                report.major_version = vi->major_version;
                report.minor_version = vi->minor_version;
                report.ntfs_version_str = std::to_wstring(vi->major_version) + L"." + std::to_wstring(vi->minor_version);
                report.flags_raw = vi->flags;

                if (vi->flags & kVolFlagDirty) {
                    report.is_dirty = true;
                    report.flag_descriptions.push_back(L"VOLUME_IS_DIRTY");
                }
                if (vi->flags & kVolFlagResizeLogFile) {
                    report.resize_log_file = true;
                    report.flag_descriptions.push_back(L"VOLUME_RESIZE_LOG_FILE");
                }
                if (vi->flags & kVolFlagUpgradeOnMount) {
                    report.upgrade_on_mount = true;
                    report.flag_descriptions.push_back(L"VOLUME_UPGRADE_ON_MOUNT");
                }
                if (vi->flags & kVolFlagMountedOnNt4) {
                    report.flag_descriptions.push_back(L"VOLUME_MOUNTED_ON_NT4");
                }
                if (vi->flags & kVolFlagDeleteUsnUnderway) {
                    report.delete_usn_underway = true;
                    report.flag_descriptions.push_back(L"VOLUME_DELETE_USN_UNDERWAY");
                }
                if (vi->flags & kVolFlagRepairObjectId) {
                    report.repair_object_id = true;
                    report.flag_descriptions.push_back(L"VOLUME_REPAIR_OBJECT_ID");
                }
                if (vi->flags & kVolFlagChkdskRan) {
                    report.chkdsk_ran = true;
                    report.flag_descriptions.push_back(L"VOLUME_CHKDSK_RAN");
                }
                if (vi->flags & kVolFlagModifiedByChkdsk) {
                    report.modified_by_chkdsk = true;
                    report.flag_descriptions.push_back(L"VOLUME_MODIFIED_BY_CHKDSK");
                }
            }
        }

        offset += attr->record_length;
    }

    if (report.volume_label.empty()) {
        report.volume_label = L"(Unlabeled Volume)";
    }

    if (report.is_dirty) {
        report.health_assessment = L"DIRTY (Autochk / Chkdsk required on next boot)";
    } else if (report.modified_by_chkdsk) {
        report.health_assessment = L"CLEAN (Previously repaired by Chkdsk)";
    } else {
        report.health_assessment = L"CLEAN (Consistent filesystem metadata)";
    }

    return report;
}

Result<VolumeInfoReport> VolumeInfoAnalyzer::inspect(VolumeReader& volume) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> rec_buf(rec_size);

    auto read_res = volume.read_file_record(3, rec_buf.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    auto rep = parse_record_buffer(
        rec_buf.data(),
        rec_size,
        volume.geometry().bytes_per_sector,
        volume.drive_letter()
    );

    if (!rep.valid) {
        return Error(ERROR_INVALID_DATA, L"Failed to parse Record 3 ($Volume)");
    }

    return rep;
}

void VolumeInfoAnalyzer::print_report(const VolumeInfoReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS VOLUME INFORMATION AND DIRTY STATE AUDIT ($Volume)\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Volume Letter        : " << report.volume_letter << L":\n";
    std::wcout << L"  Volume Label         : " << report.volume_label << L"\n";
    std::wcout << L"  NTFS Version         : " << report.ntfs_version_str << L"\n";
    std::wcout << L"  Health Assessment    : " << report.health_assessment << L"\n";
    std::wcout << L"  Dirty Flag (0x0001)  : " << (report.is_dirty ? L"TRUE (CORRUPTED / UNCLEAN)" : L"FALSE (CLEAN)") << L"\n";
    std::wcout << L"  Chkdsk Ran (0x4000)  : " << (report.chkdsk_ran ? L"YES" : L"NO") << L"\n";
    std::wcout << L"  Chkdsk Modified(0x80): " << (report.modified_by_chkdsk ? L"YES (Metadata altered by repair)" : L"NO") << L"\n";
    std::wcout << L"  Resize Log (0x0002)  : " << (report.resize_log_file ? L"YES" : L"NO") << L"\n";
    std::wcout << L"  Flags Raw Hex        : 0x" << std::hex << std::setw(4) << std::setfill(L'0') << std::uppercase << report.flags_raw << std::dec << std::setfill(L' ') << L"\n";

    if (!report.flag_descriptions.empty()) {
        std::wcout << L"  Active Flags         : ";
        for (size_t i = 0; i < report.flag_descriptions.size(); ++i) {
            std::wcout << report.flag_descriptions[i] << (i + 1 < report.flag_descriptions.size() ? L", " : L"");
        }
        std::wcout << L"\n";
    }

    if (report.volume_creation_time > 0) {
        std::wcout << L"  Volume Created       : " << report.creation_time_str << L"\n";
    }
    if (report.volume_modification_time > 0) {
        std::wcout << L"  Volume Modified      : " << report.modification_time_str << L"\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
