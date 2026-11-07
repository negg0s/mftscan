#include "mftscan/system_files.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/inspector.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <vector>

namespace mftscan {

const wchar_t* SystemFilesInspector::get_standard_system_name(uint64_t frn) noexcept {
    switch (frn) {
    case 0:  return L"$MFT";
    case 1:  return L"$MFTMirr";
    case 2:  return L"$LogFile";
    case 3:  return L"$Volume";
    case 4:  return L"$AttrDef";
    case 5:  return L". (Root)";
    case 6:  return L"$Bitmap";
    case 7:  return L"$Boot";
    case 8:  return L"$BadClus";
    case 9:  return L"$Secure";
    case 10: return L"$UpCase";
    case 11: return L"$Extend";
    default: return L"$Reserved";
    }
}

const wchar_t* SystemFilesInspector::get_standard_system_purpose(uint64_t frn) noexcept {
    switch (frn) {
    case 0:  return L"Master File Table primary database";
    case 1:  return L"Duplicate mirror of first four MFT records";
    case 2:  return L"Transactional journal and restart logging area";
    case 3:  return L"Volume label, version, and integrity flags";
    case 4:  return L"NTFS attribute definition table";
    case 5:  return L"Filesystem root directory node";
    case 6:  return L"Volume cluster allocation bitmap";
    case 7:  return L"Volume bootstrap code and BIOS parameter block";
    case 8:  return L"Hardware bad cluster defect tracking";
    case 9:  return L"Security descriptor database ($SDS, $SDH, $SII)";
    case 10: return L"Unicode uppercase conversion table";
    case 11: return L"Extension directory for optional metadata features";
    default: return L"Reserved NTFS metadata segment";
    }
}

Result<SystemAuditReport> SystemFilesInspector::inspect(VolumeReader& volume) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    SystemAuditReport report{};
    report.volume_letter = volume.drive_letter();

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> buffer(rec_size);

    for (uint64_t frn = 0; frn <= 11; ++frn) {
        SystemFileInfo info{};
        info.frn = frn;
        info.standard_name = get_standard_system_name(frn);
        info.purpose = get_standard_system_purpose(frn);

        auto read_res = volume.read_file_record(frn, buffer.data(), rec_size);
        if (!read_res) {
            info.is_present = false;
            info.extra_info = L"Unreadable / not present";
            report.files.push_back(std::move(info));
            continue;
        }

        info.is_present = true;
        RecordParser::apply_fixup(buffer.data(), rec_size, volume.geometry().bytes_per_sector);

        const auto* header = reinterpret_cast<const MftRecordHeader*>(buffer.data());
        if (header->magic != kMftMagicFile && header->magic != kMftMagicBaad) {
            info.extra_info = L"Invalid record magic";
            report.files.push_back(std::move(info));
            continue;
        }

        uint32_t offset = header->first_attribute_offset;
        while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
            const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(buffer.data() + offset);
            if (attr->type_code == kAttrEnd || attr->record_length == 0) {
                break;
            }
            if (offset + attr->record_length > rec_size) {
                break;
            }

            info.attribute_types.push_back(RecordInspector::attribute_type_to_string(attr->type_code));

            if (attr->type_code == kAttrData) {
                bool is_default_data = (attr->name_length == 0);
                std::wstring stream_name;
                if (attr->name_length > 0 && attr->name_offset + attr->name_length * sizeof(wchar_t) <= attr->record_length) {
                    const auto* name_chars = reinterpret_cast<const wchar_t*>(buffer.data() + offset + attr->name_offset);
                    stream_name = std::wstring(name_chars, attr->name_length);
                }

                if (attr->non_resident_flag == 0) {
                    if (is_default_data) {
                        info.is_resident = true;
                        info.size_bytes = attr->resident.value_length;
                        info.allocated_bytes = attr->resident.value_length;
                        info.fragment_count = 1;
                    }
                } else {
                    if (is_default_data || frn == 8) {
                        info.is_resident = false;
                        info.size_bytes = attr->non_resident.real_size;
                        info.allocated_bytes = attr->non_resident.allocated_size;

                        const uint16_t runs_off = attr->non_resident.data_runs_offset;
                        if (runs_off < attr->record_length) {
                            const uint8_t* run_ptr = buffer.data() + offset + runs_off;
                            const size_t max_run_bytes = attr->record_length - runs_off;
                            auto extents = DataRunDecoder::decode_mapping_pairs(
                                run_ptr,
                                max_run_bytes,
                                attr->non_resident.starting_vcn
                            );
                            info.fragment_count = static_cast<uint32_t>(extents.size());

                            if (frn == 8 && stream_name == L"$Bad") {
                                uint64_t bad_clusters = 0;
                                for (const auto& ext : extents) {
                                    if (!ext.is_sparse) {
                                        bad_clusters += ext.cluster_count;
                                    }
                                }
                                report.bad_clusters_count = bad_clusters;
                                if (bad_clusters > 0) {
                                    info.extra_info += L"Bad clusters: " + std::to_wstring(bad_clusters) + L"; ";
                                }
                            }
                        }
                    }
                }
            } else if (attr->type_code == kAttrVolumeInformation) {
                if (attr->non_resident_flag == 0 && attr->resident.value_length >= sizeof(VolumeInformationPayload)) {
                    const uint16_t val_off = attr->resident.value_offset;
                    if (val_off + sizeof(VolumeInformationPayload) <= attr->record_length) {
                        const auto* payload = reinterpret_cast<const VolumeInformationPayload*>(
                            buffer.data() + offset + val_off
                        );
                        report.ntfs_major_version = payload->major_version;
                        report.ntfs_minor_version = payload->minor_version;
                        report.volume_flags = payload->volume_flags;
                        report.is_dirty = (payload->volume_flags & kVolumeDirty) != 0;

                        info.extra_info += L"NTFS v" + std::to_wstring(payload->major_version) +
                                           L"." + std::to_wstring(payload->minor_version);
                        if (report.is_dirty) {
                            info.extra_info += L" [DIRTY BIT SET]";
                        }
                    }
                }
            } else if (attr->type_code == kAttrIndexRoot) {
                if (frn == 5 || frn == 11) {
                    info.is_resident = true;
                    info.extra_info += L"Directory index root";
                }
            }

            offset += attr->record_length;
        }

        report.files.push_back(std::move(info));
    }

    return report;
}

} // namespace mftscan
