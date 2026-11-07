#include "mftscan/secure.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

namespace mftscan {

std::wstring SecureAnalyzer::sid_to_string(const uint8_t* sid_bytes, size_t max_bytes) {
    if (!sid_bytes || max_bytes < 8) {
        return L"";
    }

    const uint8_t revision = sid_bytes[0];
    const uint8_t sub_count = sid_bytes[1];

    if (max_bytes < 8 + static_cast<size_t>(sub_count) * sizeof(uint32_t)) {
        return L"";
    }

    uint64_t authority = 0;
    for (int i = 0; i < 6; ++i) {
        authority = (authority << 8) | sid_bytes[2 + i];
    }

    std::wstring result = L"S-" + std::to_wstring(revision) + L"-" + std::to_wstring(authority);

    const auto* sub_auth = reinterpret_cast<const uint32_t*>(sid_bytes + 8);
    for (uint8_t i = 0; i < sub_count; ++i) {
        result += L"-" + std::to_wstring(sub_auth[i]);
    }

    return result;
}

SecureDatabaseReport SecureAnalyzer::parse_sds_buffer(
    const uint8_t* sds_data,
    size_t sds_size,
    const std::vector<RecordInfo>& records,
    wchar_t drive_letter
) {
    SecureDatabaseReport report{};
    report.volume_letter = drive_letter;
    report.total_sds_stream_bytes = sds_size;

    if (!sds_data || sds_size < sizeof(SdsEntryHeader) + sizeof(RawSecurityDescriptorRelative)) {
        return report;
    }

    report.valid = true;

    // Count occurrences of each security_id across all files on volume
    std::unordered_map<uint32_t, size_t> file_sec_counts;
    size_t total_scanned_files = 0;
    for (const auto& rec : records) {
        if (!rec.is_deleted && rec.security_id != 0) {
            ++file_sec_counts[rec.security_id];
            ++total_scanned_files;
        }
    }

    std::unordered_set<uint32_t> found_sds_sec_ids;

    size_t cursor = 0;
    while (cursor + sizeof(SdsEntryHeader) <= sds_size) {
        const auto* hdr = reinterpret_cast<const SdsEntryHeader*>(sds_data + cursor);

        // Check for padding/slack block at end of 256KB pool
        if (hdr->length == 0 || hdr->length > 65536) {
            // Seek to next 256KB boundary or advance 16 bytes
            size_t next_boundary = ((cursor + 0x40000) / 0x40000) * 0x40000;
            if (next_boundary > cursor && next_boundary < sds_size) {
                cursor = next_boundary;
                continue;
            }
            break;
        }

        if (cursor + hdr->length > sds_size) {
            break;
        }

        SdsDescriptorInfo info{};
        info.security_id = hdr->security_id;
        info.hash = hdr->hash;
        info.offset = hdr->offset;
        info.length = hdr->length;

        found_sds_sec_ids.insert(hdr->security_id);

        auto it = file_sec_counts.find(hdr->security_id);
        if (it != file_sec_counts.end()) {
            info.referenced_file_count = it->second;
            ++report.active_referenced_entries;
        } else {
            info.is_orphaned = true;
            ++report.orphaned_entries;
        }

        const size_t sd_offset = cursor + sizeof(SdsEntryHeader);
        const size_t sd_bytes = hdr->length - sizeof(SdsEntryHeader);

        if (sd_bytes >= sizeof(RawSecurityDescriptorRelative)) {
            const auto* sd = reinterpret_cast<const RawSecurityDescriptorRelative*>(sds_data + sd_offset);
            info.control_flags = sd->control;

            // Owner SID
            if (sd->owner_offset > 0 && sd->owner_offset + 8 <= sd_bytes) {
                info.owner_sid_str = sid_to_string(sds_data + sd_offset + sd->owner_offset, sd_bytes - sd->owner_offset);
            }

            // Group SID
            if (sd->group_offset > 0 && sd->group_offset + 8 <= sd_bytes) {
                info.group_sid_str = sid_to_string(sds_data + sd_offset + sd->group_offset, sd_bytes - sd->group_offset);
            }

            // DACL
            if (sd->dacl_offset == 0) {
                info.has_dacl = false;
                info.is_dacl_null = true;
                ++report.null_dacl_descriptors;
            } else if (sd->dacl_offset + sizeof(RawAclHeader) <= sd_bytes) {
                info.has_dacl = true;
                const auto* acl = reinterpret_cast<const RawAclHeader*>(sds_data + sd_offset + sd->dacl_offset);
                info.ace_count = acl->ace_count;

                if (acl->ace_count == 0) {
                    info.is_dacl_empty = true;
                } else {
                    size_t ace_cursor = sd_offset + sd->dacl_offset + sizeof(RawAclHeader);
                    const size_t acl_end = sd_offset + sd->dacl_offset + acl->acl_size;

                    for (uint16_t ace_idx = 0; ace_idx < acl->ace_count && ace_cursor + sizeof(RawAceHeader) <= acl_end && ace_cursor + sizeof(RawAceHeader) <= sds_size; ++ace_idx) {
                        const auto* ace = reinterpret_cast<const RawAceHeader*>(sds_data + ace_cursor);
                        if (ace->ace_size < sizeof(RawAceHeader) || ace_cursor + ace->ace_size > acl_end) {
                            break;
                        }

                        // Type 0 = ACCESS_ALLOWED_ACE_TYPE
                        if (ace->ace_type == 0 && ace->ace_size >= sizeof(RawAceHeader) + sizeof(uint32_t) + 8) {
                            const uint32_t mask = *reinterpret_cast<const uint32_t*>(sds_data + ace_cursor + sizeof(RawAceHeader));
                            const uint8_t* ace_sid = sds_data + ace_cursor + sizeof(RawAceHeader) + sizeof(uint32_t);
                            const size_t ace_sid_max = ace->ace_size - sizeof(RawAceHeader) - sizeof(uint32_t);
                            std::wstring ace_sid_str = sid_to_string(ace_sid, ace_sid_max);

                            constexpr uint32_t kWriteMask = 0x0002 | 0x0004 | 0x0010 | 0x00020000 | 0x40000000 | 0x10000000;
                            if ((mask & kWriteMask) && (ace_sid_str == L"S-1-1-0" || ace_sid_str == L"S-1-5-11")) {
                                info.is_world_writable = true;
                            }
                        }

                        ace_cursor += ace->ace_size;
                    }
                }
            }
        }

        if (info.is_world_writable) {
            ++report.world_writable_descriptors;
        }

        report.descriptors.push_back(std::move(info));

        // Advance aligned to 16 bytes
        cursor += ((hdr->length + 15) / 16) * 16;
    }

    report.total_sds_entries = report.descriptors.size();

    // Check for files pointing to nonexistent security_id
    for (const auto& pair : file_sec_counts) {
        if (found_sds_sec_ids.find(pair.first) == found_sds_sec_ids.end()) {
            report.unreferenced_security_ids_count += pair.second;
        }
    }

    if (total_scanned_files > 0 && report.total_sds_entries > 0) {
        report.deduplication_ratio = (1.0 - (static_cast<double>(report.total_sds_entries) / static_cast<double>(total_scanned_files))) * 100.0;
        if (report.deduplication_ratio < 0.0) {
            report.deduplication_ratio = 0.0;
        }
    }

    return report;
}

Result<SecureDatabaseReport> SecureAnalyzer::inspect(
    VolumeReader& volume,
    const std::vector<RecordInfo>& records
) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> rec_buf(rec_size);

    auto read_res = volume.read_file_record(9, rec_buf.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    if (!RecordParser::apply_fixup(rec_buf.data(), rec_size, volume.geometry().bytes_per_sector)) {
        return Error(ERROR_INVALID_DATA, L"Fixup failed on Record 9 ($Secure)");
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
    if (header->magic != kMftMagicFile) {
        return Error(ERROR_INVALID_DATA, L"Record 9 does not have FILE signature");
    }

    uint32_t offset = header->first_attribute_offset;
    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_buf.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > rec_size) {
            break;
        }

        if (attr->type_code == kAttrData && attr->name_length > 0) {
            if (attr->name_offset + attr->name_length * sizeof(wchar_t) <= attr->record_length) {
                const auto* name_ptr = reinterpret_cast<const wchar_t*>(rec_buf.data() + offset + attr->name_offset);
                std::wstring stream_name(name_ptr, attr->name_length);

                if (stream_name == L"$SDS") {
                    if (attr->non_resident_flag == 0) {
                        // Resident $SDS
                        const uint32_t val_len = attr->resident.value_length;
                        const uint16_t val_off = attr->resident.value_offset;
                        if (val_off + val_len <= attr->record_length) {
                            const uint8_t* payload = rec_buf.data() + offset + val_off;
                            return parse_sds_buffer(payload, val_len, records, volume.drive_letter());
                        }
                    } else {
                        // Non-resident $SDS
                        const uint64_t real_size = attr->non_resident.real_size;
                        const uint16_t runs_off = attr->non_resident.data_runs_offset;
                        if (runs_off < attr->record_length) {
                            const uint8_t* run_ptr = rec_buf.data() + offset + runs_off;
                            const size_t max_run_bytes = attr->record_length - runs_off;

                            auto extents = DataRunDecoder::decode_mapping_pairs(
                                run_ptr,
                                max_run_bytes,
                                attr->non_resident.starting_vcn
                            );

                            std::vector<uint8_t> sds_payload;
                            sds_payload.reserve(static_cast<size_t>(real_size));

                            const uint32_t cluster_size = volume.geometry().bytes_per_cluster;
                            std::vector<uint8_t> cluster_buf(cluster_size);

                            uint64_t bytes_remaining = real_size;
                            HANDLE h_vol = volume.native_handle();

                            for (const auto& ext : extents) {
                                if (bytes_remaining == 0) {
                                    break;
                                }
                                if (ext.is_sparse || ext.starting_lcn <= 0) {
                                    const uint64_t span = std::min(ext.cluster_count * cluster_size, bytes_remaining);
                                    sds_payload.insert(sds_payload.end(), static_cast<size_t>(span), uint8_t{0});
                                    bytes_remaining -= span;
                                    continue;
                                }

                                for (uint64_t c = 0; c < ext.cluster_count && bytes_remaining > 0; ++c) {
                                    LARGE_INTEGER seek_pos{};
                                    seek_pos.QuadPart = (ext.starting_lcn + c) * cluster_size;
                                    if (!SetFilePointerEx(h_vol, seek_pos, nullptr, FILE_BEGIN)) {
                                        break;
                                    }

                                    DWORD bytes_read = 0;
                                    if (!ReadFile(h_vol, cluster_buf.data(), cluster_size, &bytes_read, nullptr) || bytes_read == 0) {
                                        break;
                                    }

                                    const uint32_t to_copy = static_cast<uint32_t>(std::min<uint64_t>(bytes_remaining, bytes_read));
                                    sds_payload.insert(sds_payload.end(), cluster_buf.data(), cluster_buf.data() + to_copy);
                                    bytes_remaining -= to_copy;
                                }
                            }

                            return parse_sds_buffer(sds_payload.data(), sds_payload.size(), records, volume.drive_letter());
                        }
                    }
                }
            }
        }

        offset += attr->record_length;
    }

    return Error(ERROR_NOT_FOUND, L"Failed to locate $SDS stream in Record 9 ($Secure)");
}

void SecureAnalyzer::print_report(const SecureDatabaseReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS SECURITY DESCRIPTOR DATABASE ($Secure:$SDS) AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Volume Letter        : " << report.volume_letter << L":\n";
    std::wcout << L"  Total $SDS Entries   : " << report.total_sds_entries << L"\n";
    std::wcout << L"  Active Referenced    : " << report.active_referenced_entries << L"\n";
    std::wcout << L"  Orphaned Descriptors : " << report.orphaned_entries << L" (defined in $SDS, 0 files point to them)\n";
    std::wcout << L"  Unresolved File IDs  : " << report.unreferenced_security_ids_count << L" (files referencing missing Security ID)\n";
    std::wcout << L"  Total $SDS Stream    : " << Formatter::format_bytes(report.total_sds_stream_bytes) << L"\n";
    std::wcout << L"  Deduplication Ratio  : " << std::fixed << std::setprecision(2) << report.deduplication_ratio << L"%\n";
    std::wcout << L"  World-Writable Descr : " << report.world_writable_descriptors << L"\n";
    std::wcout << L"  NULL DACL Descr      : " << report.null_dacl_descriptors << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(12) << L"Security ID"
               << std::setw(12) << L"Hash"
               << std::setw(10) << L"Length"
               << std::setw(8)  << L"Files"
               << std::setw(28) << L"Owner SID"
               << std::setw(10) << L"ACEs"
               << L"Flags\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    const size_t show_count = std::min<size_t>(report.descriptors.size(), 30);
    for (size_t i = 0; i < show_count; ++i) {
        const auto& d = report.descriptors[i];
        std::wstring flags;
        if (d.is_world_writable) flags += L"WORLD_WRITE ";
        if (d.is_dacl_null) flags += L"NULL_DACL ";
        if (d.is_dacl_empty) flags += L"EMPTY_DACL ";
        if (d.is_orphaned) flags += L"ORPHAN ";
        if (flags.empty()) flags = L"OK";
        else if (flags.back() == L' ') flags.pop_back();

        std::wcout << std::left
                   << L"0x" << std::hex << std::setw(10) << std::uppercase << d.security_id << std::dec
                   << L"0x" << std::hex << std::setw(10) << std::uppercase << d.hash << std::dec
                   << std::setw(10) << d.length
                   << std::setw(8)  << d.referenced_file_count
                   << std::setw(28) << (d.owner_sid_str.empty() ? L"N/A" : d.owner_sid_str)
                   << std::setw(10) << d.ace_count
                   << flags << L"\n";
    }

    if (report.descriptors.size() > show_count) {
        std::wcout << L"  ... and " << (report.descriptors.size() - show_count) << L" more security descriptors.\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
