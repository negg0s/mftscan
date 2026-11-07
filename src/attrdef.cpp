#include "mftscan/attrdef.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

std::wstring AttrDefAnalyzer::collation_rule_to_string(uint32_t rule) {
    switch (rule) {
    case 0x00: return L"BINARY";
    case 0x01: return L"FILE_NAME";
    case 0x02: return L"UNICODE";
    case 0x10: return L"ULONG";
    case 0x11: return L"SID";
    case 0x12: return L"SECURITY_HASH";
    case 0x13: return L"MULTIPLE_ULONG";
    default:   return L"CUSTOM_" + std::to_wstring(rule);
    }
}

std::wstring AttrDefAnalyzer::flags_to_string(uint32_t flags) {
    std::wstring result;
    if (flags & 0x02) {
        result += L"INDEXABLE ";
    }
    if (flags & 0x40) {
        result += L"MULTIPLE ";
    }
    if (flags & 0x80) {
        result += L"NOT_RESIDENT ";
    }
    if (result.empty()) {
        result = L"NONE";
    } else if (result.back() == L' ') {
        result.pop_back();
    }
    return result;
}

bool AttrDefAnalyzer::is_standard_type(uint32_t type_code) {
    switch (type_code) {
    case kAttrStandardInformation:
    case kAttrAttributeList:
    case kAttrFileName:
    case kAttrObjectId:
    case kAttrSecurityDescriptor:
    case kAttrVolumeName:
    case kAttrVolumeInformation:
    case kAttrData:
    case kAttrIndexRoot:
    case kAttrIndexAllocation:
    case kAttrBitmap:
    case kAttrReparsePoint:
    case kAttrEaInformation:
    case kAttrEa:
    case kAttrPropertySet:
    case kAttrLoggedUtilityStream:
        return true;
    default:
        return false;
    }
}

AttrDefReport AttrDefAnalyzer::parse_from_buffer(const uint8_t* data, size_t size, wchar_t drive_letter) {
    AttrDefReport report{};
    report.volume_letter = drive_letter;
    report.record_frn = 4;

    if (!data || size < sizeof(RawAttrDefEntry)) {
        return report;
    }

    report.valid = true;
    const size_t entry_count = size / sizeof(RawAttrDefEntry);

    for (size_t i = 0; i < entry_count; ++i) {
        const auto* raw = reinterpret_cast<const RawAttrDefEntry*>(data + i * sizeof(RawAttrDefEntry));

        // Stop if name is empty or type code is zero
        if (raw->name[0] == 0 || raw->type_code == 0) {
            break;
        }

        AttrDefEntryInfo entry{};
        // Name is null-terminated or up to 64 wchar_t
        size_t name_len = 0;
        while (name_len < 64 && raw->name[name_len] != 0) {
            ++name_len;
        }
        entry.name = std::wstring(raw->name, name_len);
        entry.type_code = raw->type_code;
        entry.display_rule = raw->display_rule;
        entry.collation_rule = raw->collation_rule;
        entry.collation_name = collation_rule_to_string(raw->collation_rule);
        entry.flags = raw->flags;
        entry.is_indexable = (raw->flags & 0x02) != 0;
        entry.allows_multiple = (raw->flags & 0x40) != 0;
        entry.not_resident = (raw->flags & 0x80) != 0;
        entry.min_size = raw->min_size;
        entry.max_size = raw->max_size;
        entry.is_custom = !is_standard_type(raw->type_code);

        if (entry.is_custom) {
            ++report.custom_types_count;
        } else {
            ++report.standard_types_count;
        }
        if (entry.is_indexable) {
            ++report.indexable_count;
        }
        if (entry.allows_multiple) {
            ++report.multiple_count;
        }

        report.entries.push_back(std::move(entry));
    }

    report.total_definitions = report.entries.size();
    return report;
}

Result<AttrDefReport> AttrDefAnalyzer::inspect(VolumeReader& volume) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> rec_buf(rec_size);

    auto read_res = volume.read_file_record(4, rec_buf.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    if (!RecordParser::apply_fixup(rec_buf.data(), rec_size, volume.geometry().bytes_per_sector)) {
        return Error(ERROR_INVALID_DATA, L"Fixup failed on Record 4 ($AttrDef)");
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
    if (header->magic != kMftMagicFile) {
        return Error(ERROR_INVALID_DATA, L"Record 4 does not have FILE signature");
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

        if (attr->type_code == kAttrData && attr->name_length == 0) {
            if (attr->non_resident_flag == 0) {
                // Resident $DATA in Record 4
                const uint32_t val_len = attr->resident.value_length;
                const uint16_t val_off = attr->resident.value_offset;
                if (val_off + val_len <= attr->record_length) {
                    const uint8_t* payload = rec_buf.data() + offset + val_off;
                    return parse_from_buffer(payload, val_len, volume.drive_letter());
                }
            } else {
                // Non-resident $DATA in Record 4
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

                    std::vector<uint8_t> attrdef_payload;
                    attrdef_payload.reserve(static_cast<size_t>(real_size));

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
                            attrdef_payload.insert(attrdef_payload.end(), static_cast<size_t>(span), uint8_t{0});
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
                            attrdef_payload.insert(attrdef_payload.end(), cluster_buf.data(), cluster_buf.data() + to_copy);
                            bytes_remaining -= to_copy;
                        }
                    }

                    return parse_from_buffer(attrdef_payload.data(), attrdef_payload.size(), volume.drive_letter());
                }
            }
            break;
        }

        offset += attr->record_length;
    }

    return Error(ERROR_NOT_FOUND, L"Failed to locate $DATA stream in Record 4 ($AttrDef)");
}

void AttrDefAnalyzer::print_report(const AttrDefReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS ATTRIBUTE DEFINITION TABLE ($AttrDef) SCHEMA AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Volume Letter        : " << report.volume_letter << L":\n";
    std::wcout << L"  Record FRN           : " << report.record_frn << L" ($AttrDef)\n";
    std::wcout << L"  Total Definitions    : " << report.total_definitions << L"\n";
    std::wcout << L"  Standard Types       : " << report.standard_types_count << L"\n";
    std::wcout << L"  Custom Types         : " << report.custom_types_count << L"\n";
    std::wcout << L"  Indexable Attributes : " << report.indexable_count << L"\n";
    std::wcout << L"  Multiple Attributes  : " << report.multiple_count << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(12) << L"Type Code"
               << std::setw(26) << L"Attribute Name"
               << std::setw(18) << L"Collation"
               << std::setw(24) << L"Flags"
               << std::right
               << std::setw(18) << L"Max Size\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& e : report.entries) {
        std::wstring max_str;
        if (e.max_size == static_cast<uint64_t>(-1) || e.max_size == 0) {
            max_str = L"Unbounded";
        } else {
            max_str = Formatter::format_bytes(e.max_size);
        }

        std::wcout << std::left
                   << L"0x" << std::hex << std::setw(10) << std::uppercase << e.type_code << std::dec
                   << std::setw(26) << e.name
                   << std::setw(18) << e.collation_name
                   << std::setw(24) << flags_to_string(e.flags)
                   << std::right
                   << std::setw(18) << max_str << L"\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
