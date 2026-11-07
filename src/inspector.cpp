#include "mftscan/inspector.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace mftscan {

std::wstring RecordInspector::attribute_type_to_string(uint32_t type_code) {
    switch (type_code) {
        case 0x10: return L"$STANDARD_INFORMATION";
        case 0x20: return L"$ATTRIBUTE_LIST";
        case 0x30: return L"$FILE_NAME";
        case 0x40: return L"$OBJECT_ID";
        case 0x50: return L"$SECURITY_DESCRIPTOR";
        case 0x60: return L"$VOLUME_NAME";
        case 0x70: return L"$VOLUME_INFORMATION";
        case 0x80: return L"$DATA";
        case 0x90: return L"$INDEX_ROOT";
        case 0xA0: return L"$INDEX_ALLOCATION";
        case 0xB0: return L"$BITMAP";
        case 0xC0: return L"$REPARSE_POINT";
        case 0xD0: return L"$EA_INFORMATION";
        case 0xE0: return L"$EA";
        case 0x100: return L"$LOGGED_UTILITY_STREAM";
        default: {
            std::wostringstream oss;
            oss << L"UNKNOWN (0x" << std::hex << std::uppercase << type_code << L")";
            return oss.str();
        }
    }
}

std::string RecordInspector::format_hex_dump(const uint8_t* data, size_t size, size_t max_bytes) {
    if (!data || size == 0) {
        return "";
    }

    const size_t display_bytes = (std::min)(size, max_bytes);
    std::ostringstream oss;

    for (size_t row_start = 0; row_start < display_bytes; row_start += 16) {
        // Hex offset
        oss << std::hex << std::setfill('0') << std::setw(4) << row_start << ": ";

        // Hex bytes
        const size_t row_len = (std::min)(size_t{16}, display_bytes - row_start);
        for (size_t col = 0; col < 16; ++col) {
            if (col < row_len) {
                oss << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<uint32_t>(data[row_start + col]) << " ";
            } else {
                oss << "   ";
            }
            if (col == 7) {
                oss << " ";
            }
        }

        // ASCII representation
        oss << " |";
        for (size_t col = 0; col < row_len; ++col) {
            const uint8_t byte = data[row_start + col];
            if (byte >= 32 && byte <= 126) {
                oss << static_cast<char>(byte);
            } else {
                oss << '.';
            }
        }
        oss << "|";

        if (row_start + 16 < display_bytes) {
            oss << "\n";
        }
    }

    return oss.str();
}

Result<RecordDumpReport> RecordInspector::inspect(VolumeReader& volume, uint64_t record_number) {
    const uint32_t rec_size = volume.geometry().bytes_per_record;
    if (rec_size < sizeof(MftRecordHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid record size in volume geometry");
    }

    std::vector<uint8_t> buffer(rec_size);
    auto read_res = volume.read_file_record(record_number, buffer.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    RecordDumpReport report;
    report.record_number = record_number;

    const auto* header = reinterpret_cast<const MftRecordHeader*>(buffer.data());
    report.sequence_number = header->sequence_number;
    report.is_allocated = (header->flags & kRecordInUse) != 0;
    report.is_directory = (header->flags & kRecordDirectory) != 0;
    report.bytes_used = header->bytes_used;
    report.bytes_allocated = header->bytes_allocated;
    report.base_record_ref = header->base_file_record;

    // Apply fixups on a copy
    std::vector<uint8_t> fixup_copy = buffer;
    report.fixup_valid = RecordParser::apply_fixup(
        fixup_copy.data(),
        rec_size,
        volume.geometry().bytes_per_sector
    );

    const uint8_t* parse_buf = report.fixup_valid ? fixup_copy.data() : buffer.data();
    uint32_t offset = header->first_attribute_offset;

    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(parse_buf + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > rec_size) {
            break;
        }

        AttributeDetail detail;
        detail.type_code = attr->type_code;
        detail.type_name = attribute_type_to_string(attr->type_code);
        detail.record_length = attr->record_length;
        detail.is_non_resident = (attr->non_resident_flag != 0);

        if (attr->name_length > 0 && attr->name_offset + (attr->name_length * sizeof(wchar_t)) <= attr->record_length) {
            const wchar_t* name_ptr = reinterpret_cast<const wchar_t*>(parse_buf + offset + attr->name_offset);
            detail.stream_name = std::wstring(name_ptr, attr->name_length);
        }

        if (!detail.is_non_resident) {
            detail.content_size = attr->resident.value_length;
            detail.allocated_size = attr->record_length;
            if (attr->resident.value_offset + attr->resident.value_length <= attr->record_length) {
                const uint8_t* payload = parse_buf + offset + attr->resident.value_offset;
                detail.hex_preview = format_hex_dump(payload, attr->resident.value_length, 48);

                if (attr->type_code == kAttrAttributeList) {
                    detail.attr_list_entries = AttrListDecoder::decode(payload, attr->resident.value_length);
                }
            }
        } else {
            detail.content_size = attr->non_resident.real_size;
            detail.allocated_size = attr->non_resident.allocated_size;
            if (attr->non_resident.data_runs_offset < attr->record_length) {
                const uint8_t* runs_ptr = parse_buf + offset + attr->non_resident.data_runs_offset;
                const size_t runs_len = attr->record_length - attr->non_resident.data_runs_offset;
                detail.hex_preview = format_hex_dump(runs_ptr, runs_len, 48);
            }
        }

        report.attributes.push_back(std::move(detail));
        offset += attr->record_length;
    }

    return report;
}

void RecordInspector::print_report(const RecordDumpReport& report) {
    std::wcout << L"============================================================\n";
    std::wcout << L" MFT RECORD INSPECTION REPORT: FRN " << report.record_number << L"\n";
    std::wcout << L"============================================================\n";
    std::wcout << L"  Sequence Number  : " << report.sequence_number << L"\n";
    std::wcout << L"  Allocation State : " << (report.is_allocated ? L"In Use (Active)" : L"Free (Deleted / Unallocated)") << L"\n";
    std::wcout << L"  Record Type      : " << (report.is_directory ? L"Directory" : L"File") << L"\n";
    std::wcout << L"  Fixup Integrity  : " << (report.fixup_valid ? L"Valid (Verified)" : L"Invalid (Fixup mismatch or torn write)") << L"\n";
    std::wcout << L"  Record Size      : " << report.bytes_used << L" bytes used / " << report.bytes_allocated << L" bytes allocated\n";
    std::wcout << L"  Base Record Ref  : 0x" << std::hex << report.base_record_ref << std::dec << L"\n";
    std::wcout << L"------------------------------------------------------------\n";
    std::wcout << L" Attributes (" << report.attributes.size() << L"):\n";

    for (size_t i = 0; i < report.attributes.size(); ++i) {
        const auto& attr = report.attributes[i];
        std::wcout << L"  [" << i << L"] Type: 0x" << std::hex << attr.type_code << std::dec
                   << L" (" << attr.type_name << L")";
        if (!attr.stream_name.empty()) {
            std::wcout << L" : \"" << attr.stream_name << L"\"";
        }
        std::wcout << L"\n";
        std::wcout << L"      Resident Status : " << (attr.is_non_resident ? L"Non-Resident" : L"Resident") << L"\n";
        std::wcout << L"      Record Length   : " << attr.record_length << L" bytes\n";
        std::wcout << L"      Content Size    : " << attr.content_size << L" bytes\n";
        std::wcout << L"      Allocated Size  : " << attr.allocated_size << L" bytes\n";

        if (!attr.hex_preview.empty()) {
            std::wcout << L"      Data Preview:\n";
            std::istringstream stream(attr.hex_preview);
            std::string line;
            while (std::getline(stream, line)) {
                std::wcout << L"        " << std::wstring(line.begin(), line.end()) << L"\n";
            }
        }

        if (!attr.attr_list_entries.empty()) {
            std::wcout << L"      Attribute List Mappings (" << attr.attr_list_entries.size() << L" entries):\n";
            for (const auto& ale : attr.attr_list_entries) {
                std::wcout << L"        * " << AttrListDecoder::format_entry(ale) << L"\n";
            }
        }
        std::wcout << L"\n";
    }
    std::wcout << L"============================================================\n";
}

} // namespace mftscan
