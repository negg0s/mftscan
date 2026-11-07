#include "mftscan/mft_slack.hpp"
#include "mftscan/inspector.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <cctype>

namespace mftscan {

std::vector<ResidualString> MftSlackCarver::extract_residual_strings(
    const uint8_t* data,
    size_t size,
    size_t min_len
) {
    std::vector<ResidualString> results;
    if (!data || size < min_len) {
        return results;
    }

    // 1. Scan for ASCII printable strings
    size_t ascii_start = 0;
    bool in_ascii = false;
    for (size_t i = 0; i < size; ++i) {
        const uint8_t b = data[i];
        const bool is_printable = (b >= 0x20 && b <= 0x7E);
        if (is_printable) {
            if (!in_ascii) {
                ascii_start = i;
                in_ascii = true;
            }
        } else {
            if (in_ascii) {
                const size_t len = i - ascii_start;
                if (len >= min_len) {
                    ResidualString s;
                    s.offset = ascii_start;
                    s.is_utf16 = false;
                    s.text.reserve(len);
                    for (size_t k = 0; k < len; ++k) {
                        s.text.push_back(static_cast<wchar_t>(data[ascii_start + k]));
                    }
                    results.push_back(std::move(s));
                }
                in_ascii = false;
            }
        }
    }
    if (in_ascii && (size - ascii_start >= min_len)) {
        ResidualString s;
        s.offset = ascii_start;
        s.is_utf16 = false;
        const size_t len = size - ascii_start;
        s.text.reserve(len);
        for (size_t k = 0; k < len; ++k) {
            s.text.push_back(static_cast<wchar_t>(data[ascii_start + k]));
        }
        results.push_back(std::move(s));
    }

    // 2. Scan for UTF-16LE printable strings (2-byte aligned or any even/odd offset)
    for (size_t align = 0; align < 2; ++align) {
        size_t utf16_start = 0;
        bool in_utf16 = false;
        for (size_t i = align; i + 1 < size; i += 2) {
            const uint16_t ch = static_cast<uint16_t>(data[i]) | (static_cast<uint16_t>(data[i + 1]) << 8);
            const bool is_printable_utf16 = (ch >= 0x20 && ch <= 0x7E) || (ch >= 0x0400 && ch <= 0x04FF);
            if (is_printable_utf16) {
                if (!in_utf16) {
                    utf16_start = i;
                    in_utf16 = true;
                }
            } else {
                if (in_utf16) {
                    const size_t char_count = (i - utf16_start) / 2;
                    if (char_count >= min_len) {
                        // Avoid duplicates if this is just ASCII with zeroes that coincided
                        ResidualString s;
                        s.offset = utf16_start;
                        s.is_utf16 = true;
                        s.text.reserve(char_count);
                        for (size_t k = 0; k < char_count; ++k) {
                            const size_t idx = utf16_start + (k * 2);
                            const uint16_t val = static_cast<uint16_t>(data[idx]) | (static_cast<uint16_t>(data[idx + 1]) << 8);
                            s.text.push_back(static_cast<wchar_t>(val));
                        }
                        results.push_back(std::move(s));
                    }
                    in_utf16 = false;
                }
            }
        }
        if (in_utf16) {
            const size_t char_count = (size - utf16_start) / 2;
            if (char_count >= min_len) {
                ResidualString s;
                s.offset = utf16_start;
                s.is_utf16 = true;
                s.text.reserve(char_count);
                for (size_t k = 0; k < char_count; ++k) {
                    const size_t idx = utf16_start + (k * 2);
                    const uint16_t val = static_cast<uint16_t>(data[idx]) | (static_cast<uint16_t>(data[idx + 1]) << 8);
                    s.text.push_back(static_cast<wchar_t>(val));
                }
                results.push_back(std::move(s));
            }
        }
    }

    // Sort by offset
    std::sort(results.begin(), results.end(), [](const ResidualString& a, const ResidualString& b) {
        return a.offset < b.offset;
    });

    return results;
}

std::vector<ResidualAttribute> MftSlackCarver::extract_residual_attributes(
    const uint8_t* data,
    size_t size
) {
    std::vector<ResidualAttribute> attrs;
    if (!data || size < sizeof(AttributeRecordHeader)) {
        return attrs;
    }

    // Valid NTFS attribute types range
    auto is_known_type = [](uint32_t t) -> bool {
        switch (t) {
            case 0x10: // $STANDARD_INFORMATION
            case 0x20: // $ATTRIBUTE_LIST
            case 0x30: // $FILE_NAME
            case 0x40: // $OBJECT_ID
            case 0x50: // $SECURITY_DESCRIPTOR
            case 0x60: // $VOLUME_NAME
            case 0x70: // $VOLUME_INFORMATION
            case 0x80: // $DATA
            case 0x90: // $INDEX_ROOT
            case 0xA0: // $INDEX_ALLOCATION
            case 0xB0: // $BITMAP
            case 0xC0: // $REPARSE_POINT
            case 0xD0: // $EA_INFORMATION
            case 0xE0: // $EA
            case 0x100: // $LOGGED_UTILITY_STREAM
                return true;
            default:
                return false;
        }
    };

    // Scan on 4-byte boundaries (attributes in NTFS are quadword or dword aligned)
    for (size_t offset = 0; offset + sizeof(AttributeRecordHeader) <= size; offset += 4) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(data + offset);
        if (!is_known_type(attr->type_code)) {
            continue;
        }

        // Validate basic fields
        if (attr->record_length < sizeof(AttributeRecordHeader)) {
            continue;
        }
        if (attr->record_length % 4 != 0) {
            continue;
        }
        if (attr->non_resident_flag > 1) {
            continue;
        }
        if (offset + attr->record_length > size) {
            continue;
        }

        ResidualAttribute ra;
        ra.offset = offset;
        ra.type_code = attr->type_code;
        ra.type_name = RecordInspector::attribute_type_to_string(attr->type_code);
        ra.length = attr->record_length;
        attrs.push_back(ra);

        // Jump forward past this attribute to find subsequent ones
        offset += attr->record_length - 4; // loop will add 4
    }

    return attrs;
}

Result<MftSlackReport> MftSlackCarver::analyze_record_slack(
    const uint8_t* record_buffer,
    uint32_t record_size,
    uint64_t frn
) {
    if (!record_buffer || record_size < sizeof(MftRecordHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Record buffer too small for header analysis");
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(record_buffer);
    MftSlackReport report;
    report.frn = frn;
    report.bytes_used = header->bytes_used;
    report.bytes_allocated = header->bytes_allocated;

    if (report.bytes_allocated == 0 || report.bytes_allocated > record_size) {
        report.bytes_allocated = record_size;
    }

    if (report.bytes_used > report.bytes_allocated) {
        return Error(ERROR_INVALID_DATA, L"Corrupted record: bytes_used exceeds bytes_allocated");
    }

    report.slack_size = report.bytes_allocated - report.bytes_used;
    if (report.slack_size == 0) {
        return report;
    }

    const uint8_t* slack_ptr = record_buffer + report.bytes_used;

    uint32_t non_zero_count = 0;
    for (size_t i = 0; i < report.slack_size; ++i) {
        if (slack_ptr[i] != 0) {
            ++non_zero_count;
        }
    }
    report.non_zero_bytes_count = non_zero_count;
    report.has_non_zero_slack = (non_zero_count > 0);

    report.residual_strings = extract_residual_strings(slack_ptr, report.slack_size, 4);
    report.residual_attributes = extract_residual_attributes(slack_ptr, report.slack_size);
    report.hex_dump = RecordInspector::format_hex_dump(slack_ptr, report.slack_size, 256);

    return report;
}

Result<MftSlackReport> MftSlackCarver::inspect_record(VolumeReader& volume, uint64_t frn) {
    const uint32_t rec_size = volume.geometry().bytes_per_record;
    if (rec_size < sizeof(MftRecordHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid volume record size");
    }

    std::vector<uint8_t> buffer(rec_size);
    auto read_res = volume.read_file_record(frn, buffer.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    return analyze_record_slack(buffer.data(), rec_size, frn);
}

} // namespace mftscan
