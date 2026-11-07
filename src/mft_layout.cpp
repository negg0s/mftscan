#include "mftscan/mft_layout.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>

namespace mftscan {

std::wstring MftLayoutAuditor::attribute_type_to_string(uint32_t type_code) {
    switch (type_code) {
    case kAttrStandardInformation: return L"$STANDARD_INFORMATION (0x10)";
    case kAttrAttributeList:       return L"$ATTRIBUTE_LIST (0x20)";
    case kAttrFileName:            return L"$FILE_NAME (0x30)";
    case kAttrObjectId:            return L"$OBJECT_ID (0x40)";
    case kAttrSecurityDescriptor:  return L"$SECURITY_DESCRIPTOR (0x50)";
    case kAttrVolumeName:          return L"$VOLUME_NAME (0x60)";
    case kAttrVolumeInformation:   return L"$VOLUME_INFORMATION (0x70)";
    case kAttrData:                return L"$DATA (0x80)";
    case kAttrIndexRoot:           return L"$INDEX_ROOT (0x90)";
    case kAttrIndexAllocation:     return L"$INDEX_ALLOCATION (0xA0)";
    case kAttrBitmap:              return L"$BITMAP (0xB0)";
    case kAttrReparsePoint:        return L"$REPARSE_POINT (0xC0)";
    case 0xD0:                     return L"$EA_INFORMATION (0xD0)";
    case 0xE0:                     return L"$EA (0xE0)";
    case 0xF0:                     return L"$PROPERTY_SET (0xF0)";
    case 0x100:                    return L"$LOGGED_UTILITY_STREAM (0x100)";
    default:                       return L"Custom (0x" + std::to_wstring(type_code) + L")";
    }
}

MftLayoutReport MftLayoutAuditor::analyze(
    VolumeReader& volume,
    const std::vector<RecordInfo>& records,
    size_t top_limit
) {
    MftLayoutReport report{};
    report.total_records_evaluated = records.size();

    const bool has_volume = volume.is_open();
    report.bytes_per_record = has_volume ? volume.geometry().bytes_per_record : 1024;
    const uint32_t rec_size = report.bytes_per_record;
    std::vector<uint8_t> rec_buf(rec_size);

    std::vector<MftCapacityWarning> congested;

    for (const auto& rec : records) {
        if (rec.is_deleted) {
            ++report.unallocated_records;
            continue;
        }

        ++report.allocated_records;
        report.total_allocated_record_bytes += rec_size;

        uint32_t bytes_used = 0;
        uint32_t bytes_allocated = rec_size;
        size_t attr_count = 0;
        size_t fn_count = 0;
        bool has_attr_list = false;

        if (has_volume) {
            auto read_res = volume.read_file_record(rec.record_index, rec_buf.data(), rec_size);
            if (read_res) {
                RecordParser::apply_fixup(rec_buf.data(), rec_size, volume.geometry().bytes_per_sector);
                const auto* mft_hdr = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());

                bytes_used = mft_hdr->bytes_used;
                bytes_allocated = mft_hdr->bytes_allocated;
                if (bytes_allocated == 0) bytes_allocated = rec_size;
                if (bytes_used > bytes_allocated) bytes_used = bytes_allocated;

                uint32_t offset = mft_hdr->first_attribute_offset;
                while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
                    const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_buf.data() + offset);
                    if (attr->type_code == kAttrEnd || attr->record_length == 0) break;
                    if (offset + attr->record_length > rec_size) break;

                    ++attr_count;
                    report.attribute_frequency[attr->type_code]++;

                    if (attr->type_code == kAttrFileName) {
                        ++fn_count;
                    } else if (attr->type_code == kAttrAttributeList) {
                        has_attr_list = true;
                    }

                    offset += attr->record_length;
                }
            }
        }

        if (bytes_used == 0) {
            // Approximation for records analyzed offline
            bytes_used = 48 + 12 + 72 + 96; // basic headers + SI + FN
            if (rec.is_resident) {
                bytes_used += static_cast<uint32_t>(24 + rec.size_bytes);
            } else {
                bytes_used += 72; // non-resident data header
            }
            if (bytes_used > rec_size) bytes_used = rec_size;
        }

        report.total_used_record_bytes += bytes_used;
        const uint32_t slack = (bytes_allocated >= bytes_used) ? (bytes_allocated - bytes_used) : 0;
        report.total_internal_slack_bytes += slack;

        if (bytes_used >= 900) {
            ++report.records_near_capacity_count;
            MftCapacityWarning w{};
            w.frn = rec.record_index;
            w.path = rec.full_path.empty() ? rec.name : rec.full_path;
            w.bytes_used = bytes_used;
            w.bytes_allocated = bytes_allocated;
            w.free_slack = slack;
            w.attribute_count = attr_count;
            congested.push_back(std::move(w));
        } else if (bytes_used <= 350) {
            ++report.records_compact_count;
        }

        if (has_attr_list) {
            ++report.records_with_attr_list;
        }
        if (fn_count > 1) {
            ++report.records_with_multiple_names;
        }
    }

    if (report.allocated_records > 0) {
        report.average_bytes_used = static_cast<double>(report.total_used_record_bytes) /
                                    static_cast<double>(report.allocated_records);
        report.average_internal_slack = static_cast<double>(report.total_internal_slack_bytes) /
                                        static_cast<double>(report.allocated_records);
        if (report.total_allocated_record_bytes > 0) {
            report.overall_mft_packing_density = (static_cast<double>(report.total_used_record_bytes) /
                                                 static_cast<double>(report.total_allocated_record_bytes)) * 100.0;
        }
    }

    std::sort(congested.begin(), congested.end(), [](const MftCapacityWarning& a, const MftCapacityWarning& b) {
        return a.bytes_used > b.bytes_used;
    });

    const size_t take = std::min(top_limit, congested.size());
    report.top_congested_records.assign(congested.begin(), congested.begin() + take);

    return report;
}

void MftLayoutAuditor::print_report(const MftLayoutReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS MFT RECORD INTERNAL PACKING AND ATTRIBUTE LAYOUT AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Evaluated Records    : " << report.total_records_evaluated << L"\n";
    std::wcout << L"  Allocated Records    : " << report.allocated_records << L"\n";
    std::wcout << L"  Unallocated Records  : " << report.unallocated_records << L"\n";
    std::wcout << L"  Record Segment Size  : " << report.bytes_per_record << L" bytes\n";
    std::wcout << L"  Total MFT In-Use     : " << Formatter::format_bytes(report.total_used_record_bytes)
               << L" / " << Formatter::format_bytes(report.total_allocated_record_bytes) << L"\n";
    std::wcout << L"  Total Internal Slack : " << Formatter::format_bytes(report.total_internal_slack_bytes) << L" (reclaimable resident space)\n";
    std::wcout << L"  Packing Density      : " << std::fixed << std::setprecision(1) << report.overall_mft_packing_density << L"%\n";
    std::wcout << L"  Average Record Usage : " << std::fixed << std::setprecision(1) << report.average_bytes_used << L" bytes ("
               << report.average_internal_slack << L" bytes free slack)\n";
    std::wcout << L"  Records Near Limit   : " << report.records_near_capacity_count << L" records (used >= 900 bytes)\n";
    std::wcout << L"  Compact Records      : " << report.records_compact_count << L" records (used <= 350 bytes)\n";
    std::wcout << L"  Attribute Lists (0x20): " << report.records_with_attr_list << L" multi-record files\n";
    std::wcout << L"  Multiple File Names  : " << report.records_with_multiple_names << L" records with 8.3 / alias names\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (!report.attribute_frequency.empty()) {
        std::wcout << L" ATTRIBUTE TYPE DISTRIBUTION ACROSS VOLUME MFT\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        for (const auto& [code, count] : report.attribute_frequency) {
            std::wcout << L"  " << std::left << std::setw(36) << attribute_type_to_string(code)
                       << L": " << std::right << std::setw(10) << count << L" instances\n";
        }
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    }

    if (!report.top_congested_records.empty()) {
        std::wcout << L" TOP CONGESTED MFT RECORDS (RISK OF ATTRIBUTE LIST OVERFLOW >= 900 BYTES)\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::right
                   << std::setw(10) << L"Used"
                   << std::setw(10) << L"Total"
                   << std::setw(10) << L"Slack"
                   << std::setw(8)  << L"Attrs"
                   << L"  "
                   << std::left
                   << L"Path\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        for (const auto& c : report.top_congested_records) {
            std::wcout << std::left
                       << std::setw(12) << c.frn
                       << std::right
                       << std::setw(8)  << c.bytes_used << L" B"
                       << std::setw(8)  << c.bytes_allocated << L" B"
                       << std::setw(8)  << c.free_slack << L" B"
                       << std::setw(8)  << c.attribute_count
                       << L"  "
                       << std::left
                       << c.path << L"\n";
        }
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
