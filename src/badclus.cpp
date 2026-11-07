#include "mftscan/badclus.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <iomanip>
#include <iostream>

namespace mftscan {

Result<BadClusterReport> BadClusterAnalyzer::analyze(VolumeReader& volume) {
    const uint32_t rec_size = volume.geometry().bytes_per_record;
    if (rec_size < sizeof(MftRecordHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid record size in volume geometry");
    }

    std::vector<uint8_t> buffer(rec_size);
    auto read_res = volume.read_file_record(kRecordBadClus, buffer.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    // Apply fixup
    RecordParser::apply_fixup(buffer.data(), rec_size, volume.geometry().bytes_per_sector);

    BadClusterReport report;
    report.total_volume_clusters = volume.geometry().total_clusters;

    const auto* header = reinterpret_cast<const MftRecordHeader*>(buffer.data());
    uint32_t offset = header->first_attribute_offset;
    const uint32_t cluster_size = volume.geometry().bytes_per_cluster;

    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(buffer.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > rec_size) {
            break;
        }

        if (attr->type_code == kAttrData) {
            if (attr->non_resident_flag != 0) {
                if (attr->non_resident.data_runs_offset < attr->record_length) {
                    const uint8_t* runs_ptr = buffer.data() + offset + attr->non_resident.data_runs_offset;
                    const size_t runs_len = attr->record_length - attr->non_resident.data_runs_offset;

                    auto extents = DataRunDecoder::decode_mapping_pairs(runs_ptr, runs_len, attr->non_resident.starting_vcn);
                    for (const auto& run : extents) {
                        if (!run.is_sparse && run.starting_lcn > 0 && run.cluster_count > 0) {
                            BadClusterExtent bce;
                            bce.start_lcn = static_cast<uint64_t>(run.starting_lcn);
                            bce.cluster_count = run.cluster_count;
                            bce.byte_length = run.cluster_count * cluster_size;

                            report.bad_cluster_count += run.cluster_count;
                            report.bad_bytes_count += bce.byte_length;
                            report.extents.push_back(bce);
                        }
                    }
                }
            }
        }

        offset += attr->record_length;
    }

    report.is_healthy = (report.bad_cluster_count == 0);
    return report;
}

void BadClusterAnalyzer::print_report(const BadClusterReport& report) {
    std::wcout << L"============================================================\n";
    std::wcout << L" NTFS DEFECTIVE CLUSTER & HARDWARE SECTOR HEALTH ($BadClus)\n";
    std::wcout << L"============================================================\n";
    std::wcout << L"  Total Volume Clusters  : " << report.total_volume_clusters << L"\n";
    std::wcout << L"  Defective Clusters     : " << report.bad_cluster_count << L"\n";
    std::wcout << L"  Defective Space        : " << Formatter::format_bytes(report.bad_bytes_count) << L"\n";
    std::wcout << L"  Hardware Health State  : " << (report.is_healthy ? L"Clean (Zero bad sectors reported)" : L"Defective sectors mapped out") << L"\n";
    std::wcout << L"------------------------------------------------------------\n";

    if (report.extents.empty()) {
        std::wcout << L"  No bad clusters detected. File system reports 100% surface integrity.\n";
    } else {
        std::wcout << L"  Mapped Defective Extents (" << report.extents.size() << L"):\n";
        std::wcout << L"  " << std::left << std::setw(16) << L"Start LCN"
                   << std::right << std::setw(14) << L"Clusters"
                   << std::setw(18) << L"Byte Length\n";
        std::wcout << L"  ----------------------------------------------------------\n";

        for (const auto& ext : report.extents) {
            std::wcout << L"  " << std::left << std::setw(16) << ext.start_lcn
                       << std::right << std::setw(14) << ext.cluster_count
                       << std::setw(18) << Formatter::format_bytes(ext.byte_length) << L"\n";
        }
    }
    std::wcout << L"============================================================\n\n";
}

} // namespace mftscan
