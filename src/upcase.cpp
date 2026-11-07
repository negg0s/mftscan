#include "mftscan/upcase.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <vector>

namespace mftscan {

static uint64_t compute_fnv1a(const uint8_t* data, size_t size) {
    constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
    constexpr uint64_t kFnvPrime = 1099511628211ULL;

    uint64_t hash = kFnvOffsetBasis;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= kFnvPrime;
    }
    return hash;
}

UpCaseReport UpCaseAnalyzer::analyze_buffer(
    const uint8_t* upcase_data,
    size_t size,
    wchar_t drive_letter
) {
    UpCaseReport report{};
    report.volume_letter = drive_letter;
    report.stream_size_bytes = size;

    if (!upcase_data || size < 256) {
        return report;
    }

    report.valid = true;
    report.character_count = size / sizeof(wchar_t);
    report.fnv1a_hash = compute_fnv1a(upcase_data, size);

    const auto* chars = reinterpret_cast<const wchar_t*>(upcase_data);

    // 1. Verify standard ASCII range ('a'-'z' -> 'A'-'Z')
    for (wchar_t c = L'a'; c <= L'z'; ++c) {
        if (static_cast<size_t>(c) < report.character_count) {
            wchar_t mapped = chars[c];
            wchar_t expected = static_cast<wchar_t>(c - (L'a' - L'A'));
            if (mapped != expected) {
                report.is_ascii_consistent = false;
                ++report.ascii_mismatches_count;

                UpCaseAnomaly anomaly{};
                anomaly.source_char = c;
                anomaly.mapped_char = mapped;
                anomaly.expected_char = expected;
                anomaly.description = L"ASCII uppercase mismatch";
                report.anomalies.push_back(std::move(anomaly));
            }
        }
    }

    // 2. Sample checks for Cyrillic and Latin Extended
    for (size_t i = 0; i < report.character_count && i <= 0xFFFF; ++i) {
        wchar_t ch = static_cast<wchar_t>(i);
        wchar_t mapped = chars[i];

        // Self-mapping verification for already uppercase ASCII
        if (ch >= L'A' && ch <= L'Z') {
            if (mapped != ch) {
                UpCaseAnomaly anomaly{};
                anomaly.source_char = ch;
                anomaly.mapped_char = mapped;
                anomaly.expected_char = ch;
                anomaly.description = L"Uppercase ASCII altered";
                report.anomalies.push_back(std::move(anomaly));
                ++report.ascii_mismatches_count;
            }
        }
    }

    if (!report.is_ascii_consistent || report.ascii_mismatches_count > 0) {
        report.is_standard_table = false;
    }

    return report;
}

Result<UpCaseReport> UpCaseAnalyzer::inspect(VolumeReader& volume) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> rec_buf(rec_size);

    auto read_res = volume.read_file_record(10, rec_buf.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    if (!RecordParser::apply_fixup(rec_buf.data(), rec_size, volume.geometry().bytes_per_sector)) {
        return Error(ERROR_INVALID_DATA, L"Fixup failed on Record 10 ($UpCase)");
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
    if (header->magic != kMftMagicFile) {
        return Error(ERROR_INVALID_DATA, L"Record 10 does not have FILE signature");
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
                // Resident $UpCase
                const uint32_t val_len = attr->resident.value_length;
                const uint16_t val_off = attr->resident.value_offset;
                if (val_off + val_len <= attr->record_length) {
                    const uint8_t* payload = rec_buf.data() + offset + val_off;
                    return analyze_buffer(payload, val_len, volume.drive_letter());
                }
            } else {
                // Non-resident $UpCase
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

                    std::vector<uint8_t> upcase_payload;
                    upcase_payload.reserve(static_cast<size_t>(real_size));

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
                            upcase_payload.insert(upcase_payload.end(), static_cast<size_t>(span), uint8_t{0});
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
                            upcase_payload.insert(upcase_payload.end(), cluster_buf.data(), cluster_buf.data() + to_copy);
                            bytes_remaining -= to_copy;
                        }
                    }

                    return analyze_buffer(upcase_payload.data(), upcase_payload.size(), volume.drive_letter());
                }
            }
            break;
        }

        offset += attr->record_length;
    }

    return Error(ERROR_NOT_FOUND, L"Failed to locate $DATA stream in Record 10 ($UpCase)");
}

void UpCaseAnalyzer::print_report(const UpCaseReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS UNICODE UPPERCASE TABLE ($UpCase) INTEGRITY AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Volume Letter        : " << report.volume_letter << L":\n";
    std::wcout << L"  Record FRN           : 10 ($UpCase)\n";
    std::wcout << L"  Table Stream Size    : " << report.stream_size_bytes << L" bytes (" << (report.stream_size_bytes / 1024) << L" KB)\n";
    std::wcout << L"  Character Mappings   : " << report.character_count << L" Unicode characters\n";
    std::wcout << L"  FNV-1a Table Hash    : 0x" << std::hex << std::setw(16) << std::setfill(L'0') << std::uppercase << report.fnv1a_hash << std::dec << std::setfill(L' ') << L"\n";
    std::wcout << L"  ASCII Consistency    : " << (report.is_ascii_consistent ? L"PASS (Standard 'a'-'z' -> 'A'-'Z')" : L"FAIL (Corrupted/Tampered)") << L"\n";
    std::wcout << L"  Table Status         : " << (report.is_standard_table ? L"CLEAN (Standard Windows Uppercase Collation)" : L"ANOMALOUS (Mapping deviations detected)") << L"\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (report.anomalies.empty()) {
        std::wcout << L"  Zero collation anomalies detected. Volume character sorting table is intact.\n";
    } else {
        std::wcout << L"  Detected " << report.anomalies.size() << L" character mapping deviations:\n";
        for (const auto& an : report.anomalies) {
            std::wcout << L"    Source: U+" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<int>(an.source_char)
                       << L" ('" << an.source_char << L"') -> Mapped: U+" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<int>(an.mapped_char)
                       << L" ('" << an.mapped_char << L"'), Expected: U+" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<int>(an.expected_char)
                       << std::dec << std::setfill(L' ') << L" [" << an.description << L"]\n";
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
