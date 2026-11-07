#include "mftscan/carver.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <cwctype>
#include <vector>

namespace mftscan {

std::wstring FileCarver::sanitize_filename(const std::wstring& name) {
    std::wstring clean = name;
    for (auto& ch : clean) {
        if (ch == L'<' || ch == L'>' || ch == L':' || ch == L'\"' ||
            ch == L'/' || ch == L'\\' || ch == L'|' || ch == L'?' || ch == L'*' ||
            static_cast<uint32_t>(ch) < 32) {
            ch = L'_';
        }
    }
    if (clean.empty()) {
        clean = L"unnamed";
    }
    return clean;
}

bool FileCarver::ensure_directory_exists(const std::wstring& dir_path) {
    if (dir_path.empty()) {
        return false;
    }

    const DWORD attrs = GetFileAttributesW(dir_path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;
    }

    std::wstring sub;
    for (size_t i = 0; i < dir_path.size(); ++i) {
        sub += dir_path[i];
        if (dir_path[i] == L'\\' || dir_path[i] == L'/' || i == dir_path.size() - 1) {
            if (sub.size() >= 2 && sub[1] == L':' && sub.size() <= 3) {
                continue;
            }
            CreateDirectoryW(sub.c_str(), nullptr);
        }
    }

    const DWORD post_attrs = GetFileAttributesW(dir_path.c_str());
    return (post_attrs != INVALID_FILE_ATTRIBUTES && (post_attrs & FILE_ATTRIBUTE_DIRECTORY));
}

Result<CarveResult> FileCarver::carve_from_buffer(
    HANDLE volume_handle,
    const VolumeGeometry& geometry,
    const uint8_t* record_buffer,
    uint32_t record_size,
    uint64_t frn,
    const std::wstring& output_path,
    const std::wstring& stream_name,
    bool include_slack
) {
    if (!record_buffer || record_size < sizeof(MftRecordHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid MFT record buffer");
    }

    std::vector<uint8_t> rec_copy(record_buffer, record_buffer + record_size);
    RecordParser::apply_fixup(rec_copy.data(), record_size, geometry.bytes_per_sector);

    const auto* header = reinterpret_cast<const MftRecordHeader*>(rec_copy.data());
    if (header->magic != kMftMagicFile && header->magic != kMftMagicBaad) {
        return Error(ERROR_INVALID_DATA, L"Record does not have FILE or BAAD magic");
    }

    const bool is_deleted = (header->flags & kRecordInUse) == 0;

    CarveResult result{};
    result.frn = frn;
    result.stream_name = stream_name;
    result.output_path = output_path;
    result.is_deleted_record = is_deleted;

    uint32_t offset = header->first_attribute_offset;
    bool found_data_stream = false;

    while (offset + sizeof(AttributeRecordHeader) <= record_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_copy.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > record_size) {
            break;
        }

        if (attr->type_code == kAttrData) {
            std::wstring current_stream_name;
            if (attr->name_length > 0 && attr->name_offset + attr->name_length * sizeof(wchar_t) <= attr->record_length) {
                const auto* name_ptr = reinterpret_cast<const wchar_t*>(
                    rec_copy.data() + offset + attr->name_offset
                );
                current_stream_name = std::wstring(name_ptr, attr->name_length);
            }

            bool match = false;
            if (stream_name.empty()) {
                match = current_stream_name.empty();
            } else {
                if (stream_name.size() == current_stream_name.size()) {
                    match = true;
                    for (size_t i = 0; i < stream_name.size(); ++i) {
                        if (towlower(stream_name[i]) != towlower(current_stream_name[i])) {
                            match = false;
                            break;
                        }
                    }
                }
            }

            if (match) {
                found_data_stream = true;

                HANDLE out_file = CreateFileW(
                    output_path.c_str(),
                    GENERIC_WRITE,
                    0,
                    nullptr,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                if (out_file == INVALID_HANDLE_VALUE) {
                    const DWORD err = GetLastError();
                    result.error_message = L"Failed to create output file: " + output_path;
                    return Error(err, result.error_message);
                }

                if (attr->non_resident_flag == 0) {
                    // Resident stream
                    result.is_resident = true;
                    const uint32_t val_len = attr->resident.value_length;
                    const uint16_t val_off = attr->resident.value_offset;

                    if (val_off + val_len <= attr->record_length) {
                        const uint8_t* payload = rec_copy.data() + offset + val_off;
                        DWORD written = 0;
                        if (val_len > 0) {
                            WriteFile(out_file, payload, val_len, &written, nullptr);
                        }
                        result.bytes_written = written;
                    }
                    CloseHandle(out_file);
                    result.success = true;
                    return result;
                } else {
                    // Non-resident stream
                    result.is_resident = false;
                    if (volume_handle == INVALID_HANDLE_VALUE) {
                        CloseHandle(out_file);
                        result.error_message = L"Non-resident attribute requires valid volume handle";
                        return Error(ERROR_INVALID_HANDLE, result.error_message);
                    }

                    const uint64_t target_size = include_slack
                        ? attr->non_resident.allocated_size
                        : attr->non_resident.real_size;

                    const uint16_t runs_off = attr->non_resident.data_runs_offset;
                    if (runs_off >= attr->record_length) {
                        CloseHandle(out_file);
                        result.error_message = L"Invalid mapping pairs offset in non-resident attribute";
                        return Error(ERROR_INVALID_DATA, result.error_message);
                    }

                    const uint8_t* run_ptr = rec_copy.data() + offset + runs_off;
                    const size_t max_run_bytes = attr->record_length - runs_off;

                    auto extents = DataRunDecoder::decode_mapping_pairs(
                        run_ptr,
                        max_run_bytes,
                        attr->non_resident.starting_vcn
                    );

                    uint64_t remaining_bytes = target_size;
                    constexpr DWORD kChunkSize = 64 * 1024;
                    std::vector<uint8_t> io_buf(kChunkSize, 0);

                    for (const auto& extent : extents) {
                        if (remaining_bytes == 0) {
                            break;
                        }

                        const uint64_t extent_bytes = extent.cluster_count * geometry.bytes_per_cluster;
                        uint64_t to_process = std::min(extent_bytes, remaining_bytes);

                        result.clusters_read += extent.cluster_count;

                        if (extent.is_sparse || extent.starting_lcn <= 0) {
                            // Sparse run: fill with zeros
                            std::fill(io_buf.begin(), io_buf.end(), uint8_t{0});
                            while (to_process > 0) {
                                const DWORD chunk = static_cast<DWORD>(std::min<uint64_t>(to_process, kChunkSize));
                                DWORD written = 0;
                                WriteFile(out_file, io_buf.data(), chunk, &written, nullptr);
                                result.bytes_written += written;
                                to_process -= written;
                                remaining_bytes -= written;
                            }
                        } else {
                            // Allocated run on volume
                            LARGE_INTEGER seek_pos{};
                            seek_pos.QuadPart = static_cast<LONGLONG>(extent.starting_lcn * geometry.bytes_per_cluster);

                            if (!SetFilePointerEx(volume_handle, seek_pos, nullptr, FILE_BEGIN)) {
                                break;
                            }

                            while (to_process > 0) {
                                const DWORD chunk = static_cast<DWORD>(std::min<uint64_t>(to_process, kChunkSize));
                                DWORD read_bytes = 0;
                                if (!ReadFile(volume_handle, io_buf.data(), chunk, &read_bytes, nullptr) || read_bytes == 0) {
                                    break;
                                }

                                DWORD written = 0;
                                WriteFile(out_file, io_buf.data(), read_bytes, &written, nullptr);
                                result.bytes_written += written;
                                to_process -= written;
                                remaining_bytes -= written;
                            }
                        }
                    }

                    CloseHandle(out_file);
                    result.success = true;
                    return result;
                }
            }
        }

        offset += attr->record_length;
    }

    if (!found_data_stream) {
        result.error_message = L"Requested $DATA stream not found in record";
        return Error(ERROR_NOT_FOUND, result.error_message);
    }

    result.success = true;
    return result;
}

Result<CarveResult> FileCarver::carve_record(
    VolumeReader& volume,
    uint64_t frn,
    const std::wstring& output_path,
    const std::wstring& stream_name,
    bool include_slack
) {
    if (!volume.is_open()) {
        return Error(ERROR_INVALID_HANDLE, L"Volume reader is not open");
    }

    const uint32_t rec_size = volume.geometry().bytes_per_record;
    std::vector<uint8_t> buffer(rec_size);

    auto res = volume.read_file_record(frn, buffer.data(), rec_size);
    if (!res) {
        return res.error();
    }

    return carve_from_buffer(
        volume.native_handle(),
        volume.geometry(),
        buffer.data(),
        rec_size,
        frn,
        output_path,
        stream_name,
        include_slack
    );
}

BatchCarveStats FileCarver::carve_deleted_files(
    VolumeReader& volume,
    const std::vector<RecordInfo>& records,
    const std::wstring& output_dir,
    const std::wstring& ext_filter,
    bool include_slack
) {
    BatchCarveStats stats{};
    ensure_directory_exists(output_dir);

    for (const auto& rec : records) {
        if (!rec.is_deleted || rec.is_directory) {
            continue;
        }

        if (!ext_filter.empty()) {
            size_t dot = rec.name.rfind(L'.');
            if (dot == std::wstring::npos) {
                continue;
            }
            std::wstring ext = rec.name.substr(dot + 1);
            for (auto& c : ext) {
                c = static_cast<wchar_t>(towlower(c));
            }
            std::wstring expected = ext_filter;
            for (auto& c : expected) {
                c = static_cast<wchar_t>(towlower(c));
            }
            if (ext != expected) {
                continue;
            }
        }

        stats.attempted++;
        std::wstring out_name = output_dir + L"\\carved_frn_" + std::to_wstring(rec.record_index);
        if (!rec.name.empty()) {
            out_name += L"_" + sanitize_filename(rec.name);
        } else {
            out_name += L".bin";
        }

        auto carve_res = carve_record(volume, rec.record_index, out_name, L"", include_slack);
        if (carve_res && carve_res.value().success) {
            stats.succeeded++;
            stats.total_bytes += carve_res.value().bytes_written;
        } else {
            stats.failed++;
        }
    }

    return stats;
}

} // namespace mftscan
