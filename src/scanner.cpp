#include "mftscan/scanner.hpp"
#include "mftscan/record_parser.hpp"

#include <chrono>
#include <filesystem>
#include <vector>

namespace mftscan {

VolumeScanner::VolumeScanner(wchar_t drive_letter)
    : drive_letter_(towupper(drive_letter)),
      reader_(drive_letter_),
      path_builder_(drive_letter_) {
}

Result<std::vector<RecordInfo>> VolumeScanner::scan(
    const QueryFilter& filter,
    ProgressCallback on_progress
) {
    stats_ = ScanStats{};
    path_builder_.clear();

    LARGE_INTEGER freq{}, t_start{}, t_end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t_start);

    auto open_res = reader_.open();
    if (!open_res) {
        return open_res.error();
    }

    const auto& geom = reader_.geometry();
    const uint64_t total_records = geom.total_records_estimate;

    std::vector<RecordInfo> raw_candidates;
    raw_candidates.reserve(100000);

    const uint32_t rec_size = geom.bytes_per_record;
    constexpr uint32_t kBatchRecords = 128;
    std::vector<uint8_t> batch_buf(kBatchRecords * rec_size);

    uint64_t curr_record = 0;

    while (curr_record < total_records) {
        const uint32_t to_fetch = static_cast<uint32_t>((std::min<uint64_t>)(kBatchRecords, total_records - curr_record));

        for (uint32_t i = 0; i < to_fetch; ++i) {
            uint8_t* slot = batch_buf.data() + (i * rec_size);
            auto read_res = reader_.read_file_record(curr_record + i, slot, rec_size);
            if (!read_res) {
                memset(slot, 0, rec_size);
            }
        }

        auto parsed_batch = RecordParser::parse_batch(
            batch_buf.data(),
            to_fetch,
            rec_size,
            curr_record,
            geom.bytes_per_sector
        );

        for (auto& r : parsed_batch) {
            stats_.total_records_read++;
            if (r.is_deleted) {
                stats_.deleted_records_found++;
            } else if (r.is_directory) {
                stats_.active_directories++;
                path_builder_.add_directory(r.record_index, r.parent_record_index, r.name);
            } else {
                stats_.active_files++;
            }

            raw_candidates.push_back(std::move(r));
        }

        curr_record += to_fetch;

        if (on_progress) {
            on_progress(curr_record, total_records);
        }
    }

    // Resolve paths
    path_builder_.resolve_all_paths(raw_candidates);

    // Apply query filters
    QueryEngine engine(filter);
    std::vector<RecordInfo> matches;
    matches.reserve(raw_candidates.size() / 4);

    for (auto& cand : raw_candidates) {
        if (engine.matches(cand)) {
            stats_.matched_records++;
            stats_.total_bytes_matched += cand.size_bytes;
            matches.push_back(std::move(cand));
        }
    }

    QueryPerformanceCounter(&t_end);
    const double elapsed_sec = static_cast<double>(t_end.QuadPart - t_start.QuadPart) / static_cast<double>(freq.QuadPart);
    stats_.scan_duration_ms = elapsed_sec * 1000.0;

    const double bytes_read = static_cast<double>(stats_.total_records_read * geom.bytes_per_record);
    if (elapsed_sec > 0.000001) {
        stats_.read_throughput_mbs = (bytes_read / (1024.0 * 1024.0)) / elapsed_sec;
    }

    return matches;
}

Result<std::vector<RecordInfo>> VolumeScanner::scan_fallback_win32(
    const std::wstring& root_path,
    const QueryFilter& filter
) {
    stats_ = ScanStats{};
    namespace fs = std::filesystem;

    LARGE_INTEGER freq{}, t_start{}, t_end{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t_start);

    QueryEngine engine(filter);
    std::vector<RecordInfo> matches;

    std::error_code ec;
    fs::path base_path(root_path.empty() ? (std::wstring(1, drive_letter_) + L":\\") : root_path);

    for (const auto& entry : fs::recursive_directory_iterator(base_path, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }

        stats_.total_records_read++;
        RecordInfo info;
        info.name = entry.path().filename().wstring();
        info.full_path = entry.path().wstring();
        info.is_directory = entry.is_directory(ec);

        if (info.is_directory) {
            stats_.active_directories++;
        } else {
            stats_.active_files++;
            info.size_bytes = entry.file_size(ec);
            if (ec) {
                info.size_bytes = 0;
                ec.clear();
            }
        }

        auto ftime = entry.last_write_time(ec);
        if (!ec) {
            info.modification_time = static_cast<uint64_t>(ftime.time_since_epoch().count());
        } else {
            ec.clear();
        }

        if (engine.matches(info)) {
            stats_.matched_records++;
            stats_.total_bytes_matched += info.size_bytes;
            matches.push_back(std::move(info));
        }
    }

    QueryPerformanceCounter(&t_end);
    const double elapsed_sec = static_cast<double>(t_end.QuadPart - t_start.QuadPart) / static_cast<double>(freq.QuadPart);
    stats_.scan_duration_ms = elapsed_sec * 1000.0;

    return matches;
}

} // namespace mftscan