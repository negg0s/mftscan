#include "mftscan/disk_usage.hpp"
#include "mftscan/query.hpp"

#include <algorithm>
#include <unordered_map>

namespace mftscan {

std::vector<RecordInfo> DiskUsageAnalyzer::top_largest_files(
    const std::vector<RecordInfo>& records,
    size_t limit
) {
    std::vector<RecordInfo> files;
    files.reserve(records.size());

    for (const auto& r : records) {
        if (!r.is_directory && !r.is_deleted && r.size_bytes > 0) {
            files.push_back(r);
        }
    }

    if (files.size() > limit) {
        std::partial_sort(
            files.begin(),
            files.begin() + limit,
            files.end(),
            [](const RecordInfo& a, const RecordInfo& b) {
                return a.size_bytes > b.size_bytes;
            }
        );
        files.resize(limit);
    } else {
        std::sort(
            files.begin(),
            files.end(),
            [](const RecordInfo& a, const RecordInfo& b) {
                return a.size_bytes > b.size_bytes;
            }
        );
    }

    return files;
}

std::vector<ExtensionStat> DiskUsageAnalyzer::compute_extension_histogram(
    const std::vector<RecordInfo>& records,
    size_t limit
) {
    std::unordered_map<std::wstring, ExtensionStat> map;

    for (const auto& r : records) {
        if (!r.is_directory && !r.is_deleted) {
            std::wstring ext = QueryEngine::extract_extension(r.name);
            if (ext.empty()) {
                ext = L"<none>";
            }

            auto& entry = map[ext];
            entry.extension = ext;
            entry.count++;
            entry.total_bytes += r.size_bytes;
        }
    }

    std::vector<ExtensionStat> result;
    result.reserve(map.size());
    for (auto& pair : map) {
        result.push_back(std::move(pair.second));
    }

    std::sort(
        result.begin(),
        result.end(),
        [](const ExtensionStat& a, const ExtensionStat& b) {
            return a.total_bytes > b.total_bytes;
        }
    );

    if (result.size() > limit) {
        result.resize(limit);
    }

    return result;
}

std::vector<DirectoryUsage> DiskUsageAnalyzer::compute_top_directories(
    const std::vector<RecordInfo>& records,
    size_t limit
) {
    std::unordered_map<std::wstring, DirectoryUsage> dir_map;

    for (const auto& r : records) {
        if (!r.is_directory && !r.is_deleted && !r.full_path.empty()) {
            const size_t last_slash = r.full_path.find_last_of(L"\\/");
            if (last_slash != std::wstring::npos) {
                const std::wstring parent_dir = r.full_path.substr(0, last_slash);
                auto& usage = dir_map[parent_dir];
                usage.path = parent_dir;
                usage.file_count++;
                usage.total_bytes += r.size_bytes;
            }
        }
    }

    std::vector<DirectoryUsage> result;
    result.reserve(dir_map.size());
    for (auto& pair : dir_map) {
        result.push_back(std::move(pair.second));
    }

    std::sort(
        result.begin(),
        result.end(),
        [](const DirectoryUsage& a, const DirectoryUsage& b) {
            return a.total_bytes > b.total_bytes;
        }
    );

    if (result.size() > limit) {
        result.resize(limit);
    }

    return result;
}

} // namespace mftscan