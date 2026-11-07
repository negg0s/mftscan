#include "mftscan/path_builder.hpp"
#include "mftscan/ntfs_defs.hpp"

#include <unordered_set>

namespace mftscan {

PathBuilder::PathBuilder(wchar_t drive_letter)
    : drive_letter_(towupper(drive_letter)) {
    // Root directory (record 5) path is "X:\"
    path_cache_[kRecordRootDir] = std::wstring(1, drive_letter_) + L":\\";
}

void PathBuilder::clear() noexcept {
    dir_tree_.clear();
    path_cache_.clear();
    path_cache_[kRecordRootDir] = std::wstring(1, drive_letter_) + L":\\";
}

void PathBuilder::add_directory(uint64_t record_index, uint64_t parent_index, std::wstring name) {
    if (record_index == kRecordRootDir || name == L".") {
        return;
    }
    dir_tree_[record_index] = DirNode{ parent_index, std::move(name) };
}

const std::wstring& PathBuilder::get_directory_path(uint64_t dir_index) {
    const auto it = path_cache_.find(dir_index);
    if (it != path_cache_.end()) {
        return it->second;
    }

    if (dir_index == kRecordRootDir || dir_index == 0) {
        return path_cache_[kRecordRootDir];
    }

    // Traverse upwards to root
    std::vector<uint64_t> chain;
    std::unordered_set<uint64_t> visited;

    uint64_t curr = dir_index;
    while (curr != kRecordRootDir && curr != 0) {
        if (!visited.insert(curr).second || chain.size() > 128) {
            // Loop detected or max depth exceeded
            break;
        }

        const auto found_cache = path_cache_.find(curr);
        if (found_cache != path_cache_.end()) {
            break;
        }

        chain.push_back(curr);
        const auto node_it = dir_tree_.find(curr);
        if (node_it == dir_tree_.end()) {
            break;
        }
        curr = node_it->second.parent_index;
    }

    // Now resolve forward from top of chain down to dir_index
    for (auto rit = chain.rbegin(); rit != chain.rend(); ++rit) {
        const uint64_t node_idx = *rit;
        const auto node_it = dir_tree_.find(node_idx);
        if (node_it == dir_tree_.end()) {
            path_cache_[node_idx] = std::wstring(1, drive_letter_) + L":\\$OrphanFiles\\" + std::to_wstring(node_idx) + L"\\";
            continue;
        }

        const uint64_t parent_idx = node_it->second.parent_index;
        const auto parent_cache_it = path_cache_.find(parent_idx);
        const std::wstring& parent_path = (parent_cache_it != path_cache_.end())
            ? parent_cache_it->second
            : path_cache_[kRecordRootDir];

        std::wstring full_dir = parent_path;
        if (!full_dir.empty() && full_dir.back() != L'\\') {
            full_dir += L'\\';
        }
        full_dir += node_it->second.name + L'\\';
        path_cache_[node_idx] = std::move(full_dir);
    }

    const auto final_it = path_cache_.find(dir_index);
    if (final_it != path_cache_.end()) {
        return final_it->second;
    }

    static const std::wstring kEmpty;
    return kEmpty;
}

std::wstring PathBuilder::resolve_path(uint64_t parent_index, const std::wstring& file_name) {
    const std::wstring& dir_path = get_directory_path(parent_index);
    if (dir_path.empty()) {
        return std::wstring(1, drive_letter_) + L":\\$OrphanFiles\\" + file_name;
    }
    if (dir_path.back() == L'\\') {
        return dir_path + file_name;
    }
    return dir_path + L'\\' + file_name;
}

void PathBuilder::resolve_all_paths(std::vector<RecordInfo>& records) {
    for (auto& rec : records) {
        if (rec.full_path.empty()) {
            rec.full_path = resolve_path(rec.parent_record_index, rec.name);
        }
    }
}

} // namespace mftscan