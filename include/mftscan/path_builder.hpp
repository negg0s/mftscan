#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace mftscan {

class PathBuilder {
public:
    explicit PathBuilder(wchar_t drive_letter);

    void add_directory(uint64_t record_index, uint64_t parent_index, std::wstring name);
    std::wstring resolve_path(uint64_t parent_index, const std::wstring& file_name);
    void resolve_all_paths(std::vector<RecordInfo>& records);

    void clear() noexcept;

private:
    struct DirNode {
        uint64_t parent_index{0};
        std::wstring name;
    };

    wchar_t drive_letter_{L'C'};
    std::unordered_map<uint64_t, DirNode> dir_tree_;
    std::unordered_map<uint64_t, std::wstring> path_cache_;

    const std::wstring& get_directory_path(uint64_t dir_index);
};

} // namespace mftscan