#include "mftscan/query.hpp"

#include <cwctype>
#include <algorithm>

namespace mftscan {

static std::wstring to_lower_string(std::wstring_view sv) {
    std::wstring result;
    result.reserve(sv.size());
    for (wchar_t ch : sv) {
        result.push_back(static_cast<wchar_t>(towlower(ch)));
    }
    return result;
}

bool QueryEngine::wildcard_match(std::wstring_view pattern, std::wstring_view text) noexcept {
    size_t p_idx = 0;
    size_t t_idx = 0;
    size_t star_p = std::wstring_view::npos;
    size_t star_t = 0;

    while (t_idx < text.size()) {
        if (p_idx < pattern.size() && (pattern[p_idx] == L'?' || towlower(pattern[p_idx]) == towlower(text[t_idx]))) {
            p_idx++;
            t_idx++;
        } else if (p_idx < pattern.size() && pattern[p_idx] == L'*') {
            star_p = p_idx++;
            star_t = t_idx;
        } else if (star_p != std::wstring_view::npos) {
            p_idx = star_p + 1;
            t_idx = ++star_t;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.size() && pattern[p_idx] == L'*') {
        p_idx++;
    }

    return p_idx == pattern.size();
}

std::wstring QueryEngine::extract_extension(std::wstring_view filename) {
    const size_t dot = filename.find_last_of(L'.');
    if (dot == std::wstring_view::npos || dot == 0 || dot == filename.size() - 1) {
        return {};
    }
    return to_lower_string(filename.substr(dot + 1));
}

QueryEngine::QueryEngine(QueryFilter filter)
    : filter_(std::move(filter)) {
    init_regex();
    for (auto& ext : filter_.extensions) {
        ext = to_lower_string(ext);
        if (!ext.empty() && ext.front() == L'.') {
            ext.erase(0, 1);
        }
    }
}

void QueryEngine::init_regex() {
    if (!filter_.regex_str.empty()) {
        try {
            regex_ = std::wregex(filter_.regex_str, std::regex_constants::icase | std::regex_constants::optimize);
        } catch (...) {
            regex_ = std::nullopt;
        }
    }
}

bool QueryEngine::matches(const RecordInfo& record) const {
    // 1. Deleted filter
    if (filter_.only_deleted && !record.is_deleted) {
        return false;
    }
    if (!filter_.include_deleted && !filter_.only_deleted && record.is_deleted) {
        return false;
    }

    // 2. Type filter
    if (filter_.only_files && record.is_directory) {
        return false;
    }
    if (filter_.only_directories && !record.is_directory) {
        return false;
    }

    // 3. ADS filter
    if (filter_.only_ads && !record.has_ads) {
        return false;
    }

    // 4. Sparse and Compressed filters
    if (filter_.only_sparse && !record.is_sparse) {
        return false;
    }
    if (filter_.only_compressed && !record.is_compressed) {
        return false;
    }

    // 5. Fragmentation and Slack filters
    if (filter_.min_fragments && record.fragment_count < *filter_.min_fragments) {
        return false;
    }
    if (filter_.min_slack && record.slack_bytes < *filter_.min_slack) {
        return false;
    }

    // 4. Size filter (only applies to files)
    if (!record.is_directory) {
        if (filter_.min_size && record.size_bytes < *filter_.min_size) {
            return false;
        }
        if (filter_.max_size && record.size_bytes > *filter_.max_size) {
            return false;
        }
    }

    // 5. Date filter
    if (filter_.min_modification_time && record.modification_time < *filter_.min_modification_time) {
        return false;
    }
    if (filter_.max_modification_time && record.modification_time > *filter_.max_modification_time) {
        return false;
    }

    // 6. Extension filter
    if (!filter_.extensions.empty()) {
        if (record.is_directory) {
            return false;
        }
        const std::wstring file_ext = extract_extension(record.name);
        const bool ext_found = std::any_of(
            filter_.extensions.begin(),
            filter_.extensions.end(),
            [&](const std::wstring& e) { return e == file_ext; }
        );
        if (!ext_found) {
            return false;
        }
    }

    // 7. Regex filter
    if (regex_.has_value()) {
        if (!std::regex_search(record.name, *regex_)) {
            if (record.full_path.empty() || !std::regex_search(record.full_path, *regex_)) {
                return false;
            }
        }
    }

    // 8. Wildcard / Name filter
    if (!filter_.name_pattern.empty()) {
        if (!wildcard_match(filter_.name_pattern, record.name)) {
            return false;
        }
    }

    return true;
}

} // namespace mftscan