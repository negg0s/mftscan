#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace mftscan {

struct QueryFilter {
    std::wstring name_pattern;
    std::wstring regex_str;
    std::vector<std::wstring> extensions;
    std::optional<uint64_t> min_size;
    std::optional<uint64_t> max_size;
    std::optional<uint64_t> min_modification_time;
    std::optional<uint64_t> max_modification_time;
    bool only_files{false};
    bool only_directories{false};
    bool include_deleted{false};
    bool only_deleted{false};
    bool only_ads{false};
};

class QueryEngine {
public:
    explicit QueryEngine(QueryFilter filter);

    bool matches(const RecordInfo& record) const;

    static bool wildcard_match(std::wstring_view pattern, std::wstring_view text) noexcept;
    static std::wstring extract_extension(std::wstring_view filename);

private:
    QueryFilter filter_;
    std::optional<std::wregex> regex_;

    void init_regex();
};

} // namespace mftscan