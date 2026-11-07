#pragma once

#include "mftscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct NamespaceAnomalyEntry {
    uint64_t frn{0};
    std::wstring name;
    std::wstring full_path;
    uint8_t file_name_namespace{1};
    std::wstring namespace_name;
    std::wstring anomaly_description;
    bool is_directory{false};
    bool is_deleted{false};
    bool has_trailing_dot{false};
    bool has_trailing_space{false};
    bool is_dos_device_name{false};
    bool has_illegal_chars{false};
    bool is_posix_only{false};
};

struct NamespaceReport {
    size_t total_files_analyzed{0};
    size_t total_anomalies{0};
    size_t posix_files_count{0};
    size_t trailing_dot_count{0};
    size_t trailing_space_count{0};
    size_t dos_device_name_count{0};
    size_t illegal_chars_count{0};

    std::vector<NamespaceAnomalyEntry> anomalies;
};

class NamespaceAuditor {
public:
    static NamespaceReport analyze(const std::vector<RecordInfo>& records);
    static bool is_dos_device_name(const std::wstring& filename);
    static bool has_illegal_win32_chars(const std::wstring& filename);
    static std::wstring namespace_to_string(uint8_t ns);
    static void print_report(const NamespaceReport& report);
};

} // namespace mftscan
