#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct ExtendSubEntry {
    uint64_t frn{0};
    std::wstring name;
    uint64_t size_bytes{0};
    uint64_t allocated_bytes{0};
    bool is_directory{false};
    std::wstring purpose;
    std::vector<std::wstring> stream_names;
};

struct ExtendReport {
    bool valid{false};
    wchar_t volume_letter{L'C'};
    uint64_t extend_frn{11};
    size_t total_subsystems{0};
    uint64_t total_metadata_bytes{0};
    uint64_t total_allocated_bytes{0};
    std::vector<ExtendSubEntry> subsystems;
};

class ExtendAnalyzer {
public:
    static ExtendReport analyze(
        const std::vector<RecordInfo>& records,
        wchar_t drive_letter = L'C'
    );

    static Result<ExtendReport> inspect(
        VolumeReader& volume,
        const std::vector<RecordInfo>& records
    );

    static std::wstring get_subsystem_purpose(const std::wstring& name);
    static void print_report(const ExtendReport& report);
};

} // namespace mftscan
