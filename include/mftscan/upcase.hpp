#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct UpCaseAnomaly {
    wchar_t source_char{0};
    wchar_t mapped_char{0};
    wchar_t expected_char{0};
    std::wstring description;
};

struct UpCaseReport {
    bool valid{false};
    wchar_t volume_letter{L'C'};
    uint64_t stream_size_bytes{0};
    size_t character_count{0};
    uint64_t fnv1a_hash{0};
    bool is_ascii_consistent{true};
    size_t ascii_mismatches_count{0};
    size_t reference_deviations_count{0};
    bool is_standard_table{true};
    std::vector<UpCaseAnomaly> anomalies;
};

class UpCaseAnalyzer {
public:
    static UpCaseReport analyze_buffer(
        const uint8_t* upcase_data,
        size_t size,
        wchar_t drive_letter = L'C'
    );

    static Result<UpCaseReport> inspect(VolumeReader& volume);
    static void print_report(const UpCaseReport& report);
};

} // namespace mftscan
