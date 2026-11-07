#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

struct ResidualString {
    size_t offset{0};
    bool is_utf16{false};
    std::wstring text;
};

struct ResidualAttribute {
    size_t offset{0};
    uint32_t type_code{0};
    std::wstring type_name;
    uint32_t length{0};
};

struct MftSlackReport {
    uint64_t frn{0};
    uint32_t bytes_used{0};
    uint32_t bytes_allocated{0};
    uint32_t slack_size{0};
    bool has_non_zero_slack{false};
    uint32_t non_zero_bytes_count{0};
    std::vector<ResidualString> residual_strings;
    std::vector<ResidualAttribute> residual_attributes;
    std::string hex_dump;
};

class MftSlackCarver {
public:
    static Result<MftSlackReport> analyze_record_slack(
        const uint8_t* record_buffer,
        uint32_t record_size,
        uint64_t frn = 0
    );

    static Result<MftSlackReport> inspect_record(VolumeReader& volume, uint64_t frn);

    static std::vector<ResidualString> extract_residual_strings(
        const uint8_t* data,
        size_t size,
        size_t min_len = 4
    );

    static std::vector<ResidualAttribute> extract_residual_attributes(
        const uint8_t* data,
        size_t size
    );
};

} // namespace mftscan
