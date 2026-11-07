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

namespace mftscan {

struct LogFileReport {
    wchar_t volume_letter{L'C'};
    bool is_valid_rstr{false};
    uint32_t magic{0};
    int16_t major_version{0};
    int16_t minor_version{0};
    uint32_t system_page_size{0};
    uint32_t log_page_size{0};
    uint64_t current_lsn{0};
    uint16_t log_clients{0};
    uint16_t restart_flags{0};
    bool is_clean_shutdown{false};
    uint64_t file_size{0};
    uint32_t restart_open_log_count{0};
    std::wstring extra_notes;
};

class LogFileAnalyzer {
public:
    static Result<LogFileReport> analyze(VolumeReader& volume);

    static Result<LogFileReport> analyze_from_page(
        const uint8_t* page_buffer,
        size_t page_size,
        wchar_t volume_letter = L'C'
    );
};

} // namespace mftscan
