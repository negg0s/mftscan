#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <functional>
#include <string>
#include <vector>

namespace mftscan {

struct UsnChangeRecord {
    uint64_t file_ref{0};
    uint64_t parent_ref{0};
    uint64_t usn{0};
    uint64_t timestamp{0};
    uint32_t reason{0};
    std::wstring file_name;
    std::wstring reason_string;
};

class UsnMonitor {
public:
    explicit UsnMonitor(VolumeReader& volume);

    Result<USN_JOURNAL_DATA_V0> query_journal();

    using ChangeCallback = std::function<bool(const UsnChangeRecord& change)>;

    Result<uint64_t> read_changes(
        uint64_t start_usn,
        uint64_t max_records,
        ChangeCallback on_change
    );

    static std::wstring format_reason(uint32_t reason);

private:
    VolumeReader& volume_;
    USN_JOURNAL_DATA_V0 journal_data_{};
};

} // namespace mftscan