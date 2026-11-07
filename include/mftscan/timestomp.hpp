#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

enum class TimestompAnomaly {
    SiCreatedBeforeFnCreated,    // Standard Info creation earlier than File Name creation
    SiModifiedBeforeFnCreated,   // Standard Info modification earlier than File Name creation
    SiCreatedInFuture,           // Standard Info creation is in the future
    SiModifiedInFuture,          // Standard Info modification is in the future
    Pre1980Timestamp,            // Timestamp is older than year 1980
    NanosecondsZeroed            // Fractional seconds are zero in SI while FN has non-zero fractional seconds
};

struct TimestompEntry {
    uint64_t record_index{0};
    std::wstring name;
    std::wstring full_path;
    uint64_t si_creation_time{0};
    uint64_t si_modification_time{0};
    uint64_t fn_creation_time{0};
    uint64_t fn_modification_time{0};
    std::vector<TimestompAnomaly> anomalies;
};

struct TimestompReport {
    std::vector<TimestompEntry> entries;
    uint64_t total_scanned{0};
    uint64_t anomalies_detected{0};
};

class TimestompDetector {
public:
    static TimestompReport analyze(const std::vector<RecordInfo>& records);
    static std::wstring anomaly_to_string(TimestompAnomaly anomaly);
};

} // namespace mftscan
