#include "mftscan/timestomp.hpp"

namespace mftscan {

std::wstring TimestompDetector::anomaly_to_string(TimestompAnomaly anomaly) {
    switch (anomaly) {
        case TimestompAnomaly::SiCreatedBeforeFnCreated:
            return L"SI creation < FN creation";
        case TimestompAnomaly::SiModifiedBeforeFnCreated:
            return L"SI modified < FN created";
        case TimestompAnomaly::SiCreatedInFuture:
            return L"SI creation in future";
        case TimestompAnomaly::SiModifiedInFuture:
            return L"SI modification in future";
        case TimestompAnomaly::Pre1980Timestamp:
            return L"Timestamp earlier than 1980";
        case TimestompAnomaly::NanosecondsZeroed:
            return L"Fractional seconds zeroed";
        default:
            return L"Unknown anomaly";
    }
}

TimestompReport TimestompDetector::analyze(const std::vector<RecordInfo>& records) {
    TimestompReport report;
    report.total_scanned = records.size();

    FILETIME now_ft{};
    GetSystemTimeAsFileTime(&now_ft);
    const uint64_t now_ts = (static_cast<uint64_t>(now_ft.dwHighDateTime) << 32) | now_ft.dwLowDateTime;

    constexpr uint64_t kOneDayTicks = 86400ULL * 10000000ULL;
    constexpr uint64_t kTenSecondsTicks = 10ULL * 10000000ULL;
    constexpr uint64_t kYear1980Ticks = 119600064000000000ULL; // 1980-01-01 00:00:00 UTC
    const uint64_t future_threshold = now_ts + kOneDayTicks;

    for (const auto& r : records) {
        if (r.is_directory || r.is_deleted) {
            continue;
        }

        std::vector<TimestompAnomaly> anomalies;

        // Check 1: SI created earlier than FN created
        if (r.creation_time > 0 && r.fn_creation_time > 0) {
            if (r.fn_creation_time > r.creation_time + kTenSecondsTicks) {
                anomalies.push_back(TimestompAnomaly::SiCreatedBeforeFnCreated);
            }
        }

        // Check 2: SI modified earlier than FN created
        if (r.modification_time > 0 && r.fn_creation_time > 0) {
            if (r.fn_creation_time > r.modification_time + kTenSecondsTicks) {
                anomalies.push_back(TimestompAnomaly::SiModifiedBeforeFnCreated);
            }
        }

        // Check 3: Timestamps in the future
        if (r.creation_time > future_threshold) {
            anomalies.push_back(TimestompAnomaly::SiCreatedInFuture);
        }
        if (r.modification_time > future_threshold) {
            anomalies.push_back(TimestompAnomaly::SiModifiedInFuture);
        }

        // Check 4: Pre-1980 timestamps
        if ((r.creation_time > 0 && r.creation_time < kYear1980Ticks) ||
            (r.modification_time > 0 && r.modification_time < kYear1980Ticks)) {
            anomalies.push_back(TimestompAnomaly::Pre1980Timestamp);
        }

        // Check 5: Nanoseconds zeroed (second truncation artifact)
        const bool si_c_zeroed = (r.creation_time > 0) && (r.creation_time % 10000000ULL == 0);
        const bool fn_c_nonzero = (r.fn_creation_time > 0) && (r.fn_creation_time % 10000000ULL != 0);
        const bool si_m_zeroed = (r.modification_time > 0) && (r.modification_time % 10000000ULL == 0);
        const bool fn_m_nonzero = (r.fn_modification_time > 0) && (r.fn_modification_time % 10000000ULL != 0);

        if ((si_c_zeroed && fn_c_nonzero) || (si_m_zeroed && fn_m_nonzero)) {
            anomalies.push_back(TimestompAnomaly::NanosecondsZeroed);
        }

        if (!anomalies.empty()) {
            TimestompEntry entry;
            entry.record_index = r.record_index;
            entry.name = r.name;
            entry.full_path = r.full_path;
            entry.si_creation_time = r.creation_time;
            entry.si_modification_time = r.modification_time;
            entry.fn_creation_time = r.fn_creation_time;
            entry.fn_modification_time = r.fn_modification_time;
            entry.anomalies = std::move(anomalies);
            report.entries.push_back(std::move(entry));
        }
    }

    report.anomalies_detected = report.entries.size();
    return report;
}

} // namespace mftscan
