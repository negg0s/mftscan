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

struct OwnerQuotaUsage {
    uint32_t owner_id{0};
    uint64_t file_count{0};
    uint64_t total_logical_bytes{0};
    uint64_t total_quota_charged{0};
    std::wstring description;
};

struct QuotaReport {
    uint64_t total_files_analyzed{0};
    uint64_t total_quota_charged_bytes{0};
    uint64_t uncharged_files_count{0};
    std::vector<OwnerQuotaUsage> owners;
};

class QuotaAnalyzer {
public:
    static QuotaReport analyze(const std::vector<RecordInfo>& records);
    static void print_report(const QuotaReport& report);
};

} // namespace mftscan
