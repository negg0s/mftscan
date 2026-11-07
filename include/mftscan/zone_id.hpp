#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace mftscan {

struct ZoneIdentifierInfo {
    uint64_t frn{0};
    std::wstring file_path;
    std::wstring file_name;
    uint32_t zone_id{3};
    std::wstring zone_name;
    std::wstring host_url;
    std::wstring referrer_url;
    std::wstring host_domain;
    std::wstring package_family_name;
    bool is_executable{false};
    uint64_t file_size{0};
};

struct ZoneIdentifierReport {
    size_t total_scanned_files{0};
    size_t files_with_ads{0};
    size_t zone_identifier_files_count{0};
    size_t internet_zone_count{0};
    size_t restricted_zone_count{0};
    size_t trusted_zone_count{0};
    size_t intranet_zone_count{0};
    size_t downloaded_executables_count{0};

    std::map<std::wstring, size_t> domain_breakdown;
    std::vector<ZoneIdentifierInfo> entries;
};

class ZoneIdentifierAuditor {
public:
    static ZoneIdentifierInfo parse_payload(
        const uint8_t* data,
        size_t size,
        uint64_t frn,
        const std::wstring& path,
        const std::wstring& name,
        uint64_t file_size
    );

    static std::wstring zone_id_to_string(uint32_t zone_id);
    static std::wstring extract_domain_from_url(const std::wstring& url);

    static ZoneIdentifierReport analyze(
        VolumeReader& volume,
        const std::vector<RecordInfo>& records
    );

    static void print_report(const ZoneIdentifierReport& report);
};

} // namespace mftscan
