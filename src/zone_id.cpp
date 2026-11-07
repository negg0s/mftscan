#include "mftscan/zone_id.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/record_parser.hpp"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace mftscan {

std::wstring ZoneIdentifierAuditor::zone_id_to_string(uint32_t zone_id) {
    switch (zone_id) {
    case 0: return L"Local Machine (0)";
    case 1: return L"Local Intranet (1)";
    case 2: return L"Trusted Sites (2)";
    case 3: return L"Internet (3)";
    case 4: return L"Restricted Sites (4)";
    default: return L"Custom (" + std::to_wstring(zone_id) + L")";
    }
}

std::wstring ZoneIdentifierAuditor::extract_domain_from_url(const std::wstring& url) {
    if (url.empty()) return L"(unknown)";

    size_t scheme_pos = url.find(L"://");
    size_t start_pos = 0;
    if (scheme_pos != std::wstring::npos) {
        start_pos = scheme_pos + 3;
    }

    size_t slash_pos = url.find(L'/', start_pos);
    size_t colon_pos = url.find(L':', start_pos);
    size_t end_pos = slash_pos;
    if (colon_pos != std::wstring::npos && (slash_pos == std::wstring::npos || colon_pos < slash_pos)) {
        end_pos = colon_pos;
    }

    std::wstring domain;
    if (end_pos == std::wstring::npos) {
        domain = url.substr(start_pos);
    } else {
        domain = url.substr(start_pos, end_pos - start_pos);
    }

    for (auto& c : domain) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return domain.empty() ? L"(unknown)" : domain;
}

static bool check_is_executable(const std::wstring& name) {
    size_t dot_pos = name.rfind(L'.');
    if (dot_pos == std::wstring::npos) return false;
    std::wstring ext = name.substr(dot_pos);
    for (auto& c : ext) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return (ext == L".exe" || ext == L".dll" || ext == L".msi" ||
            ext == L".bat" || ext == L".cmd" || ext == L".ps1" ||
            ext == L".vbs" || ext == L".js"  || ext == L".iso" ||
            ext == L".scr" || ext == L".com" || ext == L".hta");
}

ZoneIdentifierInfo ZoneIdentifierAuditor::parse_payload(
    const uint8_t* data,
    size_t size,
    uint64_t frn,
    const std::wstring& path,
    const std::wstring& name,
    uint64_t file_size
) {
    ZoneIdentifierInfo info{};
    info.frn = frn;
    info.file_path = path;
    info.file_name = name;
    info.file_size = file_size;
    info.is_executable = check_is_executable(name);

    if (data == nullptr || size == 0) {
        info.zone_name = zone_id_to_string(info.zone_id);
        return info;
    }

    std::wstring content;

    // Check if payload is UTF-16 LE
    if (size >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        const auto* wptr = reinterpret_cast<const wchar_t*>(data + 2);
        size_t wlen = (size - 2) / sizeof(wchar_t);
        content.assign(wptr, wlen);
    } else if (size >= 4 && data[1] == 0x00 && data[3] == 0x00) {
        const auto* wptr = reinterpret_cast<const wchar_t*>(data);
        size_t wlen = size / sizeof(wchar_t);
        content.assign(wptr, wlen);
    } else {
        // ANSI or UTF-8
        content.reserve(size);
        for (size_t i = 0; i < size; ++i) {
            content.push_back(static_cast<wchar_t>(data[i]));
        }
    }

    std::wistringstream stream(content);
    std::wstring line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }

        size_t eq_pos = line.find(L'=');
        if (eq_pos == std::wstring::npos) continue;

        std::wstring key = line.substr(0, eq_pos);
        std::wstring val = line.substr(eq_pos + 1);

        for (auto& c : key) c = static_cast<wchar_t>(towlower(c));

        if (key == L"zoneid") {
            info.zone_id = static_cast<uint32_t>(_wtoi(val.c_str()));
        } else if (key == L"hosturl") {
            info.host_url = val;
            info.host_domain = extract_domain_from_url(val);
        } else if (key == L"referrerurl") {
            info.referrer_url = val;
        } else if (key == L"lastwriterpackagefamilyname") {
            info.package_family_name = val;
        }
    }

    info.zone_name = zone_id_to_string(info.zone_id);
    return info;
}

ZoneIdentifierReport ZoneIdentifierAuditor::analyze(
    VolumeReader& volume,
    const std::vector<RecordInfo>& records
) {
    ZoneIdentifierReport report{};
    report.total_scanned_files = records.size();

    const bool has_volume = volume.is_open();
    const uint32_t rec_size = has_volume ? volume.geometry().bytes_per_record : 1024;
    std::vector<uint8_t> rec_buf(rec_size);

    for (const auto& rec : records) {
        if (rec.is_deleted || rec.is_directory) {
            continue;
        }

        if (rec.has_ads) {
            ++report.files_with_ads;
        }

        bool has_zone_stream = false;
        for (const auto& stream_name : rec.ads_names) {
            if (stream_name == L"Zone.Identifier") {
                has_zone_stream = true;
                break;
            }
        }

        if (!has_zone_stream) {
            continue;
        }

        ZoneIdentifierInfo item{};
        bool extracted = false;

        if (has_volume) {
            auto read_res = volume.read_file_record(rec.record_index, rec_buf.data(), rec_size);
            if (read_res) {
                RecordParser::apply_fixup(rec_buf.data(), rec_size, volume.geometry().bytes_per_sector);
                const auto* mft_hdr = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
                uint32_t offset = mft_hdr->first_attribute_offset;

                while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
                    const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_buf.data() + offset);
                    if (attr->type_code == kAttrEnd || attr->record_length == 0) break;
                    if (offset + attr->record_length > rec_size) break;

                    if (attr->type_code == kAttrData && attr->name_length > 0) {
                        const uint16_t n_off = attr->name_offset;
                        if (n_off + attr->name_length * sizeof(wchar_t) <= attr->record_length) {
                            const wchar_t* name_ptr = reinterpret_cast<const wchar_t*>(
                                rec_buf.data() + offset + n_off
                            );
                            std::wstring a_name(name_ptr, attr->name_length);
                            if (a_name == L"Zone.Identifier" && attr->non_resident_flag == 0) {
                                const uint16_t v_off = attr->resident.value_offset;
                                const uint32_t v_len = attr->resident.value_length;
                                if (v_off + v_len <= attr->record_length) {
                                    item = parse_payload(
                                        rec_buf.data() + offset + v_off,
                                        v_len,
                                        rec.record_index,
                                        rec.full_path.empty() ? rec.name : rec.full_path,
                                        rec.name,
                                        rec.size_bytes
                                    );
                                    extracted = true;
                                    break;
                                }
                            }
                        }
                    }
                    offset += attr->record_length;
                }
            }
        }

        if (!extracted) {
            item.frn = rec.record_index;
            item.file_path = rec.full_path.empty() ? rec.name : rec.full_path;
            item.file_name = rec.name;
            item.file_size = rec.size_bytes;
            item.zone_id = 3; // Default Internet Zone
            item.zone_name = zone_id_to_string(3);
            item.is_executable = check_is_executable(rec.name);
        }

        ++report.zone_identifier_files_count;
        if (item.zone_id == 3) ++report.internet_zone_count;
        else if (item.zone_id == 4) ++report.restricted_zone_count;
        else if (item.zone_id == 2) ++report.trusted_zone_count;
        else if (item.zone_id == 1) ++report.intranet_zone_count;

        if (item.is_executable) {
            ++report.downloaded_executables_count;
        }

        if (!item.host_domain.empty() && item.host_domain != L"(unknown)") {
            report.domain_breakdown[item.host_domain]++;
        }

        report.entries.push_back(std::move(item));
    }

    return report;
}

void ZoneIdentifierAuditor::print_report(const ZoneIdentifierReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS WEB DOWNLOAD PROVENANCE & ZONE.IDENTIFIER (MOTW) AUDIT\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Files Evaluated      : " << report.total_scanned_files << L"\n";
    std::wcout << L"  Files with Streams   : " << report.files_with_ads << L" (Alternate Data Streams)\n";
    std::wcout << L"  Zone.Identifier (MOTW): " << report.zone_identifier_files_count << L" downloaded files\n";
    std::wcout << L"  Internet Zone (3)    : " << report.internet_zone_count << L"\n";
    std::wcout << L"  Restricted Zone (4)  : " << report.restricted_zone_count << L"\n";
    std::wcout << L"  Intranet / Trusted   : " << (report.intranet_zone_count + report.trusted_zone_count) << L"\n";
    std::wcout << L"  Downloaded Binaries  : " << report.downloaded_executables_count << L" executables/scripts from external zones\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    if (!report.domain_breakdown.empty()) {
        std::wcout << L" TOP DOWNLOAD SOURCE DOMAINS\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        std::vector<std::pair<std::wstring, size_t>> sorted_domains(
            report.domain_breakdown.begin(),
            report.domain_breakdown.end()
        );
        std::sort(sorted_domains.begin(), sorted_domains.end(), [](const auto& a, const auto& b) {
            return a.second > b.second;
        });

        const size_t dom_take = std::min(size_t{10}, sorted_domains.size());
        for (size_t i = 0; i < dom_take; ++i) {
            std::wcout << L"  " << std::left << std::setw(32) << sorted_domains[i].first
                       << L": " << std::right << std::setw(6) << sorted_domains[i].second << L" files\n";
        }
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    }

    if (report.entries.empty()) {
        std::wcout << L"  Zero files with Zone.Identifier alternate data streams found on the volume.\n";
    } else {
        std::wcout << L" AUDITED WEB DOWNLOADS (MARK-OF-THE-WEB ENTRIES)\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::setw(14) << L"Zone"
                   << std::setw(8)  << L"Type"
                   << std::setw(24) << L"Domain"
                   << L"Path\n";
        std::wcout << L"----------------------------------------------------------------------------------------------------\n";

        for (const auto& e : report.entries) {
            std::wstring type_str = e.is_executable ? L"Binary" : L"Doc/Data";
            std::wstring dom_str = e.host_domain.empty() ? L"(unknown)" : e.host_domain;
            if (dom_str.size() > 22) {
                dom_str = dom_str.substr(0, 19) + L"...";
            }

            std::wcout << std::left
                       << std::setw(12) << e.frn
                       << std::setw(14) << (L"Zone " + std::to_wstring(e.zone_id))
                       << std::setw(8)  << type_str
                       << std::setw(24) << dom_str
                       << e.file_path << L"\n";

            if (!e.host_url.empty()) {
                std::wcout << L"             URL: " << e.host_url << L"\n";
            }
        }
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
