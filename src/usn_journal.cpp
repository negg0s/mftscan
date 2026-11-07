#include "mftscan/usn_journal.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/usn_monitor.hpp"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <iostream>

namespace mftscan {

Result<UsnJournalStats> UsnJournalAnalyzer::query_stats(VolumeReader& volume) {
    HANDLE hVolume = volume.native_handle();
    if (hVolume == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Invalid volume handle");
    }

    USN_JOURNAL_DATA_V0 jd{};
    DWORD bytes_returned = 0;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &jd, sizeof(jd), &bytes_returned, nullptr)) {
        return Error(GetLastError(), L"FSCTL_QUERY_USN_JOURNAL failed");
    }

    UsnJournalStats s;
    s.journal_id = jd.UsnJournalID;
    s.lowest_valid_usn = jd.LowestValidUsn;
    s.first_usn = jd.LowestValidUsn;
    s.next_usn = jd.NextUsn;
    s.maximum_size = jd.MaximumSize;
    s.allocation_delta = jd.AllocationDelta;
    s.max_usn = jd.MaxUsn;

    if (s.next_usn >= s.lowest_valid_usn) {
        const uint64_t diff = s.next_usn - s.lowest_valid_usn;
        s.estimated_active_size_mb = static_cast<double>(diff) / (1024.0 * 1024.0);
        s.approximate_event_count = diff / 96;

        if (s.maximum_size > 0) {
            s.utilization_percentage = (static_cast<double>(diff) / static_cast<double>(s.maximum_size)) * 100.0;
        }
    }

    if (s.max_usn > 0) {
        s.rollover_percentage = (static_cast<double>(s.next_usn) / static_cast<double>(s.max_usn)) * 100.0;
    }

    return s;
}

Result<UsnHistoryReport> UsnJournalAnalyzer::extract_history(
    VolumeReader& volume,
    uint64_t target_frn,
    size_t max_events
) {
    HANDLE hVolume = volume.native_handle();
    if (hVolume == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Invalid volume handle");
    }

    USN_JOURNAL_DATA_V0 jd{};
    DWORD bytes_returned = 0;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &jd, sizeof(jd), &bytes_returned, nullptr)) {
        return Error(GetLastError(), L"FSCTL_QUERY_USN_JOURNAL failed");
    }

    UsnHistoryReport rep;
    rep.target_frn = target_frn;

    USN curr_usn = jd.LowestValidUsn;
    READ_USN_JOURNAL_DATA_V0 read_input{};
    read_input.ReasonMask = 0xFFFFFFFF;
    read_input.ReturnOnlyOnClose = 0;
    read_input.Timeout = 0;
    read_input.BytesToWaitFor = 0;
    read_input.UsnJournalID = jd.UsnJournalID;

    std::vector<uint8_t> out_buffer(65536);

    while (curr_usn < jd.NextUsn && rep.entries.size() < max_events) {
        read_input.StartUsn = curr_usn;
        bytes_returned = 0;

        const BOOL ok = DeviceIoControl(
            hVolume,
            FSCTL_READ_USN_JOURNAL,
            &read_input,
            sizeof(read_input),
            out_buffer.data(),
            static_cast<DWORD>(out_buffer.size()),
            &bytes_returned,
            nullptr
        );

        if (!ok || bytes_returned <= sizeof(USN)) {
            break;
        }

        const USN next_page_usn = *reinterpret_cast<const USN*>(out_buffer.data());
        if (next_page_usn <= curr_usn) {
            break;
        }

        uint32_t offset = sizeof(USN);
        while (offset < bytes_returned && rep.entries.size() < max_events) {
            const auto* rec = reinterpret_cast<const USN_RECORD_V2*>(out_buffer.data() + offset);
            if (rec->RecordLength == 0 || offset + rec->RecordLength > bytes_returned) {
                break;
            }

            const uint64_t rec_frn = extract_record_number(rec->FileReferenceNumber);
            if (rec_frn == target_frn) {
                UsnHistoryEntry entry;
                entry.usn = static_cast<uint64_t>(rec->Usn);
                entry.timestamp = static_cast<uint64_t>(rec->TimeStamp.QuadPart);
                entry.frn = rec_frn;
                entry.parent_frn = extract_record_number(rec->ParentFileReferenceNumber);
                entry.reason = rec->Reason;
                entry.reason_string = UsnMonitor::format_reason(rec->Reason);

                if (rec->FileNameLength > 0 && static_cast<uint32_t>(rec->FileNameOffset) + static_cast<uint32_t>(rec->FileNameLength) <= rec->RecordLength) {
                    const wchar_t* fn_ptr = reinterpret_cast<const wchar_t*>(
                        reinterpret_cast<const uint8_t*>(rec) + rec->FileNameOffset
                    );
                    entry.file_name = std::wstring(fn_ptr, rec->FileNameLength / sizeof(wchar_t));
                }

                rep.entries.push_back(std::move(entry));
            }

            offset += rec->RecordLength;
        }

        curr_usn = next_page_usn;
    }

    return rep;
}

uint32_t UsnJournalAnalyzer::parse_reason_string(const std::wstring& reason_str) {
    if (reason_str.empty()) {
        return 0;
    }

    if (reason_str.size() > 2 && (reason_str.rfind(L"0x", 0) == 0 || reason_str.rfind(L"0X", 0) == 0)) {
        return static_cast<uint32_t>(wcstoul(reason_str.c_str(), nullptr, 16));
    }

    std::wstring upper = reason_str;
    for (auto& c : upper) {
        c = static_cast<wchar_t>(towupper(c));
    }

    uint32_t mask = 0;
    if (upper.find(L"CREATE") != std::wstring::npos) mask |= 0x00000100; // USN_REASON_FILE_CREATE
    if (upper.find(L"DELETE") != std::wstring::npos) mask |= 0x00000200; // USN_REASON_FILE_DELETE
    if (upper.find(L"OVERWRITE") != std::wstring::npos) mask |= 0x00000001; // USN_REASON_DATA_OVERWRITE
    if (upper.find(L"EXTEND") != std::wstring::npos) mask |= 0x00000002; // USN_REASON_DATA_EXTEND
    if (upper.find(L"TRUNCATE") != std::wstring::npos) mask |= 0x00000004; // USN_REASON_DATA_TRUNCATION
    if (upper.find(L"SECURITY") != std::wstring::npos) mask |= 0x00000800; // USN_REASON_SECURITY_CHANGE
    if (upper.find(L"RENAME") != std::wstring::npos) mask |= (0x00001000 | 0x00002000); // RENAME_OLD | RENAME_NEW
    if (upper.find(L"LINK") != std::wstring::npos) mask |= 0x00010000; // HARD_LINK_CHANGE
    if (upper.find(L"COMPRESS") != std::wstring::npos) mask |= 0x00020000; // COMPRESSION_CHANGE
    if (upper.find(L"CLOSE") != std::wstring::npos) mask |= 0x80000000; // USN_REASON_CLOSE

    return mask;
}

Result<UsnDumpReport> UsnJournalAnalyzer::dump_journal(
    VolumeReader& volume,
    const UsnDumpFilter& filter
) {
    HANDLE hVolume = volume.native_handle();
    if (hVolume == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Invalid volume handle");
    }

    USN_JOURNAL_DATA_V0 jd{};
    DWORD bytes_returned = 0;
    if (!DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &jd, sizeof(jd), &bytes_returned, nullptr)) {
        return Error(GetLastError(), L"FSCTL_QUERY_USN_JOURNAL failed");
    }

    UsnDumpReport rep;
    rep.journal_id = jd.UsnJournalID;
    rep.lowest_usn = jd.LowestValidUsn;
    rep.next_usn = jd.NextUsn;
    rep.applied_reason_mask = filter.reason_mask;

    USN curr_usn = (filter.start_usn > static_cast<uint64_t>(jd.LowestValidUsn)) ? static_cast<USN>(filter.start_usn) : jd.LowestValidUsn;
    READ_USN_JOURNAL_DATA_V0 read_input{};
    read_input.ReasonMask = (filter.reason_mask != 0) ? filter.reason_mask : 0xFFFFFFFF;
    read_input.ReturnOnlyOnClose = 0;
    read_input.Timeout = 0;
    read_input.BytesToWaitFor = 0;
    read_input.UsnJournalID = jd.UsnJournalID;

    std::vector<uint8_t> out_buffer(65536);

    while (curr_usn < jd.NextUsn && rep.entries.size() < filter.limit) {
        read_input.StartUsn = curr_usn;
        bytes_returned = 0;

        const BOOL ok = DeviceIoControl(
            hVolume,
            FSCTL_READ_USN_JOURNAL,
            &read_input,
            sizeof(read_input),
            out_buffer.data(),
            static_cast<DWORD>(out_buffer.size()),
            &bytes_returned,
            nullptr
        );

        if (!ok || bytes_returned <= sizeof(USN)) {
            break;
        }

        const USN next_page_usn = *reinterpret_cast<const USN*>(out_buffer.data());
        if (next_page_usn <= curr_usn) {
            break;
        }

        uint32_t offset = sizeof(USN);
        while (offset < bytes_returned && rep.entries.size() < filter.limit) {
            const auto* rec = reinterpret_cast<const USN_RECORD_V2*>(out_buffer.data() + offset);
            if (rec->RecordLength == 0 || offset + rec->RecordLength > bytes_returned) {
                break;
            }

            if (filter.reason_mask == 0 || (rec->Reason & filter.reason_mask) != 0) {
                UsnHistoryEntry entry;
                entry.usn = static_cast<uint64_t>(rec->Usn);
                entry.timestamp = static_cast<uint64_t>(rec->TimeStamp.QuadPart);
                entry.frn = extract_record_number(rec->FileReferenceNumber);
                entry.parent_frn = extract_record_number(rec->ParentFileReferenceNumber);
                entry.reason = rec->Reason;
                entry.reason_string = UsnMonitor::format_reason(rec->Reason);

                if (rec->FileNameLength > 0 && static_cast<uint32_t>(rec->FileNameOffset) + static_cast<uint32_t>(rec->FileNameLength) <= rec->RecordLength) {
                    const wchar_t* fn_ptr = reinterpret_cast<const wchar_t*>(
                        reinterpret_cast<const uint8_t*>(rec) + rec->FileNameOffset
                    );
                    entry.file_name = std::wstring(fn_ptr, rec->FileNameLength / sizeof(wchar_t));
                }

                rep.entries.push_back(std::move(entry));
            }

            offset += rec->RecordLength;
        }

        curr_usn = next_page_usn;
    }

    return rep;
}

void UsnJournalAnalyzer::print_stats_report(const UsnJournalStats& stats) {
    std::wcout << L"============================================================\n";
    std::wcout << L" NTFS USN CHANGE JOURNAL SPECIFICATION & HEALTH AUDIT\n";
    std::wcout << L"============================================================\n";
    std::wcout << L"  Journal ID               : 0x" << std::hex << std::uppercase << stats.journal_id << std::dec << L"\n";
    std::wcout << L"  Lowest Valid USN         : " << stats.lowest_valid_usn << L"\n";
    std::wcout << L"  Next Sequence (USN)      : " << stats.next_usn << L"\n";
    std::wcout << L"  Maximum Allowed USN      : " << stats.max_usn << L"\n";
    std::wcout << L"  Configured Maximum Size  : " << Formatter::format_bytes(stats.maximum_size) << L"\n";
    std::wcout << L"  Cluster Allocation Delta : " << Formatter::format_bytes(stats.allocation_delta) << L"\n";
    std::wcout << L"------------------------------------------------------------\n";
    std::wcout << L"  Active Stream Size       : " << std::fixed << std::setprecision(2) << stats.estimated_active_size_mb << L" MB\n";
    std::wcout << L"  Recorded Events Estimate : ~" << stats.approximate_event_count << L" entries\n";
    std::wcout << L"  Buffer Capacity Used     : " << std::fixed << std::setprecision(1) << stats.utilization_percentage << L"%\n";
    std::wcout << L"  USN Rollover Exhaustion  : " << std::fixed << std::setprecision(4) << stats.rollover_percentage << L"%\n";
    std::wcout << L"============================================================\n\n";
}

void UsnJournalAnalyzer::print_history_report(const UsnHistoryReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" USN JOURNAL HISTORICAL TIMELINE FORENSICS (FRN " << report.target_frn << L", "
               << report.entries.size() << L" events recorded)\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << std::left
               << std::setw(12) << L"USN"
               << std::setw(22) << L"Timestamp"
               << std::setw(32) << L"Operation Reasons"
               << L"Filename\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& e : report.entries) {
        std::wcout << std::left
                   << std::setw(12) << e.usn
                   << std::setw(22) << Formatter::format_filetime(e.timestamp)
                   << std::setw(32) << e.reason_string
                   << e.file_name << L"\n";
    }

    if (report.entries.empty()) {
        std::wcout << L"  No historical events found in the active USN journal window for this FRN.\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

void UsnJournalAnalyzer::print_dump_report(const UsnDumpReport& report) {
    std::wcout << L"====================================================================================================\n";
    std::wcout << L" NTFS USN CHANGE JOURNAL SEQUENTIAL TRANSACTION LOG ("
               << report.entries.size() << L" events streamed)\n";
    std::wcout << L"====================================================================================================\n";
    std::wcout << L"  Journal ID           : 0x" << std::hex << std::uppercase << report.journal_id << std::dec << L"\n";
    std::wcout << L"  Lowest / Next USN    : " << report.lowest_usn << L" / " << report.next_usn << L"\n";
    if (report.applied_reason_mask != 0) {
        std::wcout << L"  Filter Reason Mask   : 0x" << std::hex << std::uppercase << report.applied_reason_mask << std::dec << L"\n";
    } else {
        std::wcout << L"  Filter Reason Mask   : (All operations)\n";
    }
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    std::wcout << std::left
               << std::setw(12) << L"USN"
               << std::setw(12) << L"FRN"
               << std::setw(22) << L"Timestamp"
               << std::setw(30) << L"Reasons"
               << L"Filename\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";

    for (const auto& e : report.entries) {
        std::wcout << std::left
                   << std::setw(12) << e.usn
                   << std::setw(12) << e.frn
                   << std::setw(22) << Formatter::format_filetime(e.timestamp)
                   << std::setw(30) << e.reason_string
                   << e.file_name << L"\n";
    }

    if (report.entries.empty()) {
        std::wcout << L"  Zero matching events found in the current USN journal stream.\n";
    }
    std::wcout << L"====================================================================================================\n\n";
}

} // namespace mftscan
