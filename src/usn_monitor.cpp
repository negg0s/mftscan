#include "mftscan/usn_monitor.hpp"

#include <vector>

namespace mftscan {

UsnMonitor::UsnMonitor(VolumeReader& volume)
    : volume_(volume) {
}

Result<USN_JOURNAL_DATA_V0> UsnMonitor::query_journal() {
    HANDLE hVolume = volume_.native_handle();
    if (hVolume == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Volume handle is invalid");
    }

    DWORD bytes_returned = 0;
    const BOOL ok = DeviceIoControl(
        hVolume,
        FSCTL_QUERY_USN_JOURNAL,
        nullptr,
        0,
        &journal_data_,
        sizeof(journal_data_),
        &bytes_returned,
        nullptr
    );

    if (!ok) {
        return Error(GetLastError(), L"FSCTL_QUERY_USN_JOURNAL failed");
    }

    return journal_data_;
}

std::wstring UsnMonitor::format_reason(uint32_t reason) {
    std::wstring s;
    auto append_tag = [&](std::wstring_view tag) {
        if (!s.empty()) s += L"|";
        s += tag;
    };

    if (reason & USN_REASON_FILE_CREATE) append_tag(L"CREATE");
    if (reason & USN_REASON_FILE_DELETE) append_tag(L"DELETE");
    if (reason & USN_REASON_DATA_OVERWRITE) append_tag(L"DATA_OVERWRITE");
    if (reason & USN_REASON_DATA_EXTEND) append_tag(L"DATA_EXTEND");
    if (reason & USN_REASON_RENAME_OLD_NAME) append_tag(L"RENAME_OLD");
    if (reason & USN_REASON_RENAME_NEW_NAME) append_tag(L"RENAME_NEW");
    if (reason & USN_REASON_SECURITY_CHANGE) append_tag(L"SECURITY");
    if (reason & USN_REASON_BASIC_INFO_CHANGE) append_tag(L"ATTRIBUTES");
    if (reason & USN_REASON_CLOSE) append_tag(L"CLOSE");

    return s.empty() ? L"NONE" : s;
}

Result<uint64_t> UsnMonitor::read_changes(
    uint64_t start_usn,
    uint64_t max_records,
    ChangeCallback on_change
) {
    if (journal_data_.UsnJournalID == 0) {
        auto q_res = query_journal();
        if (!q_res) {
            return q_res.error();
        }
    }

    HANDLE hVolume = volume_.native_handle();
    if (hVolume == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Volume handle is invalid");
    }

    READ_USN_JOURNAL_DATA_V0 read_input{};
    read_input.StartUsn = static_cast<USN>(start_usn);
    read_input.ReasonMask = 0xFFFFFFFF;
    read_input.ReturnOnlyOnClose = 0;
    read_input.Timeout = 0;
    read_input.BytesToWaitFor = 0;
    read_input.UsnJournalID = journal_data_.UsnJournalID;

    std::vector<uint8_t> out_buffer(65536);
    DWORD bytes_returned = 0;

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

    if (!ok) {
        return Error(GetLastError(), L"FSCTL_READ_USN_JOURNAL failed");
    }

    if (bytes_returned <= sizeof(USN)) {
        return static_cast<uint64_t>(read_input.StartUsn);
    }

    const USN next_usn = *reinterpret_cast<const USN*>(out_buffer.data());
    uint32_t offset = sizeof(USN);
    uint64_t processed = 0;

    while (offset < bytes_returned && processed < max_records) {
        const auto* rec = reinterpret_cast<const USN_RECORD_V2*>(out_buffer.data() + offset);
        if (rec->RecordLength == 0 || offset + rec->RecordLength > bytes_returned) {
            break;
        }

        UsnChangeRecord change;
        change.file_ref = rec->FileReferenceNumber;
        change.parent_ref = rec->ParentFileReferenceNumber;
        change.usn = static_cast<uint64_t>(rec->Usn);
        change.timestamp = static_cast<uint64_t>(rec->TimeStamp.QuadPart);
        change.reason = rec->Reason;
        change.reason_string = format_reason(rec->Reason);

        if (rec->FileNameLength > 0 && rec->FileNameOffset < rec->RecordLength) {
            const wchar_t* name_ptr = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const uint8_t*>(rec) + rec->FileNameOffset
            );
            change.file_name = std::wstring(name_ptr, rec->FileNameLength / sizeof(wchar_t));
        }

        if (!on_change(change)) {
            break;
        }

        processed++;
        offset += rec->RecordLength;
    }

    return static_cast<uint64_t>(next_usn);
}

} // namespace mftscan