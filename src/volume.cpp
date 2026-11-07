#include "mftscan/volume.hpp"
#include "mftscan/privileges.hpp"

#include <vector>

namespace mftscan {

VolumeReader::VolumeReader(wchar_t drive_letter)
    : drive_letter_(towupper(drive_letter)) {
    geometry_.volume_letter = drive_letter_;
}

VolumeReader::~VolumeReader() {
    close();
}

VolumeReader::VolumeReader(VolumeReader&& other) noexcept
    : drive_letter_(other.drive_letter_),
      handle_(other.handle_),
      geometry_(other.geometry_) {
    other.handle_ = INVALID_HANDLE_VALUE;
}

VolumeReader& VolumeReader::operator=(VolumeReader&& other) noexcept {
    if (this != &other) {
        close();
        drive_letter_ = other.drive_letter_;
        handle_ = other.handle_;
        geometry_ = other.geometry_;
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    return *this;
}

void VolumeReader::close() noexcept {
    if (handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
}

Result<void> VolumeReader::open() {
    close();
    PrivilegeManager::enable_volume_privileges();

    const std::wstring volume_path = L"\\\\.\\" + std::wstring(1, drive_letter_) + L":";

    handle_ = CreateFileW(
        volume_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (handle_ == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        return Error(err, L"Failed to open volume handle for " + volume_path);
    }

    auto geom_res = query_geometry();
    if (!geom_res) {
        close();
        return geom_res;
    }

    return {};
}

Result<void> VolumeReader::query_geometry() {
    NTFS_VOLUME_DATA_BUFFER ntfs_data{};
    DWORD bytes_returned = 0;

    const BOOL success = DeviceIoControl(
        handle_,
        FSCTL_GET_NTFS_VOLUME_DATA,
        nullptr,
        0,
        &ntfs_data,
        sizeof(ntfs_data),
        &bytes_returned,
        nullptr
    );

    if (!success) {
        const DWORD err = GetLastError();
        return Error(err, L"FSCTL_GET_NTFS_VOLUME_DATA failed on volume " + std::wstring(1, drive_letter_) + L":");
    }

    geometry_.volume_letter = drive_letter_;
    geometry_.bytes_per_sector = ntfs_data.BytesPerSector;
    geometry_.bytes_per_cluster = ntfs_data.BytesPerCluster;
    geometry_.bytes_per_record = ntfs_data.BytesPerFileRecordSegment;
    geometry_.total_clusters = ntfs_data.TotalClusters.QuadPart;
    geometry_.free_clusters = ntfs_data.FreeClusters.QuadPart;
    geometry_.mft_start_lcn = ntfs_data.MftStartLcn.QuadPart;
    geometry_.mft_valid_length = ntfs_data.MftValidDataLength.QuadPart;

    if (geometry_.bytes_per_record > 0) {
        geometry_.total_records_estimate = geometry_.mft_valid_length / geometry_.bytes_per_record;
    }

    return {};
}

Result<void> VolumeReader::read_file_record(uint64_t record_number, uint8_t* out_buffer, uint32_t buffer_size) {
    if (handle_ == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Volume handle is not open");
    }
    if (buffer_size < geometry_.bytes_per_record) {
        return Error(ERROR_INSUFFICIENT_BUFFER, L"Buffer size too small for MFT record");
    }

    NTFS_FILE_RECORD_INPUT_BUFFER input{};
    input.FileReferenceNumber.QuadPart = static_cast<LONGLONG>(record_number);

    const DWORD alloc_size = sizeof(NTFS_FILE_RECORD_OUTPUT_BUFFER) + geometry_.bytes_per_record;
    std::vector<uint8_t> temp_buf(alloc_size);

    DWORD bytes_returned = 0;
    const BOOL success = DeviceIoControl(
        handle_,
        FSCTL_GET_NTFS_FILE_RECORD,
        &input,
        sizeof(input),
        temp_buf.data(),
        alloc_size,
        &bytes_returned,
        nullptr
    );

    if (!success) {
        return Error(GetLastError(), L"FSCTL_GET_NTFS_FILE_RECORD failed for record " + std::to_wstring(record_number));
    }

    const auto* output = reinterpret_cast<const NTFS_FILE_RECORD_OUTPUT_BUFFER*>(temp_buf.data());
    if (output->FileRecordLength > buffer_size) {
        return Error(ERROR_INSUFFICIENT_BUFFER, L"Returned record length exceeds buffer size");
    }

    memcpy(out_buffer, output->FileRecordBuffer, output->FileRecordLength);
    return {};
}

Result<void> VolumeReader::enumerate_records(uint64_t start_record, uint64_t count, RecordBatchCallback callback) {
    if (handle_ == INVALID_HANDLE_VALUE) {
        return Error(ERROR_INVALID_HANDLE, L"Volume handle is not open");
    }

    constexpr uint32_t kBatchSize = 64;
    const uint32_t rec_size = geometry_.bytes_per_record;
    std::vector<uint8_t> batch_data(kBatchSize * rec_size);

    uint64_t curr = start_record;
    const uint64_t end = start_record + count;

    while (curr < end) {
        uint32_t batch_count = 0;
        const uint32_t to_fetch = static_cast<uint32_t>((std::min<uint64_t>)(kBatchSize, end - curr));

        for (uint32_t i = 0; i < to_fetch; ++i) {
            uint8_t* dest = batch_data.data() + (i * rec_size);
            auto read_res = read_file_record(curr + i, dest, rec_size);
            if (read_res) {
                batch_count++;
            } else {
                // If record cannot be read (e.g. sparse gap), zero out the slot
                memset(dest, 0, rec_size);
            }
        }

        if (batch_count > 0 || to_fetch > 0) {
            if (!callback(curr, batch_data.data(), to_fetch)) {
                break;
            }
        }

        curr += to_fetch;
    }

    return {};
}

} // namespace mftscan