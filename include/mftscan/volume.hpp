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

#include <functional>
#include <memory>

namespace mftscan {

class VolumeReader {
public:
    explicit VolumeReader(wchar_t drive_letter);
    ~VolumeReader();

    VolumeReader(const VolumeReader&) = delete;
    VolumeReader& operator=(const VolumeReader&) = delete;
    VolumeReader(VolumeReader&& other) noexcept;
    VolumeReader& operator=(VolumeReader&& other) noexcept;

    Result<void> open();
    void close() noexcept;
    bool is_open() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

    const VolumeGeometry& geometry() const noexcept { return geometry_; }
    wchar_t drive_letter() const noexcept { return drive_letter_; }
    HANDLE native_handle() const noexcept { return handle_; }

    Result<void> read_file_record(uint64_t record_number, uint8_t* out_buffer, uint32_t buffer_size);

    using RecordBatchCallback = std::function<bool(uint64_t start_index, const uint8_t* records_data, uint32_t record_count)>;
    Result<void> enumerate_records(uint64_t start_record, uint64_t count, RecordBatchCallback callback);

private:
    wchar_t drive_letter_{L'C'};
    HANDLE handle_{INVALID_HANDLE_VALUE};
    VolumeGeometry geometry_;

    Result<void> query_geometry();
};

} // namespace mftscan