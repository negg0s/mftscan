#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <variant>

namespace mftscan {

struct RecordInfo {
    uint64_t record_index{0};
    uint16_t sequence_number{0};
    uint64_t parent_record_index{0};
    std::wstring name;
    std::wstring full_path;
    uint64_t size_bytes{0};
    uint64_t allocated_bytes{0};
    uint64_t creation_time{0};
    uint64_t modification_time{0};
    uint64_t fn_creation_time{0};
    uint64_t fn_modification_time{0};
    uint32_t attributes{0};
    bool is_directory{false};
    bool is_deleted{false};
    bool has_ads{false};
    bool is_sparse{false};
    bool is_compressed{false};
    uint32_t fragment_count{0};
    uint64_t slack_bytes{0};
    std::vector<std::wstring> ads_names;
};

struct VolumeGeometry {
    wchar_t volume_letter{L'C'};
    uint32_t bytes_per_sector{512};
    uint32_t bytes_per_cluster{4096};
    uint32_t bytes_per_record{1024};
    uint64_t total_clusters{0};
    uint64_t free_clusters{0};
    uint64_t mft_start_lcn{0};
    uint64_t mft_valid_length{0};
    uint64_t total_records_estimate{0};
};

struct ScanStats {
    uint64_t total_records_read{0};
    uint64_t active_files{0};
    uint64_t active_directories{0};
    uint64_t deleted_records_found{0};
    uint64_t matched_records{0};
    uint64_t total_bytes_matched{0};
    double scan_duration_ms{0.0};
    double read_throughput_mbs{0.0};
};

class Error {
public:
    Error() = default;
    explicit Error(DWORD win32_code, std::wstring message = {})
        : win32_code_(win32_code), message_(std::move(message)) {}

    DWORD code() const noexcept { return win32_code_; }
    const std::wstring& message() const noexcept { return message_; }

    std::wstring to_string() const {
        if (!message_.empty()) {
            return message_ + L" (Win32 error: " + std::to_wstring(win32_code_) + L")";
        }
        return L"Win32 error: " + std::to_wstring(win32_code_);
    }

private:
    DWORD win32_code_{ERROR_SUCCESS};
    std::wstring message_;
};

template <typename T>
class Result {
public:
    Result() requires std::is_default_constructible_v<T> : data_(T{}) {}
    Result(const T& val) : data_(val) {}
    Result(T&& val) : data_(std::move(val)) {}
    Result(const Error& err) : data_(err) {}
    Result(Error&& err) : data_(std::move(err)) {}

    bool ok() const noexcept { return std::holds_alternative<T>(data_); }
    explicit operator bool() const noexcept { return ok(); }

    T& value() & { return std::get<T>(data_); }
    const T& value() const & { return std::get<T>(data_); }
    T&& value() && { return std::get<T>(std::move(data_)); }

    const Error& error() const & { return std::get<Error>(data_); }

private:
    std::variant<T, Error> data_;
};

template <>
class Result<void> {
public:
    Result() : has_error_(false), error_() {}
    Result(const Error& err) : has_error_(true), error_(err) {}
    Result(Error&& err) : has_error_(true), error_(std::move(err)) {}

    bool ok() const noexcept { return !has_error_; }
    explicit operator bool() const noexcept { return ok(); }
    const Error& error() const noexcept { return error_; }

private:
    bool has_error_{false};
    Error error_;
};

} // namespace mftscan