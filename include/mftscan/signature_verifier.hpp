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

enum class KnownFileType {
    Unknown,
    PeExecutable,
    PdfDocument,
    ZipArchive,
    SevenZipArchive,
    RarArchive,
    PngImage,
    JpegImage,
    GifImage,
    BmpImage,
    GzipArchive,
    SqliteDatabase,
    ElfBinary
};

struct SignatureMismatchEntry {
    uint64_t record_index{0};
    std::wstring name;
    std::wstring full_path;
    std::wstring declared_extension;
    KnownFileType detected_type{KnownFileType::Unknown};
    std::wstring detected_type_name;
    bool is_executable_masquerading{false};
    uint64_t size_bytes{0};
};

struct SignatureReport {
    std::vector<SignatureMismatchEntry> entries;
    uint64_t total_inspected{0};
    uint64_t mismatches_detected{0};
    uint64_t critical_executables_detected{0};
};

class SignatureVerifier {
public:
    static KnownFileType identify_type(const uint8_t* header, size_t length);
    static std::wstring type_to_string(KnownFileType type);
    static bool is_extension_compatible(KnownFileType type, const std::wstring& ext);

    static SignatureReport analyze(const std::vector<RecordInfo>& records);
};

} // namespace mftscan
