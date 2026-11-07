#include "mftscan/signature_verifier.hpp"
#include "mftscan/query.hpp"

#include <algorithm>
#include <cwctype>

namespace mftscan {

KnownFileType SignatureVerifier::identify_type(const uint8_t* header, size_t length) {
    if (!header || length < 2) {
        return KnownFileType::Unknown;
    }

    // PE / COFF Executable: 'MZ'
    if (header[0] == 0x4D && header[1] == 0x5A) {
        return KnownFileType::PeExecutable;
    }

    // JPEG: 0xFF, 0xD8, 0xFF
    if (length >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF) {
        return KnownFileType::JpegImage;
    }

    // PNG: 0x89, 'P', 'N', 'G'
    if (length >= 4 && header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47) {
        return KnownFileType::PngImage;
    }

    // PDF: '%', 'P', 'D', 'F'
    if (length >= 4 && header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 && header[3] == 0x46) {
        return KnownFileType::PdfDocument;
    }

    // ZIP / OpenXML: 'P', 'K', 0x03, 0x04
    if (length >= 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) {
        return KnownFileType::ZipArchive;
    }

    // 7-Zip: '7', 'z', 0xBC, 0xAF, 0x27, 0x1C
    if (length >= 6 && header[0] == 0x37 && header[1] == 0x7A && header[2] == 0xBC &&
        header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C) {
        return KnownFileType::SevenZipArchive;
    }

    // RAR: 'R', 'a', 'r', '!', 0x1A, 0x07
    if (length >= 6 && header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 &&
        header[3] == 0x21 && header[4] == 0x1A && header[5] == 0x07) {
        return KnownFileType::RarArchive;
    }

    // BMP: 'B', 'M'
    if (header[0] == 0x42 && header[1] == 0x4D) {
        return KnownFileType::BmpImage;
    }

    // GZIP: 0x1F, 0x8B
    if (header[0] == 0x1F && header[1] == 0x8B) {
        return KnownFileType::GzipArchive;
    }

    // GIF: 'G', 'I', 'F', '8'
    if (length >= 4 && header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38) {
        return KnownFileType::GifImage;
    }

    // ELF Binary: 0x7F, 'E', 'L', 'F'
    if (length >= 4 && header[0] == 0x7F && header[1] == 0x45 && header[2] == 0x4C && header[3] == 0x46) {
        return KnownFileType::ElfBinary;
    }

    // SQLite 3: "SQLite format 3\0"
    if (length >= 16 && memcmp(header, "SQLite format 3\0", 16) == 0) {
        return KnownFileType::SqliteDatabase;
    }

    return KnownFileType::Unknown;
}

std::wstring SignatureVerifier::type_to_string(KnownFileType type) {
    switch (type) {
        case KnownFileType::PeExecutable: return L"PE/COFF Executable";
        case KnownFileType::PdfDocument: return L"PDF Document";
        case KnownFileType::ZipArchive: return L"ZIP Archive / OpenXML";
        case KnownFileType::SevenZipArchive: return L"7-Zip Archive";
        case KnownFileType::RarArchive: return L"RAR Archive";
        case KnownFileType::PngImage: return L"PNG Image";
        case KnownFileType::JpegImage: return L"JPEG Image";
        case KnownFileType::GifImage: return L"GIF Image";
        case KnownFileType::BmpImage: return L"BMP Image";
        case KnownFileType::GzipArchive: return L"GZIP Archive";
        case KnownFileType::SqliteDatabase: return L"SQLite Database";
        case KnownFileType::ElfBinary: return L"ELF Linux Binary";
        default: return L"Unknown";
    }
}

bool SignatureVerifier::is_extension_compatible(KnownFileType type, const std::wstring& ext) {
    std::wstring lower_ext = ext;
    for (auto& c : lower_ext) {
        c = static_cast<wchar_t>(towlower(c));
    }

    switch (type) {
        case KnownFileType::PeExecutable:
            return lower_ext == L"exe" || lower_ext == L"dll" || lower_ext == L"sys" ||
                   lower_ext == L"scr" || lower_ext == L"cpl" || lower_ext == L"ocx" ||
                   lower_ext == L"efi" || lower_ext == L"drv" || lower_ext == L"node";
        case KnownFileType::PdfDocument:
            return lower_ext == L"pdf";
        case KnownFileType::ZipArchive:
            return lower_ext == L"zip" || lower_ext == L"docx" || lower_ext == L"xlsx" ||
                   lower_ext == L"pptx" || lower_ext == L"jar" || lower_ext == L"apk" ||
                   lower_ext == L"msix" || lower_ext == L"nupkg" || lower_ext == L"vsix" ||
                   lower_ext == L"whl" || lower_ext == L"crate" || lower_ext == L"aar";
        case KnownFileType::SevenZipArchive:
            return lower_ext == L"7z";
        case KnownFileType::RarArchive:
            return lower_ext == L"rar";
        case KnownFileType::PngImage:
            return lower_ext == L"png";
        case KnownFileType::JpegImage:
            return lower_ext == L"jpg" || lower_ext == L"jpeg" || lower_ext == L"jpe";
        case KnownFileType::GifImage:
            return lower_ext == L"gif";
        case KnownFileType::BmpImage:
            return lower_ext == L"bmp";
        case KnownFileType::GzipArchive:
            return lower_ext == L"gz" || lower_ext == L"tgz";
        case KnownFileType::SqliteDatabase:
            return lower_ext == L"db" || lower_ext == L"sqlite" || lower_ext == L"sqlite3";
        case KnownFileType::ElfBinary:
            return lower_ext == L"elf" || lower_ext == L"so";
        default:
            return true;
    }
}

SignatureReport SignatureVerifier::analyze(const std::vector<RecordInfo>& records) {
    SignatureReport report;

    for (const auto& r : records) {
        if (r.is_directory || r.is_deleted || r.size_bytes == 0) {
            continue;
        }

        uint8_t header_buf[16]{};
        size_t bytes_available = 0;

        if (r.is_resident && !r.resident_magic.empty()) {
            bytes_available = (std::min)(sizeof(header_buf), r.resident_magic.size());
            memcpy(header_buf, r.resident_magic.data(), bytes_available);
        } else if (!r.full_path.empty()) {
            HANDLE h_file = CreateFileW(
                r.full_path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr
            );

            if (h_file != INVALID_HANDLE_VALUE) {
                DWORD bytes_read = 0;
                if (ReadFile(h_file, header_buf, sizeof(header_buf), &bytes_read, nullptr)) {
                    bytes_available = bytes_read;
                }
                CloseHandle(h_file);
            }
        }

        if (bytes_available < 2) {
            continue;
        }

        report.total_inspected++;
        const KnownFileType detected = identify_type(header_buf, bytes_available);
        if (detected == KnownFileType::Unknown) {
            continue;
        }

        const std::wstring ext = QueryEngine::extract_extension(r.name);
        if (!is_extension_compatible(detected, ext)) {
            SignatureMismatchEntry entry;
            entry.record_index = r.record_index;
            entry.name = r.name;
            entry.full_path = r.full_path;
            entry.declared_extension = ext.empty() ? L"(none)" : ext;
            entry.detected_type = detected;
            entry.detected_type_name = type_to_string(detected);
            entry.size_bytes = r.size_bytes;
            entry.is_executable_masquerading = (detected == KnownFileType::PeExecutable);

            if (entry.is_executable_masquerading) {
                report.critical_executables_detected++;
            }
            report.mismatches_detected++;
            report.entries.push_back(std::move(entry));
        }
    }

    return report;
}

} // namespace mftscan
