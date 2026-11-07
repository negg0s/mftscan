#include "mftscan/reparse.hpp"

#include <iomanip>
#include <sstream>

namespace mftscan {

std::wstring ReparsePointAnalyzer::tag_to_string(uint32_t tag) noexcept {
    switch (tag) {
    case kTagMountPoint:  return L"Directory Junction / Mount Point";
    case kTagSymlink:     return L"Symbolic Link";
    case kTagWof:         return L"Windows Overlay Filter (Compact OS)";
    case kTagAppExecLink: return L"App Execution Alias";
    case kTagCloud:       return L"Cloud File Placeholder";
    default: {
        std::wostringstream oss;
        oss << L"Reparse Tag 0x" << std::hex << std::uppercase << tag;
        return oss.str();
    }
    }
}

bool ReparsePointAnalyzer::check_target_exists(
    const std::wstring& target_path,
    const std::wstring& source_path
) {
    if (target_path.empty()) {
        return false;
    }

    std::wstring clean_target = target_path;
    if (clean_target.starts_with(L"\\??\\")) {
        clean_target = clean_target.substr(4);
    }

    if (clean_target.size() >= 2 && clean_target[1] == L':') {
        const DWORD attrs = GetFileAttributesW(clean_target.c_str());
        return (attrs != INVALID_FILE_ATTRIBUTES);
    }

    // Relative path check
    if (!source_path.empty()) {
        size_t last_slash = source_path.rfind(L'\\');
        if (last_slash != std::wstring::npos) {
            std::wstring parent = source_path.substr(0, last_slash + 1);
            std::wstring combined = parent + clean_target;
            const DWORD attrs = GetFileAttributesW(combined.c_str());
            return (attrs != INVALID_FILE_ATTRIBUTES);
        }
    }

    return true;
}

Result<ReparseInfo> ReparsePointAnalyzer::parse_attribute(
    const uint8_t* data,
    size_t size,
    uint64_t frn,
    const std::wstring& source_path
) {
    if (!data || size < 8) {
        return Error(ERROR_INVALID_PARAMETER, L"Buffer too small for reparse header");
    }

    const uint32_t tag = *reinterpret_cast<const uint32_t*>(data);

    ReparseInfo info{};
    info.frn = frn;
    info.source_path = source_path;
    info.reparse_tag = tag;
    info.tag_name = tag_to_string(tag);

    if (tag == kTagSymlink) {
        info.is_symlink = true;
        if (size >= 20) {
            const uint16_t sub_off = *reinterpret_cast<const uint16_t*>(data + 8);
            const uint16_t sub_len = *reinterpret_cast<const uint16_t*>(data + 10);
            const uint16_t print_off = *reinterpret_cast<const uint16_t*>(data + 12);
            const uint16_t print_len = *reinterpret_cast<const uint16_t*>(data + 14);
            const uint32_t flags = *reinterpret_cast<const uint32_t*>(data + 16);

            info.is_relative = (flags & kSymlinkFlagRelative) != 0;

            if (20 + sub_off + sub_len <= size && sub_len > 0) {
                const auto* chars = reinterpret_cast<const wchar_t*>(data + 20 + sub_off);
                info.target_path = std::wstring(chars, sub_len / sizeof(wchar_t));
            }

            if (20 + print_off + print_len <= size && print_len > 0) {
                const auto* chars = reinterpret_cast<const wchar_t*>(data + 20 + print_off);
                info.print_name = std::wstring(chars, print_len / sizeof(wchar_t));
            }

            if (info.print_name.empty()) {
                info.print_name = info.target_path;
            }

            info.is_broken = !check_target_exists(info.target_path, source_path);
        }
    } else if (tag == kTagMountPoint) {
        info.is_junction = true;
        if (size >= 16) {
            const uint16_t sub_off = *reinterpret_cast<const uint16_t*>(data + 8);
            const uint16_t sub_len = *reinterpret_cast<const uint16_t*>(data + 10);
            const uint16_t print_off = *reinterpret_cast<const uint16_t*>(data + 12);
            const uint16_t print_len = *reinterpret_cast<const uint16_t*>(data + 14);

            if (16 + sub_off + sub_len <= size && sub_len > 0) {
                const auto* chars = reinterpret_cast<const wchar_t*>(data + 16 + sub_off);
                info.target_path = std::wstring(chars, sub_len / sizeof(wchar_t));
            }

            if (16 + print_off + print_len <= size && print_len > 0) {
                const auto* chars = reinterpret_cast<const wchar_t*>(data + 16 + print_off);
                info.print_name = std::wstring(chars, print_len / sizeof(wchar_t));
            }

            if (info.print_name.empty()) {
                info.print_name = info.target_path;
            }

            info.is_broken = !check_target_exists(info.target_path, source_path);
        }
    } else if (tag == kTagAppExecLink) {
        info.extra_details = L"UWP / Windows Store Execution Alias";
    } else if (tag == kTagWof) {
        info.extra_details = L"Compact OS Compression Overlay";
    } else if (tag == kTagCloud) {
        info.extra_details = L"Cloud Sync Placeholder";
    }

    return info;
}

} // namespace mftscan
