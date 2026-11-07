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

constexpr uint32_t kTagMountPoint   = 0xA0000003; // IO_REPARSE_TAG_MOUNT_POINT
constexpr uint32_t kTagSymlink      = 0xA000000C; // IO_REPARSE_TAG_SYMLINK
constexpr uint32_t kTagWof          = 0x80000017; // IO_REPARSE_TAG_WOF
constexpr uint32_t kTagAppExecLink  = 0x8000001B; // IO_REPARSE_TAG_APPEXECLINK
constexpr uint32_t kTagCloud        = 0x9000001A; // IO_REPARSE_TAG_CLOUD

constexpr uint32_t kSymlinkFlagRelative = 0x00000001;

struct ReparseInfo {
    uint64_t frn{0};
    std::wstring source_path;
    uint32_t reparse_tag{0};
    std::wstring tag_name;
    std::wstring target_path;
    std::wstring print_name;
    bool is_symlink{false};
    bool is_junction{false};
    bool is_relative{false};
    bool is_broken{false};
    std::wstring extra_details;
};

class ReparsePointAnalyzer {
public:
    static Result<ReparseInfo> parse_attribute(
        const uint8_t* data,
        size_t size,
        uint64_t frn = 0,
        const std::wstring& source_path = L""
    );

    static std::wstring tag_to_string(uint32_t tag) noexcept;
    static bool check_target_exists(const std::wstring& target_path, const std::wstring& source_path);
};

} // namespace mftscan
