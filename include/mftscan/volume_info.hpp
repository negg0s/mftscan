#pragma once

#include "mftscan/common.hpp"
#include "mftscan/volume.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

#pragma pack(push, 1)
struct RawVolumeInformationAttr {
    uint64_t reserved;
    uint8_t major_version;
    uint8_t minor_version;
    uint16_t flags;
};
#pragma pack(pop)

static_assert(sizeof(RawVolumeInformationAttr) == 12, "RawVolumeInformationAttr must be 12 bytes");

constexpr uint16_t kVolFlagDirty                  = 0x0001;
constexpr uint16_t kVolFlagResizeLogFile          = 0x0002;
constexpr uint16_t kVolFlagUpgradeOnMount         = 0x0004;
constexpr uint16_t kVolFlagMountedOnNt4           = 0x0008;
constexpr uint16_t kVolFlagDeleteUsnUnderway      = 0x0010;
constexpr uint16_t kVolFlagRepairObjectId         = 0x0020;
constexpr uint16_t kVolFlagChkdskRan              = 0x4000;
constexpr uint16_t kVolFlagModifiedByChkdsk       = 0x8000;

struct VolumeInfoReport {
    bool valid{false};
    wchar_t volume_letter{L'C'};
    std::wstring volume_label;
    uint8_t major_version{0};
    uint8_t minor_version{0};
    std::wstring ntfs_version_str;
    uint16_t flags_raw{0};
    bool is_dirty{false};
    bool resize_log_file{false};
    bool upgrade_on_mount{false};
    bool delete_usn_underway{false};
    bool repair_object_id{false};
    bool chkdsk_ran{false};
    bool modified_by_chkdsk{false};
    std::vector<std::wstring> flag_descriptions;
    std::wstring health_assessment;

    uint64_t volume_creation_time{0};
    uint64_t volume_modification_time{0};
    std::wstring creation_time_str;
    std::wstring modification_time_str;
};

class VolumeInfoAnalyzer {
public:
    static VolumeInfoReport parse_record_buffer(
        const uint8_t* record_data,
        uint32_t record_size,
        uint32_t sector_size = 512,
        wchar_t drive_letter = L'C'
    );

    static Result<VolumeInfoReport> inspect(VolumeReader& volume);
    static void print_report(const VolumeInfoReport& report);
};

} // namespace mftscan
