#include "mftscan/extended_attributes.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace mftscan {

Result<FileEaReport> ExtendedAttributesAnalyzer::parse_ea_stream(
    const uint8_t* ea_data,
    size_t ea_data_size,
    uint64_t frn,
    const std::wstring& path
) {
    if (!ea_data || ea_data_size < 8) {
        return Error(ERROR_INVALID_PARAMETER, L"Extended attribute stream too small");
    }

    FileEaReport rep;
    rep.frn = frn;
    rep.path = path;
    rep.packed_ea_size = static_cast<uint32_t>(ea_data_size);

    size_t offset = 0;
    while (offset + 8 <= ea_data_size) {
        const uint32_t next_entry_offset = *reinterpret_cast<const uint32_t*>(ea_data + offset);
        const uint8_t flags = ea_data[offset + 4];
        const uint8_t name_len = ea_data[offset + 5];
        const uint16_t val_len = *reinterpret_cast<const uint16_t*>(ea_data + offset + 6);

        // Header (8) + name (name_len + 1) + val_len
        const size_t entry_min_size = 8 + static_cast<size_t>(name_len) + 1 + static_cast<size_t>(val_len);
        if (offset + entry_min_size > ea_data_size) {
            break;
        }

        ExtendedAttributeItem item;
        item.flags = flags;
        item.is_need_ea = (flags & 0x80) != 0;
        if (item.is_need_ea) {
            rep.need_ea_count++;
        }

        const char* name_ptr = reinterpret_cast<const char*>(ea_data + offset + 8);
        item.name = std::string(name_ptr, name_len);
        item.value_length = val_len;

        // Check if WSL attribute
        if (item.name.find("LX") != std::string::npos || item.name.find("$LX") != std::string::npos) {
            item.is_wsl_attribute = true;
            rep.has_wsl_metadata = true;
        }

        const uint8_t* val_ptr = ea_data + offset + 8 + name_len + 1;
        // Preview value
        if (val_len > 0) {
            bool all_ascii = true;
            const size_t preview_len = (std::min)(static_cast<size_t>(val_len), size_t{32});
            for (size_t i = 0; i < preview_len; ++i) {
                if (val_ptr[i] < 32 || val_ptr[i] > 126) {
                    all_ascii = false;
                    break;
                }
            }

            if (all_ascii) {
                item.value_preview = std::string(reinterpret_cast<const char*>(val_ptr), preview_len);
            } else {
                std::ostringstream oss;
                for (size_t i = 0; i < preview_len; ++i) {
                    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<uint32_t>(val_ptr[i]);
                    if (i + 1 < preview_len) oss << " ";
                }
                if (val_len > preview_len) oss << "...";
                item.value_preview = oss.str();
            }
        }

        rep.attributes.push_back(std::move(item));

        if (next_entry_offset == 0) {
            break;
        }
        offset += next_entry_offset;
    }

    return rep;
}

} // namespace mftscan
