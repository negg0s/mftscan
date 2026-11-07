#include "mftscan/attr_list.hpp"
#include "mftscan/inspector.hpp"
#include "mftscan/ntfs_defs.hpp"

#include <sstream>

namespace mftscan {

std::vector<AttributeListEntryInfo> AttrListDecoder::decode(const uint8_t* data, size_t size) {
    std::vector<AttributeListEntryInfo> entries;
    if (!data || size < sizeof(AttributeListEntryHeader)) {
        return entries;
    }

    size_t offset = 0;
    while (offset + sizeof(AttributeListEntryHeader) <= size) {
        const auto* entry = reinterpret_cast<const AttributeListEntryHeader*>(data + offset);
        if (entry->record_length == 0 || offset + entry->record_length > size) {
            break;
        }

        AttributeListEntryInfo info{};
        info.attribute_type = entry->attribute_type;
        info.type_name = RecordInspector::attribute_type_to_string(entry->attribute_type);
        info.lowest_vcn = entry->lowest_vcn;
        info.child_record_frn = extract_record_number(entry->file_reference_number);
        info.child_sequence_number = extract_sequence_number(entry->file_reference_number);
        info.attribute_id = entry->attribute_id;
        info.entry_length = entry->record_length;

        if (entry->name_length > 0) {
            const size_t name_bytes = entry->name_length * sizeof(wchar_t);
            if (entry->name_offset + name_bytes <= entry->record_length) {
                const auto* name_chars = reinterpret_cast<const wchar_t*>(
                    data + offset + entry->name_offset
                );
                info.attribute_name = std::wstring(name_chars, entry->name_length);
            }
        }

        entries.push_back(std::move(info));
        offset += entry->record_length;
    }

    return entries;
}

std::wstring AttrListDecoder::format_entry(const AttributeListEntryInfo& entry) {
    std::wostringstream oss;
    oss << entry.type_name;
    if (!entry.attribute_name.empty()) {
        oss << L" (\"" << entry.attribute_name << L"\")";
    }
    oss << L" -> Child FRN: " << entry.child_record_frn
        << L" (Seq: " << entry.child_sequence_number << L")"
        << L", Lowest VCN: " << entry.lowest_vcn
        << L", ID: " << entry.attribute_id;
    return oss.str();
}

} // namespace mftscan
