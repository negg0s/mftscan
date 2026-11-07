#include "mftscan/record_parser.hpp"
#include "mftscan/data_run.hpp"

#include <cstring>
#include <vector>

namespace mftscan {

bool RecordParser::apply_fixup(uint8_t* record_buffer, uint32_t record_size, uint32_t sector_size) noexcept {
    if (!record_buffer || record_size < sizeof(MftRecordHeader) || sector_size == 0) {
        return false;
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(record_buffer);
    if (header->magic != kMftMagicFile) {
        return false;
    }

    const uint16_t usa_offset = header->update_sequence_offset;
    const uint16_t usa_count = header->update_sequence_size;

    if (usa_count == 0) {
        return true;
    }

    const uint32_t required_bytes = usa_offset + (usa_count * sizeof(uint16_t));
    if (required_bytes > record_size) {
        return false;
    }

    const uint16_t* usa = reinterpret_cast<const uint16_t*>(record_buffer + usa_offset);
    const uint16_t usn = usa[0];
    const uint32_t sector_count = usa_count - 1;

    for (uint32_t i = 0; i < sector_count; ++i) {
        const uint32_t sector_end_offset = (i + 1) * sector_size - sizeof(uint16_t);
        if (sector_end_offset + sizeof(uint16_t) > record_size) {
            return false;
        }

        uint16_t* sector_tag = reinterpret_cast<uint16_t*>(record_buffer + sector_end_offset);
        if (*sector_tag != usn) {
            // Torn write or corrupt fixup tag
            return false;
        }

        // Restore original bytes
        *sector_tag = usa[i + 1];
    }

    return true;
}

std::optional<RecordInfo> RecordParser::parse_record(
    const uint8_t* raw_record,
    uint32_t record_size,
    uint64_t fallback_record_index,
    uint32_t sector_size
) {
    if (!raw_record || record_size < sizeof(MftRecordHeader)) {
        return std::nullopt;
    }

    // Work on a mutable copy to apply fixup safely
    std::vector<uint8_t> record(raw_record, raw_record + record_size);
    if (!apply_fixup(record.data(), record_size, sector_size)) {
        return std::nullopt;
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(record.data());

    RecordInfo info;
    info.record_index = (header->record_number != 0) ? header->record_number : fallback_record_index;
    info.sequence_number = header->sequence_number;
    info.is_directory = (header->flags & kRecordDirectory) != 0;
    info.is_deleted = (header->flags & kRecordInUse) == 0;

    // If this is an extension record (child segment), skip it as base record holds primary metadata
    if (header->base_file_record != 0) {
        return std::nullopt;
    }

    uint32_t offset = header->first_attribute_offset;
    if (offset < sizeof(MftRecordHeader) || offset >= record_size) {
        return std::nullopt;
    }

    int best_namespace_priority = -1; // We prefer Win32 (1) or Win32&DOS (3) over DOS (2) or POSIX (0)

    while (offset + sizeof(AttributeRecordHeader) <= record_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(record.data() + offset);

        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > record_size) {
            break;
        }

        // 1. $STANDARD_INFORMATION (0x10)
        if (attr->type_code == kAttrStandardInformation && attr->non_resident_flag == 0) {
            const uint32_t val_offset = offset + attr->resident.value_offset;
            const uint32_t val_len = attr->resident.value_length;

            if (val_offset + sizeof(StandardInformation) <= record_size && val_len >= sizeof(StandardInformation)) {
                const auto* si = reinterpret_cast<const StandardInformation*>(record.data() + val_offset);
                info.creation_time = si->creation_time;
                info.modification_time = si->modification_time;
                info.attributes = si->file_attributes;
            }
        }
        // 2. $FILE_NAME (0x30)
        else if (attr->type_code == kAttrFileName && attr->non_resident_flag == 0) {
            const uint32_t val_offset = offset + attr->resident.value_offset;
            const uint32_t val_len = attr->resident.value_length;

            if (val_offset + sizeof(FileNamePayloadHeader) <= record_size && val_len >= sizeof(FileNamePayloadHeader)) {
                const auto* fn_hdr = reinterpret_cast<const FileNamePayloadHeader*>(record.data() + val_offset);
                const uint32_t name_chars = fn_hdr->file_name_length;
                const uint32_t name_bytes = name_chars * sizeof(wchar_t);

                if (val_offset + sizeof(FileNamePayloadHeader) + name_bytes <= record_size) {
                    const wchar_t* name_ptr = reinterpret_cast<const wchar_t*>(
                        record.data() + val_offset + sizeof(FileNamePayloadHeader)
                    );

                    int priority = 0;
                    switch (fn_hdr->file_name_namespace) {
                        case 1: priority = 3; break; // Win32
                        case 3: priority = 2; break; // Win32 & DOS
                        case 0: priority = 1; break; // POSIX
                        case 2: priority = 0; break; // DOS (8.3)
                        default: priority = 0; break;
                    }

                    if (priority > best_namespace_priority || info.name.empty()) {
                        best_namespace_priority = priority;
                        info.name = std::wstring(name_ptr, name_chars);
                        info.parent_record_index = extract_record_number(fn_hdr->parent_directory_ref);
                        info.fn_creation_time = fn_hdr->creation_time;
                        info.fn_modification_time = fn_hdr->modification_time;
                        if (info.size_bytes == 0) {
                            info.size_bytes = fn_hdr->real_size;
                            info.allocated_bytes = fn_hdr->allocated_size;
                        }
                    }
                }
            }
        }
        // 3. $DATA (0x80)
        else if (attr->type_code == kAttrData) {
            if (attr->name_length > 0) {
                // Alternate Data Stream (ADS)
                const uint32_t name_offset = offset + attr->name_offset;
                const uint32_t name_chars = attr->name_length;
                if (name_offset + (name_chars * sizeof(wchar_t)) <= record_size) {
                    const wchar_t* ads_name_ptr = reinterpret_cast<const wchar_t*>(record.data() + name_offset);
                    info.has_ads = true;
                    info.ads_names.emplace_back(ads_name_ptr, name_chars);
                }
            } else {
                // Primary unnamed data stream: extract exact size, compression, and fragmentation
                info.is_compressed = (attr->flags & 0x0001) != 0 || (info.attributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
                info.is_sparse = (attr->flags & 0x8000) != 0 || (info.attributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0;

                if (attr->non_resident_flag == 0) {
                    info.size_bytes = attr->resident.value_length;
                    info.allocated_bytes = 0; // Resident within MFT record
                    info.slack_bytes = 0;
                    info.fragment_count = 0;
                } else {
                    info.size_bytes = attr->non_resident.real_size;
                    info.allocated_bytes = attr->non_resident.allocated_size;
                    if (info.allocated_bytes > info.size_bytes) {
                        info.slack_bytes = info.allocated_bytes - info.size_bytes;
                    }

                    const uint32_t runs_offset = attr->non_resident.data_runs_offset;
                    if (runs_offset < attr->record_length) {
                        const uint8_t* run_ptr = record.data() + offset + runs_offset;
                        const size_t max_run_len = attr->record_length - runs_offset;
                        auto extents = DataRunDecoder::decode_mapping_pairs(run_ptr, max_run_len);
                        if (extents.size() > 1) {
                            info.fragment_count = static_cast<uint32_t>(extents.size() - 1);
                        }
                    }
                }
            }
        }

        offset += attr->record_length;
    }

    if (info.name.empty()) {
        return std::nullopt;
    }

    return info;
}

std::vector<RecordInfo> RecordParser::parse_batch(
    const uint8_t* records_data,
    uint32_t record_count,
    uint32_t record_size,
    uint64_t start_index,
    uint32_t sector_size
) {
    std::vector<RecordInfo> result;
    result.reserve(record_count);

    for (uint32_t i = 0; i < record_count; ++i) {
        const uint8_t* rec_ptr = records_data + (i * record_size);
        auto opt_rec = parse_record(rec_ptr, record_size, start_index + i, sector_size);
        if (opt_rec) {
            result.push_back(std::move(*opt_rec));
        }
    }

    return result;
}

} // namespace mftscan