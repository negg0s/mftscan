#include "mftscan/index_parser.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/record_parser.hpp"

#include <iomanip>
#include <iostream>

namespace mftscan {

Result<DirectoryIndexReport> IndexParser::parse_directory_index(VolumeReader& volume, uint64_t directory_frn) {
    const uint32_t rec_size = volume.geometry().bytes_per_record;
    if (rec_size < sizeof(MftRecordHeader)) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid record size in volume geometry");
    }

    std::vector<uint8_t> buffer(rec_size);
    auto read_res = volume.read_file_record(directory_frn, buffer.data(), rec_size);
    if (!read_res) {
        return read_res.error();
    }

    if (!RecordParser::apply_fixup(buffer.data(), rec_size, volume.geometry().bytes_per_sector)) {
        return Error(ERROR_FILE_CORRUPT, L"MFT fixup validation failed for directory record");
    }

    const auto* header = reinterpret_cast<const MftRecordHeader*>(buffer.data());
    if ((header->flags & kRecordDirectory) == 0) {
        return Error(ERROR_DIRECTORY, L"Target record is a file, not a directory");
    }

    DirectoryIndexReport report;
    report.directory_frn = directory_frn;

    uint32_t offset = header->first_attribute_offset;
    bool found_index_root = false;

    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(buffer.data() + offset);
        if (attr->type_code == kAttrEnd || attr->record_length == 0) {
            break;
        }
        if (offset + attr->record_length > rec_size) {
            break;
        }

        // $INDEX_ROOT (0x90)
        if (attr->type_code == kAttrIndexRoot && attr->non_resident_flag == 0) {
            const uint32_t val_offset = offset + attr->resident.value_offset;
            const uint32_t val_len = attr->resident.value_length;

            if (val_offset + sizeof(IndexRootHeader) + sizeof(IndexNodeHeader) <= rec_size &&
                val_len >= sizeof(IndexRootHeader) + sizeof(IndexNodeHeader)) {
                
                const auto* root_hdr = reinterpret_cast<const IndexRootHeader*>(buffer.data() + val_offset);
                // Only parse $FILE_NAME collation indexes ($I30)
                if (root_hdr->attribute_type == kAttrFileName) {
                    found_index_root = true;

                    const uint32_t node_base_offset = val_offset + sizeof(IndexRootHeader);
                    const auto* node_hdr = reinterpret_cast<const IndexNodeHeader*>(buffer.data() + node_base_offset);

                    report.has_sub_nodes = (node_hdr->flags & 0x01) != 0;
                    report.allocated_index_size = node_hdr->allocated_index_size;
                    report.total_index_size = node_hdr->total_index_size;

                    const uint8_t* node_base = buffer.data() + node_base_offset;
                    uint32_t entry_rel_offset = node_hdr->first_entry_offset;

                    while (entry_rel_offset + sizeof(IndexEntryHeader) <= node_hdr->total_index_size &&
                           node_base_offset + entry_rel_offset + sizeof(IndexEntryHeader) <= rec_size) {

                        const auto* entry = reinterpret_cast<const IndexEntryHeader*>(node_base + entry_rel_offset);
                        if (entry->length == 0 || (entry->flags & 0x02) != 0) {
                            // Last entry in node or termination
                            break;
                        }
                        if (entry_rel_offset + entry->length > node_hdr->total_index_size) {
                            break;
                        }

                        if (entry->key_length >= sizeof(FileNamePayloadHeader)) {
                            const uint32_t key_offset = node_base_offset + entry_rel_offset + sizeof(IndexEntryHeader);
                            if (key_offset + sizeof(FileNamePayloadHeader) <= rec_size) {
                                const auto* fn_hdr = reinterpret_cast<const FileNamePayloadHeader*>(buffer.data() + key_offset);
                                const uint32_t name_len = fn_hdr->file_name_length;
                                const uint32_t name_bytes = name_len * sizeof(wchar_t);

                                if (key_offset + sizeof(FileNamePayloadHeader) + name_bytes <= rec_size) {
                                    const wchar_t* name_ptr = reinterpret_cast<const wchar_t*>(
                                        buffer.data() + key_offset + sizeof(FileNamePayloadHeader)
                                    );

                                    IndexEntryInfo info;
                                    info.record_index = extract_record_number(entry->file_reference);
                                    info.sequence_number = extract_sequence_number(entry->file_reference);
                                    info.name = std::wstring(name_ptr, name_len);
                                    info.real_size = fn_hdr->real_size;
                                    info.allocated_size = fn_hdr->allocated_size;
                                    info.creation_time = fn_hdr->creation_time;
                                    info.modification_time = fn_hdr->modification_time;
                                    info.is_directory = (fn_hdr->file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                                    info.is_carved_from_slack = false;

                                    if (info.name != L".") {
                                        report.entries.push_back(std::move(info));
                                    }
                                }
                            }
                        }

                        entry_rel_offset += entry->length;
                    }

                    // Carve deleted entries in slack space
                    if (node_hdr->allocated_index_size > node_hdr->total_index_size) {
                        uint32_t slack_offset = node_hdr->total_index_size;
                        while (slack_offset + sizeof(IndexEntryHeader) + sizeof(FileNamePayloadHeader) <= node_hdr->allocated_index_size) {
                            const uint32_t abs_slack = node_base_offset + slack_offset;
                            if (abs_slack + sizeof(IndexEntryHeader) + sizeof(FileNamePayloadHeader) > rec_size) {
                                break;
                            }

                            const auto* slack_entry = reinterpret_cast<const IndexEntryHeader*>(buffer.data() + abs_slack);
                            if (slack_entry->length >= sizeof(IndexEntryHeader) + sizeof(FileNamePayloadHeader) &&
                                slack_entry->key_length >= sizeof(FileNamePayloadHeader) &&
                                slack_offset + slack_entry->length <= node_hdr->allocated_index_size) {

                                const auto* fn_hdr = reinterpret_cast<const FileNamePayloadHeader*>(
                                    buffer.data() + abs_slack + sizeof(IndexEntryHeader)
                                );

                                const uint32_t name_len = fn_hdr->file_name_length;
                                if (name_len > 0 && name_len < 255) {
                                    const uint32_t name_bytes = name_len * sizeof(wchar_t);
                                    if (abs_slack + sizeof(IndexEntryHeader) + sizeof(FileNamePayloadHeader) + name_bytes <= rec_size) {
                                        const wchar_t* name_ptr = reinterpret_cast<const wchar_t*>(
                                            buffer.data() + abs_slack + sizeof(IndexEntryHeader) + sizeof(FileNamePayloadHeader)
                                        );

                                        IndexEntryInfo carved;
                                        carved.record_index = extract_record_number(slack_entry->file_reference);
                                        carved.sequence_number = extract_sequence_number(slack_entry->file_reference);
                                        carved.name = std::wstring(name_ptr, name_len);
                                        carved.real_size = fn_hdr->real_size;
                                        carved.allocated_size = fn_hdr->allocated_size;
                                        carved.creation_time = fn_hdr->creation_time;
                                        carved.modification_time = fn_hdr->modification_time;
                                        carved.is_directory = (fn_hdr->file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                                        carved.is_carved_from_slack = true;

                                        report.slack_carved_entries.push_back(std::move(carved));
                                        slack_offset += slack_entry->length;
                                        continue;
                                    }
                                }
                            }
                            slack_offset += 4; // Scan in 4-byte steps
                        }
                    }

                    break;
                }
            }
        }

        offset += attr->record_length;
    }

    if (!found_index_root) {
        return Error(ERROR_NOT_FOUND, L"Directory does not contain a standard $INDEX_ROOT attribute");
    }

    return report;
}

void IndexParser::print_index_report(const DirectoryIndexReport& report) {
    std::wcout << L"====================================================================================================================\n";
    std::wcout << L" NTFS DIRECTORY B-TREE INDEX: FRN #" << report.directory_frn << L"\n";
    std::wcout << L" Index Structure: " << (report.has_sub_nodes ? L"Large B-Tree (Has $INDEX_ALLOCATION sub-nodes)" : L"Small B-Tree (Contained in $INDEX_ROOT)")
               << L" | Used: " << report.total_index_size << L" bytes / Allocated: " << report.allocated_index_size << L" bytes\n";
    std::wcout << L"====================================================================================================================\n";

    if (report.entries.empty()) {
        std::wcout << L"Directory index is empty.\n\n";
    } else {
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::setw(8)  << L"Type"
                   << std::setw(14) << L"Size"
                   << std::setw(22) << L"Modified"
                   << L"Name\n";
        std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

        for (const auto& e : report.entries) {
            std::wcout << std::left
                       << std::setw(12) << e.record_index
                       << std::setw(8)  << (e.is_directory ? L"<DIR>" : L"FILE")
                       << std::setw(14) << (e.is_directory ? L"-" : Formatter::format_bytes(e.real_size))
                       << std::setw(22) << Formatter::format_filetime(e.modification_time)
                       << e.name << L"\n";
        }
    }

    if (!report.slack_carved_entries.empty()) {
        std::wcout << L"\n--------------------------------------------------------------------------------------------------------------------\n";
        std::wcout << L" Carved Residual Index Slack Entries (" << report.slack_carved_entries.size() << L" deleted files found):\n";
        std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";
        std::wcout << std::left
                   << std::setw(12) << L"FRN"
                   << std::setw(8)  << L"Type"
                   << std::setw(14) << L"Size"
                   << std::setw(22) << L"Modified"
                   << L"Name (Carved from Slack)\n";
        std::wcout << L"--------------------------------------------------------------------------------------------------------------------\n";

        for (const auto& e : report.slack_carved_entries) {
            std::wcout << std::left
                       << std::setw(12) << e.record_index
                       << std::setw(8)  << (e.is_directory ? L"<DIR>" : L"FILE")
                       << std::setw(14) << (e.is_directory ? L"-" : Formatter::format_bytes(e.real_size))
                       << std::setw(22) << Formatter::format_filetime(e.modification_time)
                       << e.name << L" [CARVED DELETED]\n";
        }
    }
    std::wcout << L"====================================================================================================================\n\n";
}

} // namespace mftscan
