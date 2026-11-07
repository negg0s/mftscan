#include "mftscan/common.hpp"
#include "mftscan/disk_usage.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/path_builder.hpp"
#include "mftscan/privileges.hpp"
#include "mftscan/query.hpp"
#include "mftscan/record_parser.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using namespace mftscan;

static void check(bool condition, const char* msg) {
    if (!condition) {
        std::wcerr << L"[FAIL] " << msg << L"\n";
        exit(1);
    }
}

static void test_privileges_check() {
    bool elevated = PrivilegeManager::is_elevated_admin();
    (void)elevated;
    auto res = PrivilegeManager::enable_volume_privileges();
    (void)res;
}

static void test_wildcard_matching() {
    check(QueryEngine::wildcard_match(L"*.log", L"system.log"), "wildcard extension match");
    check(QueryEngine::wildcard_match(L"*.LOG", L"system.log"), "case-insensitive wildcard");
    check(QueryEngine::wildcard_match(L"app*", L"application.exe"), "prefix wildcard match");
    check(QueryEngine::wildcard_match(L"*test*", L"my_test_file.txt"), "middle wildcard match");
    check(QueryEngine::wildcard_match(L"test?.txt", L"test1.txt"), "question mark match");
    check(!QueryEngine::wildcard_match(L"test?.txt", L"test12.txt"), "question mark length mismatch");
    check(!QueryEngine::wildcard_match(L"*.dll", L"program.exe"), "different extension mismatch");
    check(QueryEngine::wildcard_match(L"*", L"anything.xyz"), "match all wildcard");
}

static void test_extension_extraction() {
    check(QueryEngine::extract_extension(L"document.pdf") == L"pdf", "extract pdf extension");
    check(QueryEngine::extract_extension(L"archive.tar.gz") == L"gz", "extract gz extension");
    check(QueryEngine::extract_extension(L"Makefile") == L"", "file without extension");
    check(QueryEngine::extract_extension(L".gitignore") == L"", "dotfile without extension");
    check(QueryEngine::extract_extension(L"TEST.EXE") == L"exe", "uppercase extension normalized");
}

static void test_size_formatting() {
    check(Formatter::format_bytes(0) == L"0 B", "format 0 bytes");
    check(Formatter::format_bytes(512) == L"512 B", "format 512 bytes");
    check(Formatter::format_bytes(1024) == L"1.00 KB", "format 1 KB");
    check(Formatter::format_bytes(1048576) == L"1.00 MB", "format 1 MB");
    check(Formatter::format_bytes(1073741824) == L"1.00 GB", "format 1 GB");
    check(Formatter::format_bytes(1099511627776ULL) == L"1.00 TB", "format 1 TB");
}

static void test_filetime_formatting() {
    check(Formatter::format_filetime(0) == L"-", "zero filetime formatted as dash");

    SYSTEMTIME st{};
    st.wYear = 2026;
    st.wMonth = 11;
    st.wDay = 7;
    st.wHour = 14;
    st.wMinute = 30;
    st.wSecond = 0;

    FILETIME win_ft{};
    check(SystemTimeToFileTime(&st, &win_ft), "SystemTimeToFileTime succeeds");

    uint64_t ft = (static_cast<uint64_t>(win_ft.dwHighDateTime) << 32) | win_ft.dwLowDateTime;
    std::wstring s = Formatter::format_filetime(ft);
    check(!s.empty() && s.find(L"2026-11-07") != std::wstring::npos, "filetime formatted correctly with ISO date");
}

static void test_path_builder_resolution() {
    PathBuilder pb(L'D');

    // Add directory hierarchy:
    // Root = D:\ (record 5)
    // Projects = D:\Projects (record 100, parent 5)
    // mftscan = D:\Projects\mftscan (record 200, parent 100)
    // src = D:\Projects\mftscan\src (record 300, parent 200)

    pb.add_directory(100, kRecordRootDir, L"Projects");
    pb.add_directory(200, 100, L"mftscan");
    pb.add_directory(300, 200, L"src");

    std::wstring path1 = pb.resolve_path(kRecordRootDir, L"bootmgr");
    check(path1 == L"D:\\bootmgr", "root file path resolved");

    std::wstring path2 = pb.resolve_path(100, L"notes.txt");
    check(path2 == L"D:\\Projects\\notes.txt", "first level dir file path resolved");

    std::wstring path3 = pb.resolve_path(300, L"main.cpp");
    check(path3 == L"D:\\Projects\\mftscan\\src\\main.cpp", "deep hierarchy path resolved");

    // Orphan file path resolution
    std::wstring orphan = pb.resolve_path(9999, L"lost.dat");
    check(orphan.find(L"$OrphanFiles") != std::wstring::npos, "orphan file path handled safely");
}

static void test_query_engine_filtering() {
    QueryFilter filter;
    filter.name_pattern = L"*.log";
    filter.min_size = 1000;
    filter.max_size = 50000;

    QueryEngine qe(filter);

    RecordInfo r1;
    r1.name = L"install.log";
    r1.size_bytes = 5000;
    r1.is_directory = false;
    check(qe.matches(r1), "r1 matches log and size criteria");

    RecordInfo r2;
    r2.name = L"install.log";
    r2.size_bytes = 100; // too small
    r2.is_directory = false;
    check(!qe.matches(r2), "r2 fails min_size check");

    RecordInfo r3;
    r3.name = L"install.txt";
    r3.size_bytes = 5000;
    r3.is_directory = false;
    check(!qe.matches(r3), "r3 fails name_pattern check");

    RecordInfo r4;
    r4.name = L"logs";
    r4.size_bytes = 0;
    r4.is_directory = true;
    check(!qe.matches(r4), "r4 is directory and fails log pattern check");
}

static void test_disk_usage_analyzer() {
    std::vector<RecordInfo> records;

    RecordInfo f1; f1.name = L"video.mp4"; f1.size_bytes = 500000000; f1.full_path = L"D:\\Videos\\video.mp4"; records.push_back(f1);
    RecordInfo f2; f2.name = L"image.jpg"; f2.size_bytes = 10000000; f2.full_path = L"D:\\Photos\\image.jpg"; records.push_back(f2);
    RecordInfo f3; f3.name = L"archive.zip"; f3.size_bytes = 800000000; f3.full_path = L"D:\\Backups\\archive.zip"; records.push_back(f3);
    RecordInfo f4; f4.name = L"doc.pdf"; f4.size_bytes = 5000000; f4.full_path = L"D:\\Photos\\doc.pdf"; records.push_back(f4);

    auto top_files = DiskUsageAnalyzer::top_largest_files(records, 2);
    check(top_files.size() == 2, "top files size 2");
    check(top_files[0].name == L"archive.zip", "largest file first");
    check(top_files[1].name == L"video.mp4", "second largest file");

    auto hist = DiskUsageAnalyzer::compute_extension_histogram(records, 10);
    check(!hist.empty(), "extension histogram computed");
    check(hist[0].extension == L"zip", "zip is top consumed extension");

    auto dirs = DiskUsageAnalyzer::compute_top_directories(records, 10);
    check(!dirs.empty(), "directory usage computed");
    check(dirs[0].path == L"D:\\Backups", "D:\\Backups is heaviest folder");
}

static void test_record_parser_fixup_and_attributes() {
    // Construct a synthetic valid 1024-byte MFT record
    constexpr uint32_t kRecSize = 1024;
    std::vector<uint8_t> buffer(kRecSize, 0);

    auto* hdr = reinterpret_cast<MftRecordHeader*>(buffer.data());
    hdr->magic = kMftMagicFile;
    hdr->update_sequence_offset = sizeof(MftRecordHeader);
    hdr->update_sequence_size = 3; // 1 USN + 2 sectors
    hdr->sequence_number = 1;
    hdr->hard_link_count = 1;
    hdr->flags = kRecordInUse; // File allocated
    hdr->bytes_used = 400;
    hdr->bytes_allocated = kRecSize;
    hdr->record_number = 500;

    const uint16_t kUsn = 0xABCD;
    const uint16_t kSec1Orig = 0x1122;
    const uint16_t kSec2Orig = 0x3344;

    uint16_t* usa = reinterpret_cast<uint16_t*>(buffer.data() + hdr->update_sequence_offset);
    usa[0] = kUsn;
    usa[1] = kSec1Orig;
    usa[2] = kSec2Orig;

    // Place USN at sector boundaries
    *reinterpret_cast<uint16_t*>(buffer.data() + 510) = kUsn;
    *reinterpret_cast<uint16_t*>(buffer.data() + 1022) = kUsn;

    uint32_t attr_offset = (sizeof(MftRecordHeader) + 3 * sizeof(uint16_t) + 7) & ~7U;
    hdr->first_attribute_offset = static_cast<uint16_t>(attr_offset);

    // 1. Add $FILE_NAME attribute (0x30)
    auto* attr_fn = reinterpret_cast<AttributeRecordHeader*>(buffer.data() + attr_offset);
    attr_fn->type_code = kAttrFileName;
    attr_fn->non_resident_flag = 0; // resident
    attr_fn->name_length = 0;
    attr_fn->flags = 0;
    attr_fn->attribute_id = 1;

    const std::wstring test_name = L"benchmark_report.docx";
    const uint32_t fn_payload_size = static_cast<uint32_t>(sizeof(FileNamePayloadHeader) + (test_name.size() * sizeof(wchar_t)));
    const uint32_t fn_attr_len = (sizeof(AttributeRecordHeader) + fn_payload_size + 7) & ~7U;

    attr_fn->record_length = fn_attr_len;
    attr_fn->resident.value_length = fn_payload_size;
    attr_fn->resident.value_offset = sizeof(AttributeRecordHeader);

    auto* fn_payload = reinterpret_cast<FileNamePayloadHeader*>(buffer.data() + attr_offset + sizeof(AttributeRecordHeader));
    fn_payload->parent_directory_ref = 5; // root dir
    fn_payload->real_size = 987654;
    fn_payload->allocated_size = 991232;
    fn_payload->file_name_length = static_cast<uint8_t>(test_name.size());
    fn_payload->file_name_namespace = 1; // Win32
    memcpy(reinterpret_cast<uint8_t*>(fn_payload) + sizeof(FileNamePayloadHeader), test_name.data(), test_name.size() * sizeof(wchar_t));

    attr_offset += fn_attr_len;

    // 2. Add $DATA attribute (0x80)
    auto* attr_data = reinterpret_cast<AttributeRecordHeader*>(buffer.data() + attr_offset);
    attr_data->type_code = kAttrData;
    attr_data->non_resident_flag = 1; // non-resident
    attr_data->name_length = 0;
    attr_data->record_length = 64;
    attr_data->non_resident.real_size = 987654;
    attr_data->non_resident.allocated_size = 991232;

    attr_offset += 64;

    // End attribute marker
    *reinterpret_cast<uint32_t*>(buffer.data() + attr_offset) = kAttrEnd;

    // Test parse
    auto parsed_opt = RecordParser::parse_record(buffer.data(), kRecSize, 500);
    check(parsed_opt.has_value(), "synthetic MFT record parsed successfully");

    const auto& rec = parsed_opt.value();
    check(rec.record_index == 500, "record index matched");
    check(rec.name == test_name, "filename matched");
    check(rec.size_bytes == 987654, "real size matched");
    check(rec.parent_record_index == 5, "parent record index matched");
    check(!rec.is_directory, "is not directory");
    check(!rec.is_deleted, "is not deleted");
}

static void test_record_parser_deleted_file() {
    constexpr uint32_t kRecSize = 1024;
    std::vector<uint8_t> buffer(kRecSize, 0);

    auto* hdr = reinterpret_cast<MftRecordHeader*>(buffer.data());
    hdr->magic = kMftMagicFile;
    hdr->update_sequence_offset = sizeof(MftRecordHeader);
    hdr->update_sequence_size = 3;
    hdr->flags = 0; // NOT allocated -> deleted!
    hdr->record_number = 777;

    const uint16_t kUsn = 0x5566;
    uint16_t* usa = reinterpret_cast<uint16_t*>(buffer.data() + hdr->update_sequence_offset);
    usa[0] = kUsn;
    usa[1] = 0;
    usa[2] = 0;

    *reinterpret_cast<uint16_t*>(buffer.data() + 510) = kUsn;
    *reinterpret_cast<uint16_t*>(buffer.data() + 1022) = kUsn;

    uint32_t attr_offset = (sizeof(MftRecordHeader) + 3 * sizeof(uint16_t) + 7) & ~7U;
    hdr->first_attribute_offset = static_cast<uint16_t>(attr_offset);

    auto* attr_fn = reinterpret_cast<AttributeRecordHeader*>(buffer.data() + attr_offset);
    attr_fn->type_code = kAttrFileName;
    attr_fn->non_resident_flag = 0;

    const std::wstring del_name = L"deleted_secret.key";
    const uint32_t fn_payload_size = static_cast<uint32_t>(sizeof(FileNamePayloadHeader) + (del_name.size() * sizeof(wchar_t)));
    const uint32_t fn_attr_len = (sizeof(AttributeRecordHeader) + fn_payload_size + 7) & ~7U;

    attr_fn->record_length = fn_attr_len;
    attr_fn->resident.value_length = fn_payload_size;
    attr_fn->resident.value_offset = sizeof(AttributeRecordHeader);

    auto* fn_payload = reinterpret_cast<FileNamePayloadHeader*>(buffer.data() + attr_offset + sizeof(AttributeRecordHeader));
    fn_payload->parent_directory_ref = 5;
    fn_payload->real_size = 2048;
    fn_payload->file_name_length = static_cast<uint8_t>(del_name.size());
    fn_payload->file_name_namespace = 1;
    memcpy(reinterpret_cast<uint8_t*>(fn_payload) + sizeof(FileNamePayloadHeader), del_name.data(), del_name.size() * sizeof(wchar_t));

    attr_offset += fn_attr_len;
    *reinterpret_cast<uint32_t*>(buffer.data() + attr_offset) = kAttrEnd;

    auto parsed_opt = RecordParser::parse_record(buffer.data(), kRecSize, 777);
    check(parsed_opt.has_value(), "deleted record parsed successfully");
    check(parsed_opt->is_deleted, "record detected as deleted");
    check(parsed_opt->name == del_name, "deleted filename preserved");
}

static void test_record_parser_corrupted_fixup() {
    constexpr uint32_t kRecSize = 1024;
    std::vector<uint8_t> buffer(kRecSize, 0);

    auto* hdr = reinterpret_cast<MftRecordHeader*>(buffer.data());
    hdr->magic = kMftMagicFile;
    hdr->update_sequence_offset = sizeof(MftRecordHeader);
    hdr->update_sequence_size = 3;

    uint16_t* usa = reinterpret_cast<uint16_t*>(buffer.data() + hdr->update_sequence_offset);
    usa[0] = 0xAAAA;

    // Intentionally put mismatched tag at sector 0 end
    *reinterpret_cast<uint16_t*>(buffer.data() + 510) = 0xBBBB;

    bool fixup_ok = RecordParser::apply_fixup(buffer.data(), kRecSize);
    check(!fixup_ok, "mismatched fixup detected corruption and rejected safely");
}

static void test_json_and_csv_formatting() {
    std::vector<RecordInfo> records;
    RecordInfo r;
    r.record_index = 42;
    r.name = L"test.json";
    r.full_path = L"D:\\test.json";
    r.size_bytes = 1234;
    r.is_directory = false;
    r.is_deleted = false;
    records.push_back(r);

    ScanStats stats;
    stats.total_records_read = 100;
    stats.matched_records = 1;

    VolumeGeometry geom;
    geom.volume_letter = L'D';

    std::string json_str = Formatter::to_json(records, stats, geom);
    check(json_str.find("\"volume\": \"D:\"") != std::string::npos, "JSON contains volume D:");
    check(json_str.find("\"name\": \"test.json\"") != std::string::npos, "JSON contains filename");

    std::string csv_str = Formatter::to_csv(records);
    check(csv_str.find("RecordIndex,Type,SizeBytes") != std::string::npos, "CSV header present");
    check(csv_str.find("42,FILE,1234") != std::string::npos, "CSV data row present");
}

int main() {
    std::wcout << L"[RUN] test_privileges_check\n";
    test_privileges_check();

    std::wcout << L"[RUN] test_wildcard_matching\n";
    test_wildcard_matching();

    std::wcout << L"[RUN] test_extension_extraction\n";
    test_extension_extraction();

    std::wcout << L"[RUN] test_size_formatting\n";
    test_size_formatting();

    std::wcout << L"[RUN] test_filetime_formatting\n";
    test_filetime_formatting();

    std::wcout << L"[RUN] test_path_builder_resolution\n";
    test_path_builder_resolution();

    std::wcout << L"[RUN] test_query_engine_filtering\n";
    test_query_engine_filtering();

    std::wcout << L"[RUN] test_disk_usage_analyzer\n";
    test_disk_usage_analyzer();

    std::wcout << L"[RUN] test_record_parser_fixup_and_attributes\n";
    test_record_parser_fixup_and_attributes();

    std::wcout << L"[RUN] test_record_parser_deleted_file\n";
    test_record_parser_deleted_file();

    std::wcout << L"[RUN] test_record_parser_corrupted_fixup\n";
    test_record_parser_corrupted_fixup();

    std::wcout << L"[RUN] test_json_and_csv_formatting\n";
    test_json_and_csv_formatting();

    std::wcout << L"All 12 unit test suites passed successfully.\n";
    return 0;
}
