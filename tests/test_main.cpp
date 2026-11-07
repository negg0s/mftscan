#include "mftscan/common.hpp"
#include "mftscan/data_run.hpp"
#include "mftscan/disk_usage.hpp"
#include "mftscan/duplicate_detector.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/fragmentation_analyzer.hpp"
#include "mftscan/inspector.hpp"
#include "mftscan/ntfs_defs.hpp"
#include "mftscan/path_builder.hpp"
#include "mftscan/privileges.hpp"
#include "mftscan/query.hpp"
#include "mftscan/record_parser.hpp"
#include "mftscan/signature_verifier.hpp"
#include "mftscan/carver.hpp"
#include "mftscan/security_auditor.hpp"
#include "mftscan/sparse_slack_analyzer.hpp"
#include "mftscan/thread_pool.hpp"
#include "mftscan/timestomp.hpp"
#include "mftscan/usn_monitor.hpp"

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

static void test_data_run_decoder() {
    const uint8_t runs[] = {
        0x21, 0x08, 0xE8, 0x03,
        0x11, 0x04, 0xFE,
        0x01, 0x10,
        0x00
    };

    auto extents = DataRunDecoder::decode_mapping_pairs(runs, sizeof(runs));
    check(extents.size() == 3, "decoded 3 extents");

    check(extents[0].starting_vcn == 0, "ext0 starting vcn");
    check(extents[0].cluster_count == 8, "ext0 cluster count");
    check(extents[0].starting_lcn == 1000, "ext0 starting lcn");
    check(!extents[0].is_sparse, "ext0 is not sparse");

    check(extents[1].starting_vcn == 8, "ext1 starting vcn");
    check(extents[1].cluster_count == 4, "ext1 cluster count");
    check(extents[1].starting_lcn == 998, "ext1 starting lcn with negative delta");
    check(!extents[1].is_sparse, "ext1 is not sparse");

    check(extents[2].starting_vcn == 12, "ext2 starting vcn");
    check(extents[2].cluster_count == 16, "ext2 cluster count");
    check(extents[2].is_sparse, "ext2 is sparse");

    uint64_t total = DataRunDecoder::calculate_total_clusters(extents);
    check(total == 28, "total clusters calculated correctly");
}

static void test_duplicate_detector_grouping() {
    std::vector<RecordInfo> records;

    RecordInfo r1; r1.name = L"unique.dat"; r1.size_bytes = 10000; r1.full_path = L"D:\\unique.dat"; records.push_back(r1);
    RecordInfo r2; r2.name = L"fileA.bin"; r2.size_bytes = 20000; r2.full_path = L"D:\\fileA.bin"; records.push_back(r2);
    RecordInfo r3; r3.name = L"fileB.bin"; r3.size_bytes = 20000; r3.full_path = L"D:\\fileB.bin"; records.push_back(r3);

    auto report = DuplicateDetector::find_duplicates(records, 1000);
    (void)report;
}

static void test_usn_reason_formatting() {
    std::wstring s1 = UsnMonitor::format_reason(USN_REASON_FILE_CREATE | USN_REASON_CLOSE);
    check(s1.find(L"CREATE") != std::wstring::npos, "format_reason contains CREATE");
    check(s1.find(L"CLOSE") != std::wstring::npos, "format_reason contains CLOSE");

    std::wstring s2 = UsnMonitor::format_reason(USN_REASON_FILE_DELETE);
    check(s2 == L"DELETE", "format_reason single tag DELETE");

    std::wstring s3 = UsnMonitor::format_reason(0);
    check(s3 == L"NONE", "format_reason zero is NONE");
}

static void test_fragmentation_analyzer() {
    std::vector<RecordInfo> records;

    RecordInfo r1; r1.name = L"contiguous.dat"; r1.size_bytes = 100000; r1.fragment_count = 0; records.push_back(r1);
    RecordInfo r2; r2.name = L"frag_mild.dat"; r2.size_bytes = 500000; r2.fragment_count = 5; records.push_back(r2);
    RecordInfo r3; r3.name = L"frag_heavy.dat"; r3.size_bytes = 2000000; r3.fragment_count = 42; records.push_back(r3);

    auto rep = FragmentationAnalyzer::analyze(records, 1);
    check(rep.total_fragmented_files == 2, "2 fragmented files detected");
    check(rep.total_excess_fragments == 47, "47 excess fragments total");
    check(rep.highest_fragment_count == 42, "highest fragment count is 42");
    check(rep.most_fragmented_files.size() == 2, "most fragmented size 2");
    check(rep.most_fragmented_files[0].name == L"frag_heavy.dat", "heaviest fragmented file first");
}

static void test_sparse_and_slack_analyzer() {
    std::vector<RecordInfo> records;

    RecordInfo r1;
    r1.name = L"slack_file.dat";
    r1.size_bytes = 1000;
    r1.allocated_bytes = 4096;
    r1.slack_bytes = 3096;
    records.push_back(r1);

    RecordInfo r2;
    r2.name = L"sparse_vm.vhdx";
    r2.size_bytes = 50000000000ULL;
    r2.allocated_bytes = 5000000000ULL;
    r2.is_sparse = true;
    records.push_back(r2);

    RecordInfo r3;
    r3.name = L"compressed_log.txt";
    r3.size_bytes = 10000000;
    r3.allocated_bytes = 2000000;
    r3.is_compressed = true;
    records.push_back(r3);

    auto slack_rep = SparseSlackAnalyzer::analyze_slack(records);
    check(slack_rep.total_files_with_slack == 1, "1 file with slack");
    check(slack_rep.total_slack_bytes == 3096, "3096 bytes slack wasted");

    auto comp_rep = SparseSlackAnalyzer::analyze_compression(records);
    check(comp_rep.sparse_file_count == 1, "1 sparse file");
    check(comp_rep.sparse_saved_bytes == 45000000000ULL, "45 GB sparse savings");
    check(comp_rep.compressed_file_count == 1, "1 compressed file");
    check(comp_rep.compressed_saved_bytes == 8000000, "8 MB compression savings");
}

static void test_thread_pool() {
    ThreadPool pool(4);
    std::atomic<int> counter{0};

    for (int i = 0; i < 50; ++i) {
        pool.enqueue([&counter]() {
            counter.fetch_add(1, std::memory_order_relaxed);
        });
    }

    pool.wait_idle();
    check(counter.load() == 50, "thread pool processed all 50 tasks concurrently");
}

static void test_record_inspector_attribute_names() {
    check(RecordInspector::attribute_type_to_string(0x10) == L"$STANDARD_INFORMATION", "0x10 standard information");
    check(RecordInspector::attribute_type_to_string(0x20) == L"$ATTRIBUTE_LIST", "0x20 attribute list");
    check(RecordInspector::attribute_type_to_string(0x30) == L"$FILE_NAME", "0x30 file name");
    check(RecordInspector::attribute_type_to_string(0x40) == L"$OBJECT_ID", "0x40 object id");
    check(RecordInspector::attribute_type_to_string(0x50) == L"$SECURITY_DESCRIPTOR", "0x50 security descriptor");
    check(RecordInspector::attribute_type_to_string(0x60) == L"$VOLUME_NAME", "0x60 volume name");
    check(RecordInspector::attribute_type_to_string(0x70) == L"$VOLUME_INFORMATION", "0x70 volume information");
    check(RecordInspector::attribute_type_to_string(0x80) == L"$DATA", "0x80 data");
    check(RecordInspector::attribute_type_to_string(0x90) == L"$INDEX_ROOT", "0x90 index root");
    check(RecordInspector::attribute_type_to_string(0xA0) == L"$INDEX_ALLOCATION", "0xA0 index allocation");
    check(RecordInspector::attribute_type_to_string(0xB0) == L"$BITMAP", "0xB0 bitmap");
    check(RecordInspector::attribute_type_to_string(0xC0) == L"$REPARSE_POINT", "0xC0 reparse point");
    check(RecordInspector::attribute_type_to_string(0x100) == L"$LOGGED_UTILITY_STREAM", "0x100 logged utility stream");
    check(RecordInspector::attribute_type_to_string(0x1234).find(L"UNKNOWN") != std::wstring::npos, "unknown type code formatted");
}

static void test_record_inspector_hex_dump() {
    check(RecordInspector::format_hex_dump(nullptr, 0).empty(), "empty data produces empty hex dump");

    const uint8_t sample_bytes[] = "FILE0123456789\x01\x02";
    std::string dump = RecordInspector::format_hex_dump(sample_bytes, sizeof(sample_bytes) - 1, 32);
    check(!dump.empty(), "hex dump output not empty");
    check(dump.find("0000: ") != std::string::npos, "hex dump contains line prefix 0000:");
    check(dump.find("|FILE0123456789..|") != std::string::npos, "hex dump contains printable ASCII representation");
}

static void test_timestomp_detection() {
    std::vector<RecordInfo> records;

    RecordInfo normal_rec;
    normal_rec.record_index = 10;
    normal_rec.name = L"normal.txt";
    normal_rec.full_path = L"D:\\normal.txt";
    normal_rec.creation_time = 133500000000001234ULL;
    normal_rec.fn_creation_time = 133500000000001234ULL;
    normal_rec.modification_time = 133500000000005678ULL;
    normal_rec.fn_modification_time = 133500000000005678ULL;
    records.push_back(normal_rec);

    RecordInfo stomped_rec;
    stomped_rec.record_index = 20;
    stomped_rec.name = L"malware.dll";
    stomped_rec.full_path = L"D:\\malware.dll";
    stomped_rec.creation_time = 130000000000000000ULL;
    stomped_rec.fn_creation_time = 133500000000001234ULL;
    records.push_back(stomped_rec);

    RecordInfo zeroed_rec;
    zeroed_rec.record_index = 30;
    zeroed_rec.name = L"payload.exe";
    zeroed_rec.full_path = L"D:\\payload.exe";
    zeroed_rec.creation_time = 133500000000000000ULL;
    zeroed_rec.fn_creation_time = 133500000000004321ULL;
    records.push_back(zeroed_rec);

    RecordInfo ancient_rec;
    ancient_rec.record_index = 40;
    ancient_rec.name = L"ancient.bin";
    ancient_rec.full_path = L"D:\\ancient.bin";
    ancient_rec.creation_time = 116444736000000000ULL;
    ancient_rec.fn_creation_time = 116444736000000000ULL;
    records.push_back(ancient_rec);

    auto report = TimestompDetector::analyze(records);
    check(report.total_scanned == 4, "timestomp total scanned count");
    check(report.anomalies_detected == 3, "timestomp detected exactly 3 anomalous files");

    bool found_si_fn_mismatch = false;
    for (const auto& entry : report.entries) {
        if (entry.record_index == 20) {
            for (auto a : entry.anomalies) {
                if (a == TimestompAnomaly::SiCreatedBeforeFnCreated) {
                    found_si_fn_mismatch = true;
                }
            }
        }
    }
    check(found_si_fn_mismatch, "SiCreatedBeforeFnCreated identified");

    bool found_zeroed = false;
    for (const auto& entry : report.entries) {
        if (entry.record_index == 30) {
            for (auto a : entry.anomalies) {
                if (a == TimestompAnomaly::NanosecondsZeroed) {
                    found_zeroed = true;
                }
            }
        }
    }
    check(found_zeroed, "NanosecondsZeroed identified");

    bool found_ancient = false;
    for (const auto& entry : report.entries) {
        if (entry.record_index == 40) {
            for (auto a : entry.anomalies) {
                if (a == TimestompAnomaly::Pre1980Timestamp) {
                    found_ancient = true;
                }
            }
        }
    }
    check(found_ancient, "Pre1980Timestamp identified");
}

static void test_signature_verifier() {
    const uint8_t mz_hdr[] = {0x4D, 0x5A, 0x90, 0x00};
    check(SignatureVerifier::identify_type(mz_hdr, sizeof(mz_hdr)) == KnownFileType::PeExecutable, "identify PE executable");

    const uint8_t pdf_hdr[] = {0x25, 0x50, 0x44, 0x46, 0x2D};
    check(SignatureVerifier::identify_type(pdf_hdr, sizeof(pdf_hdr)) == KnownFileType::PdfDocument, "identify PDF document");

    const uint8_t zip_hdr[] = {0x50, 0x4B, 0x03, 0x04};
    check(SignatureVerifier::identify_type(zip_hdr, sizeof(zip_hdr)) == KnownFileType::ZipArchive, "identify ZIP archive");

    const uint8_t png_hdr[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    check(SignatureVerifier::identify_type(png_hdr, sizeof(png_hdr)) == KnownFileType::PngImage, "identify PNG image");

    const uint8_t jpg_hdr[] = {0xFF, 0xD8, 0xFF, 0xE0};
    check(SignatureVerifier::identify_type(jpg_hdr, sizeof(jpg_hdr)) == KnownFileType::JpegImage, "identify JPEG image");

    const uint8_t random_hdr[] = {0x12, 0x34, 0x56, 0x78};
    check(SignatureVerifier::identify_type(random_hdr, sizeof(random_hdr)) == KnownFileType::Unknown, "identify unknown type");

    check(SignatureVerifier::is_extension_compatible(KnownFileType::PeExecutable, L"exe"), "exe compatible with PE");
    check(SignatureVerifier::is_extension_compatible(KnownFileType::PeExecutable, L"dll"), "dll compatible with PE");
    check(!SignatureVerifier::is_extension_compatible(KnownFileType::PeExecutable, L"jpg"), "jpg incompatible with PE (spoof)");
    check(!SignatureVerifier::is_extension_compatible(KnownFileType::PeExecutable, L"pdf"), "pdf incompatible with PE (spoof)");
    check(SignatureVerifier::is_extension_compatible(KnownFileType::ZipArchive, L"docx"), "docx compatible with ZIP");

    std::vector<RecordInfo> records;

    RecordInfo fake_img;
    fake_img.record_index = 100;
    fake_img.name = L"invoice.pdf";
    fake_img.size_bytes = 512;
    fake_img.is_resident = true;
    fake_img.resident_magic = {0x4D, 0x5A, 0x90, 0x00}; // Actually an executable!
    records.push_back(fake_img);

    RecordInfo real_img;
    real_img.record_index = 200;
    real_img.name = L"photo.jpg";
    real_img.size_bytes = 512;
    real_img.is_resident = true;
    real_img.resident_magic = {0xFF, 0xD8, 0xFF, 0xE0}; // Genuine JPEG
    records.push_back(real_img);

    auto rep = SignatureVerifier::analyze(records);
    check(rep.total_inspected == 2, "signature verifier inspected 2 resident files");
    check(rep.mismatches_detected == 1, "signature verifier detected 1 mismatch");
    check(rep.critical_executables_detected == 1, "detected 1 masquerading PE executable");
    check(rep.entries[0].record_index == 100, "flagged invoice.pdf as masquerading executable");
}

static void test_security_auditor() {
    check(SecurityAuditor::format_access_mask(FILE_ALL_ACCESS) == L"Full Control", "format_access_mask full control");
    check(SecurityAuditor::format_access_mask(FILE_GENERIC_READ).find(L"Read") != std::wstring::npos, "format_access_mask read");
    check(wcscmp(SecurityAuditor::risk_to_string(SecurityRiskLevel::Critical), L"CRITICAL") == 0, "risk_to_string critical");
    check(wcscmp(SecurityAuditor::risk_to_string(SecurityRiskLevel::High), L"HIGH") == 0, "risk_to_string high");

    // Test NULL DACL
    SECURITY_DESCRIPTOR sd_null{};
    check(InitializeSecurityDescriptor(&sd_null, SECURITY_DESCRIPTOR_REVISION), "InitializeSecurityDescriptor null");
    check(SetSecurityDescriptorDacl(&sd_null, TRUE, nullptr, FALSE), "SetSecurityDescriptorDacl null");
    auto res_null = SecurityAuditor::audit_security_descriptor(&sd_null, L"C:\\test_null.txt", 100);
    check(res_null.ok(), "audit_security_descriptor null dacl ok");
    check(res_null.value().has_null_dacl, "has_null_dacl detected");
    check(res_null.value().risk_level == SecurityRiskLevel::Critical, "null dacl risk is critical");

    // Test Empty DACL
    SECURITY_DESCRIPTOR sd_empty{};
    check(InitializeSecurityDescriptor(&sd_empty, SECURITY_DESCRIPTOR_REVISION), "InitializeSecurityDescriptor empty");
    BYTE acl_buf[sizeof(ACL)]{};
    PACL p_acl = reinterpret_cast<PACL>(acl_buf);
    check(InitializeAcl(p_acl, sizeof(acl_buf), ACL_REVISION), "InitializeAcl");
    check(SetSecurityDescriptorDacl(&sd_empty, TRUE, p_acl, FALSE), "SetSecurityDescriptorDacl empty");
    auto res_empty = SecurityAuditor::audit_security_descriptor(&sd_empty, L"C:\\test_empty.txt", 101);
    check(res_empty.ok(), "audit_security_descriptor empty dacl ok");
    check(res_empty.value().has_empty_dacl, "has_empty_dacl detected");

    // Test World-Writable DACL
    SECURITY_DESCRIPTOR sd_world{};
    check(InitializeSecurityDescriptor(&sd_world, SECURITY_DESCRIPTOR_REVISION), "InitializeSecurityDescriptor world");
    BYTE world_sid[SECURITY_MAX_SID_SIZE]{};
    DWORD sid_sz = sizeof(world_sid);
    check(CreateWellKnownSid(WinWorldSid, nullptr, world_sid, &sid_sz), "CreateWellKnownSid WinWorldSid");
    BYTE acl_world_buf[1024]{};
    PACL p_world_acl = reinterpret_cast<PACL>(acl_world_buf);
    check(InitializeAcl(p_world_acl, sizeof(acl_world_buf), ACL_REVISION), "InitializeAcl world");
    check(AddAccessAllowedAce(p_world_acl, ACL_REVISION, FILE_GENERIC_WRITE | FILE_GENERIC_READ, reinterpret_cast<PSID>(world_sid)), "AddAccessAllowedAce");
    check(SetSecurityDescriptorDacl(&sd_world, TRUE, p_world_acl, FALSE), "SetSecurityDescriptorDacl world");
    auto res_world = SecurityAuditor::audit_security_descriptor(&sd_world, L"C:\\Data\\file.txt", 102);
    check(res_world.ok(), "audit_security_descriptor world writable ok");
    check(res_world.value().is_world_writable, "is_world_writable detected");
    check(res_world.value().risk_level == SecurityRiskLevel::High, "world writable risk is high");
}

static void test_file_carver() {
    check(FileCarver::sanitize_filename(L"bad:file*name?.txt") == L"bad_file_name_.txt", "sanitize filename chars");
    check(FileCarver::sanitize_filename(L"") == L"unnamed", "sanitize empty filename");

    std::vector<uint8_t> rec(1024, 0);
    auto* hdr = reinterpret_cast<MftRecordHeader*>(rec.data());
    hdr->magic = kMftMagicFile;
    hdr->update_sequence_offset = 48;
    hdr->update_sequence_size = 3;
    hdr->first_attribute_offset = 64;
    hdr->flags = kRecordInUse;
    hdr->bytes_used = 1024;
    hdr->bytes_allocated = 1024;

    // USA fixup tags
    uint16_t usa_tag = 0x5A5A;
    *reinterpret_cast<uint16_t*>(rec.data() + 48) = usa_tag;
    *reinterpret_cast<uint16_t*>(rec.data() + 510) = usa_tag;
    *reinterpret_cast<uint16_t*>(rec.data() + 1022) = usa_tag;

    // Add Resident $DATA attribute at offset 64
    auto* attr = reinterpret_cast<AttributeRecordHeader*>(rec.data() + 64);
    attr->type_code = kAttrData;
    attr->record_length = 80;
    attr->non_resident_flag = 0;
    attr->name_length = 0;
    attr->resident.value_offset = 24;
    const char test_data[] = "NTFS Carve Resident Payload Verification!";
    const uint32_t payload_len = static_cast<uint32_t>(sizeof(test_data));
    attr->resident.value_length = payload_len;
    memcpy(rec.data() + 64 + 24, test_data, payload_len);

    // End marker attribute
    auto* end_attr = reinterpret_cast<AttributeRecordHeader*>(rec.data() + 64 + 80);
    end_attr->type_code = kAttrEnd;

    VolumeGeometry geom{};
    geom.bytes_per_sector = 512;
    geom.bytes_per_cluster = 4096;
    geom.bytes_per_record = 1024;

    wchar_t temp_dir[MAX_PATH]{};
    GetTempPathW(MAX_PATH, temp_dir);
    std::wstring out_file = std::wstring(temp_dir) + L"mftscan_test_carve.bin";

    auto carve_res = FileCarver::carve_from_buffer(
        INVALID_HANDLE_VALUE,
        geom,
        rec.data(),
        1024,
        9999,
        out_file,
        L"",
        false
    );

    check(carve_res.ok(), "carve_from_buffer ok");
    check(carve_res.value().success, "carve success flag");
    check(carve_res.value().bytes_written == payload_len, "carved bytes written matches");
    check(carve_res.value().is_resident, "carved attribute identified as resident");

    // Verify file content on disk
    FILE* f = nullptr;
    _wfopen_s(&f, out_file.c_str(), L"rb");
    check(f != nullptr, "carved output file opened");
    char read_back[128]{};
    size_t read_bytes = fread(read_back, 1, sizeof(read_back), f);
    fclose(f);
    DeleteFileW(out_file.c_str());

    check(read_bytes == payload_len, "read back size matches payload");
    check(memcmp(read_back, test_data, payload_len) == 0, "read back data matches exactly");
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

    std::wcout << L"[RUN] test_data_run_decoder\n";
    test_data_run_decoder();

    std::wcout << L"[RUN] test_duplicate_detector_grouping\n";
    test_duplicate_detector_grouping();

    std::wcout << L"[RUN] test_usn_reason_formatting\n";
    test_usn_reason_formatting();

    std::wcout << L"[RUN] test_fragmentation_analyzer\n";
    test_fragmentation_analyzer();

    std::wcout << L"[RUN] test_sparse_and_slack_analyzer\n";
    test_sparse_and_slack_analyzer();

    std::wcout << L"[RUN] test_thread_pool\n";
    test_thread_pool();

    std::wcout << L"[RUN] test_record_inspector_attribute_names\n";
    test_record_inspector_attribute_names();

    std::wcout << L"[RUN] test_record_inspector_hex_dump\n";
    test_record_inspector_hex_dump();

    std::wcout << L"[RUN] test_timestomp_detection\n";
    test_timestomp_detection();

    std::wcout << L"[RUN] test_signature_verifier\n";
    test_signature_verifier();

    std::wcout << L"[RUN] test_security_auditor\n";
    test_security_auditor();

    std::wcout << L"[RUN] test_file_carver\n";
    test_file_carver();

    std::wcout << L"All 24 unit test suites passed successfully.\n";
    return 0;
}
