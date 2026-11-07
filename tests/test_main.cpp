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
#include "mftscan/attr_list.hpp"
#include "mftscan/boot_sector.hpp"
#include "mftscan/reparse.hpp"
#include "mftscan/density.hpp"
#include "mftscan/mft_slack.hpp"
#include "mftscan/extended_attributes.hpp"
#include "mftscan/object_id.hpp"
#include "mftscan/hardlink.hpp"
#include "mftscan/badclus.hpp"
#include "mftscan/quota.hpp"
#include "mftscan/attrdef.hpp"
#include "mftscan/churn.hpp"
#include "mftscan/secure.hpp"
#include "mftscan/volume_info.hpp"
#include "mftscan/usn_journal.hpp"
#include <cstring>
#include "mftscan/bitmap.hpp"
#include "mftscan/logfile.hpp"
#include "mftscan/carver.hpp"
#include "mftscan/system_files.hpp"
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

static void test_system_files_inspector() {
    check(wcscmp(SystemFilesInspector::get_standard_system_name(0), L"$MFT") == 0, "system file 0 is $MFT");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(1), L"$MFTMirr") == 0, "system file 1 is $MFTMirr");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(2), L"$LogFile") == 0, "system file 2 is $LogFile");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(3), L"$Volume") == 0, "system file 3 is $Volume");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(4), L"$AttrDef") == 0, "system file 4 is $AttrDef");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(5), L". (Root)") == 0, "system file 5 is . (Root)");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(6), L"$Bitmap") == 0, "system file 6 is $Bitmap");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(7), L"$Boot") == 0, "system file 7 is $Boot");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(8), L"$BadClus") == 0, "system file 8 is $BadClus");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(9), L"$Secure") == 0, "system file 9 is $Secure");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(10), L"$UpCase") == 0, "system file 10 is $UpCase");
    check(wcscmp(SystemFilesInspector::get_standard_system_name(11), L"$Extend") == 0, "system file 11 is $Extend");
    check(wcslen(SystemFilesInspector::get_standard_system_purpose(0)) > 0, "system purpose non-empty");
}

static void test_bitmap_analyzer() {
    // 64 clusters = 8 bytes
    // Byte 0: 0xFF (8 used)
    // Byte 1: 0x00 (8 free)
    // Byte 2: 0xAA = 10101010b (4 used, 4 free)
    // Byte 3..7: 0x00 (40 free in a single continuous run)
    uint8_t bmp[8] = { 0xFF, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00 };

    auto res = BitmapAnalyzer::analyze_from_buffer(bmp, 64, 4096, L'C', 16);
    check(res.ok(), "analyze_from_buffer ok");
    const auto& r = res.value();

    check(r.total_clusters == 64, "total clusters is 64");
    check(r.used_clusters == 12, "used clusters is 12");
    check(r.free_clusters == 52, "free clusters is 52");
    check(r.largest_free_extent_clusters == 40, "largest free extent is 40");
    check(r.ascii_map.size() == 18, "ascii map length is 18 (16 blocks + brackets)");
    check(r.ascii_map.front() == '[', "ascii map start bracket");
    check(r.ascii_map.back() == ']', "ascii map end bracket");
    check(r.free_percent > 80.0, "free percentage > 80%");
    check(r.free_space_fragmentation_index >= 0.0, "fragmentation index non-negative");
}

static void test_attr_list_decoder() {
    std::vector<uint8_t> buf(sizeof(AttributeListEntryHeader) * 2 + 16, 0);

    // Entry 1: $FILE_NAME with name "test"
    auto* e1 = reinterpret_cast<AttributeListEntryHeader*>(buf.data());
    e1->attribute_type = 0x30;
    e1->name_length = 4;
    e1->name_offset = sizeof(AttributeListEntryHeader);
    e1->record_length = static_cast<uint16_t>(sizeof(AttributeListEntryHeader) + 8);
    e1->lowest_vcn = 0;
    e1->file_reference_number = 1000;
    e1->attribute_id = 1;
    memcpy(buf.data() + sizeof(AttributeListEntryHeader), L"test", 8);

    // Entry 2: $DATA unnamed
    auto* e2 = reinterpret_cast<AttributeListEntryHeader*>(buf.data() + e1->record_length);
    e2->attribute_type = 0x80;
    e2->name_length = 0;
    e2->name_offset = 0;
    e2->record_length = static_cast<uint16_t>(sizeof(AttributeListEntryHeader));
    e2->lowest_vcn = 1024;
    e2->file_reference_number = 1001;
    e2->attribute_id = 2;

    const size_t total_len = e1->record_length + e2->record_length;
    auto entries = AttrListDecoder::decode(buf.data(), total_len);

    check(entries.size() == 2, "decoded exactly 2 attribute list entries");
    check(entries[0].attribute_type == 0x30, "entry 0 type is 0x30");
    check(entries[0].type_name == L"$FILE_NAME", "entry 0 type name is $FILE_NAME");
    check(entries[0].attribute_name == L"test", "entry 0 name is test");
    check(entries[0].child_record_frn == 1000, "entry 0 child FRN is 1000");

    check(entries[1].attribute_type == 0x80, "entry 1 type is 0x80");
    check(entries[1].type_name == L"$DATA", "entry 1 type name is $DATA");
    check(entries[1].lowest_vcn == 1024, "entry 1 lowest VCN is 1024");
    check(entries[1].child_record_frn == 1001, "entry 1 child FRN is 1001");

    std::wstring fmt = AttrListDecoder::format_entry(entries[0]);
    check(fmt.find(L"$FILE_NAME") != std::wstring::npos, "format_entry contains $FILE_NAME");
    check(fmt.find(L"1000") != std::wstring::npos, "format_entry contains child FRN");
}

static void test_logfile_analyzer() {
    std::vector<uint8_t> page(4096, 0);

    auto* header = reinterpret_cast<LogFileRestartPageHeader*>(page.data());
    header->magic = kLogFileMagicRstr;
    header->update_sequence_offset = 32;
    header->update_sequence_size = 9; // 1 tag + 8 sectors
    header->system_page_size = 4096;
    header->log_page_size = 4096;
    header->restart_area_offset = 64;
    header->major_version = 1;
    header->minor_version = 1;

    // Set USA fixup tag and sector end markers
    uint16_t usa_tag = 0xBEEF;
    *reinterpret_cast<uint16_t*>(page.data() + 32) = usa_tag;
    for (size_t s = 0; s < 8; ++s) {
        size_t end_pos = (s + 1) * 512 - 2;
        *reinterpret_cast<uint16_t*>(page.data() + end_pos) = usa_tag;
    }

    auto* area = reinterpret_cast<LogFileRestartArea*>(page.data() + 64);
    area->current_lsn = 0x1234567890ABCDEFULL;
    area->log_clients = 1;
    area->flags = kLogFileCleanShutdown;
    area->file_size = 64 * 1024 * 1024;
    area->restart_open_log_count = 5;

    auto res = LogFileAnalyzer::analyze_from_page(page.data(), 4096, L'C');
    check(res.ok(), "analyze_from_page ok");
    const auto& r = res.value();

    check(r.is_valid_rstr, "is_valid_rstr is true");
    check(r.is_clean_shutdown, "is_clean_shutdown is true");
    check(r.major_version == 1, "major version is 1");
    check(r.minor_version == 1, "minor version is 1");
    check(r.current_lsn == 0x1234567890ABCDEFULL, "current_lsn matches");
    check(r.file_size == 67108864, "file_size is 64MB");
    check(r.log_clients == 1, "log_clients is 1");
}

static void test_boot_sector_parser() {
    NtfsBootSector bs{};
    memcpy(bs.jump, "\xEB\x52\x90", 3);
    memcpy(bs.oem_id, "NTFS    ", 8);
    bs.bytes_per_sector = 512;
    bs.sectors_per_cluster = 8;
    bs.total_sectors = 2048000;
    bs.mft_lcn = 786432;
    bs.mft_mirr_lcn = 2;
    bs.clusters_per_record_code = -10; // 1024 bytes
    bs.clusters_per_index_code = -12;  // 4096 bytes
    bs.volume_serial_number = 0xA1B2C3D4E5F60718ULL;
    bs.boot_signature = kBootSectorSignature;

    auto res = BootSectorParser::parse_buffer(reinterpret_cast<const uint8_t*>(&bs), sizeof(bs), L'C');
    check(res.ok(), "parse_buffer ok");
    const auto& r = res.value();

    check(r.is_valid_ntfs, "is_valid_ntfs is true");
    check(r.signature_valid, "signature_valid is true");
    check(r.bytes_per_sector == 512, "bytes_per_sector is 512");
    check(r.sectors_per_cluster == 8, "sectors_per_cluster is 8");
    check(r.bytes_per_cluster == 4096, "bytes_per_cluster is 4096");
    check(r.bytes_per_record == 1024, "bytes_per_record is 1024");
    check(r.bytes_per_index_block == 4096, "bytes_per_index_block is 4096");
    check(r.total_sectors == 2048000, "total_sectors is 2048000");
    check(r.mft_start_lcn == 786432, "mft_start_lcn is 786432");
    check(r.serial_number == 0xA1B2C3D4E5F60718ULL, "serial_number matches");
    check(!r.serial_number_formatted.empty(), "serial_number_formatted non-empty");

    check(BootSectorParser::decode_size_code(-10, 4096) == 1024, "decode -10 code to 1024 bytes");
    check(BootSectorParser::decode_size_code(4, 4096) == 16384, "decode 4 clusters to 16384 bytes");
}

static void test_reparse_point_analyzer() {
    check(ReparsePointAnalyzer::tag_to_string(kTagSymlink) == L"Symbolic Link", "tag_to_string symlink");
    check(ReparsePointAnalyzer::tag_to_string(kTagMountPoint).find(L"Junction") != std::wstring::npos, "tag_to_string junction");

    // Construct synthetic Symlink attribute
    std::wstring sym_target = L"C:\\Target\\File.txt";
    const uint16_t path_bytes = static_cast<uint16_t>(sym_target.size() * sizeof(wchar_t));
    std::vector<uint8_t> sym_buf(20 + path_bytes, 0);

    *reinterpret_cast<uint32_t*>(sym_buf.data()) = kTagSymlink;
    *reinterpret_cast<uint16_t*>(sym_buf.data() + 4) = static_cast<uint16_t>(12 + path_bytes);
    *reinterpret_cast<uint16_t*>(sym_buf.data() + 8) = 0; // sub_off
    *reinterpret_cast<uint16_t*>(sym_buf.data() + 10) = path_bytes; // sub_len
    *reinterpret_cast<uint16_t*>(sym_buf.data() + 12) = 0; // print_off
    *reinterpret_cast<uint16_t*>(sym_buf.data() + 14) = path_bytes; // print_len
    *reinterpret_cast<uint32_t*>(sym_buf.data() + 16) = 0; // absolute
    memcpy(sym_buf.data() + 20, sym_target.data(), path_bytes);

    auto res = ReparsePointAnalyzer::parse_attribute(sym_buf.data(), sym_buf.size(), 500, L"C:\\Link.txt");
    check(res.ok(), "parse_attribute symlink ok");
    const auto& r = res.value();

    check(r.is_symlink, "is_symlink is true");
    check(!r.is_junction, "is_junction is false");
    check(!r.is_relative, "is_relative is false");
    check(r.target_path == sym_target, "symlink target path matches");
    check(r.tag_name == L"Symbolic Link", "symlink tag name matches");

    // Construct synthetic Junction attribute
    std::wstring junc_target = L"\\??\\C:\\TargetDir";
    const uint16_t junc_bytes = static_cast<uint16_t>(junc_target.size() * sizeof(wchar_t));
    std::vector<uint8_t> junc_buf(16 + junc_bytes, 0);

    *reinterpret_cast<uint32_t*>(junc_buf.data()) = kTagMountPoint;
    *reinterpret_cast<uint16_t*>(junc_buf.data() + 4) = static_cast<uint16_t>(8 + junc_bytes);
    *reinterpret_cast<uint16_t*>(junc_buf.data() + 8) = 0; // sub_off
    *reinterpret_cast<uint16_t*>(junc_buf.data() + 10) = junc_bytes; // sub_len
    *reinterpret_cast<uint16_t*>(junc_buf.data() + 12) = 0; // print_off
    *reinterpret_cast<uint16_t*>(junc_buf.data() + 14) = junc_bytes; // print_len
    memcpy(junc_buf.data() + 16, junc_target.data(), junc_bytes);

    auto res_j = ReparsePointAnalyzer::parse_attribute(junc_buf.data(), junc_buf.size(), 501, L"C:\\JunctionDir");
    check(res_j.ok(), "parse_attribute junction ok");
    const auto& rj = res_j.value();

    check(rj.is_junction, "is_junction is true");
    check(!rj.is_symlink, "is_symlink is false");
    check(rj.target_path == junc_target, "junction target path matches");
}

static void test_mft_slack_carver() {
    std::vector<uint8_t> buf(1024, 0);
    auto* hdr = reinterpret_cast<MftRecordHeader*>(buf.data());
    hdr->magic = kMftMagicFile;
    hdr->bytes_used = 400;
    hdr->bytes_allocated = 1024;
    hdr->flags = kRecordInUse;

    // Place residual ASCII string at offset 420
    const std::string residual_str = "ResidualForensicArtifact.doc";
    memcpy(buf.data() + 420, residual_str.data(), residual_str.size());

    // Place residual attribute header at offset 500: $FILE_NAME (0x30), length 64
    auto* attr = reinterpret_cast<AttributeRecordHeader*>(buf.data() + 500);
    attr->type_code = kAttrFileName;
    attr->record_length = 64;
    attr->non_resident_flag = 0;

    auto res = MftSlackCarver::analyze_record_slack(buf.data(), 1024, 12345);
    check(res.ok(), "analyze_record_slack ok");
    const auto& report = res.value();

    check(report.frn == 12345, "frn matches");
    check(report.bytes_used == 400, "bytes_used matches");
    check(report.bytes_allocated == 1024, "bytes_allocated matches");
    check(report.slack_size == 624, "slack_size matches");
    check(report.has_non_zero_slack, "has_non_zero_slack is true");
    check(report.non_zero_bytes_count >= residual_str.size(), "non_zero_bytes_count >= string size");

    bool found_str = false;
    for (const auto& s : report.residual_strings) {
        if (s.text.find(L"ResidualForensicArtifact") != std::wstring::npos) {
            found_str = true;
            break;
        }
    }
    check(found_str, "residual string extracted");

    bool found_attr = false;
    for (const auto& a : report.residual_attributes) {
        if (a.type_code == kAttrFileName && a.length == 64) {
            found_attr = true;
            break;
        }
    }
    check(found_attr, "residual attribute header extracted");
    check(!report.hex_dump.empty(), "hex dump generated");
}

static void test_density_analyzer() {
    std::vector<RecordInfo> records;

    // Record 0: directory
    RecordInfo d;
    d.record_index = 5;
    d.is_directory = true;
    records.push_back(d);

    // Record 1: small resident file (300 B)
    RecordInfo r1;
    r1.record_index = 100;
    r1.size_bytes = 300;
    r1.allocated_bytes = 0;
    r1.is_resident = true;
    records.push_back(r1);

    // Record 2: non-resident file (5000 B, allocated 8192 B, slack 3192 B)
    RecordInfo r2;
    r2.record_index = 101;
    r2.size_bytes = 5000;
    r2.allocated_bytes = 8192;
    r2.slack_bytes = 3192;
    r2.is_resident = false;
    records.push_back(r2);

    // Record 3: empty file (0 B)
    RecordInfo r3;
    r3.record_index = 102;
    r3.size_bytes = 0;
    r3.allocated_bytes = 0;
    r3.is_resident = true;
    records.push_back(r3);

    auto report = DensityAnalyzer::analyze(records, 4096);
    check(report.total_records == 4, "total records matches");
    check(report.active_directories == 1, "active directories matches");
    check(report.active_files == 3, "active files matches");
    check(report.resident_files == 2, "resident files matches");
    check(report.non_resident_files == 1, "non-resident files matches");
    check(report.zero_byte_files == 1, "zero byte files matches");
    check(report.total_resident_bytes == 300, "total resident bytes matches");
    check(report.cluster_slack_saved_bytes == 8192, "cluster slack saved bytes matches (2 * 4096)");
    check(report.buckets.size() == 9, "9 size buckets present");
}

static void test_object_id_analyzer() {
    std::vector<uint8_t> payload(64, 0);

    // Object ID
    payload[0] = 0xAA;
    payload[15] = 0x11;

    // Birth Volume ID
    payload[16] = 0xBB;
    payload[31] = 0x22;

    // Birth Object ID (distinct from Object ID)
    payload[32] = 0xCC;
    payload[47] = 0x33;

    auto res = ObjectIdAnalyzer::parse_attribute(payload.data(), 64, 2048, L"C:\\Data\\Migrated.doc");
    check(res.ok(), "parse_attribute object_id ok");
    const auto& info = res.value();

    check(info.frn == 2048, "frn matches");
    check(info.has_birth_data, "has_birth_data is true");
    check(info.is_migrated, "is_migrated is true (object_id != birth_object_id)");
    check(!info.object_id_str.empty(), "object_id_str not empty");
    check(!info.birth_object_id_str.empty(), "birth_object_id_str not empty");
    check(info.object_id_str != info.birth_object_id_str, "object_id differs from birth_object_id");
}

static void test_extended_attributes_analyzer() {
    // Construct 2 packed EA records
    std::string name1 = "LXATTRB";
    std::string name2 = "UserComment";
    std::string val2 = "TagData";

    const size_t e1_aligned = 24; // 4-byte aligned
    const size_t e2_len = 8 + name2.size() + 1 + val2.size(); // 8 hdr + 11 name + 1 null + 7 val = 27

    std::vector<uint8_t> ea_buf(e1_aligned + e2_len + 4, 0);

    // Entry 1
    *reinterpret_cast<uint32_t*>(ea_buf.data()) = static_cast<uint32_t>(e1_aligned); // next_entry_offset
    ea_buf[4] = 0; // flags
    ea_buf[5] = static_cast<uint8_t>(name1.size()); // ea_name_length
    *reinterpret_cast<uint16_t*>(ea_buf.data() + 6) = 4; // ea_value_length
    memcpy(ea_buf.data() + 8, name1.data(), name1.size());
    ea_buf[8 + name1.size()] = 0; // null terminator
    ea_buf[8 + name1.size() + 1] = 0x01; // val byte

    // Entry 2
    uint8_t* e2_ptr = ea_buf.data() + e1_aligned;
    *reinterpret_cast<uint32_t*>(e2_ptr) = 0; // last entry
    e2_ptr[4] = 0x80; // NEED_EA flag
    e2_ptr[5] = static_cast<uint8_t>(name2.size());
    *reinterpret_cast<uint16_t*>(e2_ptr + 6) = static_cast<uint16_t>(val2.size());
    memcpy(e2_ptr + 8, name2.data(), name2.size());
    e2_ptr[8 + name2.size()] = 0; // null terminator
    memcpy(e2_ptr + 8 + name2.size() + 1, val2.data(), val2.size());

    auto res = ExtendedAttributesAnalyzer::parse_ea_stream(ea_buf.data(), e1_aligned + e2_len, 3000, L"C:\\WSL\\file");
    check(res.ok(), "parse_ea_stream ok");
    const auto& rep = res.value();

    check(rep.frn == 3000, "frn matches");
    check(rep.attributes.size() == 2, "2 EA items parsed");
    check(rep.has_wsl_metadata, "has_wsl_metadata is true for LXATTRB");
    check(rep.need_ea_count == 1, "need_ea_count == 1");
    check(rep.attributes[0].is_wsl_attribute, "entry 1 is_wsl_attribute");
    check(rep.attributes[1].is_need_ea, "entry 2 is_need_ea");
    check(rep.attributes[1].value_preview == "TagData", "entry 2 value preview matches");
}

static void test_hard_link_tracker() {
    std::vector<RecordInfo> records;

    RecordInfo r1;
    r1.record_index = 500;
    r1.hard_link_count = 3;
    r1.size_bytes = 10000;
    r1.allocated_bytes = 12288;
    r1.full_path = L"C:\\Windows\\System32\\driver.sys";
    r1.sibling_names = { L"driver.sys", L"driver_alias1.sys", L"driver_alias2.sys" };
    records.push_back(r1);

    RecordInfo r2;
    r2.record_index = 501;
    r2.hard_link_count = 1;
    r2.size_bytes = 500;
    r2.allocated_bytes = 4096;
    records.push_back(r2);

    RecordInfo d;
    d.record_index = 5;
    d.is_directory = true;
    records.push_back(d);

    auto rep = HardLinkTracker::analyze(records);
    check(rep.total_multi_link_files == 1, "total_multi_link_files matches 1");
    check(rep.total_link_references == 3, "total_link_references matches 3");
    check(rep.total_space_saved_bytes == 24576, "total_space_saved_bytes matches 24576 (2 * 12288)");
    check(!rep.groups.empty(), "groups not empty");
    check(rep.groups[0].frn == 500, "group frn matches 500");
    check(rep.groups[0].hard_link_count == 3, "group hard_link_count matches 3");
    check(rep.groups[0].saved_bytes == 24576, "group saved_bytes matches 24576");
    check(rep.groups[0].names.size() == 3, "group names count matches 3");
}

static void test_usn_journal_stats() {
    UsnJournalStats s{};
    s.journal_id = 0x1234567890ABCDEFULL;
    s.lowest_valid_usn = 1000000;
    s.next_usn = 5000000;
    s.maximum_size = 33554432; // 32 MB
    s.allocation_delta = 4194304; // 4 MB
    s.max_usn = 100000000;

    const uint64_t diff = s.next_usn - s.lowest_valid_usn;
    s.estimated_active_size_mb = static_cast<double>(diff) / (1024.0 * 1024.0);
    s.approximate_event_count = diff / 96;
    s.utilization_percentage = (static_cast<double>(diff) / static_cast<double>(s.maximum_size)) * 100.0;
    s.rollover_percentage = (static_cast<double>(s.next_usn) / static_cast<double>(s.max_usn)) * 100.0;

    check(s.journal_id == 0x1234567890ABCDEFULL, "journal_id matches");
    check(s.approximate_event_count == 4000000 / 96, "approximate_event_count matches");
    check(s.rollover_percentage == 5.0, "rollover_percentage matches 5.0%");
    check(s.utilization_percentage > 10.0 && s.utilization_percentage < 15.0, "utilization_percentage in expected range");
}

static void test_bad_cluster_report() {
    BadClusterReport report;
    report.total_volume_clusters = 50000000;

    BadClusterExtent ext1;
    ext1.start_lcn = 100000;
    ext1.cluster_count = 4;
    ext1.byte_length = 16384;
    report.extents.push_back(ext1);

    BadClusterExtent ext2;
    ext2.start_lcn = 250000;
    ext2.cluster_count = 8;
    ext2.byte_length = 32768;
    report.extents.push_back(ext2);

    report.bad_cluster_count = 12;
    report.bad_bytes_count = 49152;
    report.is_healthy = false;

    check(!report.is_healthy, "report is_healthy is false");
    check(report.bad_cluster_count == 12, "bad_cluster_count matches 12");
    check(report.bad_bytes_count == 49152, "bad_bytes_count matches 49152");
    check(report.extents.size() == 2, "2 extents present");
    check(report.extents[0].start_lcn == 100000, "extent 0 lcn matches");
    check(report.extents[1].start_lcn == 250000, "extent 1 lcn matches");
}

static void test_quota_analyzer() {
    std::vector<RecordInfo> records;

    RecordInfo r1;
    r1.record_index = 1000;
    r1.owner_id = 1;
    r1.size_bytes = 10485760;
    r1.quota_charged = 10485760;
    records.push_back(r1);

    RecordInfo r2;
    r2.record_index = 1001;
    r2.owner_id = 1;
    r2.size_bytes = 5242880;
    r2.quota_charged = 5242880;
    records.push_back(r2);

    RecordInfo r3;
    r3.record_index = 1002;
    r3.owner_id = 2;
    r3.size_bytes = 2097152;
    r3.quota_charged = 2097152;
    records.push_back(r3);

    RecordInfo r4;
    r4.record_index = 1003;
    r4.owner_id = 0;
    r4.size_bytes = 1024;
    r4.quota_charged = 0; // uncharged
    records.push_back(r4);

    RecordInfo dir;
    dir.record_index = 5;
    dir.is_directory = true;
    records.push_back(dir);

    auto rep = QuotaAnalyzer::analyze(records);
    check(rep.total_files_analyzed == 4, "total_files_analyzed matches 4");
    check(rep.total_quota_charged_bytes == 17825792, "total_quota_charged_bytes matches 17825792");
    check(rep.uncharged_files_count == 1, "uncharged_files_count matches 1");
    check(rep.owners.size() == 3, "3 distinct owners present");
    check(rep.owners[0].owner_id == 1, "top owner is ID 1");
    check(rep.owners[0].total_quota_charged == 15728640, "owner 1 charged matches 15728640");
    check(rep.owners[0].file_count == 2, "owner 1 file_count matches 2");
}

static void test_attrdef_analyzer() {
    std::vector<RawAttrDefEntry> entries(3);
    std::memset(entries.data(), 0, entries.size() * sizeof(RawAttrDefEntry));

    // Entry 1: $STANDARD_INFORMATION
    const wchar_t* n1 = L"$STANDARD_INFORMATION";
    std::memcpy(entries[0].name, n1, wcslen(n1) * sizeof(wchar_t));
    entries[0].type_code = 0x10;
    entries[0].display_rule = 0;
    entries[0].collation_rule = 0x00; // BINARY
    entries[0].flags = 0x40; // MULTIPLE
    entries[0].min_size = 48;
    entries[0].max_size = 72;

    // Entry 2: $FILE_NAME
    const wchar_t* n2 = L"$FILE_NAME";
    std::memcpy(entries[1].name, n2, wcslen(n2) * sizeof(wchar_t));
    entries[1].type_code = 0x30;
    entries[1].display_rule = 0;
    entries[1].collation_rule = 0x01; // FILE_NAME
    entries[1].flags = 0x42; // INDEXABLE | MULTIPLE
    entries[1].min_size = 68;
    entries[1].max_size = 578;

    // Entry 3: Custom attribute
    const wchar_t* n3 = L"$CUSTOM_TELEMETRY";
    std::memcpy(entries[2].name, n3, wcslen(n3) * sizeof(wchar_t));
    entries[2].type_code = 0x200;
    entries[2].display_rule = 0;
    entries[2].collation_rule = 0x00;
    entries[2].flags = 0x80; // NOT_RESIDENT
    entries[2].min_size = 0;
    entries[2].max_size = 1048576;

    const uint8_t* raw_bytes = reinterpret_cast<const uint8_t*>(entries.data());
    const size_t raw_len = entries.size() * sizeof(RawAttrDefEntry);

    auto rep = AttrDefAnalyzer::parse_from_buffer(raw_bytes, raw_len, L'C');
    check(rep.valid, "rep.valid is true");
    check(rep.total_definitions == 3, "total_definitions == 3");
    check(rep.standard_types_count == 2, "standard_types_count == 2");
    check(rep.custom_types_count == 1, "custom_types_count == 1");
    check(rep.indexable_count == 1, "indexable_count == 1");
    check(rep.multiple_count == 2, "multiple_count == 2");

    check(rep.entries[0].name == L"$STANDARD_INFORMATION", "entry 0 name matches");
    check(rep.entries[0].type_code == 0x10, "entry 0 type code matches");
    check(rep.entries[0].collation_name == L"BINARY", "entry 0 collation matches BINARY");

    check(rep.entries[1].name == L"$FILE_NAME", "entry 1 name matches");
    check(rep.entries[1].is_indexable, "entry 1 is_indexable is true");
    check(rep.entries[1].collation_name == L"FILE_NAME", "entry 1 collation matches FILE_NAME");

    check(rep.entries[2].is_custom, "entry 2 is_custom is true");
    check(rep.entries[2].not_resident, "entry 2 not_resident is true");
    check(rep.entries[2].max_size == 1048576, "entry 2 max_size matches 1048576");
}

static void test_churn_analyzer() {
    std::vector<RecordInfo> records;

    RecordInfo r1;
    r1.record_index = 100;
    r1.sequence_number = 2;
    r1.size_bytes = 5000;
    records.push_back(r1);

    RecordInfo r2;
    r2.record_index = 101;
    r2.sequence_number = 12;
    r2.size_bytes = 8000;
    records.push_back(r2);

    RecordInfo r3;
    r3.record_index = 102;
    r3.sequence_number = 75;
    r3.size_bytes = 12000;
    records.push_back(r3);

    RecordInfo r4;
    r4.record_index = 103;
    r4.sequence_number = 61000;
    r4.size_bytes = 3000;
    records.push_back(r4);

    RecordInfo r5;
    r5.record_index = 104;
    r5.sequence_number = 150;
    r5.size_bytes = 0;
    r5.is_deleted = true;
    records.push_back(r5);

    RecordInfo r6;
    r6.record_index = 105;
    r6.sequence_number = 0; // invalid
    records.push_back(r6);

    auto rep = ChurnAnalyzer::analyze(records, 5);
    check(rep.total_records_evaluated == 6, "total_records_evaluated matches 6");
    check(rep.active_records == 5, "active_records matches 5");
    check(rep.deleted_records == 1, "deleted_records matches 1");
    check(rep.min_sequence == 2, "min_sequence matches 2");
    check(rep.max_sequence == 61000, "max_sequence matches 61000");
    check(rep.rollover_risk_count == 1, "rollover_risk_count matches 1");

    check(rep.tier_1_to_5 == 1, "tier_1_to_5 matches 1");
    check(rep.tier_6_to_20 == 1, "tier_6_to_20 matches 1");
    check(rep.tier_51_to_100 == 1, "tier_51_to_100 matches 1");
    check(rep.tier_101_to_500 == 1, "tier_101_to_500 matches 1");
    check(rep.tier_above_500 == 1, "tier_above_500 matches 1");

    check(rep.top_churn_records.size() == 5, "top_churn_records size matches 5");
    check(rep.top_churn_records[0].frn == 103, "top churn record 0 frn is 103");
    check(rep.top_churn_records[0].sequence_number == 61000, "top churn record 0 seq is 61000");
    check(rep.top_churn_records[1].frn == 104, "top churn record 1 frn is 104");
    check(rep.top_churn_records[1].is_deleted, "top churn record 1 is_deleted is true");
}

static void test_secure_database_analyzer() {
    // Construct synthetic $SDS buffer with 2 entries
    std::vector<uint8_t> sds_buf(256, 0);

    // Entry 1 at offset 0: length = 80
    auto* h1 = reinterpret_cast<SdsEntryHeader*>(sds_buf.data());
    h1->hash = 0x11223344;
    h1->security_id = 0x100;
    h1->offset = 0;
    h1->length = 80;

    auto* sd1 = reinterpret_cast<RawSecurityDescriptorRelative*>(sds_buf.data() + 20);
    sd1->revision = 1;
    sd1->control = 0x8004; // SE_SELF_RELATIVE | SE_DACL_PRESENT
    sd1->owner_offset = 20; // offset in SD = 20 + 20 = 40 in sds_buf
    sd1->group_offset = 36; // offset in SD = 20 + 36 = 56 in sds_buf
    sd1->dacl_offset = 0;   // NULL DACL

    // Owner SID: S-1-5-32-544 (16 bytes)
    uint8_t* sid1 = sds_buf.data() + 40;
    sid1[0] = 1; // revision
    sid1[1] = 2; // sub_count
    sid1[7] = 5; // authority = 5
    *reinterpret_cast<uint32_t*>(sid1 + 8) = 32;
    *reinterpret_cast<uint32_t*>(sid1 + 12) = 544;

    // Group SID: S-1-5-32-544
    std::memcpy(sds_buf.data() + 56, sid1, 16);

    // Entry 2 at offset 80: length = 112
    auto* h2 = reinterpret_cast<SdsEntryHeader*>(sds_buf.data() + 80);
    h2->hash = 0x55667788;
    h2->security_id = 0x101;
    h2->offset = 80;
    h2->length = 112;

    auto* sd2 = reinterpret_cast<RawSecurityDescriptorRelative*>(sds_buf.data() + 100);
    sd2->revision = 1;
    sd2->control = 0x8004;
    sd2->owner_offset = 20; // 100 + 20 = 120
    sd2->group_offset = 20;
    sd2->dacl_offset = 36;  // 100 + 36 = 136

    // Owner SID for Entry 2
    std::memcpy(sds_buf.data() + 120, sid1, 16);

    // DACL for Entry 2 at 136
    auto* acl2 = reinterpret_cast<RawAclHeader*>(sds_buf.data() + 136);
    acl2->acl_revision = 2;
    acl2->ace_count = 1;
    acl2->acl_size = 32;

    // ACE at 136 + 8 = 144
    auto* ace2 = reinterpret_cast<RawAceHeader*>(sds_buf.data() + 144);
    ace2->ace_type = 0; // ACCESS_ALLOWED
    ace2->ace_size = 20;
    // Mask at 144 + 4 = 148
    *reinterpret_cast<uint32_t*>(sds_buf.data() + 148) = 0x10000000; // GENERIC_ALL
    // SID at 148 + 4 = 152: S-1-1-0 (Everyone)
    uint8_t* sid_everyone = sds_buf.data() + 152;
    sid_everyone[0] = 1; // revision
    sid_everyone[1] = 1; // sub_count
    sid_everyone[7] = 1; // authority = 1
    *reinterpret_cast<uint32_t*>(sid_everyone + 8) = 0; // sub_auth = 0

    // Volume records
    std::vector<RecordInfo> recs;
    RecordInfo r1; r1.record_index = 1000; r1.security_id = 0x100; recs.push_back(r1);
    RecordInfo r2; r2.record_index = 1001; r2.security_id = 0x100; recs.push_back(r2);
    RecordInfo r3; r3.record_index = 1002; r3.security_id = 0x200; recs.push_back(r3); // missing ID

    auto rep = SecureAnalyzer::parse_sds_buffer(sds_buf.data(), 80 + 112, recs, L'C');
    check(rep.valid, "rep.valid is true");
    check(rep.total_sds_entries == 2, "total_sds_entries == 2");
    check(rep.active_referenced_entries == 1, "active_referenced_entries == 1");
    check(rep.orphaned_entries == 1, "orphaned_entries == 1");
    check(rep.null_dacl_descriptors == 1, "null_dacl_descriptors == 1");
    check(rep.world_writable_descriptors == 1, "world_writable_descriptors == 1");
    check(rep.unreferenced_security_ids_count == 1, "unreferenced_security_ids_count == 1");

    check(rep.descriptors[0].security_id == 0x100, "descriptor 0 security_id == 0x100");
    check(rep.descriptors[0].owner_sid_str == L"S-1-5-32-544", "descriptor 0 owner SID matches S-1-5-32-544");
    check(rep.descriptors[0].referenced_file_count == 2, "descriptor 0 file count == 2");

    check(rep.descriptors[1].security_id == 0x101, "descriptor 1 security_id == 0x101");
    check(rep.descriptors[1].is_orphaned, "descriptor 1 is_orphaned is true");
    check(rep.descriptors[1].is_world_writable, "descriptor 1 is_world_writable is true");
}

static void test_volume_info_analyzer() {
    std::vector<uint8_t> rec(1024, 0);

    auto* hdr = reinterpret_cast<MftRecordHeader*>(rec.data());
    hdr->magic = kMftMagicFile;
    hdr->update_sequence_offset = 48;
    hdr->update_sequence_size = 3;
    hdr->flags = 1; // in-use
    hdr->first_attribute_offset = 56;
    hdr->record_number = 3;

    // USA array
    uint16_t* usa = reinterpret_cast<uint16_t*>(rec.data() + 48);
    usa[0] = 0xAA55;
    usa[1] = 0x1111;
    usa[2] = 0x2222;

    // Sector tags at ends of 512-byte sectors
    *reinterpret_cast<uint16_t*>(rec.data() + 510) = 0xAA55;
    *reinterpret_cast<uint16_t*>(rec.data() + 1022) = 0xAA55;

    uint32_t off = 56;

    // Attr 1: $STANDARD_INFORMATION (0x10)
    auto* a1 = reinterpret_cast<AttributeRecordHeader*>(rec.data() + off);
    a1->type_code = kAttrStandardInformation;
    a1->record_length = sizeof(AttributeRecordHeader) + sizeof(StandardInformation);
    a1->non_resident_flag = 0;
    a1->resident.value_length = sizeof(StandardInformation);
    a1->resident.value_offset = sizeof(AttributeRecordHeader);

    auto* si = reinterpret_cast<StandardInformation*>(rec.data() + off + a1->resident.value_offset);
    si->creation_time = 133000000000000000ULL;
    si->modification_time = 133500000000000000ULL;
    off += a1->record_length;

    // Attr 2: $VOLUME_NAME (0x60)
    const wchar_t* label = L"StorageVolume";
    const uint32_t label_bytes = static_cast<uint32_t>(wcslen(label) * sizeof(wchar_t));
    auto* a2 = reinterpret_cast<AttributeRecordHeader*>(rec.data() + off);
    a2->type_code = kAttrVolumeName;
    a2->record_length = sizeof(AttributeRecordHeader) + label_bytes;
    a2->non_resident_flag = 0;
    a2->resident.value_length = label_bytes;
    a2->resident.value_offset = sizeof(AttributeRecordHeader);
    std::memcpy(rec.data() + off + a2->resident.value_offset, label, label_bytes);
    off += a2->record_length;

    // Attr 3: $VOLUME_INFORMATION (0x70)
    auto* a3 = reinterpret_cast<AttributeRecordHeader*>(rec.data() + off);
    a3->type_code = kAttrVolumeInformation;
    a3->record_length = sizeof(AttributeRecordHeader) + sizeof(RawVolumeInformationAttr);
    a3->non_resident_flag = 0;
    a3->resident.value_length = sizeof(RawVolumeInformationAttr);
    a3->resident.value_offset = sizeof(AttributeRecordHeader);

    auto* vi = reinterpret_cast<RawVolumeInformationAttr*>(rec.data() + off + a3->resident.value_offset);
    vi->major_version = 3;
    vi->minor_version = 1;
    vi->flags = kVolFlagDirty | kVolFlagChkdskRan;
    off += a3->record_length;

    // Attr End
    auto* a_end = reinterpret_cast<AttributeRecordHeader*>(rec.data() + off);
    a_end->type_code = kAttrEnd;
    a_end->record_length = 8;

    auto rep = VolumeInfoAnalyzer::parse_record_buffer(rec.data(), 1024, 512, L'D');
    check(rep.valid, "rep.valid is true");
    check(rep.volume_label == L"StorageVolume", "volume_label == StorageVolume");
    check(rep.major_version == 3, "major_version == 3");
    check(rep.minor_version == 1, "minor_version == 1");
    check(rep.ntfs_version_str == L"3.1", "ntfs_version_str == 3.1");
    check(rep.is_dirty, "is_dirty is true");
    check(rep.chkdsk_ran, "chkdsk_ran is true");
    check(!rep.modified_by_chkdsk, "modified_by_chkdsk is false");
    check(rep.flag_descriptions.size() == 2, "2 flag descriptions present");
    check(rep.volume_creation_time == 133000000000000000ULL, "creation time matches");
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

    std::wcout << L"[RUN] test_system_files_inspector\n";
    test_system_files_inspector();

    std::wcout << L"[RUN] test_bitmap_analyzer\n";
    test_bitmap_analyzer();

    std::wcout << L"[RUN] test_attr_list_decoder\n";
    test_attr_list_decoder();

    std::wcout << L"[RUN] test_logfile_analyzer\n";
    test_logfile_analyzer();

    std::wcout << L"[RUN] test_boot_sector_parser\n";
    test_boot_sector_parser();

    std::wcout << L"[RUN] test_reparse_point_analyzer\n";
    test_reparse_point_analyzer();
    std::wcout << L"[RUN] test_mft_slack_carver\n";
    test_mft_slack_carver();

    std::wcout << L"[RUN] test_density_analyzer\n";
    test_density_analyzer();
    std::wcout << L"[RUN] test_object_id_analyzer\n";
    test_object_id_analyzer();

    std::wcout << L"[RUN] test_extended_attributes_analyzer\n";
    test_extended_attributes_analyzer();
    std::wcout << L"[RUN] test_hard_link_tracker\n";
    test_hard_link_tracker();

    std::wcout << L"[RUN] test_usn_journal_stats\n";
    test_usn_journal_stats();
    std::wcout << L"[RUN] test_bad_cluster_report\n";
    test_bad_cluster_report();

    std::wcout << L"[RUN] test_quota_analyzer\n";
    test_quota_analyzer();

    std::wcout << L"[RUN] test_attrdef_analyzer\n";
    test_attrdef_analyzer();

    std::wcout << L"[RUN] test_churn_analyzer\n";
    test_churn_analyzer();

    std::wcout << L"[RUN] test_secure_database_analyzer\n";
    test_secure_database_analyzer();

    std::wcout << L"[RUN] test_volume_info_analyzer\n";
    test_volume_info_analyzer();

    std::wcout << L"All 42 unit test suites passed successfully.\n";
    return 0;
}
