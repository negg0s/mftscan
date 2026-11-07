#include "mftscan/common.hpp"
#include "mftscan/disk_usage.hpp"
#include "mftscan/duplicate_detector.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/fragmentation_analyzer.hpp"
#include "mftscan/index_parser.hpp"
#include "mftscan/inspector.hpp"
#include "mftscan/privileges.hpp"
#include "mftscan/scanner.hpp"
#include "mftscan/signature_verifier.hpp"
#include "mftscan/sparse_slack_analyzer.hpp"
#include "mftscan/timestomp.hpp"
#include "mftscan/tui.hpp"
#include "mftscan/usn_monitor.hpp"

#include <cwctype>
#include <iostream>
#include <string>
#include <vector>

namespace mftscan {

static uint64_t parse_size_string(std::wstring_view s) {
    if (s.empty()) return 0;
    wchar_t* end_ptr = nullptr;
    double val = wcstod(s.data(), &end_ptr);
    if (val < 0.0) val = 0.0;

    std::wstring unit;
    if (end_ptr) {
        while (*end_ptr != L'\0' && iswspace(*end_ptr)) end_ptr++;
        unit = end_ptr;
        for (auto& c : unit) c = static_cast<wchar_t>(towupper(c));
    }

    if (unit == L"KB" || unit == L"K") val *= 1024.0;
    else if (unit == L"MB" || unit == L"M") val *= (1024.0 * 1024.0);
    else if (unit == L"GB" || unit == L"G") val *= (1024.0 * 1024.0 * 1024.0);
    else if (unit == L"TB" || unit == L"T") val *= (1024.0 * 1024.0 * 1024.0 * 1024.0);

    return static_cast<uint64_t>(val);
}

static void print_help() {
    Formatter::print_banner();
    std::wcout << L"Usage: mftscan [volume] [options]\n\n";
    std::wcout << L"Volumes:\n";
    std::wcout << L"  C:, D:, E:               Target drive letter (default: D:)\n\n";
    std::wcout << L"Search Filters:\n";
    std::wcout << L"  -s, --search <pattern>   Wildcard filename search (e.g. \"*.log\", \"app*\")\n";
    std::wcout << L"  -r, --regex <pattern>    Regular expression match\n";
    std::wcout << L"  -e, --ext <list>         Comma-separated extensions (e.g. \"exe,dll,pdb\")\n";
    std::wcout << L"  --min-size <size>        Minimum file size (e.g. \"100MB\", \"1.5GB\")\n";
    std::wcout << L"  --max-size <size>        Maximum file size\n";
    std::wcout << L"  --files                  Filter files only\n";
    std::wcout << L"  --dirs                   Filter directories only\n";
    std::wcout << L"  --deleted                Scan for deleted / unallocated MFT file records\n";
    std::wcout << L"  --ads                    Search Alternate Data Streams (:stream)\n";
    std::wcout << L"  --sparse                 Filter sparse files only\n";
    std::wcout << L"  --compressed             Filter NTFS-compressed files only\n\n";
    std::wcout << L"Analysis & Views:\n";
    std::wcout << L"  -i, --tui                Interactive fullscreen Terminal UI with live filtering\n";
    std::wcout << L"  --inspect <FRN>          Low-level MFT record inspector and attribute hex dump\n";
    std::wcout << L"  --ls <dir_FRN>           List directory index contents and carved slack from $INDEX_ROOT\n";
    std::wcout << L"  --dup [min_size]         Scan for duplicate files by size and hash (default: 4KB)\n";
    std::wcout << L"  --defrag [min_frags]     Analyze file fragmentation on volume (default: 1)\n";
    std::wcout << L"  --slack                  Analyze cluster slack space and waste\n";
    std::wcout << L"  --compression            Report NTFS compression and sparse space savings\n";
    std::wcout << L"  --timestomp              Detect timestamp anomalies and timestomping signatures\n";
    std::wcout << L"  --type-mismatch          Detect file extension spoofing and masquerading executables\n";
    std::wcout << L"  --watch                  Live monitor real-time volume changes via USN Journal\n";
    std::wcout << L"  --top [N]                List top N largest files (default: 20)\n";
    std::wcout << L"  --du [N]                 Analyze top directory disk consumption (default: 20)\n";
    std::wcout << L"  --types [N]              Show file extension breakdown histogram (default: 20)\n\n";
    std::wcout << L"Output Formats:\n";
    std::wcout << L"  --json                   Export results in machine-readable JSON format\n";
    std::wcout << L"  --csv                    Export results in CSV format\n";
    std::wcout << L"  --limit <N>              Maximum rows to display in table view (default: 100)\n";
    std::wcout << L"  --fallback               Force standard Win32 directory traversal\n";
    std::wcout << L"  -h, --help               Display this help message\n";
    std::wcout << L"  -v, --version            Display version information\n\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  mftscan D: -i\n";
    std::wcout << L"  mftscan D: --dup 10MB\n";
    std::wcout << L"  mftscan D: --watch\n";
    std::wcout << L"  mftscan D: --search \"*.iso\" --min-size 1GB\n";
    std::wcout << L"  mftscan D: --top 25\n";
    std::wcout << L"  mftscan D: --du\n\n";
}

} // namespace mftscan

int wmain(int argc, wchar_t* argv[]) {
    using namespace mftscan;

    wchar_t drive_letter = L'D';
    QueryFilter filter;
    bool mode_tui = false;
    bool mode_inspect = false;
    uint64_t inspect_frn = 0;
    bool mode_ls = false;
    uint64_t ls_dir_frn = 5;
    bool mode_dup = false;
    uint64_t dup_min_size = 4096;
    bool mode_defrag = false;
    uint32_t defrag_min_frags = 1;
    bool mode_slack = false;
    bool mode_compression = false;
    bool mode_timestomp = false;
    bool mode_signature = false;
    bool mode_watch = false;
    bool mode_top = false;
    size_t top_limit = 20;
    bool mode_du = false;
    size_t du_limit = 20;
    bool mode_types = false;
    size_t types_limit = 20;
    bool output_json = false;
    bool output_csv = false;
    bool force_fallback = false;
    size_t display_limit = 100;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

        if (arg == L"-h" || arg == L"--help" || arg == L"/?") {
            print_help();
            return 0;
        }
        if (arg == L"-v" || arg == L"--version") {
            std::wcout << L"mftscan 0.3.0 (Windows x64/ARM64)\n";
            return 0;
        }
        if (arg.size() == 2 && arg[1] == L':' && iswalpha(arg[0])) {
            drive_letter = arg[0];
            continue;
        }
        if (arg == L"-i" || arg == L"--tui") {
            mode_tui = true;
        } else if (arg == L"--inspect" || arg == L"--dump") {
            mode_inspect = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                inspect_frn = static_cast<uint64_t>(_wtoi64(argv[++i]));
            }
        } else if (arg == L"--ls" || arg == L"--dir-index") {
            mode_ls = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                ls_dir_frn = static_cast<uint64_t>(_wtoi64(argv[++i]));
            }
        } else if (arg == L"--type-mismatch" || arg == L"--audit-ext") {
            mode_signature = true;
        } else if (arg == L"--dup") {
            mode_dup = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                dup_min_size = parse_size_string(argv[++i]);
            }
        } else if (arg == L"--defrag" || arg == L"--fragmented") {
            mode_defrag = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                defrag_min_frags = static_cast<uint32_t>(_wtoi(argv[++i]));
            }
        } else if (arg == L"--slack") {
            mode_slack = true;
        } else if (arg == L"--compression") {
            mode_compression = true;
        } else if (arg == L"--timestomp" || arg == L"--forensics") {
            mode_timestomp = true;
        } else if (arg == L"--sparse") {
            filter.only_sparse = true;
        } else if (arg == L"--compressed") {
            filter.only_compressed = true;
        } else if (arg == L"--watch") {
            mode_watch = true;
        } else if (arg == L"-s" || arg == L"--search") {
            if (i + 1 < argc) filter.name_pattern = argv[++i];
        } else if (arg == L"-r" || arg == L"--regex") {
            if (i + 1 < argc) filter.regex_str = argv[++i];
        } else if (arg == L"-e" || arg == L"--ext") {
            if (i + 1 < argc) {
                std::wstring list = argv[++i];
                size_t pos = 0;
                while (pos < list.size()) {
                    size_t comma = list.find(L',', pos);
                    if (comma == std::wstring::npos) comma = list.size();
                    if (comma > pos) {
                        filter.extensions.push_back(list.substr(pos, comma - pos));
                    }
                    pos = comma + 1;
                }
            }
        } else if (arg == L"--min-size") {
            if (i + 1 < argc) filter.min_size = parse_size_string(argv[++i]);
        } else if (arg == L"--max-size") {
            if (i + 1 < argc) filter.max_size = parse_size_string(argv[++i]);
        } else if (arg == L"--files") {
            filter.only_files = true;
        } else if (arg == L"--dirs") {
            filter.only_directories = true;
        } else if (arg == L"--deleted") {
            filter.only_deleted = true;
        } else if (arg == L"--ads") {
            filter.only_ads = true;
        } else if (arg == L"--top") {
            mode_top = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                top_limit = static_cast<size_t>(_wtoi(argv[++i]));
            }
        } else if (arg == L"--du") {
            mode_du = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                du_limit = static_cast<size_t>(_wtoi(argv[++i]));
            }
        } else if (arg == L"--types") {
            mode_types = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                types_limit = static_cast<size_t>(_wtoi(argv[++i]));
            }
        } else if (arg == L"--json") {
            output_json = true;
        } else if (arg == L"--csv") {
            output_csv = true;
        } else if (arg == L"--limit") {
            if (i + 1 < argc) display_limit = static_cast<size_t>(_wtoi(argv[++i]));
        } else if (arg == L"--fallback") {
            force_fallback = true;
        }
    }

    // Inspect mode: Direct record attribute inspection
    if (mode_inspect) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto insp_res = RecordInspector::inspect(vr, inspect_frn);
        if (!insp_res) {
            std::wcerr << L"Failed to inspect record " << inspect_frn << L": " << insp_res.error().to_string() << L"\n";
            return 1;
        }

        RecordInspector::print_report(insp_res.value());
        return 0;
    }

    // Directory index mode: Direct B-Tree $INDEX_ROOT listing and slack carving
    if (mode_ls) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto idx_res = IndexParser::parse_directory_index(vr, ls_dir_frn);
        if (!idx_res) {
            std::wcerr << L"Failed to parse directory index for FRN " << ls_dir_frn << L": " << idx_res.error().to_string() << L"\n";
            return 1;
        }

        IndexParser::print_index_report(idx_res.value());
        return 0;
    }

    // Watch mode: Monitor live USN journal events
    if (mode_watch) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        UsnMonitor monitor(vr);
        auto q_res = monitor.query_journal();
        if (!q_res) {
            std::wcerr << L"USN Journal query failed: " << q_res.error().to_string() << L"\n";
            return 1;
        }

        uint64_t curr_usn = q_res.value().NextUsn;
        std::wcout << L"Watching live changes on volume " << drive_letter << L": (Starting USN: " << curr_usn << L")...\n";
        std::wcout << L"Press Ctrl+C to stop.\n\n";

        while (true) {
            auto read_res = monitor.read_changes(curr_usn, 100, [&](const UsnChangeRecord& c) {
                Formatter::print_usn_change(c);
                return true;
            });

            if (read_res) {
                curr_usn = read_res.value();
            }
            Sleep(250);
        }
    }

    if (!output_json && !output_csv && !mode_tui) {
        Formatter::print_banner();
    }

    VolumeScanner scanner(drive_letter);
    Result<std::vector<RecordInfo>> scan_res;

    if (force_fallback || !PrivilegeManager::is_elevated_admin()) {
        if (!output_json && !output_csv && !mode_tui) {
            if (!PrivilegeManager::is_elevated_admin() && !force_fallback) {
                std::wcout << L"[NOTE] Running without elevated administrator privileges.\n";
                std::wcout << L"       Switching to standard Win32 directory traversal engine.\n";
                std::wcout << L"       Run terminal as Administrator for direct raw MFT acceleration.\n\n";
            }
        }
        scan_res = scanner.scan_fallback_win32(std::wstring(1, drive_letter) + L":\\", filter);
    } else {
        scan_res = scanner.scan(filter);
    }

    if (!scan_res) {
        std::wcerr << L"Scan failed: " << scan_res.error().to_string() << L"\n";
        return 1;
    }

    auto records = std::move(scan_res.value());
    const auto& stats = scanner.stats();
    const auto& geom = scanner.geometry();

    if (mode_tui) {
        TuiViewer viewer(std::move(records), geom);
        viewer.run();
        return 0;
    }

    if (output_json) {
        std::cout << Formatter::to_json(records, stats, geom);
        return 0;
    }

    if (output_csv) {
        std::cout << Formatter::to_csv(records);
        return 0;
    }

    Formatter::print_scan_summary(stats, geom);

    if (mode_dup) {
        auto dup_report = DuplicateDetector::find_duplicates(records, dup_min_size);
        Formatter::print_duplicates_table(dup_report);
    } else if (mode_defrag) {
        auto frag_report = FragmentationAnalyzer::analyze(records, defrag_min_frags);
        Formatter::print_fragmentation_table(frag_report);
    } else if (mode_slack) {
        auto slack_report = SparseSlackAnalyzer::analyze_slack(records);
        Formatter::print_slack_table(slack_report);
    } else if (mode_compression) {
        auto comp_report = SparseSlackAnalyzer::analyze_compression(records);
        Formatter::print_compression_table(comp_report);
    } else if (mode_timestomp) {
        auto ts_report = TimestompDetector::analyze(records);
        Formatter::print_timestomp_table(ts_report);
    } else if (mode_signature) {
        auto sig_report = SignatureVerifier::analyze(records);
        Formatter::print_signature_report(sig_report);
    } else if (mode_top) {
        auto top_files = DiskUsageAnalyzer::top_largest_files(records, top_limit);
        Formatter::print_top_files_table(top_files);
    } else if (mode_du) {
        auto top_dirs = DiskUsageAnalyzer::compute_top_directories(records, du_limit);
        Formatter::print_top_directories_table(top_dirs);
    } else if (mode_types) {
        auto type_stats = DiskUsageAnalyzer::compute_extension_histogram(records, types_limit);
        Formatter::print_extension_histogram_table(type_stats);
    } else {
        Formatter::print_results_table(records, display_limit);
    }

    return 0;
}
