#include "mftscan/common.hpp"
#include "mftscan/disk_usage.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/privileges.hpp"
#include "mftscan/scanner.hpp"

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
    std::wcout << L"  --ads                    Search Alternate Data Streams (:stream)\n\n";
    std::wcout << L"Analysis Modes:\n";
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
    std::wcout << L"  mftscan D: --search \"*.iso\" --min-size 1GB\n";
    std::wcout << L"  mftscan D: --top 25\n";
    std::wcout << L"  mftscan D: --du\n";
    std::wcout << L"  mftscan D: --deleted\n";
    std::wcout << L"  mftscan C: --ext \"log,tmp,dmp\" --json\n\n";
}

} // namespace mftscan

int wmain(int argc, wchar_t* argv[]) {
    using namespace mftscan;

    wchar_t drive_letter = L'D';
    QueryFilter filter;
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
            std::wcout << L"mftscan 0.1.0 (Windows x64/ARM64)\n";
            return 0;
        }
        if (arg.size() == 2 && arg[1] == L':' && iswalpha(arg[0])) {
            drive_letter = arg[0];
            continue;
        }
        if (arg == L"-s" || arg == L"--search") {
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

    if (!output_json && !output_csv) {
        Formatter::print_banner();
    }

    VolumeScanner scanner(drive_letter);
    Result<std::vector<RecordInfo>> scan_res;

    if (force_fallback || !PrivilegeManager::is_elevated_admin()) {
        if (!output_json && !output_csv) {
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

    const auto& records = scan_res.value();
    const auto& stats = scanner.stats();
    const auto& geom = scanner.geometry();

    if (output_json) {
        std::cout << Formatter::to_json(records, stats, geom);
        return 0;
    }

    if (output_csv) {
        std::cout << Formatter::to_csv(records);
        return 0;
    }

    Formatter::print_scan_summary(stats, geom);

    if (mode_top) {
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
