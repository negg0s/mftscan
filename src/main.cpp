#include "mftscan/common.hpp"
#include "mftscan/disk_usage.hpp"
#include "mftscan/duplicate_detector.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/fragmentation_analyzer.hpp"
#include "mftscan/index_parser.hpp"
#include "mftscan/inspector.hpp"
#include "mftscan/privileges.hpp"
#include "mftscan/record_parser.hpp"
#include "mftscan/scanner.hpp"
#include "mftscan/signature_verifier.hpp"
#include "mftscan/attr_list.hpp"
#include "mftscan/bitmap.hpp"
#include "mftscan/boot_sector.hpp"
#include "mftscan/reparse.hpp"
#include "mftscan/density.hpp"
#include "mftscan/mft_slack.hpp"
#include "mftscan/extended_attributes.hpp"
#include "mftscan/object_id.hpp"
#include "mftscan/hardlink.hpp"
#include "mftscan/usn_journal.hpp"
#include "mftscan/logfile.hpp"
#include "mftscan/carver.hpp"
#include "mftscan/system_files.hpp"
#include "mftscan/security_auditor.hpp"
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
    std::wcout << L"  --security               Audit NTFS security descriptors (DACLs, owners, SIDs)\n";
    std::wcout << L"  --world-writable         Filter files with world-writable permissions\n";
    std::wcout << L"  --orphaned-sids          Filter files with unmapped orphaned SIDs\n";
    std::wcout << L"  --carve <FRN>            Directly carve / extract file content from volume clusters\n";
    std::wcout << L"  --out <path>             Destination file or directory for carved content\n";
    std::wcout << L"  --stream <name>          Alternate Data Stream name to carve (default: unnamed $DATA)\n";
    std::wcout << L"  --carve-deleted <dir>    Carve all deleted files on volume to directory\n";
    std::wcout << L"  --include-slack          Include cluster slack bytes when carving\n";
    std::wcout << L"  --system, --meta         Inspect core NTFS system metadata files ($MFT, $Volume, $Bitmap)\n";
    std::wcout << L"  --bitmap, --free-space   Analyze volume cluster allocation and free-space fragmentation map\n";
    std::wcout << L"  --logfile, --journal     Inspect NTFS transaction journal ($LogFile) restart area and health\n";
    std::wcout << L"  --boot, --bpb            Inspect NTFS Boot Sector (BPB) and verify against backup boot sector\n";
    std::wcout << L"  --reparse, --symlinks    List directory junctions, symbolic links, and reparse points\n";
    std::wcout << L"  --mft-slack <FRN>        Inspect MFT record slack space forensics and residual strings\n";
    std::wcout << L"  --density, --efficiency  Audit storage density, resident MFT files, and packing efficiency\n";
    std::wcout << L"  --objid, --object-ids    Inspect NTFS Object Identifiers and track cross-volume file migration\n";
    std::wcout << L"  --ea                     Inspect Extended Attributes ($EA) and WSL Linux metadata\n";
    std::wcout << L"  --hardlinks, --links     Audit NTFS hard links and calculate disk space saved\n";
    std::wcout << L"  --usn-stats              Inspect USN Journal buffer capacity, delta, and rollover risk\n";
    std::wcout << L"  --usn-history <FRN>      Extract chronological historical operations for FRN from USN Journal\n";
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
    bool mode_security = false;
    bool filter_world_writable = false;
    bool filter_orphaned_sids = false;
    bool mode_carve = false;
    bool mode_system = false;
    bool mode_bitmap = false;
    bool mode_logfile = false;
    bool mode_boot = false;
    bool mode_reparse = false;
    bool mode_mft_slack = false;
    uint64_t mft_slack_frn = 0;
    bool mode_density = false;
    bool mode_objid = false;
    bool mode_ea = false;
    bool mode_hardlinks = false;
    bool mode_usn_stats = false;
    bool mode_usn_history = false;
    uint64_t usn_history_frn = 0;
    uint64_t carve_frn = 0;
    std::wstring carve_out_path;
    std::wstring carve_stream_name;
    bool carve_include_slack = false;
    bool mode_carve_deleted = false;
    std::wstring carve_deleted_dir;
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
        } else if (arg == L"--security") {
            mode_security = true;
        } else if (arg == L"--world-writable") {
            mode_security = true;
            filter_world_writable = true;
        } else if (arg == L"--orphaned-sids") {
            mode_security = true;
            filter_orphaned_sids = true;
        } else if (arg == L"--carve") {
            mode_carve = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                carve_frn = static_cast<uint64_t>(_wtoi64(argv[++i]));
            }
        } else if (arg == L"--out") {
            if (i + 1 < argc) carve_out_path = argv[++i];
        } else if (arg == L"--stream") {
            if (i + 1 < argc) carve_stream_name = argv[++i];
        } else if (arg == L"--system" || arg == L"--meta") {
            mode_system = true;
        } else if (arg == L"--bitmap" || arg == L"--free-space") {
            mode_bitmap = true;
        } else if (arg == L"--logfile" || arg == L"--journal") {
            mode_logfile = true;
        } else if (arg == L"--boot" || arg == L"--bpb") {
            mode_boot = true;
        } else if (arg == L"--reparse" || arg == L"--symlinks" || arg == L"--junctions") {
            mode_reparse = true;
        } else if (arg == L"--mft-slack") {
            mode_mft_slack = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                mft_slack_frn = _wcstoui64(argv[++i], nullptr, 10);
            }
        } else if (arg == L"--density" || arg == L"--efficiency") {
            mode_density = true;
        } else if (arg == L"--objid" || arg == L"--object-ids") {
            mode_objid = true;
        } else if (arg == L"--ea") {
            mode_ea = true;
        } else if (arg == L"--hardlinks" || arg == L"--links") {
            mode_hardlinks = true;
        } else if (arg == L"--usn-stats") {
            mode_usn_stats = true;
        } else if (arg == L"--usn-history") {
            mode_usn_history = true;
            if (i + 1 < argc && iswdigit(argv[i + 1][0])) {
                usn_history_frn = _wcstoui64(argv[++i], nullptr, 10);
            }
        } else if (arg == L"--carve-deleted") {
            mode_carve_deleted = true;
            if (i + 1 < argc) carve_deleted_dir = argv[++i];
        } else if (arg == L"--include-slack") {
            carve_include_slack = true;
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

    // Carve mode: Direct file extraction from raw volume clusters
    if (mode_carve) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        if (carve_out_path.empty()) {
            carve_out_path = L"carved_frn_" + std::to_wstring(carve_frn) + L".bin";
        }

        std::wcout << L"Extracting FRN " << carve_frn << L" from volume " << drive_letter << L": to " << carve_out_path << L"...\n";
        auto carve_res = FileCarver::carve_record(vr, carve_frn, carve_out_path, carve_stream_name, carve_include_slack);
        if (!carve_res) {
            std::wcerr << L"Carving failed: " << carve_res.error().to_string() << L"\n";
            return 1;
        }

        const auto& cr = carve_res.value();
        std::wcout << L"Successfully extracted file!\n";
        std::wcout << L"  FRN:          " << cr.frn << L"\n";
        std::wcout << L"  Destination:  " << cr.output_path << L"\n";
        std::wcout << L"  Size:         " << Formatter::format_bytes(cr.bytes_written) << L" (" << cr.bytes_written << L" bytes)\n";
        std::wcout << L"  Storage:      " << (cr.is_resident ? L"Resident in MFT" : (L"Non-resident (" + std::to_wstring(cr.clusters_read) + L" clusters)")) << L"\n";
        std::wcout << L"  State:        " << (cr.is_deleted_record ? L"Deleted / Unallocated Record" : L"Active Record") << L"\n\n";
        return 0;
    }

    // System metadata mode: Audit all reserved NTFS metadata files
    if (mode_system) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto sys_res = SystemFilesInspector::inspect(vr);
        if (!sys_res) {
            std::wcerr << L"Failed to inspect system files: " << sys_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_system_audit_report(sys_res.value());
        return 0;
    }

    // Bitmap mode: Analyze volume cluster allocation and free space fragmentation
    if (mode_bitmap) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto bmp_res = BitmapAnalyzer::analyze(vr, 64);
        if (!bmp_res) {
            std::wcerr << L"Failed to analyze volume bitmap: " << bmp_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_bitmap_report(bmp_res.value());
        return 0;
    }

    // LogFile mode: Audit transaction journal restart area
    if (mode_logfile) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto log_res = LogFileAnalyzer::analyze(vr);
        if (!log_res) {
            std::wcerr << L"Failed to analyze $LogFile: " << log_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_logfile_report(log_res.value());
        return 0;
    }

    // Boot Sector mode: Inspect BPB and compare against backup sector
    if (mode_boot) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto boot_res = BootSectorParser::inspect_volume(vr);
        if (!boot_res) {
            std::wcerr << L"Failed to inspect boot sector: " << boot_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_boot_sector_report(boot_res.value());
        return 0;
    }

    // USN Stats mode: Direct journal metadata analysis
    if (mode_usn_stats) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto stats_res = UsnJournalAnalyzer::query_stats(vr);
        if (!stats_res) {
            std::wcerr << L"Failed to query USN journal stats: " << stats_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_usn_stats(stats_res.value());
        return 0;
    }

    // USN History mode: Direct file event history extraction
    if (mode_usn_history) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        std::wcout << L"Scanning USN journal for historical operations on FRN " << usn_history_frn << L"...\n";
        auto hist_res = UsnJournalAnalyzer::extract_history(vr, usn_history_frn);
        if (!hist_res) {
            std::wcerr << L"Failed to extract USN history: " << hist_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_usn_history(hist_res.value());
        return 0;
    }

    // MFT Slack mode: Direct record slack space inspection and carving
    if (mode_mft_slack) {
        Formatter::print_banner();
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }

        auto slack_res = MftSlackCarver::inspect_record(vr, mft_slack_frn);
        if (!slack_res) {
            std::wcerr << L"Failed to analyze record slack for FRN " << mft_slack_frn << L": " << slack_res.error().to_string() << L"\n";
            return 1;
        }

        Formatter::print_mft_slack_report(slack_res.value());
        return 0;
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

    if (mode_reparse) {
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        std::vector<ReparseInfo> reparse_list;

        const uint32_t rec_size = vr.is_open() ? vr.geometry().bytes_per_record : 1024;
        std::vector<uint8_t> rec_buf(rec_size);

        for (const auto& r : records) {
            if ((r.attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                continue;
            }

            if (vr.is_open()) {
                auto read_res = vr.read_file_record(r.record_index, rec_buf.data(), rec_size);
                if (read_res) {
                    RecordParser::apply_fixup(rec_buf.data(), rec_size, vr.geometry().bytes_per_sector);
                    const auto* mft_hdr = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
                    uint32_t offset = mft_hdr->first_attribute_offset;
                    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
                        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_buf.data() + offset);
                        if (attr->type_code == kAttrEnd || attr->record_length == 0) break;
                        if (offset + attr->record_length > rec_size) break;

                        if (attr->type_code == kAttrReparsePoint && attr->non_resident_flag == 0) {
                            const uint16_t v_off = attr->resident.value_offset;
                            const uint32_t v_len = attr->resident.value_length;
                            if (v_off + v_len <= attr->record_length) {
                                auto rep_res = ReparsePointAnalyzer::parse_attribute(
                                    rec_buf.data() + offset + v_off,
                                    v_len,
                                    r.record_index,
                                    r.full_path.empty() ? r.name : r.full_path
                                );
                                if (rep_res) {
                                    reparse_list.push_back(rep_res.value());
                                }
                            }
                        }
                        offset += attr->record_length;
                    }
                }
            } else {
                ReparseInfo basic_info{};
                basic_info.frn = r.record_index;
                basic_info.source_path = r.full_path.empty() ? r.name : r.full_path;
                basic_info.tag_name = L"Reparse Point";
                reparse_list.push_back(std::move(basic_info));
            }
        }
        Formatter::print_reparse_report(reparse_list);
    } else if (mode_carve_deleted) {
        VolumeReader vr(drive_letter);
        auto open_res = vr.open();
        if (!open_res) {
            std::wcerr << L"Failed to open volume " << drive_letter << L": " << open_res.error().to_string() << L"\n";
            return 1;
        }
        if (carve_deleted_dir.empty()) {
            carve_deleted_dir = L".\\carved_deleted";
        }
        std::wcout << L"Carving deleted files to " << carve_deleted_dir << L"...\n";
        std::wstring ext_filter = filter.extensions.empty() ? L"" : filter.extensions[0];
        auto carve_stats = FileCarver::carve_deleted_files(vr, records, carve_deleted_dir, ext_filter, carve_include_slack);
        Formatter::print_carve_summary(carve_stats, carve_deleted_dir);
    } else if (mode_security) {
        std::wcout << L"Auditing security descriptors for " << records.size() << L" records...\n\n";
        std::vector<SecurityAuditResult> sec_results;
        for (const auto& r : records) {
            if (r.is_deleted || r.full_path.empty()) {
                continue;
            }
            auto audit_res = SecurityAuditor::audit_path(r.full_path, r.record_index);
            if (audit_res) {
                const auto& item = audit_res.value();
                if (filter_world_writable && !item.is_world_writable) continue;
                if (filter_orphaned_sids && !item.has_orphaned_sids) continue;
                sec_results.push_back(item);
            }
        }
        Formatter::print_security_report(sec_results);
    } else if (mode_dup) {
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
    } else if (mode_hardlinks) {
        auto hl_report = HardLinkTracker::analyze(records);
        Formatter::print_hardlink_report(hl_report);
    } else if (mode_density) {
        auto density_rep = DensityAnalyzer::analyze(records, geom.bytes_per_cluster);
        Formatter::print_density_report(density_rep);
    } else if (mode_objid) {
        VolumeReader vr(drive_letter);
        vr.open();
        std::vector<ObjectIdInfo> objid_list;
        const uint32_t rec_size = vr.is_open() ? vr.geometry().bytes_per_record : 1024;
        std::vector<uint8_t> rec_buf(rec_size);

        for (const auto& r : records) {
            if (vr.is_open()) {
                auto read_res = vr.read_file_record(r.record_index, rec_buf.data(), rec_size);
                if (read_res) {
                    RecordParser::apply_fixup(rec_buf.data(), rec_size, vr.geometry().bytes_per_sector);
                    const auto* mft_hdr = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
                    uint32_t offset = mft_hdr->first_attribute_offset;
                    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
                        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_buf.data() + offset);
                        if (attr->type_code == kAttrEnd || attr->record_length == 0) break;
                        if (offset + attr->record_length > rec_size) break;

                        if (attr->type_code == kAttrObjectId && attr->non_resident_flag == 0) {
                            const uint16_t v_off = attr->resident.value_offset;
                            const uint32_t v_len = attr->resident.value_length;
                            if (v_off + v_len <= attr->record_length) {
                                auto o_res = ObjectIdAnalyzer::parse_attribute(
                                    rec_buf.data() + offset + v_off,
                                    v_len,
                                    r.record_index,
                                    r.full_path.empty() ? r.name : r.full_path
                                );
                                if (o_res) {
                                    objid_list.push_back(o_res.value());
                                }
                            }
                        }
                        offset += attr->record_length;
                    }
                }
            }
        }
        Formatter::print_object_id_report(objid_list);
    } else if (mode_ea) {
        VolumeReader vr(drive_letter);
        vr.open();
        std::vector<FileEaReport> ea_list;
        const uint32_t rec_size = vr.is_open() ? vr.geometry().bytes_per_record : 1024;
        std::vector<uint8_t> rec_buf(rec_size);

        for (const auto& r : records) {
            if (vr.is_open()) {
                auto read_res = vr.read_file_record(r.record_index, rec_buf.data(), rec_size);
                if (read_res) {
                    RecordParser::apply_fixup(rec_buf.data(), rec_size, vr.geometry().bytes_per_sector);
                    const auto* mft_hdr = reinterpret_cast<const MftRecordHeader*>(rec_buf.data());
                    uint32_t offset = mft_hdr->first_attribute_offset;
                    while (offset + sizeof(AttributeRecordHeader) <= rec_size) {
                        const auto* attr = reinterpret_cast<const AttributeRecordHeader*>(rec_buf.data() + offset);
                        if (attr->type_code == kAttrEnd || attr->record_length == 0) break;
                        if (offset + attr->record_length > rec_size) break;

                        if (attr->type_code == 0xE0 && attr->non_resident_flag == 0) { // $EA
                            const uint16_t v_off = attr->resident.value_offset;
                            const uint32_t v_len = attr->resident.value_length;
                            if (v_off + v_len <= attr->record_length) {
                                auto ea_res = ExtendedAttributesAnalyzer::parse_ea_stream(
                                    rec_buf.data() + offset + v_off,
                                    v_len,
                                    r.record_index,
                                    r.full_path.empty() ? r.name : r.full_path
                                );
                                if (ea_res) {
                                    ea_list.push_back(ea_res.value());
                                }
                            }
                        }
                        offset += attr->record_length;
                    }
                }
            }
        }
        Formatter::print_ea_report(ea_list);
    } else {
        Formatter::print_results_table(records, display_limit);
    }

    return 0;
}
