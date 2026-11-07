# mftscan

Fast NTFS Master File Table ($MFT) scanner and disk analyzer CLI for Windows.

Written in modern C++20 and pure Win32 API. Zero external dependencies, static CRT (`/MT`), self-contained single binary.

## Features

- **Direct MFT Extent Streaming**: Decodes `$DATA` mapping pairs from Record 0 to stream raw MFT records in 1 MB aligned blocks directly from physical extents.
- **Mapping Pairs Decoder**: Parses variable-length compressed NTFS data runs with sign-extended LCN deltas, VCN tracking, and sparse run handling.
- **Binary Fixup Engine**: Decodes NTFS Update Sequence Array tags, handling torn writes and recovering true sector content.
- **Path Tree Reconstruction**: Resolves full directory paths using parent file reference numbers (FRNs) with cached tree lookup and cycle prevention.
- **Attribute Decoding**: Parses `$STANDARD_INFORMATION` (timestamps, DOS attributes), `$FILE_NAME` (POSIX/Win32/DOS namespaces), and `$DATA` (resident and non-resident stream lengths).
- **Duplicate File Detection**: Groups files by exact size and computes partial and full FNV-1a hashes to identify duplicate files and calculate reclaimable space (`--dup`).
- **File Fragmentation Analysis**: Decodes non-resident `$DATA` extents to calculate fragment counts and identify the most fragmented files on the volume (`--defrag`).
- **Cluster Slack Space Analysis**: Measures wasted bytes in the final cluster of non-resident files and pinpoints the largest slack wasters (`--slack`).
- **Compression & Sparse Space Savings**: Computes physical disk space saved via native NTFS file compression and sparse allocation (`--compression`).
- **Anti-Forensics & Timestomping Detection**: Cross-examines `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps to detect tampering, such as SI modification before FN creation, inverted creation dates, and zeroed nanosecond fractional seconds (`--timestomp`).
- **File Signature & Masquerading Detection**: Inspects magic byte signatures (`MZ`, `%PDF`, `PK`, `7z`, `Rar!`, `PNG`, `JPEG`, etc.) to discover file extension spoofing and flag executables masquerading as documents or media (`--type-mismatch`).
- **NTFS Security & DACL Auditing**: Audits security descriptors, identifying NULL DACLs (unrestricted access), empty DACLs, world-writable files granted to Everyone or Authenticated Users, unmapped orphaned SIDs from removed accounts, and inheritance status (`--security`, `--world-writable`, `--orphaned-sids`).
- **Raw Cluster File Carving & Deleted Recovery**: Directly streams and extracts file contents from raw disk clusters or resident MFT payloads for any FRN (`--carve <FRN> --out <path>`), supporting Alternate Data Streams (`--stream <name>`), cluster slack extraction (`--include-slack`), and batch deleted file recovery (`--carve-deleted <dir>`).
- **Core NTFS System Metadata Files Explorer**: Audits all reserved system records (FRN 0 to 11: `$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, root directory, `$Bitmap`, `$Boot`, `$BadClus`, `$Secure`, `$UpCase`, `$Extend`), displaying version, dirty state, allocated sizes, and bad cluster counts (`--system`, `--meta`).
- **NTFS Boot Sector (BPB) & Backup Verification**: Decodes primary and backup BIOS Parameter Blocks at sector 0 and the volume end, validating OEM ID, sector matching, and volume geometry (`--boot`, `--bpb`).
- **Reparse Points & Directory Junctions**: Decodes `$REPARSE_POINT` (0xC0) structures for Directory Junctions, Symbolic Links, Compact OS compression, and cloud placeholders, verifying broken link targets (`--reparse`, `--symlinks`).
- **MFT Record Slack Space Forensics**: Extracts residual ASCII/UTF-16 strings and residual attribute headers left behind in unallocated MFT record slack bytes (`--mft-slack <FRN>`).
- **NTFS Storage Density & Packing Efficiency Audit**: Calculates resident file ratios, cluster slack saved via resident MFT inlining, payload efficiency percentages, and file size distribution histograms (`--density`, `--efficiency`).
- **NTFS Object Identifier & Provenance Tracker**: Decodes 128-bit GUIDs in `$OBJECT_ID` (0x40), detecting cross-volume file migrations by comparing current Object ID with original birth volume and birth object identifiers (`--objid`, `--object-ids`).
- **Extended Attributes & Subsystem Metadata**: Decodes packed `$EA` (0xE0) records, discovering POSIX mode, UID, and GID attributes used by Windows Subsystem for Linux (WSL) and custom extended attributes (`--ea`).
- **Hard Link Forensics & Space Savings Tracker**: Identifies multi-link files (`hard_link_count > 1`), groups sibling link aliases, and calculates volume-wide physical disk allocation saved (`--hardlinks`, `--links`).
- **USN Journal Health & Event Timeline Forensics**: Inspects journal buffer capacity, allocation delta, and rollover percentage (`--usn-stats`), and extracts chronological operations history for any FRN (`--usn-history <FRN>`).
- **Cluster Allocation & Free-Space Fragmentation Map**: Analyzes the volume cluster allocation bitmap, computing contiguous free extent counts, largest contiguous block, average extent length, free space fragmentation index, and an ASCII cluster allocation map (`--bitmap`, `--free-space`).
- **NTFS Transaction Journal ($LogFile) Analyzer**: Parses the restart page header (`RSTR`), validating USA fixups, LSN checkpoint tracking, active client lists, and clean vs dirty unmount states (`--logfile`, `--journal`).
- **Multi-Record Attribute List Decoder**: Decodes `$ATTRIBUTE_LIST` (0x20) mappings to track attributes spanning across multiple base and child MFT record segments for fragmented files and extensive streams.
- **Directory Index B-Tree Walker & Slack Carver**: Decodes `$INDEX_ROOT` and `$INDEX_ALLOCATION` nodes to list directory contents directly from internal B-Trees (`--ls <dir_FRN>`) and carves residual deleted index entries from index slack space.
- **Low-Level Record Inspector**: Decodes raw resident and non-resident attributes, tests fixup integrity, and outputs formatted 16-byte aligned hexadecimal and ASCII previews (`--inspect <FRN>`).
- **Real-Time Change Monitor**: Reads live filesystem operations via `FSCTL_READ_USN_JOURNAL` (`--watch`), showing creations, deletions, renames, and writes as they happen.
- **Interactive Fullscreen TUI**: Terminal UI (`-i`, `--tui`) featuring real-time filter-as-you-type search, instant column sorting (F1-F4), and a detailed record metadata modal on pressing `Enter`.
- **Alternate Data Stream (ADS) Discovery**: Detects secondary named `$DATA` streams attached to files.
- **Deleted Record Recovery**: Identifies unallocated MFT records (`--deleted`) whose metadata remains intact before sector overwrites.
- **Disk Usage Analysis**: Calculates top space-consuming files (`--top`), directory aggregation rollups (`--du`), and file type histograms (`--types`).
- **Flexible Filters**: Multi-criteria matching with wildcards (`*.iso`), regular expressions, file extensions, size thresholds, and date ranges.
- **Structured Export**: Outputs formatted text tables, JSON (`--json`), and CSV (`--csv`) for automation pipelines.
- **Unprivileged Fallback**: Automatically switches to standard Win32 directory traversal if launched without administrator elevation.

## System Requirements

- Windows 10, Windows 11, or Windows Server 2016+ (x64 or ARM64).
- Administrator elevation recommended for direct raw MFT parsing (requires `SeManageVolumePrivilege` and `SeBackupPrivilege`).

## Building from Source

Prerequisites: Visual Studio 2022 / 2026 with C++ Desktop Development and CMake 3.20+.

```powershell
# Clone the repository
git clone https://github.com/negg0s/mftscan.git
cd mftscan

# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Run test suite
ctest --test-dir build -C Release --output-on-failure
```

## Usage

```text
Usage: mftscan [volume] [options]

Volumes:
  C:, D:, E:               Target drive letter (default: D:)

Search Filters:
  -s, --search <pattern>   Wildcard filename search (e.g. "*.log", "app*")
  -r, --regex <pattern>    Regular expression match
  -e, --ext <list>         Comma-separated extensions (e.g. "exe,dll,pdb")
  --min-size <size>        Minimum file size (e.g. "100MB", "1.5GB")
  --max-size <size>        Maximum file size
  --files                  Filter files only
  --dirs                   Filter directories only
  --deleted                Scan for deleted / unallocated MFT file records
  --ads                    Search Alternate Data Streams (:stream)

Analysis & Views:
  -i, --tui                Interactive fullscreen Terminal UI with live filtering
  --inspect <FRN>          Low-level MFT record inspector and attribute hex dump
  --dup [min_size]         Scan for duplicate files by size and hash (default: 4KB)
  --defrag [min_frags]     Analyze file fragmentation on volume (default: 1)
  --slack                  Analyze cluster slack space and waste
  --compression            Report NTFS compression and sparse space savings
  --timestomp              Detect timestamp anomalies and timestomping signatures
  --type-mismatch          Detect file extension spoofing and masquerading executables
  --security               Audit NTFS security descriptors (DACLs, owners, SIDs)
  --world-writable         Filter files with world-writable permissions
  --orphaned-sids          Filter files with unmapped orphaned SIDs
  --carve <FRN>            Directly carve / extract file content from volume clusters
  --out <path>             Destination file or directory for carved content
  --stream <name>          Alternate Data Stream name to carve (default: unnamed $DATA)
  --carve-deleted <dir>    Carve all deleted files on volume to directory
  --include-slack          Include cluster slack bytes when carving
  --system, --meta         Inspect core NTFS system metadata files ($MFT, $Volume, $Bitmap)
  --bitmap, --free-space   Analyze volume cluster allocation and free-space fragmentation map
  --logfile, --journal     Inspect NTFS transaction journal ($LogFile) restart area and health
  --boot, --bpb            Inspect NTFS Boot Sector (BPB) and verify against backup boot sector
  --reparse, --symlinks    List directory junctions, symbolic links, and reparse points
  --mft-slack <FRN>        Inspect MFT record slack space forensics and residual strings
  --density, --efficiency  Audit storage density, resident MFT files, and packing efficiency
  --objid, --object-ids    Inspect NTFS Object Identifiers and track cross-volume file migration
  --ea                     Inspect Extended Attributes ($EA) and WSL Linux metadata
  --hardlinks, --links     Audit NTFS hard links and calculate disk space saved
  --usn-stats              Inspect USN Journal buffer capacity, delta, and rollover risk
  --usn-history <FRN>      Extract chronological historical operations for FRN from USN Journal
  --ls <dir_FRN>           List directory index contents and carved slack from $INDEX_ROOT
  --watch                  Live monitor real-time volume changes via USN Journal
  --top [N]                List top N largest files (default: 20)
  --du [N]                 Analyze top directory disk consumption (default: 20)
  --types [N]              Show file extension breakdown histogram (default: 20)

Output Formats:
  --json                   Export results in machine-readable JSON format
  --csv                    Export results in CSV format
  --limit <N>              Maximum rows to display in table view (default: 100)
  --fallback               Force standard Win32 directory traversal
  -h, --help               Display help message
  -v, --version            Display version information
```

### Examples

```powershell
# Interactive fullscreen Terminal UI (press Enter on any row to open record details)
mftscan D: -i

# Low-level MFT record inspector and attribute hex dump for record 0 ($MFT)
mftscan D: --inspect 0

# Find duplicate files consuming disk space
mftscan D: --dup 10MB

# Analyze file fragmentation and find most fragmented files
mftscan D: --defrag 5

# Analyze cluster slack space waste
mftscan D: --slack

# Report disk space savings from NTFS compression and sparse files
mftscan D: --compression

# Detect timestomping and timestamp manipulation
mftscan D: --timestomp

# Detect file extension spoofing and masquerading executables
mftscan D: --type-mismatch

# List root directory directly from raw $INDEX_ROOT B-Tree and carve slack
mftscan D: --ls 5

# Live watch filesystem change events on volume D:
mftscan D: --watch

# Search drive D: for large video or disk image files
mftscan D: --search "*.iso" --min-size 1GB

# Find top 25 largest files on secondary volume
mftscan D: --top 25

# Show directory disk usage rollup
mftscan D: --du

# Find deleted file remnants on drive D:
mftscan D: --deleted

# Search for Alternate Data Streams
mftscan D: --ads

# Audit NTFS security descriptors and permissions
mftscan D: --security

# Find world-writable files on volume
mftscan D: --world-writable

# Find files with orphaned unmapped SIDs from deleted user accounts
mftscan D: --orphaned-sids

# Carve raw file data from disk clusters for record 12345
mftscan D: --carve 12345 --out recovered.bin

# Batch carve all deleted PDF files into recovery directory
mftscan D: --carve-deleted .\recovered_pdfs --ext pdf

# Inspect core NTFS system metadata files ($MFT, $LogFile, $Volume, $Bitmap)
mftscan D: --system

# Analyze cluster allocation and display ASCII volume block map
mftscan D: --bitmap

# Inspect NTFS transaction journal ($LogFile) restart area and volume unmount state
mftscan D: --logfile

# Inspect primary and backup NTFS Boot Sectors and verify BPB geometry
mftscan D: --boot

# List reparse points, directory junctions, and symbolic links
mftscan D: --reparse

# Extract residual strings and unallocated attribute slack from MFT record
mftscan D: --mft-slack 12345

# Audit storage density, resident MFT file savings, and size distributions
mftscan D: --density

# Audit NTFS Object Identifiers and track cross-volume file migrations
mftscan D: --objid

# Inspect Extended Attributes and WSL Linux metadata
mftscan D: --ea

# Audit volume-wide hard links and calculate disk allocation savings
mftscan D: --hardlinks

# Inspect USN Journal buffer capacity, allocation delta, and rollover risk
mftscan D: --usn-stats

# Extract chronological modification history for record 12345 from USN Journal
mftscan D: --usn-history 12345

# Export all executables to JSON
mftscan D: --ext "exe,dll" --json > binaries.json
```

## License

MIT License. Copyright (c) 2026 Emir.
