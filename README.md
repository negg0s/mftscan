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
- **Real-Time Change Monitor**: Reads live filesystem operations via `FSCTL_READ_USN_JOURNAL` (`--watch`), showing creations, deletions, renames, and writes as they happen.
- **Interactive Fullscreen TUI**: Terminal UI (`-i`, `--tui`) featuring real-time filter-as-you-type search and instant column sorting (F1-F4) using pure Win32 Virtual Terminal escape sequences.
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
  --dup [min_size]         Scan for duplicate files by size and hash (default: 4KB)
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
# Interactive fullscreen Terminal UI
mftscan D: -i

# Find duplicate files consuming disk space
mftscan D: --dup 10MB

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

# Export all executables to JSON
mftscan D: --ext "exe,dll" --json > binaries.json
```

## License

MIT License. Copyright (c) 2026 Emir.
