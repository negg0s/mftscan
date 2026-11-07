# mftscan

Fast NTFS Master File Table ($MFT) scanner and disk analyzer CLI for Windows.

Written in modern C++20 and pure Win32 API. Zero external dependencies, static CRT (`/MT`), self-contained single binary.

## Features

- **Direct MFT Parsing**: Directly queries the NTFS Master File Table using `FSCTL_GET_NTFS_VOLUME_DATA` and `FSCTL_GET_NTFS_FILE_RECORD`.
- **Binary Fixup Engine**: Decodes NTFS Update Sequence Array tags, handling torn writes and recovering true sector content.
- **Path Tree Reconstruction**: Resolves full directory paths using parent file reference numbers (FRNs) with cached tree lookup and cycle prevention.
- **Attribute Decoding**: Parses `$STANDARD_INFORMATION` (timestamps, DOS attributes), `$FILE_NAME` (POSIX/Win32/DOS namespaces), and `$DATA` (resident and non-resident stream lengths).
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

Analysis Modes:
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
