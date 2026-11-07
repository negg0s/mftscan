# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-07

### Added
- Direct physical MFT extent block streaming (`RawMftStreamer`): decodes `$DATA` mapping pairs from Record 0 to stream the entire MFT in aligned 1 MB blocks directly from raw volume extents, bypassing record-by-record IOCTL overhead.
- NTFS mapping pairs decoder (`DataRunDecoder`): parses variable-length compressed data runs with sign-extended LCN deltas, VCN tracking, and sparse extent detection.
- Fast duplicate file fingerprinter (`DuplicateDetector`): groups files by exact byte size, computes 4 KB partial FNV-1a hashes to eliminate unique candidates without full reads, and computes full hashes to detect duplicate files and calculate reclaimable storage.
- Real-time USN Journal filesystem change monitor (`UsnMonitor`): reads change records via `FSCTL_READ_USN_JOURNAL` (`--watch`) displaying live file creations, deletions, renames, and data overwrites.
- Interactive fullscreen Terminal User Interface (`TuiViewer`): launched with `-i` or `--tui`, providing real-time search-as-you-type filtering, column sorting (Name, Size, Date, Path via F1-F4), and keyboard navigation using pure Win32 Virtual Terminal escape sequences.

## [0.1.0] - 2026-11-07

### Added
- Core direct NTFS Master File Table ($MFT) volume parser (`VolumeReader`) using `FSCTL_GET_NTFS_VOLUME_DATA` and `FSCTL_GET_NTFS_FILE_RECORD`.
- Low-level binary record decoder (`RecordParser`) handling Update Sequence Array fixups, resident/non-resident attributes, and namespace precedence.
- Directory hierarchy and path builder (`PathBuilder`) with parent FRN memoization and orphan file routing.
- Fast multi-criteria search engine (`QueryEngine`) supporting wildcards, regular expressions, extension sets, size limits, and date filters.
- Alternate Data Stream (ADS) detector identifying named `$DATA` attributes (`:Zone.Identifier`, metadata streams).
- Unallocated record carver discovering deleted file entries before MFT record re-allocation (`--deleted`).
- Disk usage analyzer (`DiskUsageAnalyzer`) calculating top largest files, directory rollups, and extension breakdowns.
- Multiple output formats: virtual terminal text tables, machine-readable JSON (`--json`), and CSV (`--csv`).
- Privilege manager (`PrivilegeManager`) requesting `SeManageVolumePrivilege` and `SeBackupPrivilege`.
- Unprivileged fallback engine scanning via standard Win32 directory traversal when running without administrator rights.
- GitHub Actions CI workflow supporting x64 and ARM64 Windows platforms with reproducible build checks.
