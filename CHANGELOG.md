# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
