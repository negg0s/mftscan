#include "mftscan/duplicate_detector.hpp"

#include <algorithm>
#include <map>
#include <unordered_map>
#include <vector>

namespace mftscan {

static constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
static constexpr uint64_t kFnvPrime = 1099511628211ULL;

static uint64_t hash_bytes(const uint8_t* data, size_t len, uint64_t initial = kFnvOffsetBasis) noexcept {
    uint64_t hash = initial;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= kFnvPrime;
    }
    return hash;
}

uint64_t DuplicateDetector::compute_file_partial_hash(const std::wstring& path) noexcept {
    HANDLE h = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    uint8_t buffer[4096];
    DWORD bytes_read = 0;
    const BOOL ok = ReadFile(h, buffer, sizeof(buffer), &bytes_read, nullptr);
    CloseHandle(h);

    if (!ok || bytes_read == 0) {
        return 0;
    }

    return hash_bytes(buffer, bytes_read);
}

uint64_t DuplicateDetector::compute_file_full_hash(const std::wstring& path) noexcept {
    HANDLE h = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    uint8_t buffer[65536];
    DWORD bytes_read = 0;
    uint64_t hash = kFnvOffsetBasis;

    while (ReadFile(h, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
        hash = hash_bytes(buffer, bytes_read, hash);
    }

    CloseHandle(h);
    return hash;
}

DuplicateReport DuplicateDetector::find_duplicates(
    const std::vector<RecordInfo>& records,
    uint64_t min_file_size,
    size_t max_groups
) {
    DuplicateReport report;

    // Step 1: Bucket by exact file size in bytes
    std::unordered_map<uint64_t, std::vector<const RecordInfo*>> size_buckets;
    for (const auto& r : records) {
        if (!r.is_directory && !r.is_deleted && r.size_bytes >= min_file_size && !r.full_path.empty()) {
            size_buckets[r.size_bytes].push_back(&r);
        }
    }

    // Step 2: For colliding sizes, compute partial hash
    struct HashKey {
        uint64_t size{0};
        uint64_t partial_hash{0};

        bool operator==(const HashKey& other) const noexcept {
            return size == other.size && partial_hash == other.partial_hash;
        }
    };

    struct HashKeyHasher {
        size_t operator()(const HashKey& k) const noexcept {
            return std::hash<uint64_t>{}(k.size) ^ (std::hash<uint64_t>{}(k.partial_hash) << 1);
        }
    };

    std::unordered_map<HashKey, std::vector<std::wstring>, HashKeyHasher> partial_buckets;

    for (const auto& [size, files] : size_buckets) {
        if (files.size() < 2) {
            continue;
        }

        for (const auto* f : files) {
            uint64_t ph = compute_file_partial_hash(f->full_path);
            if (ph != 0) {
                partial_buckets[{size, ph}].push_back(f->full_path);
            }
        }
    }

    // Step 3: For colliding partial hashes, verify with full hash
    struct FullKey {
        uint64_t size{0};
        uint64_t full_hash{0};

        bool operator==(const FullKey& other) const noexcept {
            return size == other.size && full_hash == other.full_hash;
        }
    };

    struct FullKeyHasher {
        size_t operator()(const FullKey& k) const noexcept {
            return std::hash<uint64_t>{}(k.size) ^ (std::hash<uint64_t>{}(k.full_hash) << 1);
        }
    };

    std::unordered_map<FullKey, std::vector<std::wstring>, FullKeyHasher> full_buckets;

    for (const auto& [key, paths] : partial_buckets) {
        if (paths.size() < 2) {
            continue;
        }

        for (const auto& p : paths) {
            uint64_t fh = compute_file_full_hash(p);
            if (fh != 0) {
                full_buckets[{key.size, fh}].push_back(p);
            }
        }
    }

    // Step 4: Populate duplicate groups
    for (const auto& [key, paths] : full_buckets) {
        if (paths.size() >= 2) {
            DuplicateGroup g;
            g.file_size = key.size;
            g.paths = paths;
            g.wasted_bytes = (paths.size() - 1) * key.size;

            report.total_duplicate_files += paths.size();
            report.total_wasted_bytes += g.wasted_bytes;
            report.groups.push_back(std::move(g));
        }
    }

    // Sort by wasted bytes descending
    std::sort(
        report.groups.begin(),
        report.groups.end(),
        [](const DuplicateGroup& a, const DuplicateGroup& b) {
            return a.wasted_bytes > b.wasted_bytes;
        }
    );

    if (report.groups.size() > max_groups) {
        report.groups.resize(max_groups);
    }

    return report;
}

} // namespace mftscan