#include "mftscan/hardlink.hpp"

#include <algorithm>

namespace mftscan {

HardLinkReport HardLinkTracker::analyze(const std::vector<RecordInfo>& records) {
    HardLinkReport report;

    for (const auto& r : records) {
        if (r.is_deleted || r.is_directory) {
            continue;
        }

        const uint16_t effective_links = (std::max)(r.hard_link_count, static_cast<uint16_t>(r.sibling_names.size()));
        if (effective_links <= 1) {
            continue;
        }

        HardLinkGroup g;
        g.frn = r.record_index;
        g.hard_link_count = effective_links;
        g.size_bytes = r.size_bytes;
        g.allocated_bytes = r.allocated_bytes;

        const uint64_t basis = (r.allocated_bytes > 0) ? r.allocated_bytes : r.size_bytes;
        g.saved_bytes = static_cast<uint64_t>(effective_links - 1) * basis;
        g.primary_path = r.full_path.empty() ? r.name : r.full_path;
        g.names = r.sibling_names;

        report.total_multi_link_files++;
        report.total_link_references += effective_links;
        report.total_space_saved_bytes += g.saved_bytes;

        report.groups.push_back(std::move(g));
    }

    std::sort(report.groups.begin(), report.groups.end(), [](const HardLinkGroup& a, const HardLinkGroup& b) {
        if (a.saved_bytes != b.saved_bytes) {
            return a.saved_bytes > b.saved_bytes;
        }
        return a.hard_link_count > b.hard_link_count;
    });

    return report;
}

} // namespace mftscan
