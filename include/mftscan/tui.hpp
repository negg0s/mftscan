#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

#include <string>
#include <vector>

namespace mftscan {

enum class SortField {
    Name,
    Size,
    Date,
    Path
};

class TuiViewer {
public:
    explicit TuiViewer(std::vector<RecordInfo> records, const VolumeGeometry& geom);
    ~TuiViewer();

    void run();

private:
    std::vector<RecordInfo> all_records_;
    std::vector<const RecordInfo*> filtered_records_;
    VolumeGeometry geometry_;

    std::wstring search_query_;
    SortField sort_field_{SortField::Size};
    bool sort_ascending_{false};
    size_t selected_index_{0};
    size_t scroll_offset_{0};
    bool show_detail_modal_{false};

    HANDLE h_stdin_{INVALID_HANDLE_VALUE};
    HANDLE h_stdout_{INVALID_HANDLE_VALUE};
    DWORD orig_in_mode_{0};
    DWORD orig_out_mode_{0};

    void setup_terminal();
    void restore_terminal() noexcept;

    void update_filter();
    void sort_records();

    void render();
    void handle_key(const KEY_EVENT_RECORD& key);
};

} // namespace mftscan