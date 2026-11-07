#include "mftscan/tui.hpp"
#include "mftscan/formatter.hpp"
#include "mftscan/query.hpp"

#include <algorithm>
#include <cwctype>
#include <iostream>
#include <sstream>

namespace mftscan {

TuiViewer::TuiViewer(std::vector<RecordInfo> records, const VolumeGeometry& geom)
    : all_records_(std::move(records)),
      geometry_(geom) {
    filtered_records_.reserve(all_records_.size());
    for (const auto& r : all_records_) {
        filtered_records_.push_back(&r);
    }
    sort_records();
}

TuiViewer::~TuiViewer() {
    restore_terminal();
}

void TuiViewer::setup_terminal() {
    h_stdin_ = GetStdHandle(STD_INPUT_HANDLE);
    h_stdout_ = GetStdHandle(STD_OUTPUT_HANDLE);

    GetConsoleMode(h_stdin_, &orig_in_mode_);
    GetConsoleMode(h_stdout_, &orig_out_mode_);

    SetConsoleMode(h_stdin_, ENABLE_WINDOW_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT);
    SetConsoleMode(h_stdout_, orig_out_mode_ | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);

    // Switch to alternate buffer and hide cursor
    std::wcout << L"\x1b[?1049h\x1b[?25l" << std::flush;
}

void TuiViewer::restore_terminal() noexcept {
    if (h_stdout_ != INVALID_HANDLE_VALUE) {
        // Show cursor and switch back to main buffer
        std::wcout << L"\x1b[?25h\x1b[?1049l" << std::flush;
        SetConsoleMode(h_stdout_, orig_out_mode_);
    }
    if (h_stdin_ != INVALID_HANDLE_VALUE) {
        SetConsoleMode(h_stdin_, orig_in_mode_);
    }
}

void TuiViewer::update_filter() {
    filtered_records_.clear();

    if (search_query_.empty()) {
        for (const auto& r : all_records_) {
            filtered_records_.push_back(&r);
        }
    } else {
        std::wstring pat = L"*" + search_query_ + L"*";
        for (const auto& r : all_records_) {
            if (QueryEngine::wildcard_match(pat, r.name)) {
                filtered_records_.push_back(&r);
            }
        }
    }

    selected_index_ = 0;
    scroll_offset_ = 0;
    sort_records();
}

void TuiViewer::sort_records() {
    auto comp = [&](const RecordInfo* a, const RecordInfo* b) {
        if (sort_field_ == SortField::Name) {
            int cmp = _wcsicmp(a->name.c_str(), b->name.c_str());
            return sort_ascending_ ? (cmp < 0) : (cmp > 0);
        }
        if (sort_field_ == SortField::Size) {
            return sort_ascending_ ? (a->size_bytes < b->size_bytes) : (a->size_bytes > b->size_bytes);
        }
        if (sort_field_ == SortField::Date) {
            return sort_ascending_ ? (a->modification_time < b->modification_time) : (a->modification_time > b->modification_time);
        }
        // Path
        int cmp = _wcsicmp(a->full_path.c_str(), b->full_path.c_str());
        return sort_ascending_ ? (cmp < 0) : (cmp > 0);
    };

    std::sort(filtered_records_.begin(), filtered_records_.end(), comp);
}

void TuiViewer::render() {
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    GetConsoleScreenBufferInfo(h_stdout_, &csbi);
    const int cols = (csbi.srWindow.Right - csbi.srWindow.Left + 1 > 20)
        ? (csbi.srWindow.Right - csbi.srWindow.Left + 1)
        : 80;
    const int rows = (csbi.srWindow.Bottom - csbi.srWindow.Top + 1 > 10)
        ? (csbi.srWindow.Bottom - csbi.srWindow.Top + 1)
        : 25;

    std::wostringstream oss;
    // Clear screen and cursor home
    oss << L"\x1b[H";

    // 1. Header Line
    oss << L"\x1b[7m mftscan TUI | Volume " << geometry_.volume_letter << L": | Records: "
        << filtered_records_.size() << L" / " << all_records_.size() << L"\x1b[0m\n";

    // 2. Search Bar
    oss << L" Filter: [" << search_query_ << L"_]\x1b[K\n";

    // 3. Table Column Header
    const wchar_t* sort_name = L"Size";
    if (sort_field_ == SortField::Name) sort_name = L"Name";
    else if (sort_field_ == SortField::Date) sort_name = L"Date";
    else if (sort_field_ == SortField::Path) sort_name = L"Path";

    oss << L"\x1b[4m"
        << L"  Type   Size         Modified             Name / Path (Sorted by: "
        << sort_name << (sort_ascending_ ? L" ASC" : L" DESC") << L")\x1b[0m\x1b[K\n";

    const int body_rows = rows - 5;

    if (show_detail_modal_ && !filtered_records_.empty() && selected_index_ < filtered_records_.size()) {
        const auto* r = filtered_records_[selected_index_];

        oss << L"\x1b[1;36m+--- [ RECORD DETAILS: FRN #" << r->record_index << L" ] "
            << std::wstring(cols > 40 ? cols - 35 : 5, L'-') << L"+\x1b[0m\x1b[K\n";

        auto print_line = [&](const std::wstring& label, const std::wstring& val) {
            oss << L"| \x1b[1m" << label << L":\x1b[0m " << val;
            int pad = cols - 4 - static_cast<int>(label.size() + val.size() + 2);
            if (pad > 0) oss << std::wstring(pad, L' ');
            oss << L"|\x1b[K\n";
        };

        print_line(L"File Name", r->name);
        print_line(L"Full Path", r->full_path.empty() ? r->name : r->full_path);
        print_line(L"File Record Number", std::to_wstring(r->record_index) + L" (Seq: " + std::to_wstring(r->sequence_number) + L")");
        print_line(L"Parent Directory FRN", std::to_wstring(r->parent_record_index));
        print_line(L"Type / State", (r->is_directory ? L"Directory" : L"File") + std::wstring(r->is_deleted ? L" [DELETED / FREE]" : L" [ACTIVE]"));
        print_line(L"Logical File Size", Formatter::format_bytes(r->size_bytes) + L" (" + std::to_wstring(r->size_bytes) + L" bytes)");
        print_line(L"Allocated Size", Formatter::format_bytes(r->allocated_bytes) + L" (" + std::to_wstring(r->allocated_bytes) + L" bytes)");
        print_line(L"Cluster Slack", Formatter::format_bytes(r->slack_bytes) + L" (" + std::to_wstring(r->slack_bytes) + L" bytes)");
        print_line(L"Fragments", std::to_wstring(r->fragment_count) + L" excess fragment(s)");
        print_line(L"NTFS Flags", (r->is_compressed ? L"Compressed " : L"") + (r->is_sparse ? std::wstring(L"Sparse ") : std::wstring(L"None")));
        
        std::wstring ads_info = L"None";
        if (r->has_ads && !r->ads_names.empty()) {
            ads_info = L"";
            for (size_t a = 0; a < r->ads_names.size(); ++a) {
                if (a > 0) ads_info += L", ";
                ads_info += L":" + r->ads_names[a];
            }
        }
        print_line(L"Alt Data Streams", ads_info);
        print_line(L"Created Timestamp", Formatter::format_filetime(r->creation_time));
        print_line(L"Modified Timestamp", Formatter::format_filetime(r->modification_time));

        oss << L"\x1b[1;36m+--- [ Press ESC or Enter to Return ] "
            << std::wstring(cols > 45 ? cols - 40 : 5, L'-') << L"+\x1b[0m\x1b[K\n";

        // Fill remaining rows
        for (int i = 15; i < body_rows; ++i) {
            oss << L"~\x1b[K\n";
        }
    } else {
        if (selected_index_ < scroll_offset_) {
            scroll_offset_ = selected_index_;
        } else if (selected_index_ >= scroll_offset_ + body_rows) {
            scroll_offset_ = selected_index_ - body_rows + 1;
        }

        for (int i = 0; i < body_rows; ++i) {
            const size_t rec_idx = scroll_offset_ + i;
            if (rec_idx < filtered_records_.size()) {
                const auto* r = filtered_records_[rec_idx];
                const bool is_selected = (rec_idx == selected_index_);

                if (is_selected) {
                    oss << L"\x1b[7m>";
                } else {
                    oss << L" ";
                }

                std::wstring type_tag = r->is_deleted ? L"[DEL]" : (r->is_directory ? L"<DIR>" : L"FILE ");
                std::wstring size_str = r->is_directory ? L"-" : Formatter::format_bytes(r->size_bytes);
                std::wstring date_str = Formatter::format_filetime(r->modification_time);

                // Fixed columns
                wchar_t line_buf[256];
                swprintf_s(line_buf, L" %-6s %-12s %-20s ", type_tag.c_str(), size_str.c_str(), date_str.c_str());
                oss << line_buf;

                int remaining_cols = cols - 45;
                if (remaining_cols > 5) {
                    std::wstring disp = r->full_path.empty() ? r->name : r->full_path;
                    if (static_cast<int>(disp.size()) > remaining_cols) {
                        disp = disp.substr(disp.size() - remaining_cols);
                    }
                    oss << disp;
                }

                if (is_selected) {
                    oss << L"\x1b[0m";
                }
                oss << L"\x1b[K\n";
            } else {
                oss << L"~\x1b[K\n";
            }
        }
    }

    // 4. Status Bar
    if (show_detail_modal_) {
        oss << L"\x1b[7m Enter or ESC: Close Details Modal \x1b[0m\x1b[K";
    } else {
        oss << L"\x1b[7m F1:Name | F2:Size | F3:Date | F4:Path | Enter:Inspect | Up/Down:Navigate | ESC:Exit \x1b[0m\x1b[K";
    }

    std::wcout << oss.str() << std::flush;
}

void TuiViewer::handle_key(const KEY_EVENT_RECORD& key) {
    if (!key.bKeyDown) {
        return;
    }

    if (show_detail_modal_) {
        if (key.wVirtualKeyCode == VK_RETURN || key.wVirtualKeyCode == VK_SPACE || key.wVirtualKeyCode == VK_ESCAPE) {
            show_detail_modal_ = false;
        }
        return;
    }

    switch (key.wVirtualKeyCode) {
        case VK_ESCAPE:
            return;
        case VK_RETURN:
            if (!filtered_records_.empty() && selected_index_ < filtered_records_.size()) {
                show_detail_modal_ = true;
            }
            break;
        case VK_UP:
            if (selected_index_ > 0) selected_index_--;
            break;
        case VK_DOWN:
            if (selected_index_ + 1 < filtered_records_.size()) selected_index_++;
            break;
        case VK_PRIOR: // Page Up
            selected_index_ = (selected_index_ > 15) ? (selected_index_ - 15) : 0;
            break;
        case VK_NEXT: // Page Down
            selected_index_ = (std::min)(selected_index_ + 15, filtered_records_.empty() ? 0 : filtered_records_.size() - 1);
            break;
        case VK_HOME:
            selected_index_ = 0;
            break;
        case VK_END:
            if (!filtered_records_.empty()) selected_index_ = filtered_records_.size() - 1;
            break;
        case VK_F1:
            if (sort_field_ == SortField::Name) sort_ascending_ = !sort_ascending_;
            else { sort_field_ = SortField::Name; sort_ascending_ = true; }
            sort_records();
            break;
        case VK_F2:
            if (sort_field_ == SortField::Size) sort_ascending_ = !sort_ascending_;
            else { sort_field_ = SortField::Size; sort_ascending_ = false; }
            sort_records();
            break;
        case VK_F3:
            if (sort_field_ == SortField::Date) sort_ascending_ = !sort_ascending_;
            else { sort_field_ = SortField::Date; sort_ascending_ = false; }
            sort_records();
            break;
        case VK_F4:
            if (sort_field_ == SortField::Path) sort_ascending_ = !sort_ascending_;
            else { sort_field_ = SortField::Path; sort_ascending_ = true; }
            sort_records();
            break;
        case VK_BACK:
            if (!search_query_.empty()) {
                search_query_.pop_back();
                update_filter();
            }
            break;
        default:
            if (key.uChar.UnicodeChar >= 32 && key.uChar.UnicodeChar < 127) {
                search_query_.push_back(key.uChar.UnicodeChar);
                update_filter();
            }
            break;
    }
}

void TuiViewer::run() {
    setup_terminal();

    bool running = true;
    while (running) {
        render();

        INPUT_RECORD rec{};
        DWORD count = 0;
        if (ReadConsoleInputW(h_stdin_, &rec, 1, &count) && count > 0) {
            if (rec.EventType == KEY_EVENT) {
                if (rec.Event.KeyEvent.bKeyDown && rec.Event.KeyEvent.wVirtualKeyCode == VK_ESCAPE) {
                    if (show_detail_modal_) {
                        show_detail_modal_ = false;
                        continue;
                    }
                    running = false;
                    break;
                }
                handle_key(rec.Event.KeyEvent);
            } else if (rec.EventType == WINDOW_BUFFER_SIZE_EVENT) {
                // Console resize, re-render automatically
            }
        }
    }

    restore_terminal();
}

} // namespace mftscan