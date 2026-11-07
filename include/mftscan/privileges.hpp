#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "mftscan/common.hpp"

namespace mftscan {

class PrivilegeManager {
public:
    static bool is_elevated_admin() noexcept;
    static Result<void> enable_volume_privileges() noexcept;
    static Result<void> enable_privilege(const wchar_t* privilege_name) noexcept;
};

} // namespace mftscan