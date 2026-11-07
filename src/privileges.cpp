#include "mftscan/privileges.hpp"

namespace mftscan {

bool PrivilegeManager::is_elevated_admin() noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const BOOL success = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);

    return (success && elevation.TokenIsElevated != 0);
}

Result<void> PrivilegeManager::enable_privilege(const wchar_t* privilege_name) noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return Error(GetLastError(), L"Failed to open process token for privilege adjustment");
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
        const DWORD err = GetLastError();
        CloseHandle(token);
        return Error(err, L"LookupPrivilegeValue failed for: " + std::wstring(privilege_name));
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        const DWORD err = GetLastError();
        CloseHandle(token);
        return Error(err, L"AdjustTokenPrivileges failed for: " + std::wstring(privilege_name));
    }

    const DWORD last_err = GetLastError();
    CloseHandle(token);

    if (last_err == ERROR_NOT_ALL_ASSIGNED) {
        return Error(ERROR_NOT_ALL_ASSIGNED, L"Privilege not held by token: " + std::wstring(privilege_name));
    }

    return {};
}

Result<void> PrivilegeManager::enable_volume_privileges() noexcept {
    static const wchar_t* const kPrivileges[] = {
        SE_BACKUP_NAME,
        SE_RESTORE_NAME,
        SE_MANAGE_VOLUME_NAME
    };

    for (const auto* priv : kPrivileges) {
        enable_privilege(priv);
    }

    return {};
}

} // namespace mftscan