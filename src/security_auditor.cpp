#include "mftscan/security_auditor.hpp"

#include <sstream>
#include <iomanip>

#pragma comment(lib, "advapi32.lib")

namespace mftscan {

std::wstring SecurityAuditor::sid_to_string(PSID sid) {
    if (!sid || !IsValidSid(sid)) {
        return L"";
    }
    LPWSTR str = nullptr;
    if (ConvertSidToStringSidW(sid, &str) && str) {
        std::wstring result(str);
        LocalFree(str);
        return result;
    }
    return L"";
}

bool SecurityAuditor::is_world_sid(PSID sid) noexcept {
    if (!sid || !IsValidSid(sid)) {
        return false;
    }

    BYTE world_sid_buf[SECURITY_MAX_SID_SIZE]{};
    DWORD sid_size = sizeof(world_sid_buf);
    if (CreateWellKnownSid(WinWorldSid, nullptr, world_sid_buf, &sid_size)) {
        if (EqualSid(sid, world_sid_buf)) {
            return true;
        }
    }

    BYTE anon_sid_buf[SECURITY_MAX_SID_SIZE]{};
    sid_size = sizeof(anon_sid_buf);
    if (CreateWellKnownSid(WinAnonymousSid, nullptr, anon_sid_buf, &sid_size)) {
        if (EqualSid(sid, anon_sid_buf)) {
            return true;
        }
    }

    BYTE auth_users_sid_buf[SECURITY_MAX_SID_SIZE]{};
    sid_size = sizeof(auth_users_sid_buf);
    if (CreateWellKnownSid(WinAuthenticatedUserSid, nullptr, auth_users_sid_buf, &sid_size)) {
        if (EqualSid(sid, auth_users_sid_buf)) {
            return true;
        }
    }

    return false;
}

std::wstring SecurityAuditor::format_access_mask(DWORD mask) {
    if ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) {
        return L"Full Control";
    }

    std::wstring perms;
    if (mask & (FILE_GENERIC_READ | FILE_READ_DATA)) {
        perms += L"Read ";
    }
    if (mask & (FILE_GENERIC_WRITE | FILE_WRITE_DATA)) {
        perms += L"Write ";
    }
    if (mask & (FILE_GENERIC_EXECUTE | FILE_EXECUTE)) {
        perms += L"Execute ";
    }
    if (mask & DELETE) {
        perms += L"Delete ";
    }
    if (mask & WRITE_DAC) {
        perms += L"WriteDAC ";
    }
    if (mask & WRITE_OWNER) {
        perms += L"WriteOwner ";
    }

    if (perms.empty()) {
        std::wostringstream ss;
        ss << L"0x" << std::hex << std::uppercase << mask;
        return ss.str();
    }

    if (!perms.empty() && perms.back() == L' ') {
        perms.pop_back();
    }
    return perms;
}

const wchar_t* SecurityAuditor::risk_to_string(SecurityRiskLevel level) noexcept {
    switch (level) {
    case SecurityRiskLevel::Critical: return L"CRITICAL";
    case SecurityRiskLevel::High:     return L"HIGH";
    case SecurityRiskLevel::Medium:   return L"MEDIUM";
    case SecurityRiskLevel::Low:      return L"LOW";
    case SecurityRiskLevel::None:
    default:                          return L"NONE";
    }
}

SecurityRiskLevel SecurityAuditor::evaluate_risk(const SecurityAuditResult& res) noexcept {
    if (res.has_null_dacl) {
        return SecurityRiskLevel::Critical;
    }

    if (res.is_world_writable) {
        std::wstring p = res.path;
        for (auto& ch : p) {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        if (p.find(L"\\windows\\") != std::wstring::npos ||
            p.find(L"\\program files\\") != std::wstring::npos ||
            p.find(L"\\program files (x86)\\") != std::wstring::npos) {
            return SecurityRiskLevel::Critical;
        }
        return SecurityRiskLevel::High;
    }

    if (res.has_orphaned_sids) {
        for (const auto& ace : res.aces) {
            if (ace.is_orphaned && (ace.grants_write || ace.grants_full_control)) {
                return SecurityRiskLevel::High;
            }
        }
        return SecurityRiskLevel::Medium;
    }

    if (res.inheritance_disabled) {
        return SecurityRiskLevel::Low;
    }

    return SecurityRiskLevel::None;
}

Result<SecurityAuditResult> SecurityAuditor::audit_security_descriptor(
    PSECURITY_DESCRIPTOR p_sd,
    const std::wstring& path,
    uint64_t frn
) {
    if (!p_sd || !IsValidSecurityDescriptor(p_sd)) {
        return Error(ERROR_INVALID_PARAMETER, L"Invalid security descriptor");
    }

    SecurityAuditResult result{};
    result.frn = frn;
    result.path = path;

    PSID p_owner = nullptr;
    BOOL owner_defaulted = FALSE;
    if (GetSecurityDescriptorOwner(p_sd, &p_owner, &owner_defaulted) && p_owner) {
        result.owner_sid = sid_to_string(p_owner);

        WCHAR name[256]{};
        DWORD name_len = 256;
        WCHAR domain[256]{};
        DWORD domain_len = 256;
        SID_NAME_USE sid_type;

        if (LookupAccountSidW(nullptr, p_owner, name, &name_len, domain, &domain_len, &sid_type)) {
            if (domain_len > 0) {
                result.owner = std::wstring(domain) + L"\\" + name;
            } else {
                result.owner = name;
            }
        } else {
            result.owner = result.owner_sid;
        }
    }

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    if (GetSecurityDescriptorControl(p_sd, &control, &revision)) {
        if (control & SE_DACL_PROTECTED) {
            result.inheritance_disabled = true;
            result.findings.push_back(L"Inheritance disabled (SE_DACL_PROTECTED)");
        }
    }

    BOOL dacl_present = FALSE;
    PACL p_dacl = nullptr;
    BOOL dacl_defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(p_sd, &dacl_present, &p_dacl, &dacl_defaulted)) {
        return Error(GetLastError(), L"GetSecurityDescriptorDacl failed");
    }

    if (!dacl_present || p_dacl == nullptr) {
        result.has_null_dacl = true;
        result.findings.push_back(L"NULL DACL detected: unrestricted access to all users");
        result.risk_level = SecurityRiskLevel::Critical;
        return result;
    }

    if (p_dacl->AceCount == 0) {
        result.has_empty_dacl = true;
        result.findings.push_back(L"Empty DACL detected: access denied to all users");
    }

    for (WORD i = 0; i < p_dacl->AceCount; ++i) {
        LPVOID p_ace_void = nullptr;
        if (!GetAce(p_dacl, i, &p_ace_void)) {
            continue;
        }

        const auto* ace_header = reinterpret_cast<const ACE_HEADER*>(p_ace_void);
        if (ace_header->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            ace_header->AceType != ACCESS_DENIED_ACE_TYPE) {
            continue;
        }

        const auto* allowed_ace = reinterpret_cast<const ACCESS_ALLOWED_ACE*>(p_ace_void);
        PSID ace_sid = const_cast<PSID>(reinterpret_cast<const void*>(&allowed_ace->SidStart));

        SecurityAceInfo ace_info{};
        ace_info.ace_type = ace_header->AceType;
        ace_info.access_mask = allowed_ace->Mask;
        ace_info.is_inherited = (ace_header->AceFlags & INHERITED_ACE) != 0;
        ace_info.trustee_sid = sid_to_string(ace_sid);

        WCHAR name[256]{};
        DWORD name_len = 256;
        WCHAR domain[256]{};
        DWORD domain_len = 256;
        SID_NAME_USE sid_type;

        if (LookupAccountSidW(nullptr, ace_sid, name, &name_len, domain, &domain_len, &sid_type)) {
            if (domain_len > 0) {
                ace_info.trustee_name = std::wstring(domain) + L"\\" + name;
            } else {
                ace_info.trustee_name = name;
            }
        } else {
            const DWORD lookup_err = GetLastError();
            if (lookup_err == ERROR_NONE_MAPPED) {
                ace_info.is_orphaned = true;
                ace_info.trustee_name = L"<Orphaned SID: " + ace_info.trustee_sid + L">";
                result.has_orphaned_sids = true;
                result.findings.push_back(L"Orphaned SID detected in DACL: " + ace_info.trustee_sid);
            } else {
                ace_info.trustee_name = ace_info.trustee_sid;
            }
        }

        constexpr DWORD kWriteMask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
                                     FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE;
        constexpr DWORD kFullMask = FILE_ALL_ACCESS | GENERIC_ALL;

        if ((ace_info.access_mask & kFullMask) == kFullMask) {
            ace_info.grants_full_control = true;
            ace_info.grants_write = true;
        } else if (ace_info.access_mask & kWriteMask) {
            ace_info.grants_write = true;
        }

        if (ace_header->AceType == ACCESS_ALLOWED_ACE_TYPE && ace_info.grants_write) {
            if (is_world_sid(ace_sid)) {
                result.is_world_writable = true;
                result.findings.push_back(L"World-writable permission granted to " + ace_info.trustee_name);
            }
        }

        result.aces.push_back(std::move(ace_info));
    }

    result.risk_level = evaluate_risk(result);
    return result;
}

Result<SecurityAuditResult> SecurityAuditor::audit_path(const std::wstring& path, uint64_t frn) {
    if (path.empty()) {
        return Error(ERROR_INVALID_PARAMETER, L"Path is empty");
    }

    PSECURITY_DESCRIPTOR p_sd = nullptr;
    const DWORD status = GetNamedSecurityInfoW(
        path.c_str(),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &p_sd
    );

    if (status != ERROR_SUCCESS || !p_sd) {
        return Error(status, L"GetNamedSecurityInfoW failed for " + path);
    }

    auto res = audit_security_descriptor(p_sd, path, frn);
    LocalFree(p_sd);
    return res;
}

} // namespace mftscan
