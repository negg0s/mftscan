#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include "mftscan/common.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace mftscan {

enum class SecurityRiskLevel {
    None = 0,
    Low,
    Medium,
    High,
    Critical
};

struct SecurityAceInfo {
    std::wstring trustee_name;
    std::wstring trustee_sid;
    DWORD access_mask{0};
    BYTE ace_type{0};
    bool is_inherited{false};
    bool is_orphaned{false};
    bool grants_write{false};
    bool grants_full_control{false};
};

struct SecurityAuditResult {
    uint64_t frn{0};
    std::wstring path;
    std::wstring owner;
    std::wstring owner_sid;
    bool has_null_dacl{false};
    bool has_empty_dacl{false};
    bool is_world_writable{false};
    bool has_orphaned_sids{false};
    bool inheritance_disabled{false};
    SecurityRiskLevel risk_level{SecurityRiskLevel::None};
    std::vector<std::wstring> findings;
    std::vector<SecurityAceInfo> aces;
};

class SecurityAuditor {
public:
    static Result<SecurityAuditResult> audit_path(const std::wstring& path, uint64_t frn = 0);

    static Result<SecurityAuditResult> audit_security_descriptor(
        PSECURITY_DESCRIPTOR p_sd,
        const std::wstring& path,
        uint64_t frn = 0
    );

    static bool is_world_sid(PSID sid) noexcept;
    static std::wstring sid_to_string(PSID sid);
    static std::wstring format_access_mask(DWORD mask);
    static const wchar_t* risk_to_string(SecurityRiskLevel level) noexcept;

    static SecurityRiskLevel evaluate_risk(const SecurityAuditResult& res) noexcept;
};

} // namespace mftscan
