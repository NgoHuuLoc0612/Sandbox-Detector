#include "plugins/TokenPrivilegePlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <ntsecapi.h>
#include <sddl.h>

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <memory>

// ─── Token info classes not always defined ────────────────────────────────
#ifndef TokenIntegrityLevel
#  define TokenIntegrityLevel   ((TOKEN_INFORMATION_CLASS)25)
#endif
#ifndef TokenAppContainerSid
#  define TokenAppContainerSid  ((TOKEN_INFORMATION_CLASS)31)
#endif
#ifndef TokenVirtualizationEnabled
#  define TokenVirtualizationEnabled ((TOKEN_INFORMATION_CLASS)24)
#endif
#ifndef TokenSource
#  define TokenSource           ((TOKEN_INFORMATION_CLASS)7)
#endif
#ifndef TokenRestrictedSids
#  define TokenRestrictedSids   ((TOKEN_INFORMATION_CLASS)11)
#endif

// Mandatory label RID values
#define SECURITY_MANDATORY_UNTRUSTED_RID    0x00000000L
#define SECURITY_MANDATORY_LOW_RID          0x00001000L
#define SECURITY_MANDATORY_MEDIUM_RID       0x00002000L
#define SECURITY_MANDATORY_HIGH_RID         0x00003000L
#define SECURITY_MANDATORY_SYSTEM_RID       0x00004000L

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  RAII handle wrapper
// ============================================================

struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE hh = INVALID_HANDLE_VALUE) : h(hh) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    operator HANDLE() const { return h; }
    bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
};

// ============================================================
//  Helper: get token information buffer
// ============================================================

template<typename T>
static std::vector<uint8_t> getTokenInfo(HANDLE hToken, TOKEN_INFORMATION_CLASS cls) {
    DWORD needed = 0;
    GetTokenInformation(hToken, cls, nullptr, 0, &needed);
    if (needed == 0) return {};
    std::vector<uint8_t> buf(needed);
    if (!GetTokenInformation(hToken, cls, buf.data(), needed, &needed))
        return {};
    return buf;
}

// ============================================================
//  Construction / lifecycle
// ============================================================

TokenPrivilegePlugin::TokenPrivilegePlugin() {
    m_meta.id           = "com.sandboxdetector.token";
    m_meta.name         = "Access Token & Privilege Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox via access token anomalies: integrity level, "
                          "AppContainer, privilege count, SeDebugPrivilege state, "
                          "mandatory label, restricted SIDs, session ID, token "
                          "virtualization, token source, and logon type.";
    m_meta.categories   = DetectionCategory::NativeAPI; // No dedicated Token category; use NativeAPI
    m_meta.priority     = 18;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

TokenPrivilegePlugin::~TokenPrivilegePlugin() { shutdown(); }

const PluginMetadata& TokenPrivilegePlugin::getMetadata() const noexcept { return m_meta; }
bool TokenPrivilegePlugin::isSupported() const noexcept { return true; }

bool TokenPrivilegePlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void TokenPrivilegePlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult TokenPrivilegePlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkIntegrityLevel());
    push(checkAppContainerToken());
    push(checkPrivilegeCount());
    push(checkSeDebugEnabled());
    push(checkMandatoryLabel());
    push(checkRestrictedSids());
    push(checkSessionId());
    push(checkVirtualizationEnabled());
    push(checkTokenSource());
    push(checkLogonType());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Checks
// ============================================================

DetectionIndicator TokenPrivilegePlugin::checkIntegrityLevel() {
    DetectionIndicator ind;
    ind.name     = "Token Integrity Level";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    auto buf = getTokenInfo<TOKEN_MANDATORY_LABEL>(hToken, TokenIntegrityLevel);
    if (buf.empty()) return ind;

    auto* tml  = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    DWORD rid  = *GetSidSubAuthority(tml->Label.Sid,
                                      *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
    ind.rawValue = rid;

    if (rid < SECURITY_MANDATORY_LOW_RID) {
        ind.detail     = "Token integrity is UNTRUSTED (RID=0x" + [&]{ std::ostringstream s; s << std::hex << rid; return s.str(); }()
                         + "). Extreme sandbox restriction.";
        ind.confidence = SandboxConfidence::Certain;
    } else if (rid == SECURITY_MANDATORY_LOW_RID) {
        ind.detail     = "Token integrity is LOW. Process running in low-integrity sandbox.";
        ind.confidence = SandboxConfidence::High;
    } else if (rid < SECURITY_MANDATORY_MEDIUM_RID) {
        ind.detail     = "Token integrity below Medium (RID=0x" + [&]{ std::ostringstream s; s << std::hex << rid; return s.str(); }()
                         + "). Downgraded by sandboxing framework.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkAppContainerToken() {
    DetectionIndicator ind;
    ind.name     = "AppContainer Token";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    DWORD isAppContainer = 0;
    DWORD retLen = 0;
    if (GetTokenInformation(hToken, TokenIsAppContainer,
                            &isAppContainer, sizeof(isAppContainer), &retLen)) {
        ind.rawValue = isAppContainer;
        if (isAppContainer) {
            ind.detail     = "Process token is an AppContainer token. "
                             "Running inside Windows AppContainer sandbox.";
            ind.confidence = SandboxConfidence::High;
        }
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkPrivilegeCount() {
    DetectionIndicator ind;
    ind.name     = "Token Privilege Count Anomaly";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    auto buf = getTokenInfo<TOKEN_PRIVILEGES>(hToken, TokenPrivileges);
    if (buf.empty()) return ind;

    auto* priv = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
    DWORD count = priv->PrivilegeCount;
    ind.rawValue = count;

    if (count < 5) {
        ind.detail     = "Token has only " + std::to_string(count)
                         + " privilege(s). Severely restricted sandbox token.";
        ind.confidence = SandboxConfidence::High;
    } else if (count > 35) {
        ind.detail     = "Token has " + std::to_string(count)
                         + " privileges (> 35). Inflated token suggests AV/EDR injection.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkSeDebugEnabled() {
    DetectionIndicator ind;
    ind.name     = "SeDebugPrivilege Enabled";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    auto buf = getTokenInfo<TOKEN_PRIVILEGES>(hToken, TokenPrivileges);
    if (buf.empty()) return ind;

    auto* priv = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());

    LUID seDebugLuid = {};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &seDebugLuid)) return ind;

    for (DWORD i = 0; i < priv->PrivilegeCount; ++i) {
        if (priv->Privileges[i].Luid.LowPart  == seDebugLuid.LowPart &&
            priv->Privileges[i].Luid.HighPart == seDebugLuid.HighPart) {
            DWORD attrs = priv->Privileges[i].Attributes;
            ind.rawValue = attrs;
            if (attrs & SE_PRIVILEGE_ENABLED) {
                ind.detail     = "SeDebugPrivilege is ENABLED in the current token. "
                                 "Indicates AV/EDR hook injection or process running under debugger.";
                ind.confidence = SandboxConfidence::Medium;
            }
            break;
        }
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkMandatoryLabel() {
    DetectionIndicator ind;
    ind.name     = "Mandatory Integrity Label";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;

    // Already covered in checkIntegrityLevel; this checks for explicit label presence
    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    auto buf = getTokenInfo<TOKEN_MANDATORY_LABEL>(hToken, TokenIntegrityLevel);
    if (buf.empty()) {
        ind.detail     = "TokenIntegrityLevel not available. Possibly pre-Vista sandbox emulation.";
        ind.confidence = SandboxConfidence::Low;
        ind.rawValue   = 0;
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkRestrictedSids() {
    DetectionIndicator ind;
    ind.name     = "Restricted Token SIDs";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    BOOL isRestricted = IsTokenRestricted(hToken);
    ind.rawValue = isRestricted ? 1 : 0;

    if (isRestricted) {
        // Get count of restricted SIDs
        auto buf = getTokenInfo<TOKEN_GROUPS>(hToken, TokenRestrictedSids);
        DWORD count = 0;
        if (!buf.empty()) {
            count = reinterpret_cast<TOKEN_GROUPS*>(buf.data())->GroupCount;
        }
        ind.detail     = "Token has " + std::to_string(count)
                         + " restricted SID(s) (CreateRestrictedToken). "
                         "Process is running under token restriction (sandbox policy).";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkSessionId() {
    DetectionIndicator ind;
    ind.name     = "Token Session ID";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    DWORD sessionId = 0xFFFFFFFF;
    DWORD retLen = 0;
    if (!GetTokenInformation(hToken, TokenSessionId,
                             &sessionId, sizeof(sessionId), &retLen)) return ind;
    ind.rawValue = sessionId;

    if (sessionId == 0) {
        ind.detail     = "Token session ID = 0. Process is running in Session 0 (service context). "
                         "Automated sandbox or service-launched sample.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkVirtualizationEnabled() {
    DetectionIndicator ind;
    ind.name     = "Token Virtualization Enabled";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    DWORD virtEnabled = 0;
    DWORD retLen = 0;
    if (GetTokenInformation(hToken, TokenVirtualizationEnabled,
                            &virtEnabled, sizeof(virtEnabled), &retLen)) {
        ind.rawValue = virtEnabled;
        if (virtEnabled) {
            ind.detail     = "Token UAC virtualization is ENABLED. "
                             "Registry/filesystem virtualization active — typically a sandboxed legacy app.";
            ind.confidence = SandboxConfidence::Low;
        }
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkTokenSource() {
    DetectionIndicator ind;
    ind.name     = "Token Source Name";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken.h)) return ind;

    TOKEN_SOURCE src = {};
    DWORD retLen = 0;
    if (!GetTokenInformation(hToken, TokenSource, &src, sizeof(src), &retLen)) return ind;

    // Token source name is 8 chars (not null-terminated)
    std::string srcName(src.SourceName, 8);
    // Trim trailing spaces/nulls
    while (!srcName.empty() && (srcName.back() == '\0' || srcName.back() == ' '))
        srcName.pop_back();

    ind.rawValue = 1;
    // Normal interactive tokens: "User32", "NtLmSsp", "Kerberos", "NTLM"
    // Sandboxes often use "SANDBOX", "CAPE", "SERVICE", or custom names
    std::string srcLo = srcName;
    std::transform(srcLo.begin(), srcLo.end(), srcLo.begin(), ::tolower);

    static constexpr std::array<const char*, 6> SUSPECT_SOURCES = {{
        "sandbox", "cape", "cuckoo", "service", "batch", "network"
    }};

    for (const char* s : SUSPECT_SOURCES) {
        if (srcLo.find(s) != std::string::npos) {
            ind.detail     = "Token source is '" + srcName + "'. "
                             "Non-interactive logon source suggests automated sandbox.";
            ind.confidence = SandboxConfidence::Medium;
            return ind;
        }
    }
    return ind;
}

DetectionIndicator TokenPrivilegePlugin::checkLogonType() {
    DetectionIndicator ind;
    ind.name     = "Logon Type Anomaly";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Get current logon SID from token to query the logon session type
    // We use GetTokenInformation(TokenStatistics) to get the AuthenticationId (LUID)
    // then enumerate logon sessions via LsaEnumerateLogonSessions if available
    HandleGuard hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken.h)) return ind;

    TOKEN_STATISTICS stats = {};
    DWORD retLen = 0;
    if (!GetTokenInformation(hToken, TokenStatistics, &stats, sizeof(stats), &retLen)) return ind;

    // stats.AuthenticationId is the logon session LUID
    // Logon type is in the logon session; try LsaGetLogonSessionData
    HMODULE hSecur32 = LoadLibraryW(L"secur32.dll");
    if (!hSecur32) return ind;
    struct SecurGuard { HMODULE h; ~SecurGuard(){ FreeLibrary(h); } } sg{hSecur32};

    using PFN_LsaGetLogonSessionData = NTSTATUS(NTAPI*)(PLUID, PSECURITY_LOGON_SESSION_DATA*);
    using PFN_LsaFreeReturnBuffer    = NTSTATUS(NTAPI*)(PVOID);

    auto LsaGetLogonSessionData = reinterpret_cast<PFN_LsaGetLogonSessionData>(
        GetProcAddress(hSecur32, "LsaGetLogonSessionData"));
    auto LsaFreeReturnBuffer = reinterpret_cast<PFN_LsaFreeReturnBuffer>(
        GetProcAddress(hSecur32, "LsaFreeReturnBuffer"));

    if (!LsaGetLogonSessionData || !LsaFreeReturnBuffer) return ind;

    SECURITY_LOGON_SESSION_DATA* pData = nullptr;
    NTSTATUS st = LsaGetLogonSessionData(&stats.AuthenticationId, &pData);
    if (st != 0 || !pData) return ind;

    DWORD logonType = pData->LogonType;
    LsaFreeReturnBuffer(pData);
    ind.rawValue = logonType;

    // SECURITY_LOGON_TYPE: Network=3, Batch=4, Service=5, Interactive=2, NetworkCleartext=8
    // Sandboxes often run samples with Network, Batch or Service logon
    std::string logonTypeName;
    bool suspicious = false;
    switch (logonType) {
        case 3: logonTypeName = "Network";           suspicious = true;  break;
        case 4: logonTypeName = "Batch";             suspicious = true;  break;
        case 5: logonTypeName = "Service";           suspicious = true;  break;
        case 8: logonTypeName = "NetworkCleartext";  suspicious = true;  break;
        case 2: logonTypeName = "Interactive";       suspicious = false; break;
        default: logonTypeName = "Type=" + std::to_string(logonType); suspicious = true; break;
    }

    if (suspicious) {
        ind.detail     = "Logon type is " + logonTypeName + " (type " + std::to_string(logonType)
                         + "). Non-interactive logon suggests automated sandbox execution.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
