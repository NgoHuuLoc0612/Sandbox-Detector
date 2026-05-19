#include "plugins/EnvironmentPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <array>
#include <cctype>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Suspicious usernames
// ============================================================

static constexpr std::array<const wchar_t*, 18> SUSPECT_USERNAMES = {{
    L"sandbox",   L"malware",  L"cuckoo",   L"virus",    L"analysis",
    L"maltest",   L"test",     L"sample",   L"honeypot", L"lab",
    L"anyrun",    L"joe",      L"analyst",  L"user",     L"currentuser",
    L"username",  L"admin",    L"john"
}};

static constexpr std::array<const wchar_t*, 12> SUSPECT_COMPUTERNAMES = {{
    L"sandbox",   L"cuckoo",   L"malware",  L"maltest",
    L"vmsandbox", L"vmware",   L"vbox",     L"analysis",
    L"anyrun",    L"joebox",   L"cape",     L"hybrid"
}};

static constexpr std::array<const wchar_t*, 8> SANDBOX_ENV_VARS = {{
    L"CUCKOO",
    L"SANDBOXIE",
    L"VBOX_VERSION",
    L"VMWARE_VERSION",
    L"CAPE_SANDBOX",
    L"ANYRUN_SANDBOX",
    L"JOESANDBOX",
    L"SANDBOX_ENABLED"
}};

// ============================================================
//  Helpers
// ============================================================

static std::wstring toLowerW(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return out;
}

// ============================================================
//  Construction / lifecycle
// ============================================================

EnvironmentPlugin::EnvironmentPlugin() {
    m_meta.id           = "com.sandboxdetector.environment";
    m_meta.name         = "Environment Variables & OS Settings Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox via suspicious username, computer name, "
                          "environment variables, system uptime, Windows edition, "
                          "install date, and OS configuration anomalies.";
    m_meta.categories   = DetectionCategory::EnvironmentVariables;
    m_meta.priority     = 15;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

EnvironmentPlugin::~EnvironmentPlugin() { shutdown(); }

const PluginMetadata& EnvironmentPlugin::getMetadata() const noexcept { return m_meta; }
bool EnvironmentPlugin::isSupported() const noexcept { return true; }

bool EnvironmentPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void EnvironmentPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult EnvironmentPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkSuspiciousUsername());
    push(checkSuspiciousComputerName());
    push(checkSandboxEnvVars());
    push(checkProcessorIdentifier());
    push(checkProcessorCount());
    push(checkSystemRoot());
    push(checkUptime());
    push(checkInstallDate());
    push(checkWindowsEdition());
    push(checkScreenSaverDisabled());
    push(checkTempPath());
    push(checkPathVariable());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Checks
// ============================================================

DetectionIndicator EnvironmentPlugin::checkSuspiciousUsername() {
    DetectionIndicator ind;
    ind.name     = "Suspicious Username";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    wchar_t buf[256] = {};
    DWORD len = 256;
    GetUserNameW(buf, &len);
    std::wstring username(buf);
    std::wstring userLo = toLowerW(username);

    for (const wchar_t* suspect : SUSPECT_USERNAMES) {
        if (userLo == suspect || userLo.find(suspect) != std::wstring::npos) {
            ind.detail     = "Username '" + WinUtils::toNarrow(username)
                             + "' matches sandbox pattern '" + WinUtils::toNarrow(suspect) + "'";
            ind.confidence = SandboxConfidence::High;
            ind.rawValue   = 1;
            return ind;
        }
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkSuspiciousComputerName() {
    DetectionIndicator ind;
    ind.name     = "Suspicious Computer Name";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 2] = {};
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(buf, &len);
    std::wstring name(buf);
    std::wstring nameLo = toLowerW(name);

    for (const wchar_t* suspect : SUSPECT_COMPUTERNAMES) {
        if (nameLo.find(suspect) != std::wstring::npos) {
            ind.detail     = "Computer name '" + WinUtils::toNarrow(name)
                             + "' contains sandbox keyword '" + WinUtils::toNarrow(suspect) + "'";
            ind.confidence = SandboxConfidence::High;
            ind.rawValue   = 1;
            return ind;
        }
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkSandboxEnvVars() {
    DetectionIndicator ind;
    ind.name     = "Sandbox Environment Variables";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::vector<std::wstring> found;
    for (const wchar_t* var : SANDBOX_ENV_VARS) {
        wchar_t buf[512] = {};
        DWORD r = GetEnvironmentVariableW(var, buf, 512);
        if (r > 0)
            found.push_back(std::wstring(var));
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Sandbox environment variable(s) found: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkProcessorIdentifier() {
    DetectionIndicator ind;
    ind.name     = "PROCESSOR_IDENTIFIER Anomaly";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    wchar_t buf[512] = {};
    GetEnvironmentVariableW(L"PROCESSOR_IDENTIFIER", buf, 512);
    std::wstring procId(buf);
    std::wstring procIdLo = toLowerW(procId);

    static constexpr std::array<const wchar_t*, 4> QEMU_STRINGS = {{
        L"qemu", L"kvm", L"bochs", L"virtual"
    }};

    for (const wchar_t* s : QEMU_STRINGS) {
        if (procIdLo.find(s) != std::wstring::npos) {
            ind.detail     = "PROCESSOR_IDENTIFIER reveals emulator: '"
                             + WinUtils::toNarrow(procId) + "'";
            ind.confidence = SandboxConfidence::Certain;
            ind.rawValue   = 1;
            return ind;
        }
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkProcessorCount() {
    DetectionIndicator ind;
    ind.name     = "Single Processor Core";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;

    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);
    ind.rawValue = si.dwNumberOfProcessors;

    if (si.dwNumberOfProcessors == 1) {
        ind.detail     = "NUMBER_OF_PROCESSORS = 1. Single-core system. "
                         "Sandboxes often allocate only one vCPU.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkSystemRoot() {
    DetectionIndicator ind;
    ind.name     = "SystemRoot Drive";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    wchar_t buf[MAX_PATH] = {};
    GetWindowsDirectoryW(buf, MAX_PATH);
    std::wstring winDir(buf);

    // Anything not on C: is unusual
    if (!winDir.empty() && towupper(winDir[0]) != L'C') {
        ind.detail     = "Windows installed on drive " + std::string(1, (char)winDir[0])
                         + ": instead of C:. Unusual configuration.";
        ind.confidence = SandboxConfidence::Low;
        ind.rawValue   = (uint64_t)winDir[0];
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkUptime() {
    DetectionIndicator ind;
    ind.name     = "System Uptime";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;

    ULONGLONG uptimeMs = GetTickCount64();
    uint64_t uptimeSec = uptimeMs / 1000;
    ind.rawValue = uptimeSec;

    if (uptimeSec < 300) {  // < 5 minutes
        ind.detail     = "System uptime is only " + std::to_string(uptimeSec)
                         + " seconds. Freshly started sandbox.";
        ind.confidence = SandboxConfidence::High;
    } else if (uptimeSec < 120) {  // < 2 minutes
        ind.detail     = "System uptime is " + std::to_string(uptimeSec)
                         + " seconds. Near-instant boot = likely sandbox.";
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkInstallDate() {
    DetectionIndicator ind;
    ind.name     = "Windows Install Date";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    auto val = WinUtils::regQueryValue(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"InstallDate");

    if (!val.has_value()) return ind;

    DWORD installEpoch = val->asDword();
    if (installEpoch == 0) return ind;

    // Get current time as UNIX timestamp
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ui;
    ui.LowPart  = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    // FILETIME epoch is 1601-01-01; convert to UNIX epoch
    uint64_t now = (ui.QuadPart - 116444736000000000ULL) / 10000000ULL;

    uint64_t ageSec  = (now > installEpoch) ? (now - installEpoch) : 0;
    uint64_t ageDays = ageSec / 86400;
    ind.rawValue = ageDays;

    if (ageDays < 7) {
        ind.detail     = "Windows installed only " + std::to_string(ageDays)
                         + " day(s) ago. Fresh install = likely sandbox.";
        ind.confidence = (ageDays == 0) ? SandboxConfidence::Certain
                       : (ageDays  < 3) ? SandboxConfidence::High
                       :                  SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkWindowsEdition() {
    DetectionIndicator ind;
    ind.name     = "Windows Edition";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    auto val = WinUtils::regQueryValue(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"EditionID");

    if (!val.has_value()) return ind;

    std::string edition = val->asString();
    std::string editionLo(edition);
    std::transform(editionLo.begin(), editionLo.end(), editionLo.begin(), ::tolower);

    static constexpr std::array<const char*, 6> SUSPECT_EDITIONS = {{
        "evaluation", "ltsc", "core", "server", "datacenter", "minimal"
    }};

    for (const char* e : SUSPECT_EDITIONS) {
        if (editionLo.find(e) != std::string::npos) {
            ind.detail     = "Windows edition '" + edition
                             + "' is common in VMs and sandbox environments.";
            ind.confidence = SandboxConfidence::Low;
            ind.rawValue   = 1;
            return ind;
        }
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkScreenSaverDisabled() {
    DetectionIndicator ind;
    ind.name     = "Screen Saver Disabled";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    auto val = WinUtils::regQueryValue(
        HKEY_CURRENT_USER,
        L"Control Panel\\Desktop",
        L"ScreenSaveActive");

    if (val.has_value()) {
        std::string v = val->asString();
        if (v == "0") {
            ind.detail     = "Screen saver is disabled (ScreenSaveActive=0). "
                             "Common in headless sandbox/VM configurations.";
            ind.confidence = SandboxConfidence::Low;
            ind.rawValue   = 0;
        }
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkTempPath() {
    DetectionIndicator ind;
    ind.name     = "TEMP Path Anomaly";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    wchar_t buf[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, buf);
    std::wstring temp(buf);
    std::wstring tempLo = toLowerW(temp);

    static constexpr std::array<const wchar_t*, 6> SUSPECT_TEMPS = {{
        L"sandbox", L"cuckoo", L"malware", L"sample", L"analysis", L"tmp"
    }};

    for (const wchar_t* s : SUSPECT_TEMPS) {
        if (tempLo.find(s) != std::wstring::npos) {
            ind.detail     = "TEMP path '" + WinUtils::toNarrow(temp)
                             + "' contains suspicious keyword.";
            ind.confidence = SandboxConfidence::Medium;
            ind.rawValue   = 1;
            return ind;
        }
    }
    return ind;
}

DetectionIndicator EnvironmentPlugin::checkPathVariable() {
    DetectionIndicator ind;
    ind.name     = "PATH Environment Anomaly";
    ind.category = DetectionCategory::EnvironmentVariables;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    wchar_t buf[32768] = {};
    GetEnvironmentVariableW(L"PATH", buf, 32768);
    std::wstring path(buf);

    // Minimal PATH = sandbox stripping environment
    // Real Windows PATH should be >100 chars
    ind.rawValue = path.size();

    if (path.size() < 50) {
        ind.detail     = "PATH environment variable is unusually short ("
                         + std::to_string(path.size()) + " chars). "
                         "Stripped sandbox environment.";
        ind.confidence = SandboxConfidence::Medium;
    } else if (path.empty()) {
        ind.detail     = "PATH environment variable is empty. Highly unusual.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
