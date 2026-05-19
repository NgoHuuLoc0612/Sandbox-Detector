#include "plugins/FileSystemPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <userenv.h>

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
//  VM guest addition / tools paths
// ============================================================

static constexpr std::array<const wchar_t*, 18> VM_GUEST_PATHS = {{
    L"C:\\Program Files\\Oracle\\VirtualBox Guest Additions",
    L"C:\\Program Files\\VMware\\VMware Tools",
    L"C:\\Program Files (x86)\\VMware\\VMware Tools",
    L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
    L"C:\\Windows\\System32\\VBoxControl.exe",
    L"C:\\Windows\\System32\\VBoxTray.exe",
    L"C:\\Windows\\System32\\vmtoolsd.exe",
    L"C:\\Windows\\System32\\drivers\\vmci.sys",
    L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    L"C:\\Windows\\System32\\drivers\\vmxnet.sys",
    L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vsock.sys",
    L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys",
    L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
    L"C:\\Windows\\System32\\drivers\\vmkbd.sys",
}};

// Sandbox agent / cuckoo files
static constexpr std::array<const wchar_t*, 12> SANDBOX_AGENT_FILES = {{
    L"C:\\agent.py",
    L"C:\\agent.exe",
    L"C:\\cuckoo_agent.exe",
    L"C:\\strawberry\\agent.py",
    L"C:\\cuckoomon.dll",
    L"C:\\analyzer.py",
    L"C:\\tmp\\cuckoo.exe",
    L"C:\\Windows\\System32\\sbiedll.dll",
    L"C:\\Windows\\SysWOW64\\sbiedll.dll",
    L"C:\\Program Files\\Sandboxie\\SbieDll.dll",
    L"C:\\Program Files (x86)\\Sandboxie\\SbieDll.dll",
    L"C:\\Windows\\System32\\drivers\\SbieDrv.sys",
}};

// Analysis tool artifact files / directories
static constexpr std::array<const wchar_t*, 10> ANALYSIS_ARTIFACTS = {{
    L"C:\\inetpub",
    L"C:\\inetsrv",
    L"C:\\logs",
    L"C:\\dump",
    L"C:\\samples",
    L"C:\\malware",
    L"C:\\analysis",
    L"C:\\capture",
    L"C:\\sandbox",
    L"C:\\cuckoo",
}};

// VM-specific DLLs that may be in system32
static constexpr std::array<const wchar_t*, 14> VM_DLLS = {{
    L"\\System32\\vboxdisp.dll",
    L"\\System32\\vboxhook.dll",
    L"\\System32\\vboxmrxnp.dll",
    L"\\System32\\vboxogl.dll",
    L"\\System32\\vboxoglarrayspu.dll",
    L"\\System32\\vboxoglcrutil.dll",
    L"\\System32\\vboxoglerrorspu.dll",
    L"\\System32\\vboxoglfeedbackspu.dll",
    L"\\System32\\vboxoglpackspu.dll",
    L"\\System32\\vboxoglpassthroughspu.dll",
    L"\\System32\\vmhgfs.dll",
    L"\\System32\\vmGuestLib.dll",
    L"\\System32\\vmGuestLibJava.dll",
    L"\\System32\\VMWSU.DLL",
}};

// ============================================================
//  Helpers
// ============================================================

static std::wstring getWindowsDir() {
    wchar_t buf[MAX_PATH] = {};
    GetWindowsDirectoryW(buf, MAX_PATH);
    return std::wstring(buf);
}

static std::wstring getSystemDir() {
    wchar_t buf[MAX_PATH] = {};
    GetSystemDirectoryW(buf, MAX_PATH);
    return std::wstring(buf);
}

static uint32_t countFilesInDirectory(const std::wstring& path) {
    std::wstring search = path + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    uint32_t count = 0;
    do {
        std::wstring name(fd.cFileName);
        if (name != L"." && name != L"..") count++;
    } while (FindNextFileW(hFind, &fd) && count < 10000);
    FindClose(hFind);
    return count;
}

static uint64_t getDriveCount() {
    DWORD driveMask = GetLogicalDrives();
    uint64_t count = 0;
    while (driveMask) {
        if (driveMask & 1) count++;
        driveMask >>= 1;
    }
    return count;
}

// ============================================================
//  Construction / lifecycle
// ============================================================

FileSystemPlugin::FileSystemPlugin() {
    m_meta.id           = "com.sandboxdetector.filesystem";
    m_meta.name         = "File System Artifact Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox/VM via filesystem artifacts: guest addition "
                          "paths, sandbox agent files, VM driver files, Wine artifacts, "
                          "drive count, directory depth, and prefetch analysis.";
    m_meta.categories   = DetectionCategory::FileSystem;
    m_meta.priority     = 40;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

FileSystemPlugin::~FileSystemPlugin() { shutdown(); }

const PluginMetadata& FileSystemPlugin::getMetadata() const noexcept { return m_meta; }
bool FileSystemPlugin::isSupported() const noexcept { return true; }

bool FileSystemPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void FileSystemPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult FileSystemPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkVmGuestAdditionPaths());
    push(checkSandboxAgentFiles());
    push(checkAnalysisToolArtifacts());
    push(checkDriveCount());
    push(checkVmDriverFiles());
    push(checkRootDirectoryFileCount());
    push(checkWineArtifacts());
    push(checkSandboxDlls());
    push(checkPrefetchDirectory());
    push(checkPagefileSizeRegistry());
    push(checkUserDirectoryDepth());
    push(checkRecentDocumentsCount());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Checks
// ============================================================

DetectionIndicator FileSystemPlugin::checkVmGuestAdditionPaths() {
    DetectionIndicator ind;
    ind.name     = "VM Guest Addition Paths";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::vector<std::wstring> found;
    for (const wchar_t* path : VM_GUEST_PATHS) {
        DWORD attrs = GetFileAttributesW(path);
        if (attrs != INVALID_FILE_ATTRIBUTES)
            found.push_back(std::wstring(path));
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "VM guest addition path(s) found (" << found.size() << "): ";
        for (size_t i = 0; i < found.size() && i < 3; ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 3) ? SandboxConfidence::Certain
                       : (found.size() >= 2) ? SandboxConfidence::High
                       :                       SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkSandboxAgentFiles() {
    DetectionIndicator ind;
    ind.name     = "Sandbox Agent Files";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::vector<std::wstring> found;
    for (const wchar_t* path : SANDBOX_AGENT_FILES) {
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
            found.push_back(std::wstring(path));
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Sandbox agent file(s) found: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkAnalysisToolArtifacts() {
    DetectionIndicator ind;
    ind.name     = "Analysis Tool Artifact Directories";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::vector<std::wstring> found;
    for (const wchar_t* path : ANALYSIS_ARTIFACTS) {
        DWORD attrs = GetFileAttributesW(path);
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_DIRECTORY))
            found.push_back(std::wstring(path));
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Analysis artifact directories present: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkDriveCount() {
    DetectionIndicator ind;
    ind.name     = "Minimal Drive Count";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;

    uint64_t count = getDriveCount();
    ind.rawValue = count;

    if (count <= 1) {
        ind.detail     = "Only " + std::to_string(count) + " logical drive(s). "
                         "Most real machines have CD-ROM or additional drives.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkVmDriverFiles() {
    DetectionIndicator ind;
    ind.name     = "VM Driver DLLs in System32";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::wstring winDir = getWindowsDir();
    std::vector<std::wstring> found;

    for (const wchar_t* suffix : VM_DLLS) {
        std::wstring full = winDir + suffix;
        if (GetFileAttributesW(full.c_str()) != INVALID_FILE_ATTRIBUTES)
            found.push_back(full);
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "VM DLL(s) found in Windows: ";
        for (size_t i = 0; i < found.size() && i < 4; ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 3) ? SandboxConfidence::Certain
                       : (found.size() >= 2) ? SandboxConfidence::High
                       :                       SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkRootDirectoryFileCount() {
    DetectionIndicator ind;
    ind.name     = "C:\\ Root File Count";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;

    uint32_t count = countFilesInDirectory(L"C:\\");
    ind.rawValue = count;

    if (count < 10) {
        ind.detail     = "C:\\ has only " + std::to_string(count)
                         + " items. Minimal install suggests fresh sandbox.";
        ind.confidence = SandboxConfidence::Medium;
    } else if (count < 5) {
        ind.detail     = "C:\\ has only " + std::to_string(count)
                         + " items. Highly suspicious.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkWineArtifacts() {
    DetectionIndicator ind;
    ind.name     = "Wine Filesystem Artifacts";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Wine maps the Unix root to Z:\ (drive)
    DWORD attrs = GetFileAttributesW(L"Z:\\");
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        // Check that Z:\etc exists (typical Wine Unix root)
        DWORD etc = GetFileAttributesW(L"Z:\\etc");
        if (etc != INVALID_FILE_ATTRIBUTES) {
            ind.detail     = "Z:\\ drive exists and Z:\\etc present — Wine Unix filesystem mapping detected.";
            ind.confidence = SandboxConfidence::Certain;
            ind.rawValue   = 1;
            return ind;
        }
        ind.detail     = "Z:\\ drive exists. Possible Wine environment.";
        ind.confidence = SandboxConfidence::Medium;
        ind.rawValue   = 1;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkSandboxDlls() {
    DetectionIndicator ind;
    ind.name     = "Sandbox Monitor DLLs Loaded";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    static constexpr std::array<const wchar_t*, 10> SANDBOX_DLLS = {{
        L"sbiedll.dll",
        L"cuckoomon.dll",
        L"api_log.dll",
        L"dir_watch.dll",
        L"pstorec.dll",
        L"vmcheck.dll",
        L"wpespy.dll",
        L"cfgapi.dll",
        L"hooksdll.dll",
        L"log_api.dll",
    }};

    std::vector<std::wstring> found;
    for (const wchar_t* dll : SANDBOX_DLLS) {
        if (GetModuleHandleW(dll) != nullptr)
            found.push_back(std::wstring(dll));
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Sandbox monitoring DLL(s) loaded in process: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkPrefetchDirectory() {
    DetectionIndicator ind;
    ind.name     = "Prefetch Directory Analysis";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;

    std::wstring prefetchPath = getWindowsDir() + L"\\Prefetch";
    DWORD attrs = GetFileAttributesW(prefetchPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        // Prefetch folder absent — disabled or not a workstation
        ind.detail     = "Windows Prefetch directory absent. Disabled in sandbox or server OS.";
        ind.confidence = SandboxConfidence::Low;
        ind.rawValue   = 0;
        return ind;
    }

    uint32_t count = countFilesInDirectory(prefetchPath);
    ind.rawValue = count;

    if (count < 5) {
        ind.detail     = "Prefetch directory has only " + std::to_string(count)
                         + " file(s). Fresh/minimal install suggests sandbox.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkPagefileSizeRegistry() {
    DetectionIndicator ind;
    ind.name     = "Pagefile Configuration";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Check registry for pagefile configuration
    auto val = WinUtils::regQueryValue(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        L"PagingFiles");

    if (val.has_value()) {
        std::string strVal = val->asString();
        // Empty PagingFiles = no pagefile = sandbox/minimal VM
        if (strVal.empty() || strVal == " ") {
            ind.detail     = "PagingFiles registry value is empty — pagefile disabled. Common in sandboxes.";
            ind.confidence = SandboxConfidence::Low;
            ind.rawValue   = 0;
        }
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkUserDirectoryDepth() {
    DetectionIndicator ind;
    ind.name     = "User Profile Directory File Count";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;

    wchar_t profileBuf[MAX_PATH] = {};
    if (!SHGetSpecialFolderPathW(nullptr, profileBuf, CSIDL_PROFILE, FALSE)) {
        DWORD sz = MAX_PATH;
        GetUserProfileDirectoryW(GetCurrentProcessToken(), profileBuf, &sz);
    }

    std::wstring profileDir(profileBuf);
    if (profileDir.empty()) return ind;

    // Count top-level entries in user profile
    uint32_t count = countFilesInDirectory(profileDir);
    ind.rawValue = count;

    if (count < 5) {
        ind.detail     = "User profile directory has only " + std::to_string(count)
                         + " items. New/template user = sandbox.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator FileSystemPlugin::checkRecentDocumentsCount() {
    DetectionIndicator ind;
    ind.name     = "Recent Documents Count";
    ind.category = DetectionCategory::FileSystem;
    ind.confidence = SandboxConfidence::None;

    wchar_t recentBuf[MAX_PATH] = {};
    SHGetSpecialFolderPathW(nullptr, recentBuf, CSIDL_RECENT, FALSE);
    std::wstring recentDir(recentBuf);
    if (recentDir.empty()) return ind;

    uint32_t count = countFilesInDirectory(recentDir);
    ind.rawValue = count;

    if (count == 0) {
        ind.detail     = "Recent Documents folder is empty (0 files). No user activity detected. Sandbox indicator.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
