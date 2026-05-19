#include "plugins/NativeApiPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <array>

// ─── Additional NT structs not always in SDK headers ────────────────────────
// winternl.h (MinGW) already defines SYSTEM_CODEINTEGRITY_INFORMATION.
// Only define it ourselves if winternl.h hasn't provided it.
#if !defined(__WINTERNL_H) && !defined(_WINTERNL_)
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;
#endif

#define CODEINTEGRITY_OPTION_ENABLED                    0x0001
#define CODEINTEGRITY_OPTION_TESTSIGN                   0x0002
#define CODEINTEGRITY_OPTION_UMCI_ENABLED               0x0004

typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved[2];
    PVOID     Base;
    ULONG     Size;
    ULONG     Flags;
    USHORT    Index;
    USHORT    NameLength;
    USHORT    LoadCount;
    USHORT    PathLength;
    CHAR      ImageName[256];
} SYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG         Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation          = 0,
    MemoryMappedFilenameInformation = 2
} MEMORY_INFORMATION_CLASS;

// NtQueryVirtualMemory
using PFN_NtQueryVirtualMemory = NTSTATUS(NTAPI*)(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    ULONG    MemoryInformationClass,
    PVOID    Buffer,
    SIZE_T   Length,
    PSIZE_T  ResultLength
);

// RtlGetVersion
using PFN_RtlGetVersion = NTSTATUS(NTAPI*)(PRTL_OSVERSIONINFOW lpVersionInformation);

// KUSER_SHARED_DATA layout (partial, Windows 10)
struct KUSER_SHARED_DATA_PARTIAL {
    ULONG   TickCountLowDeprecated;
    ULONG   TickCountMultiplier;
    // offset 0x08: KSYSTEM_TIME InterruptTime
    ULONG   InterruptTimeLow;
    ULONG   InterruptTimeHigh1;
    ULONG   InterruptTimeHigh2;
    // offset 0x14: KSYSTEM_TIME SystemTime  
    ULONG   SystemTimeLow;
    ULONG   SystemTimeHigh1;
    ULONG   SystemTimeHigh2;
    // ... more fields
};

#define KUSER_SHARED_DATA_VA 0x7FFE0000ULL

// Offset of KdDebuggerEnabled in KUSER_SHARED_DATA (constant across x86/x64)
#define KUSER_SHARED_DEBUGGER_OFFSET 0x2D4

// NtMajorVersion is at 0x26C in KUSER_SHARED_DATA
#define KUSER_SHARED_NTMAJORVER_OFFSET 0x26C
#define KUSER_SHARED_NTMINORVER_OFFSET 0x270

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  VM device object paths to probe via NtCreateFile
// ============================================================

static constexpr std::array<const wchar_t*, 8> VM_DEVICE_PATHS = {{
    L"\\Device\\VBoxGuest",         // VirtualBox guest driver
    L"\\Device\\VBoxMiniRdr",       // VirtualBox mini-redirector
    L"\\Device\\VBoxTrayIPC",       // VirtualBox tray IPC
    L"\\Device\\vmci",              // VMware VMCI
    L"\\Device\\vmx_svga",          // VMware SVGA
    L"\\Device\\hgfs",              // VMware HGFS (shared folders)
    L"\\Device\\VmMdPriv",          // VMware private
    L"\\Device\\VirtualMachineInput"// Hyper-V input
}};

// Known VM/analysis kernel drivers to look for in module list
static constexpr std::array<const char*, 16> VM_KERNEL_DRIVERS = {{
    "vboxguest.sys",  "vboxmouse.sys",  "vboxsf.sys",     "vboxvideo.sys",
    "vmci.sys",       "vmhgfs.sys",     "vmmouse.sys",    "vmxnet.sys",
    "xenevtchn.sys",  "xenpci.sys",     "xenvbd.sys",     "xennet.sys",
    "vioscsi.sys",    "viostor.sys",    "balloon.sys",     "SbieDrv.sys"
}};

// ============================================================
//  Construction / lifecycle
// ============================================================

NativeApiPlugin::NativeApiPlugin() {
    m_meta.id           = "com.sandboxdetector.nativeapi";
    m_meta.name         = "Native API (NT) Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox/VM via undocumented NT Native API: "
                          "kernel debugger info, hypervisor info, code integrity, "
                          "VM device objects, kernel driver list, KUSER_SHARED_DATA "
                          "fields, Sandboxie KnownDlls, foreground window, and "
                          "RtlGetVersion consistency.";
    m_meta.categories   = DetectionCategory::NativeAPI;
    m_meta.priority     = 7;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

NativeApiPlugin::~NativeApiPlugin() { shutdown(); }

const PluginMetadata& NativeApiPlugin::getMetadata() const noexcept { return m_meta; }
bool NativeApiPlugin::isSupported() const noexcept { return true; }

bool NativeApiPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void NativeApiPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult NativeApiPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkKernelDebuggerInfo());
    push(checkHypervisorInfo());
    push(checkCodeIntegrity());
    push(checkVmDeviceObjects());
    push(checkSandboxieKnownDll());
    push(checkSystemModuleDrivers());
    push(checkForegroundWindow());
    push(checkKuserSharedData());
    push(checkProcessHandleCount());
    push(checkThreadHideFromDebugger());
    push(checkNtdllFilePath());
    push(checkRtlVersionConsistency());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Checks
// ============================================================

DetectionIndicator NativeApiPlugin::checkKernelDebuggerInfo() {
    DetectionIndicator ind;
    ind.name     = "Kernel Debugger Present";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    SYSTEM_KERNEL_DEBUGGER_INFORMATION info = {};
    ULONG retLen = 0;
    NTSTATUS status = WinUtils::ntQuerySystemInformation(
        SystemKernelDebuggerInformation, &info, sizeof(info), &retLen);

    if (NT_SUCCESS(status)) {
        ind.rawValue = info.KernelDebuggerEnabled ? 1 : 0;
        if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent) {
            ind.detail     = "NtQuerySystemInformation(SystemKernelDebuggerInformation): "
                             "KernelDebuggerEnabled=TRUE, NotPresent=FALSE. Kernel debugger attached.";
            ind.confidence = SandboxConfidence::Certain;
        } else if (info.KernelDebuggerEnabled) {
            ind.detail     = "KernelDebuggerEnabled=TRUE (KdDebuggerEnabled bit set in KUSER_SHARED_DATA).";
            ind.confidence = SandboxConfidence::High;
        }
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkHypervisorInfo() {
    DetectionIndicator ind;
    ind.name     = "Hypervisor Query Information";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    SYSTEM_HYPERVISOR_QUERY_INFORMATION info = {};
    ULONG retLen = 0;
    NTSTATUS status = WinUtils::ntQuerySystemInformation(
        SystemHypervisorQueryInformation, &info, sizeof(info), &retLen);

    if (NT_SUCCESS(status)) {
        ind.rawValue = info.HypervisorPresent ? 1 : 0;
        if (info.HypervisorPresent) {
            std::ostringstream ss;
            ss << "NtQuerySystemInformation(SystemHypervisorQueryInformation): "
               << "HypervisorPresent=TRUE";
            if (info.HypervisorConnected)         ss << ", Connected";
            if (info.HypervisorDebuggingAllowed)  ss << ", DebuggingAllowed";
            ss << ". Enlightenments=0x" << std::hex << info.EnabledEnlightenments;
            ind.detail     = ss.str();
            ind.confidence = SandboxConfidence::Certain;
        }
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkCodeIntegrity() {
    DetectionIndicator ind;
    ind.name     = "Code Integrity Disabled";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    SYSTEM_CODEINTEGRITY_INFORMATION info = {};
    info.Length = sizeof(info);
    ULONG retLen = 0;
    // SystemCodeIntegrityInformation = 103
    NTSTATUS status = WinUtils::ntQuerySystemInformation(103, &info, sizeof(info), &retLen);

    if (NT_SUCCESS(status)) {
        ind.rawValue = info.CodeIntegrityOptions;
        bool ciEnabled    = (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) != 0;
        bool testSigning  = (info.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN) != 0;

        if (!ciEnabled) {
            ind.detail     = "Code Integrity is disabled (CodeIntegrityOptions=0x"
                             + [&]{ std::ostringstream s; s << std::hex << info.CodeIntegrityOptions; return s.str(); }()
                             + "). Sandbox environments often disable driver signing.";
            ind.confidence = SandboxConfidence::Medium;
        } else if (testSigning) {
            ind.detail     = "Test signing mode enabled. Unsigned/self-signed kernel drivers can load. "
                             "Common in VM/sandbox setups.";
            ind.confidence = SandboxConfidence::Medium;
        }
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkVmDeviceObjects() {
    DetectionIndicator ind;
    ind.name     = "VM Device Objects";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    using PFN_NtCreateFile = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    using PFN_NtClose = NTSTATUS(NTAPI*)(HANDLE);

    auto NtCreateFile = reinterpret_cast<PFN_NtCreateFile>(
        GetProcAddress(hNtdll, "NtCreateFile"));
    auto NtClose = reinterpret_cast<PFN_NtClose>(
        GetProcAddress(hNtdll, "NtClose"));

    if (!NtCreateFile || !NtClose) return ind;

    std::vector<std::wstring> found;

    for (const wchar_t* devPath : VM_DEVICE_PATHS) {
        UNICODE_STRING uniStr;
        std::wstring path(devPath);
        uniStr.Buffer        = path.data();
        uniStr.Length        = static_cast<USHORT>(path.size() * sizeof(wchar_t));
        uniStr.MaximumLength = uniStr.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES oa = {};
        InitializeObjectAttributes(&oa, &uniStr, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        IO_STATUS_BLOCK iosb = {};
        HANDLE hDev = nullptr;
        NTSTATUS status = NtCreateFile(
            &hDev,
            SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            &oa, &iosb,
            nullptr, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            nullptr, 0);

        if (NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
            // Device exists (STATUS_ACCESS_DENIED means it's present but we lack rights)
            found.push_back(devPath);
            if (NT_SUCCESS(status) && hDev) NtClose(hDev);
        }
    }

    ind.rawValue = static_cast<uint64_t>(found.size());
    if (!found.empty()) {
        std::ostringstream ss;
        ss << "VM device object(s) accessible: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 2) ? SandboxConfidence::Certain
                       :                        SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkSandboxieKnownDll() {
    DetectionIndicator ind;
    ind.name     = "Sandboxie in KnownDlls";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    using PFN_NtOpenKey = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

    auto NtOpenKey = reinterpret_cast<PFN_NtOpenKey>(GetProcAddress(hNtdll, "NtOpenKey"));
    if (!NtOpenKey) return ind;

    static constexpr std::array<const wchar_t*, 3> SBIE_KNOWN_DLLS = {{
        L"\\KnownDlls\\SbieDll.dll",
        L"\\KnownDlls\\SbieApi.dll",
        L"\\KnownDlls\\SandboxieRpcSs.dll"
    }};

    std::vector<std::wstring> found;
    for (const wchar_t* path : SBIE_KNOWN_DLLS) {
        UNICODE_STRING uniStr;
        std::wstring p(path);
        uniStr.Buffer        = p.data();
        uniStr.Length        = static_cast<USHORT>(p.size() * sizeof(wchar_t));
        uniStr.MaximumLength = uniStr.Length + sizeof(wchar_t);

        OBJECT_ATTRIBUTES oa = {};
        InitializeObjectAttributes(&oa, &uniStr, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        HANDLE hKey = nullptr;
        // We're opening a section object (KnownDlls), not a key — but NtOpenKey 
        // conveniently returns STATUS_OBJECT_TYPE_MISMATCH if the path exists
        NTSTATUS status = NtOpenKey(&hKey, KEY_READ, &oa);
        if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
            status != STATUS_OBJECT_PATH_NOT_FOUND) {
            found.push_back(path);
            if (hKey) CloseHandle(hKey);
        }
    }

    ind.rawValue = static_cast<uint64_t>(found.size());
    if (!found.empty()) {
        ind.detail     = "Sandboxie DLL(s) found in \\KnownDlls namespace: "
                         + WinUtils::toNarrow(found[0]);
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkSystemModuleDrivers() {
    DetectionIndicator ind;
    ind.name     = "VM Kernel Driver Modules";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // SystemModuleInformation = 11
    ULONG bufLen = 0;
    WinUtils::ntQuerySystemInformation(11, nullptr, 0, &bufLen);
    if (bufLen == 0) bufLen = 1024 * 1024; // fallback 1MB

    std::vector<uint8_t> buf(bufLen + 4096);
    NTSTATUS status = WinUtils::ntQuerySystemInformation(
        11, buf.data(), static_cast<ULONG>(buf.size()), &bufLen);
    if (!NT_SUCCESS(status)) return ind;

    auto* info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(buf.data());
    std::vector<std::string> found;

    for (ULONG i = 0; i < info->Count; ++i) {
        const char* imgName = info->Modules[i].ImageName;
        std::string nameLo(imgName);
        std::transform(nameLo.begin(), nameLo.end(), nameLo.begin(), ::tolower);

        // Get just the filename
        size_t slash = nameLo.rfind('\\');
        std::string fileOnly = (slash != std::string::npos) ? nameLo.substr(slash + 1) : nameLo;

        for (const char* vmDrv : VM_KERNEL_DRIVERS) {
            if (fileOnly == vmDrv) {
                found.push_back(std::string(imgName));
                break;
            }
        }
    }

    ind.rawValue = static_cast<uint64_t>(found.size());
    if (!found.empty()) {
        std::ostringstream ss;
        ss << "VM/analysis kernel driver(s) loaded (" << found.size() << "): ";
        for (size_t i = 0; i < found.size() && i < 4; ++i) {
            if (i) ss << ", ";
            ss << found[i];
        }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 3) ? SandboxConfidence::Certain
                       : (found.size() >= 2) ? SandboxConfidence::High
                       :                        SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkForegroundWindow() {
    DetectionIndicator ind;
    ind.name     = "Foreground Window Absent";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HWND hFg = GetForegroundWindow();
    ind.rawValue = (hFg != nullptr) ? 1 : 0;

    if (!hFg) {
        ind.detail     = "GetForegroundWindow() returned NULL. "
                         "No foreground window — headless/hidden sandbox desktop.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkKuserSharedData() {
    DetectionIndicator ind;
    ind.name     = "KUSER_SHARED_DATA Debug Fields";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // KUSER_SHARED_DATA is at 0x7FFE0000 (user-mode read-only mapping of kernel page)
    const uint8_t* kusd = reinterpret_cast<const uint8_t*>(KUSER_SHARED_DATA_VA);

    // KdDebuggerEnabled byte at 0x2D4
    uint8_t kdEnabled = *(kusd + KUSER_SHARED_DEBUGGER_OFFSET);
    ind.rawValue = kdEnabled;

    if (kdEnabled & 0x01) {
        ind.detail     = "KUSER_SHARED_DATA.KdDebuggerEnabled=1 at offset 0x2D4. "
                         "Kernel debugger enabled or system in debug mode.";
        ind.confidence = SandboxConfidence::High;
    }

    // Validate NtMajorVersion consistency with GetVersionEx
    DWORD kusdMajor = *reinterpret_cast<const DWORD*>(kusd + KUSER_SHARED_NTMAJORVER_OFFSET);
    DWORD kusdMinor = *reinterpret_cast<const DWORD*>(kusd + KUSER_SHARED_NTMINORVER_OFFSET);

    OSVERSIONINFOW osv = {};
    osv.dwOSVersionInfoSize = sizeof(osv);
#pragma warning(suppress: 4996)
    GetVersionExW(&osv);

    if (kusdMajor != osv.dwMajorVersion || kusdMinor != osv.dwMinorVersion) {
        ind.detail    += (ind.detail.empty() ? "" : " | ")
                       + std::string("KUSER_SHARED_DATA version mismatch: KUSD=")
                       + std::to_string(kusdMajor) + "." + std::to_string(kusdMinor)
                       + " vs GetVersionEx=" + std::to_string(osv.dwMajorVersion)
                       + "." + std::to_string(osv.dwMinorVersion)
                       + ". Sandbox may be patching GetVersionEx.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkProcessHandleCount() {
    DetectionIndicator ind;
    ind.name     = "Process Handle Count Anomaly";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;

    DWORD handleCount = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handleCount)) return ind;
    ind.rawValue = handleCount;

    // Normal process at startup: ~30-100 handles
    // A sandbox that intercepts all handle operations may see 0 or inflated counts
    if (handleCount < 10) {
        ind.detail     = "Process has only " + std::to_string(handleCount)
                         + " handles open. Abnormally low — possibly a stripped sandbox.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkThreadHideFromDebugger() {
    DetectionIndicator ind;
    ind.name     = "ThreadHideFromDebugger";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    using PFN_NtSetInformationThread = NTSTATUS(NTAPI*)(
        HANDLE, UINT, PVOID, ULONG);

    auto NtSetInformationThread = reinterpret_cast<PFN_NtSetInformationThread>(
        GetProcAddress(hNtdll, "NtSetInformationThread"));
    if (!NtSetInformationThread) return ind;

    // ThreadHideFromDebugger = 0x11
    // In normal conditions this call succeeds silently.
    // Sandboxes that monitor NtSetInformationThread may block or log it.
    NTSTATUS status = NtSetInformationThread(
        GetCurrentThread(), 0x11, nullptr, 0);

    ind.rawValue = static_cast<uint64_t>(status);
    // If the call fails with an unexpected status, the sandbox is intercepting it
    if (!NT_SUCCESS(status) && status != (NTSTATUS)0xC0000008L /* STATUS_INVALID_HANDLE */) {
        std::ostringstream ss;
        ss << "NtSetInformationThread(ThreadHideFromDebugger) returned unexpected status 0x"
           << std::hex << status << ". Sandbox may be intercepting this call.";
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkNtdllFilePath() {
    DetectionIndicator ind;
    ind.name     = "ntdll.dll Mapped File Path";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    auto NtQueryVirtualMemory = reinterpret_cast<PFN_NtQueryVirtualMemory>(
        GetProcAddress(hNtdll, "NtQueryVirtualMemory"));
    if (!NtQueryVirtualMemory) return ind;

    // Buffer for UNICODE_STRING + wchar path
    struct { UNICODE_STRING us; wchar_t buf[512]; } nameInfo = {};
    SIZE_T retLen = 0;

    NTSTATUS status = NtQueryVirtualMemory(
        GetCurrentProcess(),
        reinterpret_cast<PVOID>(hNtdll),
        static_cast<ULONG>(MemoryMappedFilenameInformation),
        &nameInfo, sizeof(nameInfo), &retLen);

    if (NT_SUCCESS(status) && nameInfo.us.Length > 0) {
        std::wstring path(nameInfo.us.Buffer, nameInfo.us.Length / sizeof(wchar_t));
        std::wstring pathLo = path;
        std::transform(pathLo.begin(), pathLo.end(), pathLo.begin(), ::towlower);

        // Should be something like \Device\HarddiskVolume3\Windows\System32\ntdll.dll
        // Sandbox may remap ntdll from an unusual path
        if (pathLo.find(L"ntdll.dll") == std::wstring::npos) {
            ind.detail     = "ntdll.dll mapped from unexpected path: "
                             + WinUtils::toNarrow(path);
            ind.confidence = SandboxConfidence::High;
            ind.rawValue   = 1;
        } else if (pathLo.find(L"system32") == std::wstring::npos &&
                   pathLo.find(L"syswow64") == std::wstring::npos) {
            ind.detail     = "ntdll.dll not mapped from System32/SysWOW64: "
                             + WinUtils::toNarrow(path);
            ind.confidence = SandboxConfidence::High;
            ind.rawValue   = 1;
        }
    }
    return ind;
}

DetectionIndicator NativeApiPlugin::checkRtlVersionConsistency() {
    DetectionIndicator ind;
    ind.name     = "RtlGetVersion vs GetVersionEx Consistency";
    ind.category = DetectionCategory::NativeAPI;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    auto RtlGetVersion = reinterpret_cast<PFN_RtlGetVersion>(
        GetProcAddress(hNtdll, "RtlGetVersion"));
    if (!RtlGetVersion) return ind;

    RTL_OSVERSIONINFOW rtlVer = {};
    rtlVer.dwOSVersionInfoSize = sizeof(rtlVer);
    NTSTATUS status = RtlGetVersion(&rtlVer);
    if (!NT_SUCCESS(status)) return ind;

    OSVERSIONINFOW apiVer = {};
    apiVer.dwOSVersionInfoSize = sizeof(apiVer);
#pragma warning(suppress: 4996)
    GetVersionExW(&apiVer);

    // RtlGetVersion always returns the true version; GetVersionEx is compatibility-shim'ed
    // A sandbox may patch GetVersionEx to lie about the OS version
    if (rtlVer.dwMajorVersion != apiVer.dwMajorVersion ||
        rtlVer.dwMinorVersion != apiVer.dwMinorVersion ||
        rtlVer.dwBuildNumber  != apiVer.dwBuildNumber) {
        std::ostringstream ss;
        ss << "Version mismatch: RtlGetVersion=" << rtlVer.dwMajorVersion
           << "." << rtlVer.dwMinorVersion << " Build " << rtlVer.dwBuildNumber
           << " vs GetVersionEx=" << apiVer.dwMajorVersion
           << "." << apiVer.dwMinorVersion << " Build " << apiVer.dwBuildNumber
           << ". Sandbox may be patching GetVersionEx.";
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Medium;
        ind.rawValue   = 1;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
