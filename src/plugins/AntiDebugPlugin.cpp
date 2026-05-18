#include "plugins/AntiDebugPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <sstream>
#include <algorithm>
#include <chrono>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// Process information classes not always in SDK
static constexpr UINT ProcessDebugPort         = 7;
static constexpr UINT ProcessDebugObjectHandle = 30;
static constexpr UINT ProcessDebugFlags        = 31;

// ============================================================
//  Construction
// ============================================================

AntiDebugPlugin::AntiDebugPlugin() {
    m_meta.id           = "com.sandboxdetector.antidebug";
    m_meta.name         = "Anti-Debug Detection Plugin";
    m_meta.version      = "1.5.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects debugger and analysis tool presence via PEB flags, "
                           "NtQueryInformationProcess, heap flags, debug registers, "
                           "exception tricks, and parent process inspection.";
    m_meta.categories   = DetectionCategory::AntiDebug;
    m_meta.priority     = 8;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

AntiDebugPlugin::~AntiDebugPlugin() { shutdown(); }

const PluginMetadata& AntiDebugPlugin::getMetadata() const noexcept { return m_meta; }
bool AntiDebugPlugin::isSupported() const noexcept { return true; }

bool AntiDebugPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void AntiDebugPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult AntiDebugPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkIsDebuggerPresent());
    push(checkRemoteDebuggerPresent());
    push(checkNtDebugPort());
    push(checkNtDebugFlags());
    push(checkNtDebugObjectHandle());
    push(checkHeapFlags());
    push(checkNtGlobalFlag());
    push(checkHardwareBreakpoints());
    push(checkOutputDebugStringTiming());
    push(checkParentProcessName());
    push(checkCloseHandleTrick());
    push(checkDebuggerWindowClass());

    result.sandboxDetected  = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();
    result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Check: IsDebuggerPresent() — PEB.BeingDebugged
// ============================================================

DetectionIndicator AntiDebugPlugin::checkIsDebuggerPresent() {
    DetectionIndicator ind;
    ind.name     = "IsDebuggerPresent (PEB.BeingDebugged)";
    ind.category = DetectionCategory::AntiDebug;

    BOOL result = IsDebuggerPresent();
    ind.rawValue = result ? 1 : 0;

    if (result) {
        ind.detail     = "IsDebuggerPresent() returned TRUE — PEB.BeingDebugged is set";
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail     = "IsDebuggerPresent() returned FALSE";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: CheckRemoteDebuggerPresent()
// ============================================================

DetectionIndicator AntiDebugPlugin::checkRemoteDebuggerPresent() {
    DetectionIndicator ind;
    ind.name     = "CheckRemoteDebuggerPresent";
    ind.category = DetectionCategory::AntiDebug;

    BOOL isPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isPresent);
    ind.rawValue = isPresent ? 1 : 0;

    if (isPresent) {
        ind.detail     = "CheckRemoteDebuggerPresent() — remote debugger attached";
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail     = "CheckRemoteDebuggerPresent() returned FALSE";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: NtQueryInformationProcess(ProcessDebugPort)
//
//  Returns non-zero HANDLE if process is being debugged.
//  This bypasses user-space hooks on IsDebuggerPresent.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkNtDebugPort() {
    DetectionIndicator ind;
    ind.name     = "NtQueryInformationProcess (DebugPort)";
    ind.category = DetectionCategory::AntiDebug;

    HANDLE debugPort = nullptr;
    ULONG returnLen  = 0;
    NTSTATUS status  = WinUtils::ntQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        &returnLen);

    if (!NT_SUCCESS(status)) {
        ind.detail     = "NtQueryInformationProcess(ProcessDebugPort) failed";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    ind.rawValue = reinterpret_cast<uint64_t>(debugPort);

    if (debugPort != nullptr) {
        std::ostringstream detail;
        detail << "ProcessDebugPort = 0x" << std::hex
               << reinterpret_cast<uintptr_t>(debugPort) << " (non-zero)";
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail     = "ProcessDebugPort = NULL (no debugger)";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: NtQueryInformationProcess(ProcessDebugFlags)
//
//  Returns 0 if EPROCESS.NoDebugInherit is clear (= being debugged).
// ============================================================

DetectionIndicator AntiDebugPlugin::checkNtDebugFlags() {
    DetectionIndicator ind;
    ind.name     = "NtQueryInformationProcess (DebugFlags)";
    ind.category = DetectionCategory::AntiDebug;

    ULONG debugFlags = 0;
    ULONG returnLen  = 0;
    NTSTATUS status  = WinUtils::ntQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugFlags,
        &debugFlags,
        sizeof(debugFlags),
        &returnLen);

    if (!NT_SUCCESS(status)) {
        ind.detail     = "NtQueryInformationProcess(ProcessDebugFlags) failed";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    ind.rawValue = debugFlags;

    // NoDebugInherit == 0 means process IS being debugged
    if (debugFlags == 0) {
        ind.detail     = "ProcessDebugFlags = 0 — process is being debugged";
        ind.confidence = SandboxConfidence::Certain;
    } else {
        std::ostringstream detail;
        detail << "ProcessDebugFlags = 0x" << std::hex << debugFlags << " (normal)";
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: NtQueryInformationProcess(ProcessDebugObjectHandle)
//
//  Returns a valid debug object handle if attached debugger exists.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkNtDebugObjectHandle() {
    DetectionIndicator ind;
    ind.name     = "NtQueryInformationProcess (DebugObjectHandle)";
    ind.category = DetectionCategory::AntiDebug;

    HANDLE debugObject = nullptr;
    ULONG returnLen    = 0;
    NTSTATUS status    = WinUtils::ntQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &debugObject,
        sizeof(debugObject),
        &returnLen);

    // STATUS_PORT_NOT_SET (0xC0000353) means no debug object = clean
    ind.rawValue = reinterpret_cast<uint64_t>(debugObject);

    if (NT_SUCCESS(status) && debugObject != nullptr) {
        std::ostringstream detail;
        detail << "ProcessDebugObjectHandle = 0x" << std::hex
               << reinterpret_cast<uintptr_t>(debugObject);
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::Certain;
        CloseHandle(debugObject);
    } else {
        ind.detail     = "ProcessDebugObjectHandle not set (no debug object)";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Heap Flags
//
//  Heap header FLAGS and FORCE_FLAGS fields are set to unusual
//  values when a debugger is present (or when page heap is enabled).
//  PEB.ProcessHeap->Flags normally = 0x2; under debugger = 0x50000062.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkHeapFlags() {
    DetectionIndicator ind;
    ind.name     = "Heap Flags (Debugger Marker)";
    ind.category = DetectionCategory::AntiDebug;

#if defined(_WIN64)
    // PEB at GS:[0x60], ProcessHeap at PEB+0x30
    PVOID pPeb          = reinterpret_cast<PVOID>(__readgsqword(0x60));
    PVOID pHeap         = *reinterpret_cast<PVOID*>(
                              static_cast<BYTE*>(pPeb) + 0x30);
    ULONG heapFlags     = *reinterpret_cast<ULONG*>(
                              static_cast<BYTE*>(pHeap) + 0x70);
    ULONG heapForceFlags= *reinterpret_cast<ULONG*>(
                              static_cast<BYTE*>(pHeap) + 0x74);
#else
    // 32-bit: PEB at FS:[0x30], ProcessHeap at PEB+0x18
    PVOID pPeb          = reinterpret_cast<PVOID>(__readfsdword(0x30));
    PVOID pHeap         = *reinterpret_cast<PVOID*>(
                              static_cast<BYTE*>(pPeb) + 0x18);
    ULONG heapFlags     = *reinterpret_cast<ULONG*>(
                              static_cast<BYTE*>(pHeap) + 0x40);
    ULONG heapForceFlags= *reinterpret_cast<ULONG*>(
                              static_cast<BYTE*>(pHeap) + 0x44);
#endif

    ind.rawValue = (static_cast<uint64_t>(heapFlags) << 32) | heapForceFlags;

    std::ostringstream detail;
    detail << "Heap.Flags=0x" << std::hex << heapFlags
           << " ForceFlags=0x" << heapForceFlags;
    ind.detail = detail.str();

    // Normal: Flags=0x2 (HEAP_GROWABLE), ForceFlags=0x0
    // Debug:  Flags may have 0x50000062, ForceFlags non-zero
    bool suspicious = ((heapFlags & ~0x2u) != 0) || (heapForceFlags != 0);

    if (suspicious) {
        ind.confidence = SandboxConfidence::High;
        ind.detail += " — suspicious (debugger/pageheap markers)";
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: PEB.NtGlobalFlag
//
//  Under a debugger: NtGlobalFlag has bits FLG_HEAP_ENABLE_TAIL_CHECK
//  (0x10), FLG_HEAP_ENABLE_FREE_CHECK (0x20), FLG_HEAP_VALIDATE_PARAMETERS
//  (0x40) set — combined = 0x70.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkNtGlobalFlag() {
    DetectionIndicator ind;
    ind.name     = "PEB.NtGlobalFlag";
    ind.category = DetectionCategory::AntiDebug;

#if defined(_WIN64)
    PVOID pPeb       = reinterpret_cast<PVOID>(__readgsqword(0x60));
    ULONG ntGlobal   = *reinterpret_cast<ULONG*>(static_cast<BYTE*>(pPeb) + 0xBC);
#else
    PVOID pPeb       = reinterpret_cast<PVOID>(__readfsdword(0x30));
    ULONG ntGlobal   = *reinterpret_cast<ULONG*>(static_cast<BYTE*>(pPeb) + 0x68);
#endif

    ind.rawValue = ntGlobal;

    std::ostringstream detail;
    detail << "PEB.NtGlobalFlag = 0x" << std::hex << ntGlobal;
    ind.detail = detail.str();

    // 0x70 = standard debug-mode heap flags
    static constexpr ULONG DEBUG_FLAGS = 0x70;
    if ((ntGlobal & DEBUG_FLAGS) == DEBUG_FLAGS) {
        ind.detail    += " — 0x70 bits set (debugger heap flags)";
        ind.confidence = SandboxConfidence::High;
    } else if (ntGlobal != 0) {
        ind.detail    += " — non-zero (possibly harmless, but unusual)";
        ind.confidence = SandboxConfidence::Low;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Hardware Breakpoints via GetThreadContext
//
//  DR0–DR3 registers are non-zero if hardware breakpoints are set.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkHardwareBreakpoints() {
    DetectionIndicator ind;
    ind.name     = "Hardware Breakpoints (DR Registers)";
    ind.category = DetectionCategory::AntiDebug;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        ind.detail     = "GetThreadContext failed";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    uint64_t drBits = ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3;
    ind.rawValue = drBits;

    std::ostringstream detail;
    detail << "DR0=0x" << std::hex << ctx.Dr0
           << " DR1=0x" << ctx.Dr1
           << " DR2=0x" << ctx.Dr2
           << " DR3=0x" << ctx.Dr3
           << " DR7=0x" << ctx.Dr7;
    ind.detail = detail.str();

    if (drBits != 0) {
        ind.detail    += " — hardware breakpoints active";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: OutputDebugString Timing Trick
//
//  If no debugger is attached, SetLastError + OutputDebugString
//  should preserve the error code. Under a debugger, GetLastError()
//  returns 0 afterwards due to DbgUiConvertStateChangeStructure.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkOutputDebugStringTiming() {
    DetectionIndicator ind;
    ind.name     = "OutputDebugString Error Code Trick";
    ind.category = DetectionCategory::AntiDebug;

    SetLastError(0xDEADBEEF);
    OutputDebugStringA("SandboxDetector probe");
    DWORD err = GetLastError();
    ind.rawValue = err;

    std::ostringstream detail;
    detail << "GetLastError after OutputDebugString = 0x" << std::hex << err;
    ind.detail = detail.str();

    if (err == 0) {
        ind.detail    += " — error code cleared (debugger consuming the string)";
        ind.confidence = SandboxConfidence::Medium;
    } else if (err == 0xDEADBEEF) {
        ind.detail    += " — preserved (no debugger)";
        ind.confidence = SandboxConfidence::None;
    } else {
        ind.detail    += " — unexpected value";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: Parent Process Name
//
//  Normal processes are spawned from explorer.exe, cmd.exe, powershell,
//  or a legitimate launcher. If parent is a known debugger or sandbox
//  runner, that's a strong signal.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkParentProcessName() {
    DetectionIndicator ind;
    ind.name     = "Parent Process Name";
    ind.category = DetectionCategory::AntiDebug;

    static const std::vector<std::wstring> suspiciousParents = {
        L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
        L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
        L"idaw.exe", L"idaw64.exe", L"idat.exe", L"idat64.exe",
        L"radare2.exe", L"r2.exe", L"cutter.exe",
        L"immunity debugger.exe", L"immunitydebugger.exe",
        L"devenv.exe", L"vsdebug.exe",
        L"cuckoo.py", L"analyzer.py", L"agent.py",
        L"python.exe", L"pythonw.exe",  // when parent of a PE sample
        L"sandboxrpc.exe",
    };

    // Get our own PID and parent PID via snapshot
    DWORD myPid = GetCurrentProcessId();
    DWORD parentPid = 0;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (pe.th32ProcessID == myPid) {
                    parentPid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    if (parentPid == 0) {
        ind.detail     = "Could not determine parent process";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    std::optional<std::wstring> parentPath = WinUtils::getProcessPath(parentPid);
    std::wstring parentName;

    if (parentPath) {
        // Extract filename
        size_t sep = parentPath->find_last_of(L"\\/");
        parentName = (sep != std::wstring::npos)
                     ? parentPath->substr(sep + 1)
                     : *parentPath;
    } else {
        ind.rawValue   = parentPid;
        ind.detail     = "Parent PID=" + std::to_string(parentPid) + " (path unavailable)";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    // Case-insensitive match
    std::wstring parentLower = parentName;
    std::transform(parentLower.begin(), parentLower.end(),
                   parentLower.begin(), ::towlower);

    bool found = false;
    for (const auto& susp : suspiciousParents) {
        std::wstring suspLower = susp;
        std::transform(suspLower.begin(), suspLower.end(),
                       suspLower.begin(), ::towlower);
        if (parentLower == suspLower) { found = true; break; }
    }

    ind.rawValue = parentPid;

    std::ostringstream detail;
    detail << "Parent process: \"" << WinUtils::toNarrow(parentName)
           << "\" (PID " << parentPid << ")";
    ind.detail = detail.str();

    if (found) {
        ind.detail    += " — known debugger/analysis tool";
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: CloseHandle(INVALID_HANDLE_VALUE) Exception Trick
//
//  Closing an invalid handle raises EXCEPTION_INVALID_HANDLE
//  only when a debugger is attached (debugger gets first-chance exception).
//  We catch it with SEH; if we reach the handler with the right code,
//  a debugger was present.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkCloseHandleTrick() {
    DetectionIndicator ind;
    ind.name     = "CloseHandle Invalid Handle Exception";
    ind.category = DetectionCategory::AntiDebug;

    bool debuggerCaught = false;

    // Use ULONG_PTR to avoid C4312 (conversion to HANDLE of greater size).
    // CloseHandle with an invalid handle raises EXCEPTION_INVALID_HANDLE
    // only when a kernel-mode debugger is attached.
    HANDLE hInvalid = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xDEADC0DEUL));

    // __try cannot be used in a function with C++ object unwinding (C2712).
    // Workaround: SetUnhandledExceptionFilter is not suitable here; instead
    // we suppress the specific exception via RaiseException and a flag.
    // Simplest correct approach for x64 MSVC: use __try in a plain helper.
    struct CloseHandleHelper {
        static bool tryClose(HANDLE h) {
            // This nested struct method has no C++ objects — __try is safe.
            __try {
                CloseHandle(h);
                return false;
            }
            __except (GetExceptionCode() == EXCEPTION_INVALID_HANDLE
                      ? EXCEPTION_EXECUTE_HANDLER
                      : EXCEPTION_CONTINUE_SEARCH) {
                return true;
            }
        }
    };
    debuggerCaught = CloseHandleHelper::tryClose(hInvalid);

    ind.rawValue = debuggerCaught ? 1 : 0;

    if (debuggerCaught) {
        ind.detail     = "EXCEPTION_INVALID_HANDLE raised by CloseHandle — debugger present";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.detail     = "No exception from CloseHandle(invalid) — normal";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Debugger Window Class Names
//
//  Look for top-level windows belonging to known debuggers.
// ============================================================

DetectionIndicator AntiDebugPlugin::checkDebuggerWindowClass() {
    DetectionIndicator ind;
    ind.name     = "Debugger Window Classes";
    ind.category = DetectionCategory::AntiDebug;

    static const std::vector<std::wstring> debuggerClasses = {
        L"OLLYDBG",        // OllyDbg
        L"WinDbgFrameClass", // WinDbg
        L"ID",             // IDA Pro
        L"Qt5QWindowIcon", // x64dbg (Qt-based)
        L"Qt6QWindowIcon",
        L"ObsidianGUI",    // Immunity Debugger
    };

    uint32_t hits = 0;
    std::vector<std::string> found;

    for (const auto& cls : debuggerClasses) {
        HWND hwnd = FindWindowW(cls.c_str(), nullptr);
        if (hwnd != nullptr) {
            ++hits;
            found.push_back(WinUtils::toNarrow(cls));
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    if (hits > 0) {
        detail << hits << " debugger window class(es) found: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) detail << ", ";
            detail << "\"" << found[i] << "\"";
        }
    } else {
        detail << "No debugger window classes detected";
    }
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::Certain;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
