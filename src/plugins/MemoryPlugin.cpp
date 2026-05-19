#include "utils/SehCompat.hpp"
#include "plugins/MemoryPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

// MinGW's winternl.h has a stripped PEB without ProcessHeap.
// Define a complete PEB layout for heap-flag detection.
// These offsets are stable across all x64/x86 Windows 10+ builds.
#ifndef _FULL_PEB_DEFINED
#define _FULL_PEB_DEFINED
typedef struct _FULL_PEB {
    BYTE  InheritedAddressSpace;
    BYTE  ReadImageFileExecOptions;
    BYTE  BeingDebugged;
    BYTE  BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;   // offset 0x30 (x64) / 0x18 (x86)
    // ... rest not needed
} FULL_PEB, *PFULL_PEB;
#endif

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <array>

// For inline hook detection: look at first bytes of a function
static constexpr uint8_t OPCODE_JMP_REL32  = 0xE9;
static constexpr uint8_t OPCODE_JMP_SHORT  = 0xEB;
static constexpr uint8_t OPCODE_PUSH_IMM32 = 0x68;
static constexpr uint8_t OPCODE_MOV_RAX    = 0x48; // REX.W prefix for mov rax, imm64

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Construction / lifecycle
// ============================================================

MemoryPlugin::MemoryPlugin() {
    m_meta.id           = "com.sandboxdetector.memory";
    m_meta.name         = "Memory Anomaly Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox/VM via memory anomalies: physical RAM size, "
                          "pagefile, ntdll/kernel32 inline hook detection, suspicious "
                          "loaded modules, PEB heap flags, VA region analysis, and "
                          "memory commit ratio checks.";
    m_meta.categories   = DetectionCategory::Memory;
    m_meta.priority     = 12;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

MemoryPlugin::~MemoryPlugin() { shutdown(); }

const PluginMetadata& MemoryPlugin::getMetadata() const noexcept { return m_meta; }
bool MemoryPlugin::isSupported() const noexcept { return true; }

bool MemoryPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void MemoryPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult MemoryPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkPhysicalMemorySize());
    push(checkPageFileSize());
    push(checkNtdllHooks());
    push(checkKernel32Hooks());
    push(checkSuspiciousModules());
    push(checkHeapFlags());
    push(checkVirtualMemoryRegions());
    push(checkWorkingSetAnomaly());
    push(checkMemoryCommitRatio());
    push(checkGuardPageBehavior());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Static helper: is a function inline-hooked?
// ============================================================

bool MemoryPlugin::isFunctionHooked(FARPROC fn) noexcept {
    if (!fn) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    // jmp rel32
    if (p[0] == OPCODE_JMP_REL32) return true;
    // jmp short
    if (p[0] == OPCODE_JMP_SHORT) return true;
    // push imm32 / ret  (old 32-bit trampoline)
    if (p[0] == OPCODE_PUSH_IMM32 && p[5] == 0xC3) return true;
    // mov rax, imm64 / jmp rax  (64-bit absolute trampoline)
    if (p[0] == OPCODE_MOV_RAX && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return true;
    // int3 at start (breakpoint inserted)
    if (p[0] == 0xCC) return true;
    return false;
}

// ============================================================
//  Static helper: count executable private VA regions
// ============================================================

uint32_t MemoryPlugin::countExecutablePrivateRegions() noexcept {
    uint32_t count = 0;
    MEMORY_BASIC_INFORMATION mbi = {};
    LPVOID addr = nullptr;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            mbi.Type  == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            count++;
        // Advance past this region
        addr = static_cast<LPVOID>(
            static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize);
        if (reinterpret_cast<uintptr_t>(addr) == 0) break; // wrapped
    }
    return count;
}

// ============================================================
//  Check: Physical Memory Size
// ============================================================

DetectionIndicator MemoryPlugin::checkPhysicalMemorySize() {
    DetectionIndicator ind;
    ind.name     = "Physical Memory Size";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;

    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return ind;

    uint64_t totalMb = ms.ullTotalPhys / (1024ULL * 1024ULL);
    ind.rawValue = totalMb;

    if (totalMb < 1024) {       // < 1 GB
        ind.detail     = "Physical RAM is only " + std::to_string(totalMb)
                         + " MB (< 1 GB). Definitive sandbox indicator.";
        ind.confidence = SandboxConfidence::Certain;
    } else if (totalMb < 2048) { // < 2 GB
        ind.detail     = "Physical RAM is " + std::to_string(totalMb)
                         + " MB (< 2 GB). Suspicious for modern systems.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

// ============================================================
//  Check: Page File Size
// ============================================================

DetectionIndicator MemoryPlugin::checkPageFileSize() {
    DetectionIndicator ind;
    ind.name     = "Pagefile Size";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;

    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return ind;

    uint64_t pageFileMb = ms.ullTotalPageFile / (1024ULL * 1024ULL);
    ind.rawValue = pageFileMb;

    // Total page file includes RAM; subtract RAM to get actual pagefile
    MEMORYSTATUSEX ms2 = ms;
    uint64_t physMb   = ms2.ullTotalPhys / (1024ULL * 1024ULL);
    int64_t  pfOnlyMb = static_cast<int64_t>(pageFileMb) - static_cast<int64_t>(physMb);

    if (pfOnlyMb <= 0) {
        ind.detail     = "No pagefile detected (ullTotalPageFile <= ullTotalPhys). "
                         "Pagefile disabled — common in minimal sandbox VMs.";
        ind.confidence = SandboxConfidence::Medium;
        ind.rawValue   = 0;
    } else if (pfOnlyMb < 100) {
        ind.detail     = "Pagefile size is only " + std::to_string(pfOnlyMb)
                         + " MB. Very small pagefile indicates minimal VM.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: ntdll.dll Inline Hooks
// ============================================================

DetectionIndicator MemoryPlugin::checkNtdllHooks() {
    DetectionIndicator ind;
    ind.name     = "ntdll.dll Inline Hook Detection";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Key ntdll exports that sandboxes commonly hook
    static constexpr std::array<const char*, 20> NTDLL_EXPORTS = {{
        "NtCreateFile",      "NtOpenFile",       "NtReadFile",
        "NtWriteFile",       "NtCreateProcess",  "NtCreateProcessEx",
        "NtCreateThread",    "NtCreateThreadEx", "NtOpenProcess",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
        "NtProtectVirtualMemory",  "NtWriteVirtualMemory",
        "NtQuerySystemInformation","NtQueryInformationProcess",
        "NtSetInformationProcess", "NtResumeThread",
        "NtSuspendThread",         "LdrLoadDll",
        "LdrGetProcedureAddress"
    }};

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    std::vector<std::string> hooked;
    for (const char* name : NTDLL_EXPORTS) {
        FARPROC fn = GetProcAddress(hNtdll, name);
        if (fn && isFunctionHooked(fn))
            hooked.push_back(name);
    }
    ind.rawValue = static_cast<uint64_t>(hooked.size());

    if (!hooked.empty()) {
        std::ostringstream ss;
        ss << "ntdll.dll inline hook(s) detected on " << hooked.size() << " export(s): ";
        for (size_t i = 0; i < hooked.size() && i < 5; ++i) {
            if (i) ss << ", ";
            ss << hooked[i];
        }
        if (hooked.size() > 5) ss << " ...";
        ind.detail     = ss.str();
        ind.confidence = (hooked.size() >= 5) ? SandboxConfidence::Certain
                       : (hooked.size() >= 3) ? SandboxConfidence::High
                       :                        SandboxConfidence::Medium;
    }
    return ind;
}

// ============================================================
//  Check: kernel32.dll Inline Hooks
// ============================================================

DetectionIndicator MemoryPlugin::checkKernel32Hooks() {
    DetectionIndicator ind;
    ind.name     = "kernel32.dll Inline Hook Detection";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    static constexpr std::array<const char*, 16> K32_EXPORTS = {{
        "CreateFileW",       "CreateFileA",       "ReadFile",
        "WriteFile",         "CreateProcessW",    "CreateProcessA",
        "OpenProcess",       "VirtualAlloc",      "VirtualFree",
        "VirtualProtect",    "LoadLibraryW",      "LoadLibraryA",
        "LoadLibraryExW",    "GetProcAddress",    "CreateThread",
        "WinExec"
    }};

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) return ind;

    std::vector<std::string> hooked;
    for (const char* name : K32_EXPORTS) {
        FARPROC fn = GetProcAddress(hK32, name);
        if (fn && isFunctionHooked(fn))
            hooked.push_back(name);
    }
    ind.rawValue = static_cast<uint64_t>(hooked.size());

    if (!hooked.empty()) {
        std::ostringstream ss;
        ss << "kernel32.dll inline hook(s) on " << hooked.size() << " export(s): ";
        for (size_t i = 0; i < hooked.size() && i < 5; ++i) {
            if (i) ss << ", ";
            ss << hooked[i];
        }
        if (hooked.size() > 5) ss << " ...";
        ind.detail     = ss.str();
        ind.confidence = (hooked.size() >= 5) ? SandboxConfidence::Certain
                       : (hooked.size() >= 3) ? SandboxConfidence::High
                       :                        SandboxConfidence::Medium;
    }
    return ind;
}

// ============================================================
//  Check: Suspicious Modules
// ============================================================

DetectionIndicator MemoryPlugin::checkSuspiciousModules() {
    DetectionIndicator ind;
    ind.name     = "Suspicious DLLs Loaded";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    static constexpr std::array<const wchar_t*, 16> SUSPECT_DLLS = {{
        L"sbiedll.dll",      // Sandboxie
        L"cuckoomon.dll",    // Cuckoo
        L"api_log.dll",      // API monitor
        L"dir_watch.dll",    // Directory watcher
        L"pstorec.dll",      // Credential stealer / monitor
        L"vmcheck.dll",      // VM check tool
        L"wpespy.dll",       // WPE Pro packet sniffer
        L"hooksdll.dll",     // Generic hooking
        L"log_api.dll",      // API logger
        L"capture.dll",      // Capture sandbox
        L"snxhk.dll",        // Avast sandbox hook
        L"hmpalert.dll",     // HitmanPro.Alert
        L"dbghelp.dll",      // Debug helper (injected by debuggers)
        L"syser.dll",        // Syser debugger
        L"sbieDll.dll",      // Sandboxie (case variant)
        L"IntelliTraceCollectionApi.dll" // VS IntelliTrace
    }};

    auto loadedModules = WinUtils::enumLoadedModules();
    std::vector<std::wstring> found;

    for (const wchar_t* suspect : SUSPECT_DLLS) {
        std::wstring suspectLo(suspect);
        std::transform(suspectLo.begin(), suspectLo.end(), suspectLo.begin(), ::towlower);
        for (const auto& mod : loadedModules) {
            std::wstring modLo = mod;
            std::transform(modLo.begin(), modLo.end(), modLo.begin(), ::towlower);
            // Match on filename portion only
            size_t slash = modLo.rfind(L'\\');
            std::wstring modFile = (slash != std::wstring::npos) ? modLo.substr(slash + 1) : modLo;
            if (modFile == suspectLo) {
                found.push_back(mod);
                break;
            }
        }
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Suspicious DLL(s) loaded: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

// ============================================================
//  Check: PEB Heap Flags
// ============================================================

DetectionIndicator MemoryPlugin::checkHeapFlags() {
    DetectionIndicator ind;
    ind.name     = "PEB Heap Debug Flags";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

#ifdef _WIN64
    // 64-bit: PEB is at GS:[0x60], ProcessHeap at offset 0x30, Flags at +0x70, ForceFlags at +0x74
    auto pPeb = reinterpret_cast<PFULL_PEB>(__readgsqword(0x60));
    if (!pPeb) return ind;
    auto heapBase = reinterpret_cast<uint8_t*>(pPeb->ProcessHeap);
    if (!heapBase) return ind;
    DWORD flags      = *reinterpret_cast<DWORD*>(heapBase + 0x70);
    DWORD forceFlags = *reinterpret_cast<DWORD*>(heapBase + 0x74);
#else
    // 32-bit: PEB at FS:[0x30], ProcessHeap at +0x18, Flags at +0x40, ForceFlags at +0x44
    auto pPeb = reinterpret_cast<PFULL_PEB>(__readfsdword(0x30));
    if (!pPeb) return ind;
    auto heapBase = reinterpret_cast<uint8_t*>(pPeb->ProcessHeap);
    if (!heapBase) return ind;
    DWORD flags      = *reinterpret_cast<DWORD*>(heapBase + 0x40);
    DWORD forceFlags = *reinterpret_cast<DWORD*>(heapBase + 0x44);
#endif

    ind.rawValue = (static_cast<uint64_t>(forceFlags) << 32) | flags;

    // Normal heap: Flags = 2 (HEAP_GROWABLE), ForceFlags = 0
    // Debug heap: Flags has extra bits set, ForceFlags != 0
    static constexpr DWORD NORMAL_FLAGS = 0x00000002;
    if ((flags & ~NORMAL_FLAGS) != 0 || forceFlags != 0) {
        std::ostringstream ss;
        ss << "Heap debug flags active: Flags=0x" << std::hex << flags
           << " ForceFlags=0x" << forceFlags
           << ". Indicates debug heap / sandbox instrumentation.";
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

// ============================================================
//  Check: Virtual Memory Region Analysis
// ============================================================

DetectionIndicator MemoryPlugin::checkVirtualMemoryRegions() {
    DetectionIndicator ind;
    ind.name     = "Executable Private VA Regions";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;

    uint32_t execPrivate = countExecutablePrivateRegions();
    ind.rawValue = execPrivate;

    // Sandboxes often inject shellcode / trampolines that appear as
    // small private executable regions. > 20 is suspicious.
    if (execPrivate > 30) {
        ind.detail     = "Found " + std::to_string(execPrivate)
                         + " executable private VA region(s). "
                         "High count indicates sandbox shellcode injection.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

// ============================================================
//  Check: Working Set Anomaly
// ============================================================

DetectionIndicator MemoryPlugin::checkWorkingSetAnomaly() {
    DetectionIndicator ind;
    ind.name     = "Process Working Set Anomaly";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;

    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) return ind;

    uint64_t wsMb = pmc.WorkingSetSize / (1024ULL * 1024ULL);
    ind.rawValue = wsMb;

    // A bare sandbox process with injected hooks typically has an inflated working set
    // > 200 MB for a simple detector process is suspicious
    if (wsMb > 200) {
        ind.detail     = "Working set is " + std::to_string(wsMb)
                         + " MB for this process. Possible injected content.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: Memory Commit Ratio
// ============================================================

DetectionIndicator MemoryPlugin::checkMemoryCommitRatio() {
    DetectionIndicator ind;
    ind.name     = "Memory Commit / Physical Ratio";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return ind;

    if (ms.ullTotalPhys == 0) return ind;

    // CommitTotal = ullTotalPageFile - ullAvailPageFile
    uint64_t commitTotal = ms.ullTotalPageFile - ms.ullAvailPageFile;
    uint64_t physTotal   = ms.ullTotalPhys;

    // Ratio > 3.0 means hugely over-committed — indicates container / nested VM
    double ratio = static_cast<double>(commitTotal) / static_cast<double>(physTotal);
    ind.rawValue = static_cast<uint64_t>(ratio * 100);

    if (ratio > 3.0) {
        std::ostringstream ss;
        ss.precision(1);
        ss << std::fixed << "Memory commit/physical ratio = " << ratio
           << " (> 3.0). Severe over-commit = container or nested VM.";
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

// ============================================================
//  Check: Guard Page Behavior
// ============================================================

DetectionIndicator MemoryPlugin::checkGuardPageBehavior() {
    DetectionIndicator ind;
    ind.name     = "Guard Page Exception Behavior";
    ind.category = DetectionCategory::Memory;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Allocate a page with PAGE_GUARD, try to access it, expect STATUS_GUARD_PAGE_VIOLATION
    // Sandboxes that intercept VirtualAlloc or VirtualProtect may suppress guard pages
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE | PAGE_GUARD);
    if (!page) return ind;

    struct Guard { void* p; ~Guard(){ if(p) VirtualFree(p, 0, MEM_RELEASE); } } g{page};

    bool guardFired = false;
#ifdef _MSC_VER
    __try {
        volatile uint8_t val = *static_cast<uint8_t*>(page);
        (void)val;
        // If we reach here, guard page did NOT fire — sandbox suppressed it
    } __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
        guardFired = true;
    }
#else
    // SEH not available on non-MSVC; skip guard-page check
    (void)page;
#endif

    ind.rawValue = guardFired ? 1 : 0;
    if (!guardFired) {
        ind.detail     = "PAGE_GUARD page access did not raise STATUS_GUARD_PAGE_VIOLATION. "
                         "Sandbox may be intercepting VirtualProtect/exceptions.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
