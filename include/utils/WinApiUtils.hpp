#pragma once

#ifndef SANDBOX_DETECTOR_WINAPI_UTILS_HPP
#define SANDBOX_DETECTOR_WINAPI_UTILS_HPP

// Minimal Windows headers - order matters
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <intrin.h>

#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <cstdint>
#include <array>

// ============================================================
//  Native API type definitions not always in SDK headers
// ============================================================

typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#  define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_HYPERVISOR_QUERY_INFORMATION {
    BOOLEAN HypervisorConnected;
    BOOLEAN HypervisorDebuggingAllowed;
    BOOLEAN HypervisorPresent;
    BOOLEAN Spare0[5];
    ULONGLONG EnabledEnlightenments;
} SYSTEM_HYPERVISOR_QUERY_INFORMATION, *PSYSTEM_HYPERVISOR_QUERY_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS_EX : UINT {
    SystemKernelDebuggerInformation    = 35,
    SystemHypervisorQueryInformation   = 123,
} SYSTEM_INFORMATION_CLASS_EX;

// NtQuerySystemInformation function pointer
using PFN_NtQuerySystemInformation = NTSTATUS(WINAPI*)(
    UINT    SystemInformationClass,
    PVOID   SystemInformation,
    ULONG   SystemInformationLength,
    PULONG  ReturnLength
);

// NtQueryInformationProcess function pointer
using PFN_NtQueryInformationProcess = NTSTATUS(WINAPI*)(
    HANDLE  ProcessHandle,
    UINT    ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength
);

// NtSetInformationThread function pointer
using PFN_NtSetInformationThread = NTSTATUS(WINAPI*)(
    HANDLE  ThreadHandle,
    UINT    ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength
);

namespace SandboxDetector {
namespace WinUtils {

// ============================================================
//  String conversions
// ============================================================

std::wstring toWide(const std::string& str);
std::string  toNarrow(const std::wstring& wstr);

// ============================================================
//  Registry helpers
// ============================================================

struct RegValueResult {
    DWORD       type;
    std::vector<uint8_t> data;
    std::string asString() const;
    DWORD       asDword()  const;
};

std::optional<RegValueResult> regQueryValue(
    HKEY        rootKey,
    const std::wstring& subKey,
    const std::wstring& valueName);

bool regKeyExists(HKEY rootKey, const std::wstring& subKey);

std::vector<std::wstring> regEnumSubKeys(HKEY rootKey, const std::wstring& subKey);
std::vector<std::wstring> regEnumValues(HKEY rootKey, const std::wstring& subKey);

// ============================================================
//  Process helpers
// ============================================================

struct ProcessInfo {
    DWORD       pid;
    std::wstring name;
    std::wstring executablePath;
};

std::vector<ProcessInfo> enumProcesses();

bool processExists(const std::wstring& processName, bool caseInsensitive = true);

std::optional<std::wstring> getProcessPath(DWORD pid);

// ============================================================
//  Module / DLL helpers
// ============================================================

bool isModuleLoaded(const std::wstring& moduleName);

std::vector<std::wstring> enumLoadedModules(HANDLE hProcess = GetCurrentProcess());

std::optional<std::wstring> getModulePath(const std::wstring& moduleName);

// ============================================================
//  File system helpers
// ============================================================

bool fileExists(const std::wstring& path);
bool directoryExists(const std::wstring& path);

std::vector<std::wstring> enumFiles(const std::wstring& directory,
                                    const std::wstring& pattern = L"*");

uint64_t getFileSizeBytes(const std::wstring& path);

// ============================================================
//  Timing / RDTSC helpers
// ============================================================

// Returns CPU timestamp counter
inline uint64_t rdtsc() noexcept {
    return __rdtsc();
}

// Measure wall-clock time of a lambda in microseconds
template<typename Fn>
uint64_t measureMicroseconds(Fn&& fn) {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    fn();
    QueryPerformanceCounter(&end);
    return static_cast<uint64_t>(
        (end.QuadPart - start.QuadPart) * 1'000'000ULL / freq.QuadPart);
}

// ============================================================
//  CPUID helpers
// ============================================================

struct CpuidResult {
    uint32_t eax, ebx, ecx, edx;
};

CpuidResult cpuid(uint32_t leaf, uint32_t subleaf = 0) noexcept;

std::string getCpuVendorString();
std::string getHypervisorVendorString();   // empty if no hypervisor
bool        isHypervisorPresent() noexcept;

// ============================================================
//  Native API dynamic resolvers
// ============================================================

// Retrieves a function pointer from ntdll.dll, cached on first call
template<typename FnPtr>
FnPtr getNtdllExport(const char* name) {
    static HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    return reinterpret_cast<FnPtr>(GetProcAddress(ntdll, name));
}

NTSTATUS ntQuerySystemInformation(UINT infoClass, PVOID buffer,
                                   ULONG length, PULONG returnLength);

NTSTATUS ntQueryInformationProcess(HANDLE hProcess, UINT infoClass,
                                    PVOID buffer, ULONG length,
                                    PULONG returnLength);

// ============================================================
//  WMI helpers
// ============================================================

class WmiSession {
public:
    WmiSession();
    ~WmiSession();

    bool initialize();
    void shutdown();

    struct WmiRow {
        std::unordered_map<std::wstring, std::wstring> columns;
    };

    std::vector<WmiRow> query(const std::wstring& wql);

private:
    IWbemLocator*   m_pLocator  = nullptr;
    IWbemServices*  m_pServices = nullptr;
    bool            m_initialized = false;
    bool            m_comOwned    = false;
};

// ============================================================
//  Environment variable helpers
// ============================================================

std::optional<std::wstring> getEnvVar(const std::wstring& name);
std::vector<std::pair<std::wstring, std::wstring>> getAllEnvVars();

// ============================================================
//  Privilege helpers
// ============================================================

bool isRunningAsAdmin() noexcept;
bool enablePrivilege(const std::wstring& privilegeName) noexcept;

// ============================================================
//  Memory helpers
// ============================================================

struct MemoryStats {
    uint64_t totalPhysicalBytes;
    uint64_t availablePhysicalBytes;
    uint64_t totalVirtualBytes;
    uint64_t availableVirtualBytes;
    uint32_t memoryLoadPercent;
};

MemoryStats getMemoryStats();

// ============================================================
//  Network helpers
// ============================================================

std::vector<std::wstring> getNetworkAdapterNames();
std::vector<std::wstring> getNetworkAdapterMacAddresses();
bool isNetworkAvailable();

} // namespace WinUtils
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_WINAPI_UTILS_HPP
