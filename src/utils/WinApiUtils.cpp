#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace SandboxDetector {
namespace WinUtils {

// ============================================================
//  String Conversions
// ============================================================

std::wstring toWide(const std::string& str) {
    if (str.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.data(),
                                  static_cast<int>(str.size()), nullptr, 0);
    if (sz <= 0) return {};
    std::wstring out(sz, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(),
                        static_cast<int>(str.size()), out.data(), sz);
    return out;
}

std::string toNarrow(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
                                  static_cast<int>(wstr.size()),
                                  nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return {};
    std::string out(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
                        static_cast<int>(wstr.size()),
                        out.data(), sz, nullptr, nullptr);
    return out;
}

// ============================================================
//  Registry helpers
// ============================================================

std::string RegValueResult::asString() const {
    if (data.empty()) return {};
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        // data is wide chars
        const wchar_t* wptr = reinterpret_cast<const wchar_t*>(data.data());
        size_t wlen = (data.size() / sizeof(wchar_t));
        // Trim null terminator
        while (wlen > 0 && wptr[wlen - 1] == L'\0') --wlen;
        return toNarrow(std::wstring(wptr, wlen));
    }
    return {};
}

DWORD RegValueResult::asDword() const {
    if (data.size() < sizeof(DWORD)) return 0;
    DWORD val{};
    std::memcpy(&val, data.data(), sizeof(DWORD));
    return val;
}

std::optional<RegValueResult> regQueryValue(HKEY rootKey,
                                             const std::wstring& subKey,
                                             const std::wstring& valueName)
{
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(rootKey, subKey.c_str(), 0,
                                 KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status != ERROR_SUCCESS) return std::nullopt;

    DWORD type  = 0;
    DWORD cbData = 0;
    // First call to get size
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr,
                               &type, nullptr, &cbData);
    if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    RegValueResult result;
    result.type = type;
    result.data.resize(cbData + sizeof(wchar_t), 0);  // extra for null-term
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type,
                               result.data.data(), &cbData);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) return std::nullopt;
    result.data.resize(cbData);
    return result;
}

bool regKeyExists(HKEY rootKey, const std::wstring& subKey) {
    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(rootKey, subKey.c_str(), 0,
                                 KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (status == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

std::vector<std::wstring> regEnumSubKeys(HKEY rootKey, const std::wstring& subKey) {
    std::vector<std::wstring> keys;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(rootKey, subKey.c_str(), 0,
                       KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return keys;

    wchar_t name[256];
    DWORD idx = 0;
    while (true) {
        DWORD nameSz = static_cast<DWORD>(std::size(name));
        LONG r = RegEnumKeyExW(hKey, idx++, name, &nameSz,
                                nullptr, nullptr, nullptr, nullptr);
        if (r != ERROR_SUCCESS) break;
        keys.emplace_back(name, nameSz);
    }
    RegCloseKey(hKey);
    return keys;
}

std::vector<std::wstring> regEnumValues(HKEY rootKey, const std::wstring& subKey) {
    std::vector<std::wstring> values;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(rootKey, subKey.c_str(), 0,
                       KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
        return values;

    wchar_t name[1024];
    DWORD idx = 0;
    while (true) {
        DWORD nameSz = static_cast<DWORD>(std::size(name));
        LONG r = RegEnumValueW(hKey, idx++, name, &nameSz,
                                nullptr, nullptr, nullptr, nullptr);
        if (r != ERROR_SUCCESS) break;
        values.emplace_back(name, nameSz);
    }
    RegCloseKey(hKey);
    return values;
}

// ============================================================
//  Process helpers
// ============================================================

std::vector<ProcessInfo> enumProcesses() {
    std::vector<ProcessInfo> procs;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            ProcessInfo info;
            info.pid  = pe.th32ProcessID;
            info.name = pe.szExeFile;

            // Try to get full path
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                       FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t path[MAX_PATH]{};
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, path, &sz))
                    info.executablePath = path;
                CloseHandle(hProc);
            }
            procs.push_back(std::move(info));
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return procs;
}

bool processExists(const std::wstring& processName, bool caseInsensitive) {
    auto procs = enumProcesses();
    return std::any_of(procs.begin(), procs.end(),
        [&](const ProcessInfo& pi) {
            if (!caseInsensitive)
                return pi.name == processName;
            auto a = pi.name, b = processName;
            std::transform(a.begin(), a.end(), a.begin(), ::towlower);
            std::transform(b.begin(), b.end(), b.begin(), ::towlower);
            return a == b;
        });
}

std::optional<std::wstring> getProcessPath(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return std::nullopt;
    wchar_t path[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    bool ok = QueryFullProcessImageNameW(hProc, 0, path, &sz) != FALSE;
    CloseHandle(hProc);
    if (!ok) return std::nullopt;
    return std::wstring(path);
}

// ============================================================
//  Module helpers
// ============================================================

bool isModuleLoaded(const std::wstring& moduleName) {
    HMODULE hMod = GetModuleHandleW(moduleName.c_str());
    return hMod != nullptr;
}

std::vector<std::wstring> enumLoadedModules(HANDLE hProcess) {
    std::vector<std::wstring> modules;
    HMODULE hMods[1024]{};
    DWORD cbNeeded = 0;

    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded,
                               LIST_MODULES_ALL))
        return modules;

    DWORD count = cbNeeded / sizeof(HMODULE);
    modules.reserve(count);
    for (DWORD i = 0; i < count; ++i) {
        wchar_t name[MAX_PATH]{};
        if (GetModuleBaseNameW(hProcess, hMods[i], name, MAX_PATH))
            modules.emplace_back(name);
    }
    return modules;
}

std::optional<std::wstring> getModulePath(const std::wstring& moduleName) {
    HMODULE hMod = GetModuleHandleW(moduleName.c_str());
    if (!hMod) return std::nullopt;
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(hMod, path, MAX_PATH)) return std::nullopt;
    return std::wstring(path);
}

// ============================================================
//  File system helpers
// ============================================================

bool fileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool directoryExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

uint64_t getFileSizeBytes(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return 0;
    return (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
}

// ============================================================
//  CPUID helpers
// ============================================================

CpuidResult cpuid(uint32_t leaf, uint32_t subleaf) noexcept {
    CpuidResult r{};
    __cpuidex(reinterpret_cast<int*>(&r), static_cast<int>(leaf),
               static_cast<int>(subleaf));
    return r;
}

std::string getCpuVendorString() {
    auto r = cpuid(0);
    char vendor[13]{};
    std::memcpy(vendor + 0, &r.ebx, 4);
    std::memcpy(vendor + 4, &r.edx, 4);
    std::memcpy(vendor + 8, &r.ecx, 4);
    vendor[12] = '\0';
    return std::string(vendor);
}

std::string getHypervisorVendorString() {
    if (!isHypervisorPresent()) return {};
    auto r = cpuid(0x40000000);
    char vendor[13]{};
    std::memcpy(vendor + 0, &r.ebx, 4);
    std::memcpy(vendor + 4, &r.ecx, 4);
    std::memcpy(vendor + 8, &r.edx, 4);
    vendor[12] = '\0';
    return std::string(vendor);
}

bool isHypervisorPresent() noexcept {
    auto r = cpuid(0x1);
    return (r.ecx & (1u << 31)) != 0;
}

// ============================================================
//  Native API helpers
// ============================================================

NTSTATUS ntQuerySystemInformation(UINT infoClass, PVOID buffer,
                                   ULONG length, PULONG returnLength) {
    static auto pfn = getNtdllExport<PFN_NtQuerySystemInformation>(
        "NtQuerySystemInformation");
    if (!pfn) return static_cast<NTSTATUS>(0xC0000001L);  // STATUS_UNSUCCESSFUL
    return pfn(infoClass, buffer, length, returnLength);
}

NTSTATUS ntQueryInformationProcess(HANDLE hProcess, UINT infoClass,
                                    PVOID buffer, ULONG length,
                                    PULONG returnLength) {
    static auto pfn = getNtdllExport<PFN_NtQueryInformationProcess>(
        "NtQueryInformationProcess");
    if (!pfn) return static_cast<NTSTATUS>(0xC0000001L);
    return pfn(hProcess, infoClass, buffer, length, returnLength);
}

// ============================================================
//  WmiSession
// ============================================================

WmiSession::WmiSession() = default;

WmiSession::~WmiSession() {
    shutdown();
}

bool WmiSession::initialize() {
    if (m_initialized) return true;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        m_comOwned = true;
    } else if (hr == RPC_E_CHANGED_MODE) {
        // Already initialized on this thread — that's fine
        m_comOwned = false;
    } else {
        return false;
    }

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                               RPC_C_AUTHN_LEVEL_DEFAULT,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, EOAC_NONE, nullptr);
    // E_ALREADY_SET is acceptable
    if (FAILED(hr) && hr != static_cast<HRESULT>(0x80010119L)) {
        if (m_comOwned) CoUninitialize();
        return false;
    }

    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator,
                          reinterpret_cast<void**>(&m_pLocator));
    if (FAILED(hr)) {
        if (m_comOwned) CoUninitialize();
        return false;
    }

    BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hr = m_pLocator->ConnectServer(bstrNamespace, nullptr, nullptr, nullptr,
                                    0, nullptr, nullptr, &m_pServices);
    SysFreeString(bstrNamespace);

    if (FAILED(hr)) {
        m_pLocator->Release();
        m_pLocator = nullptr;
        if (m_comOwned) CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(m_pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                            nullptr, RPC_C_AUTHN_LEVEL_CALL,
                            RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        m_pServices->Release();
        m_pServices = nullptr;
        m_pLocator->Release();
        m_pLocator = nullptr;
        if (m_comOwned) CoUninitialize();
        return false;
    }

    m_initialized = true;
    return true;
}

void WmiSession::shutdown() {
    if (m_pServices) { m_pServices->Release(); m_pServices = nullptr; }
    if (m_pLocator)  { m_pLocator->Release();  m_pLocator  = nullptr; }
    if (m_comOwned)  { CoUninitialize(); m_comOwned = false; }
    m_initialized = false;
}

std::vector<WmiSession::WmiRow> WmiSession::query(const std::wstring& wql) {
    std::vector<WmiRow> rows;
    if (!m_initialized || !m_pServices) return rows;

    BSTR bstrWql    = SysAllocString(L"WQL");
    BSTR bstrQuery  = SysAllocString(wql.c_str());

    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = m_pServices->ExecQuery(bstrWql, bstrQuery,
                                         WBEM_FLAG_FORWARD_ONLY |
                                         WBEM_FLAG_RETURN_IMMEDIATELY,
                                         nullptr, &pEnum);
    SysFreeString(bstrWql);
    SysFreeString(bstrQuery);

    if (FAILED(hr) || !pEnum) return rows;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;

    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == WBEM_S_NO_ERROR) {
        if (returned == 0) break;

        WmiRow row;
        SAFEARRAY* pNames = nullptr;
        if (SUCCEEDED(pObj->GetNames(nullptr, WBEM_FLAG_ALWAYS, nullptr, &pNames))) {
            LONG lBound = 0, uBound = 0;
            SafeArrayGetLBound(pNames, 1, &lBound);
            SafeArrayGetUBound(pNames, 1, &uBound);

            for (LONG i = lBound; i <= uBound; ++i) {
                BSTR bstrName = nullptr;
                SafeArrayGetElement(pNames, &i, &bstrName);

                VARIANT var;
                VariantInit(&var);
                if (SUCCEEDED(pObj->Get(bstrName, 0, &var, nullptr, nullptr))) {
                    if (var.vt == VT_BSTR && var.bstrVal) {
                        row.columns[std::wstring(bstrName)] =
                            std::wstring(var.bstrVal);
                    } else if (var.vt != VT_NULL && var.vt != VT_EMPTY) {
                        VARIANT strVar;
                        VariantInit(&strVar);
                        if (SUCCEEDED(VariantChangeType(&strVar, &var, 0, VT_BSTR))
                            && strVar.bstrVal)
                        {
                            row.columns[std::wstring(bstrName)] =
                                std::wstring(strVar.bstrVal);
                        }
                        VariantClear(&strVar);
                    }
                    VariantClear(&var);
                }
                SysFreeString(bstrName);
            }
            SafeArrayDestroy(pNames);
        }

        rows.push_back(std::move(row));
        pObj->Release();
    }

    pEnum->Release();
    return rows;
}

// ============================================================
//  Environment helpers
// ============================================================

std::optional<std::wstring> getEnvVar(const std::wstring& name) {
    wchar_t buf[32768];
    DWORD sz = GetEnvironmentVariableW(name.c_str(), buf, static_cast<DWORD>(std::size(buf)));
    if (sz == 0) return std::nullopt;
    return std::wstring(buf, sz);
}

std::vector<std::pair<std::wstring, std::wstring>> getAllEnvVars() {
    std::vector<std::pair<std::wstring, std::wstring>> result;
    wchar_t* env = GetEnvironmentStringsW();
    if (!env) return result;

    for (wchar_t* p = env; *p; ) {
        std::wstring entry = p;
        p += entry.size() + 1;
        auto eq = entry.find(L'=');
        if (eq != std::wstring::npos && eq > 0) {
            result.emplace_back(entry.substr(0, eq), entry.substr(eq + 1));
        }
    }
    FreeEnvironmentStringsW(env);
    return result;
}

// ============================================================
//  Privilege helpers
// ============================================================

bool isRunningAsAdmin() noexcept {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
                                  SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool enablePrivilege(const std::wstring& privilegeName) noexcept {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return false;

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp{ 1, { luid, SE_PRIVILEGE_ENABLED } };
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

// ============================================================
//  Memory helpers
// ============================================================

MemoryStats getMemoryStats() {
    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    return {
        ms.ullTotalPhys,
        ms.ullAvailPhys,
        ms.ullTotalVirtual,
        ms.ullAvailVirtual,
        ms.dwMemoryLoad
    };
}

// ============================================================
//  Network helpers
// ============================================================

std::vector<std::wstring> getNetworkAdapterNames() {
    std::vector<std::wstring> names;
    ULONG bufSize = 0;
    GetAdaptersInfo(nullptr, &bufSize);
    if (bufSize == 0) return names;

    std::vector<uint8_t> buf(bufSize);
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    if (GetAdaptersInfo(info, &bufSize) != ERROR_SUCCESS) return names;

    for (auto* p = info; p; p = p->Next) {
        // AdapterName is ANSI; convert to wide
        names.push_back(toWide(p->AdapterName));
    }
    return names;
}

std::vector<std::wstring> getNetworkAdapterMacAddresses() {
    std::vector<std::wstring> macs;
    ULONG bufSize = 0;
    GetAdaptersInfo(nullptr, &bufSize);
    if (bufSize == 0) return macs;

    std::vector<uint8_t> buf(bufSize);
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    if (GetAdaptersInfo(info, &bufSize) != ERROR_SUCCESS) return macs;

    for (auto* p = info; p; p = p->Next) {
        std::wostringstream woss;
        woss << std::uppercase << std::hex << std::setfill(L'0');
        for (UINT i = 0; i < p->AddressLength; ++i) {
            if (i > 0) woss << L':';
            woss << std::setw(2) << static_cast<int>(p->Address[i]);
        }
        macs.push_back(woss.str());
    }
    return macs;
}

bool isNetworkAvailable() {
    // Use GetAdaptersInfo to check if any non-loopback adapter has an IP
    ULONG bufSize = 0;
    GetAdaptersInfo(nullptr, &bufSize);
    if (bufSize == 0) return false;
    std::vector<uint8_t> buf(bufSize);
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    if (GetAdaptersInfo(info, &bufSize) != ERROR_SUCCESS) return false;
    for (auto* p = info; p; p = p->Next) {
        std::string ip = p->IpAddressList.IpAddress.String;
        if (!ip.empty() && ip != "0.0.0.0" && ip.rfind("127.", 0) != 0)
            return true;
    }
    return false;
}

} // namespace WinUtils
} // namespace SandboxDetector
