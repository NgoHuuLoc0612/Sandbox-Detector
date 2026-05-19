#include "plugins/ServicePlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winsvc.h>

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <array>
#include <unordered_set>
#include <cctype>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Service blacklists / whitelists
// ============================================================

static constexpr std::array<const wchar_t*, 18> VM_GUEST_SERVICES = {{
    // VirtualBox
    L"vboxservice",     L"vboxtray",        L"vboxguest",
    L"vboxsf",          L"vboxnetadp",      L"vboxnetflt",
    // VMware
    L"vmtools",         L"vmtoolsd",        L"vmci",
    L"vmhgfs",          L"vmx86",           L"vmmouse",
    // Parallels
    L"prl_strg",        L"prl_memdev",      L"prl_net",
    // QEMU/SPICE
    L"spiceagentd",     L"qemu-ga",         L"vioserial"
}};

static constexpr std::array<const wchar_t*, 10> SANDBOX_SERVICES = {{
    L"sbiedrv",           // Sandboxie kernel driver
    L"sandboxie",         // Sandboxie
    L"cuckooservice",     // Cuckoo
    L"capemon",           // CAPE sandbox monitor
    L"joeboxcontrol",     // Joe Sandbox
    L"anubisservice",     // Anubis
    L"threatexpertservice",// ThreatExpert
    L"idefense",          // iDefense
    L"cwsandbox",         // CWSandbox
    L"joesandbox"         // Joe Sandbox (alt)
}};

static constexpr std::array<const wchar_t*, 8> HYPERV_SERVICES = {{
    L"vmicheartbeat",     // Hyper-V Heartbeat
    L"vmicvss",           // Hyper-V Volume Shadow Copy
    L"vmicshutdown",      // Hyper-V Guest Shutdown
    L"vmicexchange",      // Hyper-V Data Exchange
    L"vmicrdv",           // Hyper-V Remote Desktop
    L"vmictimesync",      // Hyper-V Time Synchronization
    L"vmickvpexchange",   // Hyper-V KVP Exchange
    L"vmicsvc"            // Hyper-V Integration Component svc
}};

static constexpr std::array<const wchar_t*, 8> XEN_SERVICES = {{
    L"xenbus",            // Xen PCI bus
    L"xenpci",            // Xen PCI
    L"xenvbd",            // Xen virtual block device
    L"xennet",            // Xen network
    L"xenscsi",           // Xen SCSI
    L"xensvc",            // Xen service
    L"xenevtchn",         // Xen event channel
    L"xeniface"           // Xen interface
}};

static constexpr std::array<const wchar_t*, 8> QEMU_SERVICES = {{
    L"vioscsi",           // VirtIO SCSI
    L"viostor",           // VirtIO storage
    L"vioserial",         // VirtIO serial
    L"vionet",            // VirtIO net
    L"balloon",           // VirtIO balloon
    L"virtio-fs",         // VirtIO FS
    L"qxldod",            // QEMU QXL display
    L"redirserv"          // USB redirect
}};

// Services expected on a healthy Windows 10 workstation
static constexpr std::array<const wchar_t*, 10> REQUIRED_SERVICES = {{
    L"audiosrv",          // Windows Audio
    L"themes",            // Themes
    L"wscsvc",            // Security Center
    L"eventlog",          // Event Log
    L"dnscache",          // DNS Client
    L"lanmanworkstation", // Workstation
    L"netlogon",          // Net Logon (may not exist in workgroup)
    L"plugplay",          // Plug and Play
    L"rpcss",             // RPC
    L"schedule"           // Task Scheduler
}};

// ============================================================
//  Helpers
// ============================================================

static std::wstring toLowerW(const std::wstring& s) {
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::towlower);
    return out;
}

// ============================================================
//  Construction / lifecycle
// ============================================================

ServicePlugin::ServicePlugin() {
    m_meta.id           = "com.sandboxdetector.service";
    m_meta.name         = "Windows Service Control Manager Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox/VM by examining SCM service database: "
                          "total count, VM guest services, sandbox services, "
                          "missing system services, Hyper-V, Xen, QEMU services, "
                          "EventLog/WindowsUpdate state, and SCM response timing.";
    m_meta.categories   = DetectionCategory::Process; // Services are OS-process-level
    m_meta.priority     = 45;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

ServicePlugin::~ServicePlugin() { shutdown(); }

const PluginMetadata& ServicePlugin::getMetadata() const noexcept { return m_meta; }
bool ServicePlugin::isSupported() const noexcept { return true; }

bool ServicePlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void ServicePlugin::shutdown() noexcept {}

// ============================================================
//  enumAllServices()
// ============================================================

std::vector<ServicePlugin::ServiceInfo> ServicePlugin::enumAllServices() {
    std::vector<ServiceInfo> result;

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) return result;

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO,
                          SERVICE_WIN32 | SERVICE_DRIVER,
                          SERVICE_STATE_ALL,
                          nullptr, 0,
                          &bytesNeeded, &servicesReturned,
                          &resumeHandle, nullptr);

    if (bytesNeeded == 0) { CloseServiceHandle(hScm); return result; }

    std::vector<uint8_t> buf(bytesNeeded + 1024);
    BOOL ok = EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO,
                                    SERVICE_WIN32 | SERVICE_DRIVER,
                                    SERVICE_STATE_ALL,
                                    buf.data(), static_cast<DWORD>(buf.size()),
                                    &bytesNeeded, &servicesReturned,
                                    &resumeHandle, nullptr);
    if (!ok) { CloseServiceHandle(hScm); return result; }

    auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
    for (DWORD i = 0; i < servicesReturned; ++i) {
        ServiceInfo si;
        si.name        = entries[i].lpServiceName ? entries[i].lpServiceName : L"";
        si.displayName = entries[i].lpDisplayName  ? entries[i].lpDisplayName : L"";
        si.status      = entries[i].ServiceStatusProcess.dwCurrentState;
        si.type        = entries[i].ServiceStatusProcess.dwServiceType;

        // Get binary path via QueryServiceConfig
        SC_HANDLE hSvc = OpenServiceW(hScm, entries[i].lpServiceName,
                                      SERVICE_QUERY_CONFIG);
        if (hSvc) {
            DWORD cfgNeeded = 0;
            QueryServiceConfigW(hSvc, nullptr, 0, &cfgNeeded);
            if (cfgNeeded > 0) {
                std::vector<uint8_t> cfgBuf(cfgNeeded);
                auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
                if (QueryServiceConfigW(hSvc, cfg, cfgNeeded, &cfgNeeded)) {
                    si.binaryPath = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
                    si.startType  = cfg->dwStartType;
                }
            }
            CloseServiceHandle(hSvc);
        }
        result.push_back(std::move(si));
    }

    CloseServiceHandle(hScm);
    return result;
}

// ============================================================
//  run()
// ============================================================

PluginResult ServicePlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    // Enumerate once, pass to all checks
    auto services = enumAllServices();

    push(checkServiceCount(services));
    push(checkVmGuestServices(services));
    push(checkSandboxServices(services));
    push(checkMissingSystemServices(services));
    push(checkHyperVServices(services));
    push(checkXenServices(services));
    push(checkQemuServices(services));
    push(checkEventLogService(services));
    push(checkWindowsUpdateService(services));
    push(checkScmResponseTiming());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Checks
// ============================================================

DetectionIndicator ServicePlugin::checkServiceCount(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "Service Count Anomaly";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;

    uint32_t total   = static_cast<uint32_t>(services.size());
    uint32_t running = 0;
    for (const auto& s : services)
        if (s.status == SERVICE_RUNNING) running++;

    ind.rawValue = total;

    if (total < 20) {
        ind.detail     = "Only " + std::to_string(total)
                         + " services in SCM database (" + std::to_string(running)
                         + " running). Minimal sandbox install.";
        ind.confidence = (total < 10) ? SandboxConfidence::Certain
                       : (total < 15) ? SandboxConfidence::High
                       :                SandboxConfidence::Medium;
    } else if (running < 15) {
        ind.detail     = "Only " + std::to_string(running)
                         + " services running of " + std::to_string(total)
                         + ". Suspiciously few active services.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkVmGuestServices(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "VM Guest Services";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Build lowercase set of service names
    std::unordered_set<std::wstring> svcNamesLo;
    for (const auto& s : services)
        svcNamesLo.insert(toLowerW(s.name));

    std::vector<std::wstring> found;
    for (const wchar_t* vmSvc : VM_GUEST_SERVICES) {
        if (svcNamesLo.count(std::wstring(vmSvc)))
            found.push_back(vmSvc);
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "VM guest service(s) present (" << found.size() << "): ";
        for (size_t i = 0; i < found.size() && i < 5; ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 3) ? SandboxConfidence::Certain
                       : (found.size() >= 2) ? SandboxConfidence::High
                       :                        SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkSandboxServices(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "Sandbox Monitor Services";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::unordered_set<std::wstring> svcNamesLo;
    for (const auto& s : services)
        svcNamesLo.insert(toLowerW(s.name));

    std::vector<std::wstring> found;
    for (const wchar_t* sbxSvc : SANDBOX_SERVICES) {
        if (svcNamesLo.count(std::wstring(sbxSvc)))
            found.push_back(sbxSvc);
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Sandbox service(s) detected: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkMissingSystemServices(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "Missing Expected System Services";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::unordered_set<std::wstring> svcNamesLo;
    for (const auto& s : services)
        svcNamesLo.insert(toLowerW(s.name));

    std::vector<std::wstring> missing;
    for (const wchar_t* req : REQUIRED_SERVICES) {
        if (!svcNamesLo.count(std::wstring(req)))
            missing.push_back(req);
    }
    ind.rawValue = static_cast<uint64_t>(missing.size());

    if (missing.size() >= 3) {
        std::ostringstream ss;
        ss << missing.size() << " expected system service(s) absent: ";
        for (size_t i = 0; i < missing.size() && i < 5; ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(missing[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = (missing.size() >= 6) ? SandboxConfidence::Certain
                       : (missing.size() >= 4) ? SandboxConfidence::High
                       :                          SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkHyperVServices(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "Hyper-V Integration Services";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::unordered_set<std::wstring> svcNamesLo;
    for (const auto& s : services)
        svcNamesLo.insert(toLowerW(s.name));

    std::vector<std::wstring> found;
    for (const wchar_t* hvSvc : HYPERV_SERVICES) {
        if (svcNamesLo.count(std::wstring(hvSvc)))
            found.push_back(hvSvc);
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Hyper-V integration service(s) found (" << found.size() << "): ";
        for (size_t i = 0; i < found.size() && i < 4; ++i) {
            if (i) ss << ", ";
            ss << WinUtils::toNarrow(found[i]);
        }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 3) ? SandboxConfidence::Certain
                       : (found.size() >= 2) ? SandboxConfidence::High
                       :                        SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkXenServices(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "Xen/Citrix Hypervisor Services";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::unordered_set<std::wstring> svcNamesLo;
    for (const auto& s : services)
        svcNamesLo.insert(toLowerW(s.name));

    std::vector<std::wstring> found;
    for (const wchar_t* xenSvc : XEN_SERVICES) {
        if (svcNamesLo.count(std::wstring(xenSvc)))
            found.push_back(xenSvc);
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "Xen/Citrix service(s): ";
        for (size_t i = 0; i < found.size(); ++i) { if (i) ss << ", "; ss << WinUtils::toNarrow(found[i]); }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 2) ? SandboxConfidence::Certain
                       :                        SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkQemuServices(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "QEMU/VirtIO Services";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    std::unordered_set<std::wstring> svcNamesLo;
    for (const auto& s : services)
        svcNamesLo.insert(toLowerW(s.name));

    std::vector<std::wstring> found;
    for (const wchar_t* qSvc : QEMU_SERVICES) {
        if (svcNamesLo.count(std::wstring(qSvc)))
            found.push_back(qSvc);
    }
    ind.rawValue = static_cast<uint64_t>(found.size());

    if (!found.empty()) {
        std::ostringstream ss;
        ss << "QEMU/VirtIO driver service(s): ";
        for (size_t i = 0; i < found.size(); ++i) { if (i) ss << ", "; ss << WinUtils::toNarrow(found[i]); }
        ind.detail     = ss.str();
        ind.confidence = (found.size() >= 2) ? SandboxConfidence::Certain
                       :                        SandboxConfidence::High;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkEventLogService(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "EventLog Service Disabled";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 1;

    for (const auto& s : services) {
        if (toLowerW(s.name) == L"eventlog") {
            ind.rawValue = s.status;
            if (s.status != SERVICE_RUNNING) {
                ind.detail     = "EventLog service is not running (state=" + std::to_string(s.status)
                                 + "). Disabled to suppress forensic logging in sandbox.";
                ind.confidence = SandboxConfidence::Medium;
            }
            return ind;
        }
    }

    // Not found at all
    ind.detail     = "EventLog service not found in SCM database. Minimal sandbox install.";
    ind.confidence = SandboxConfidence::High;
    ind.rawValue   = 0;
    return ind;
}

DetectionIndicator ServicePlugin::checkWindowsUpdateService(const std::vector<ServiceInfo>& services) {
    DetectionIndicator ind;
    ind.name     = "Windows Update Disabled";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 1;

    static constexpr std::array<const wchar_t*, 3> WU_SERVICES = {{
        L"wuauserv", L"bits", L"cryptsvc"
    }};

    uint32_t disabled = 0;
    for (const wchar_t* wuSvc : WU_SERVICES) {
        bool found = false;
        for (const auto& s : services) {
            if (toLowerW(s.name) == wuSvc) {
                found = true;
                if (s.startType == SERVICE_DISABLED) disabled++;
                break;
            }
        }
        if (!found) disabled++;
    }
    ind.rawValue = disabled;

    if (disabled >= 2) {
        ind.detail     = std::to_string(disabled)
                         + " Windows Update component service(s) disabled/missing (wuauserv, bits, cryptsvc). "
                         "Common in isolated sandbox environments.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

DetectionIndicator ServicePlugin::checkScmResponseTiming() {
    DetectionIndicator ind;
    ind.name     = "SCM Response Timing";
    ind.category = DetectionCategory::Process;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Measure how long it takes to open SCM 5 times in a row
    // Sandboxes that intercept SCM calls may introduce latency
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    for (int i = 0; i < 5; ++i) {
        SC_HANDLE h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (h) CloseServiceHandle(h);
    }

    QueryPerformanceCounter(&end);
    uint64_t elapsedUs = (end.QuadPart - start.QuadPart) * 1000000ULL / freq.QuadPart;
    ind.rawValue = elapsedUs;

    // Normal: < 5000 µs for 5 opens (~1ms each max)
    // Hooked: can be 50ms+ per call
    if (elapsedUs > 100000) { // > 100ms for 5 opens
        ind.detail     = "SCM OpenSCManager x5 took " + std::to_string(elapsedUs / 1000)
                         + " ms. Abnormally slow — SCM calls may be intercepted.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
