#include "plugins/ProcessPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <sstream>
#include <algorithm>
#include <chrono>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Static process blacklists
// ============================================================

const std::unordered_set<std::wstring> ProcessPlugin::s_sandboxProcesses = {
    // Cuckoo Sandbox
    L"cuckoo.py", L"agent.py", L"analyzer.py", L"cuckoomon.dll",
    // Sandboxie
    L"sandboxiedcomlaunch.exe", L"sandboxierpcss.exe",
    L"sbiesvc.exe", L"sbiectrl.exe",
    // Joe Sandbox
    L"joeboxcontrol.exe", L"joeboxserver.exe",
    // Anubis
    L"anubis.exe",
    // ThreatExpert
    L"threatexpert.exe",
    // Norman Sandbox
    L"ngsandbox.exe",
    // COMODO
    L"csfalcon.exe",
    // Generic sandbox markers
    L"vxstream.exe", L"falcon-sandbox.exe", L"claycuckoo.exe",
    L"sandbox.exe", L"idefense.exe",
};

const std::unordered_set<std::wstring> ProcessPlugin::s_vmAgentProcesses = {
    // VirtualBox
    L"vboxservice.exe", L"vboxtray.exe", L"vboxsf.exe",
    // VMware
    L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
    L"vmacthlp.exe", L"vmnat.exe", L"vmnetdhcp.exe",
    // Hyper-V
    L"vmicsvc.exe",
    // QEMU/SPICE
    L"spice-agent.exe", L"qemu-ga.exe",
    // Parallels
    L"prl_tools.exe", L"prl_cc.exe",
    // Xen
    L"xenservice.exe", L"xenusbdevice.exe",
};

const std::unordered_set<std::wstring> ProcessPlugin::s_analysisToolProcesses = {
    // Debuggers
    L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
    L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
    L"idaw.exe", L"idaw64.exe",
    L"immunitydebugger.exe", L"devenv.exe",
    // Network analysis
    L"wireshark.exe", L"fiddler.exe", L"networkminer.exe",
    L"tcpdump.exe", L"rawcap.exe", L"capsa.exe",
    // Process monitoring
    L"procmon.exe", L"procmon64.exe", L"procexp.exe", L"procexp64.exe",
    L"procexp64a.exe",
    // Registry monitoring
    L"regmon.exe", L"registryworkshop.exe",
    // File monitoring
    L"filemon.exe",
    // Memory forensics / dumping
    L"rammap.exe", L"rammap64.exe",
    L"volatility.exe", L"volatility3.exe",
    // Decompilers
    L"ghidra.exe", L"cutter.exe", L"binary_ninja.exe",
    L"dnspy.exe", L"dotpeek.exe", L"ilspy.exe",
    // Sandbox frontends
    L"cuckoomon.exe", L"sandboxie.exe",
    // Sysinternals
    L"autoruns.exe", L"autoruns64.exe",
    L"tcpview.exe", L"tcpview64.exe",
    L"handle.exe", L"handle64.exe",
};

const std::unordered_set<std::wstring> ProcessPlugin::s_normalUserProcesses = {
    L"explorer.exe", L"chrome.exe", L"firefox.exe", L"msedge.exe",
    L"iexplore.exe", L"outlook.exe", L"winword.exe", L"excel.exe",
    L"notepad.exe", L"mspaint.exe",
};

// ============================================================
//  Construction
// ============================================================

ProcessPlugin::ProcessPlugin() {
    m_meta.id           = "com.sandboxdetector.process";
    m_meta.name         = "Process Inspection Plugin";
    m_meta.version      = "1.2.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox by examining running processes: known sandbox "
                           "agents, VM guest tools, analysis tools, abnormal process counts, "
                           "and absence of common user-space processes.";
    m_meta.categories   = DetectionCategory::Process;
    m_meta.priority     = 30;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

ProcessPlugin::~ProcessPlugin() { shutdown(); }

const PluginMetadata& ProcessPlugin::getMetadata() const noexcept { return m_meta; }
bool ProcessPlugin::isSupported() const noexcept { return true; }

bool ProcessPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void ProcessPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult ProcessPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    // Snapshot all processes once for performance
    auto allProcs = WinUtils::enumProcesses();

    // Build lowercase name set for fast lookups
    std::unordered_set<std::wstring> procNamesLower;
    procNamesLower.reserve(allProcs.size());
    for (const auto& p : allProcs) {
        std::wstring lower = p.name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        procNamesLower.insert(lower);
    }

    auto matchBlacklist = [&](const std::unordered_set<std::wstring>& blacklist)
        -> std::vector<std::wstring>
    {
        std::vector<std::wstring> found;
        for (const auto& bl : blacklist) {
            std::wstring blLower = bl;
            std::transform(blLower.begin(), blLower.end(), blLower.begin(), ::towlower);
            if (procNamesLower.count(blLower))
                found.push_back(bl);
        }
        return found;
    };

    // ── Sandbox processes ────────────────────────────────────
    {
        auto found = matchBlacklist(s_sandboxProcesses);
        DetectionIndicator ind;
        ind.name     = "Sandbox Process Names";
        ind.category = DetectionCategory::Process;
        ind.rawValue = found.size();
        std::ostringstream detail;
        detail << found.size() << " sandbox process(es) detected";
        for (const auto& f : found) detail << "; " << WinUtils::toNarrow(f);
        ind.detail = detail.str();
        if (found.size() >= 2)     ind.confidence = SandboxConfidence::Certain;
        else if (!found.empty())   ind.confidence = SandboxConfidence::High;
        else                       ind.confidence = SandboxConfidence::None;
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(ind);
    }

    // ── VM guest agent processes ──────────────────────────────
    {
        auto found = matchBlacklist(s_vmAgentProcesses);
        DetectionIndicator ind;
        ind.name     = "VM Guest Agent Processes";
        ind.category = DetectionCategory::Process;
        ind.rawValue = found.size();
        std::ostringstream detail;
        detail << found.size() << " VM guest agent(s) running";
        for (const auto& f : found) detail << "; " << WinUtils::toNarrow(f);
        ind.detail = detail.str();
        if (found.size() >= 2)     ind.confidence = SandboxConfidence::Certain;
        else if (!found.empty())   ind.confidence = SandboxConfidence::High;
        else                       ind.confidence = SandboxConfidence::None;
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(ind);
    }

    // ── Analysis tool processes ───────────────────────────────
    {
        auto found = matchBlacklist(s_analysisToolProcesses);
        DetectionIndicator ind;
        ind.name     = "Analysis Tool Processes";
        ind.category = DetectionCategory::Process;
        ind.rawValue = found.size();
        std::ostringstream detail;
        detail << found.size() << " analysis tool(s) running";
        for (const auto& f : found) detail << "; " << WinUtils::toNarrow(f);
        ind.detail = detail.str();
        if (found.size() >= 3)     ind.confidence = SandboxConfidence::High;
        else if (found.size() >= 1) ind.confidence = SandboxConfidence::Medium;
        else                       ind.confidence = SandboxConfidence::None;
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(ind);
    }

    push(checkProcessCount(allProcs));
    push(checkMissingUserProcesses(procNamesLower));
    push(checkSandboxieService());

    result.sandboxDetected  = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();
    result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Check: Total Process Count
// ============================================================

DetectionIndicator ProcessPlugin::checkProcessCount(
    const std::vector<WinUtils::ProcessInfo>& procs)
{
    DetectionIndicator ind;
    ind.name     = "Total Process Count";
    ind.category = DetectionCategory::Process;

    uint32_t count = static_cast<uint32_t>(procs.size());
    ind.rawValue = count;

    std::ostringstream detail;
    detail << count << " processes running (normal >" << MIN_NORMAL_PROCESS_COUNT << ")";
    ind.detail = detail.str();

    if (count < 10)                          ind.confidence = SandboxConfidence::Certain;
    else if (count < MIN_NORMAL_PROCESS_COUNT) ind.confidence = SandboxConfidence::High;
    else if (count < 30)                     ind.confidence = SandboxConfidence::Low;
    else                                     ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Missing Ordinary User Processes
// ============================================================

DetectionIndicator ProcessPlugin::checkMissingUserProcesses(
    const std::unordered_set<std::wstring>& procNamesLower)
{
    DetectionIndicator ind;
    ind.name     = "Missing Normal User Processes";
    ind.category = DetectionCategory::Process;

    uint32_t found = 0;
    for (const auto& normal : s_normalUserProcesses) {
        std::wstring lower = normal;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        if (procNamesLower.count(lower)) ++found;
    }

    uint32_t missing = static_cast<uint32_t>(s_normalUserProcesses.size()) - found;
    ind.rawValue = missing;

    std::ostringstream detail;
    detail << found << "/" << s_normalUserProcesses.size()
           << " normal user processes present, " << missing << " missing";
    ind.detail = detail.str();

    if (found == 0)      ind.confidence = SandboxConfidence::High;
    else if (found <= 1) ind.confidence = SandboxConfidence::Medium;
    else if (found <= 2) ind.confidence = SandboxConfidence::Low;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Sandboxie Service Running
// ============================================================

DetectionIndicator ProcessPlugin::checkSandboxieService() {
    DetectionIndicator ind;
    ind.name     = "Sandboxie Service";
    ind.category = DetectionCategory::Process;

    SC_HANDLE hScm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm) {
        ind.detail     = "Could not open SCM";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    static const std::vector<std::wstring> sbieServices = {
        L"SbieDrv", L"SandboxieDrv", L"SbieHide",
    };

    uint32_t hits = 0;
    for (const auto& svc : sbieServices) {
        SC_HANDLE hSvc = OpenServiceW(hScm, svc.c_str(), SERVICE_QUERY_STATUS);
        if (hSvc) {
            SERVICE_STATUS ss{};
            if (QueryServiceStatus(hSvc, &ss) &&
                ss.dwCurrentState == SERVICE_RUNNING)
            {
                ++hits;
            }
            CloseServiceHandle(hSvc);
        }
    }
    CloseServiceHandle(hScm);

    ind.rawValue = hits;

    if (hits >= 1) {
        ind.detail     = "Sandboxie driver service is running";
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail     = "No Sandboxie services running";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Forwarding wrappers for member functions
// ============================================================

DetectionIndicator ProcessPlugin::checkSandboxProcesses() {
    return DetectionIndicator{};  // handled inline in run()
}

DetectionIndicator ProcessPlugin::checkVmGuestAgents() {
    return DetectionIndicator{};  // handled inline in run()
}

DetectionIndicator ProcessPlugin::checkAnalysisTools() {
    return DetectionIndicator{};  // handled inline in run()
}

} // namespace Plugins
} // namespace SandboxDetector
