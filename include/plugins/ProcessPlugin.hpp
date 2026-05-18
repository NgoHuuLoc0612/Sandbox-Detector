#pragma once

#ifndef SANDBOX_DETECTOR_PROCESS_PLUGIN_HPP
#define SANDBOX_DETECTOR_PROCESS_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include "utils/WinApiUtils.hpp"
#include <vector>
#include <string>
#include <unordered_set>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  ProcessPlugin
//
//  Detects sandbox by examining running processes:
//    1. Known sandbox/analysis tool process names
//    2. Known VM guest agent processes
//    3. Abnormally low total process count (<20 = likely sandbox)
//    4. Missing "normal user" processes (explorer, chrome, etc.)
//    5. Sandboxie driver/service process
//    6. Cuckoo agent (agent.py runner)
//    7. Wireshark / tcpdump / procmon presence
//    8. Known AV/EDR processes indicating controlled environment
//    9. Process parent anomalies (cmd.exe spawned from svchost)
//   10. Absence of user-space processes (no browser, media player, etc.)
// ============================================================

class ProcessPlugin final : public IPlugin {
public:
    ProcessPlugin();
    ~ProcessPlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 150; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkSandboxProcesses();
    DetectionIndicator checkVmGuestAgents();
    DetectionIndicator checkProcessCount(const std::vector<WinUtils::ProcessInfo>& procs);
    DetectionIndicator checkAnalysisTools();
    DetectionIndicator checkMissingUserProcesses(const std::unordered_set<std::wstring>& procNamesLower);
    DetectionIndicator checkSandboxieService();

    // Curated process blacklists
    static const std::unordered_set<std::wstring> s_sandboxProcesses;
    static const std::unordered_set<std::wstring> s_vmAgentProcesses;
    static const std::unordered_set<std::wstring> s_analysisToolProcesses;
    static const std::unordered_set<std::wstring> s_normalUserProcesses;

    static constexpr uint32_t MIN_NORMAL_PROCESS_COUNT = 20;
    static constexpr uint32_t MIN_USER_PROCESSES       = 2;
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_PROCESS_PLUGIN_HPP
