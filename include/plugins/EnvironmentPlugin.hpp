#pragma once

#ifndef SANDBOX_DETECTOR_ENVIRONMENT_PLUGIN_HPP
#define SANDBOX_DETECTOR_ENVIRONMENT_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  EnvironmentPlugin
//
//  Detects sandbox via environment variables and OS settings:
//    1.  USERNAME is "sandbox", "malware", "john", "user", "test", "admin"
//    2.  COMPUTERNAME contains "sandbox", "cuckoo", "maltest", "vmware"
//    3.  SandboxEnvironment / CUCKOO env var presence
//    4.  VBOX_VERSION env var
//    5.  PROCESSOR_IDENTIFIER reveals QEMU/KVM
//    6.  NUMBER_OF_PROCESSORS = 1
//    7.  SystemRoot on non-C: drive
//    8.  PATH missing typical user directories
//    9.  Screen saver disabled (registry: ScreenSaveActive = 0)
//   10.  Uptime < 5 minutes (freshly spun sandbox)
//   11.  Boot time: system installed <7 days ago (registry ProductId install date)
//   12.  Windows product edition: Evaluation / LTSC (common in VMs)
//   13.  Locale: MUI fallback only (no regional settings)
//   14.  PATHEXT missing standard extensions (stripped environment)
//   15.  TEMP pointing to suspicious path
// ============================================================

class EnvironmentPlugin final : public IPlugin {
public:
    EnvironmentPlugin();
    ~EnvironmentPlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 150; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkSuspiciousUsername();
    DetectionIndicator checkSuspiciousComputerName();
    DetectionIndicator checkSandboxEnvVars();
    DetectionIndicator checkProcessorIdentifier();
    DetectionIndicator checkProcessorCount();
    DetectionIndicator checkSystemRoot();
    DetectionIndicator checkUptime();
    DetectionIndicator checkInstallDate();
    DetectionIndicator checkWindowsEdition();
    DetectionIndicator checkScreenSaverDisabled();
    DetectionIndicator checkTempPath();
    DetectionIndicator checkPathVariable();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_ENVIRONMENT_PLUGIN_HPP
