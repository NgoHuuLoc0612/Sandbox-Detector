#pragma once

#ifndef SANDBOX_DETECTOR_REGISTRY_PLUGIN_HPP
#define SANDBOX_DETECTOR_REGISTRY_PLUGIN_HPP

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  RegistryPlugin
//
//  Detects sandbox/VM artifacts in the Windows Registry:
//    1. VirtualBox registry keys & GuestAdditions
//    2. VMware registry artifacts
//    3. Hyper-V registry entries
//    4. QEMU/KVM registry entries
//    5. Sandboxie registry keys
//    6. Cuckoo Sandbox artifacts
//    7. Wine HKCU\Software\Wine presence
//    8. Known analysis tool registry keys (Wireshark, etc.)
//    9. Too-clean HKLM\SYSTEM\CurrentControlSet\Services (minimal service count)
//   10. Suspicious SystemBiosVersion / VideoBiosVersion strings
//   11. HARDWARE\DEVICEMAP\Scsi — disk model strings (VBOX, VMWARE, QEMU…)
//   12. ACPI firmware table vendor strings
// ============================================================

class RegistryPlugin final : public IPlugin {
public:
    RegistryPlugin();
    ~RegistryPlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 200; }

public:
    // KeyCheck must be public so static helper functions outside the class can use it
    struct KeyCheck {
        HKEY         rootKey;
        std::wstring subKey;
        std::wstring valueName;         // empty = just key existence
        std::wstring expectedSubstring; // empty = any value triggers
    };

    static const std::vector<KeyCheck> s_vboxChecks;
    static const std::vector<KeyCheck> s_vmwareChecks;
    static const std::vector<KeyCheck> s_qemuChecks;

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkVirtualBoxKeys();
    DetectionIndicator checkVMwareKeys();
    DetectionIndicator checkHyperVKeys();
    DetectionIndicator checkQemuKeys();
    DetectionIndicator checkSandboxieKeys();
    DetectionIndicator checkWinePresence();
    DetectionIndicator checkDiskModelStrings();
    DetectionIndicator checkBiosVersionStrings();
    DetectionIndicator checkAcpiTables();
    DetectionIndicator checkAnalysisToolKeys();
    DetectionIndicator checkSystemServiceCount();
    DetectionIndicator checkVideoDriverStrings();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_REGISTRY_PLUGIN_HPP
