#pragma once

#ifndef SANDBOX_DETECTOR_WMI_PLUGIN_HPP
#define SANDBOX_DETECTOR_WMI_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include "utils/WinApiUtils.hpp"
#include <memory>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  WmiPlugin
//
//  Uses WMI queries to detect virtualization:
//    1. Win32_ComputerSystem.Model — contains "VirtualBox" / "VMware"
//    2. Win32_ComputerSystem.Manufacturer — "innotek", "VMware Inc."
//    3. Win32_BIOS.SMBIOSBIOSVersion — "VBOX", "BOCHS"
//    4. Win32_BIOS.SerialNumber — "0"/"None"/"Not Specified"
//    5. Win32_BaseBoard.Product — virtualizer identifier
//    6. Win32_DiskDrive.Model — "VBOX HARDDISK", "VMware Virtual disk"
//    7. Win32_NetworkAdapter.MACAddress — VM OUI prefixes
//    8. Win32_VideoController.Caption — "VirtualBox Graphics", "VMware SVGA"
//    9. Win32_OperatingSystem.InstallDate — suspiciously recent
//   10. Win32_OperatingSystem.RegisteredUser — "sandbox"/"malware"/"virus"
//   11. Win32_Processor.Name — virtual CPU strings
//   12. Win32_PhysicalMemory absence (VMs often hide this)
// ============================================================

class WmiPlugin final : public IPlugin {
public:
    WmiPlugin();
    ~WmiPlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 2000; }

private:
    PluginMetadata                  m_meta;
    PluginConfig                    m_config;
    std::unique_ptr<WinUtils::WmiSession> m_wmi;

    DetectionIndicator checkComputerSystemModel();
    DetectionIndicator checkComputerSystemManufacturer();
    DetectionIndicator checkBiosVersion();
    DetectionIndicator checkBiosSerialNumber();
    DetectionIndicator checkBaseBoardProduct();
    DetectionIndicator checkDiskDriveModel();
    DetectionIndicator checkNetworkAdapterMac();
    DetectionIndicator checkVideoControllerCaption();
    DetectionIndicator checkRegisteredUser();
    DetectionIndicator checkProcessorName();
    DetectionIndicator checkOsInstallDate();
    DetectionIndicator checkPhysicalMemoryAbsence();

    // Helpers
    std::vector<std::wstring> queryColumn(const std::wstring& wql,
                                           const std::wstring& column);
    bool anyContainsSubstring(const std::vector<std::wstring>& values,
                               const std::vector<std::wstring>& needles,
                               bool caseInsensitive = true);
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_WMI_PLUGIN_HPP
