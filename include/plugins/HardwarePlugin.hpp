#pragma once

#ifndef SANDBOX_DETECTOR_HARDWARE_PLUGIN_HPP
#define SANDBOX_DETECTOR_HARDWARE_PLUGIN_HPP

#include "core/IPlugin.hpp"

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  HardwarePlugin
//
//  Detects VM/sandbox via hardware anomalies:
//    1. Physical RAM < 2 GB (VMs often given <2GB)
//    2. Logical CPU count < 2 (single-core = likely sandbox)
//    3. HDD size < 60 GB
//    4. Screen resolution anomalies (800x600, 1024x768 = VM default)
//    5. Number of monitors (VMs typically 1)
//    6. MAC address OUI matching VM vendors
//       (VirtualBox: 08:00:27, VMware: 00:0C:29/00:50:56)
//    7. Disk serial number patterns (VBOX, VMWARE, QEMU)
//    8. SMART data availability (VMs often don't expose SMART)
//    9. GPU name/VRAM — software-only renderers (SVGA, Microsoft Basic)
//   10. Sound device absence (many sandboxes disable audio)
//   11. USB controller count (VMs often have 0 or unusual counts)
//   12. Battery presence (physical machines almost always have battery on laptops)
//   13. Firmware type and OEM strings
// ============================================================

class HardwarePlugin final : public IPlugin {
public:
    HardwarePlugin();
    ~HardwarePlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 300; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkPhysicalRam();
    DetectionIndicator checkCpuCount();
    DetectionIndicator checkDiskSize();
    DetectionIndicator checkScreenResolution();
    DetectionIndicator checkMacAddressOui();
    DetectionIndicator checkDiskSerialNumber();
    DetectionIndicator checkGpuName();
    DetectionIndicator checkSoundDevice();
    DetectionIndicator checkMonitorCount();
    DetectionIndicator checkBatteryPresence();
    DetectionIndicator checkFirmwareStrings();
    DetectionIndicator checkUsbControllers();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_HARDWARE_PLUGIN_HPP
