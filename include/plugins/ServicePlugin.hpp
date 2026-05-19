#pragma once

#ifndef SANDBOX_DETECTOR_SERVICE_PLUGIN_HPP
#define SANDBOX_DETECTOR_SERVICE_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <windows.h>
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  ServicePlugin
//
//  Detects sandbox/VM via Windows Service Control Manager:
//    1.  Total running service count < 20 (minimal sandbox install)
//    2.  Known VM guest service names (VBoxService, vmtools, vmci, etc.)
//    3.  Known sandbox service names (SbieDrv, CuckooService, etc.)
//    4.  Missing expected system services (Themes, AudioSrv, etc.)
//    5.  Service binary paths pointing to non-System32 locations for system services
//    6.  XenBus / XenPCI / XenVbd driver services (Xen/Citrix hypervisor)
//    7.  Hyper-V integration services (vmicheartbeat, vmicvss, etc.)
//    8.  QEMU VirtIO driver services (vioscsi, viostor, vioserial)
//    9.  Service account anomaly: all services running as SYSTEM
//   10.  SCM database access timing (hooked SCM = delayed response)
//   11.  EventLog service running (disabled in many sandboxes)
//   12.  Windows Update service state (disabled = isolated environment)
//   13.  Spooler service (Print Spooler) absent = server/sandbox
//   14.  Total service count vs unique binary count ratio
// ============================================================

class ServicePlugin final : public IPlugin {
public:
    ServicePlugin();
    ~ServicePlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 300; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    struct ServiceInfo {
        std::wstring name;
        std::wstring displayName;
        std::wstring binaryPath;
        DWORD        status;
        DWORD        type;
        DWORD        startType;
    };

    std::vector<ServiceInfo> enumAllServices();

    DetectionIndicator checkServiceCount(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkVmGuestServices(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkSandboxServices(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkMissingSystemServices(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkHyperVServices(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkXenServices(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkQemuServices(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkEventLogService(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkWindowsUpdateService(const std::vector<ServiceInfo>& services);
    DetectionIndicator checkScmResponseTiming();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_SERVICE_PLUGIN_HPP
