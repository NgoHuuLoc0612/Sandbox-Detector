#pragma once

#ifndef SANDBOX_DETECTOR_NATIVEAPI_PLUGIN_HPP
#define SANDBOX_DETECTOR_NATIVEAPI_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  NativeApiPlugin
//
//  Detects sandbox/VM via undocumented NT Native API calls:
//    1.  NtQuerySystemInformation(SystemKernelDebuggerInformation)
//    2.  NtQuerySystemInformation(SystemHypervisorQueryInformation)
//    3.  NtQuerySystemInformation(SystemCodeIntegrityInformation) — CI.dll disabled?
//    4.  NtQuerySystemInformation(SystemSecureBootPolicyInformation)
//    5.  NtQueryObject(AllObjectsInformation) — object count anomaly
//    6.  NtQueryInformationProcess(ProcessHandleCount) — too few handles
//    7.  NtQueryInformationProcess(ProcessIoPriority)
//    8.  NtSetInformationThread(ThreadHideFromDebugger) success/failure
//    9.  NtCreateFile to \\Device\\VBoxGuest (VirtualBox device)
//   10.  NtCreateFile to \\Device\\vmci (VMware device)
//   11.  NtCreateFile to \\Device\\VBoxMiniRdrDN (VBox shared folders)
//   12.  NtOpenKey to KnownDlls\\sbiedll.dll (Sandboxie)
//   13.  NtQuerySystemInformation(SystemModuleInformation) — driver list
//   14.  NtUserGetForegroundWindow — always NULL in headless sandbox
//   15.  KUSER_SHARED_DATA: NtMajorVersion, NtMinorVersion consistency
//   16.  KUSER_SHARED_DATA: DbgKdEnabled bit
//   17.  NtQueryVirtualMemory(MemoryMappedFilenameInformation) on ntdll
//   18.  RtlGetVersion vs GetVersionEx discrepancy
// ============================================================

class NativeApiPlugin final : public IPlugin {
public:
    NativeApiPlugin();
    ~NativeApiPlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 200; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkKernelDebuggerInfo();
    DetectionIndicator checkHypervisorInfo();
    DetectionIndicator checkCodeIntegrity();
    DetectionIndicator checkVmDeviceObjects();
    DetectionIndicator checkSandboxieKnownDll();
    DetectionIndicator checkSystemModuleDrivers();
    DetectionIndicator checkForegroundWindow();
    DetectionIndicator checkKuserSharedData();
    DetectionIndicator checkProcessHandleCount();
    DetectionIndicator checkThreadHideFromDebugger();
    DetectionIndicator checkNtdllFilePath();
    DetectionIndicator checkRtlVersionConsistency();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_NATIVEAPI_PLUGIN_HPP
