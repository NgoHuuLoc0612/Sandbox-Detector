#pragma once

#ifndef SANDBOX_DETECTOR_HYPERVISOR_PLUGIN_HPP
#define SANDBOX_DETECTOR_HYPERVISOR_PLUGIN_HPP

#include "core/IPlugin.hpp"

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  HypervisorPlugin
//
//  Detects virtualization via:
//    1. CPUID leaf 0x1 bit 31 (ECX) — hypervisor present bit
//    2. CPUID leaf 0x40000000 — hypervisor vendor string
//    3. CPUID leaf 0x40000001 — hypervisor interface
//    4. CPUID leaf 0x40000002 — hypervisor system identity
//    5. NtQuerySystemInformation SystemHypervisorQueryInformation
//    6. RDMSR MSR 0x3B — last branch record (VMX indicator)
//    7. VirtualBox/VMware/KVM/Hyper-V/QEMU/Parallels fingerprinting
//    8. IN instruction port 0x5658 (VMware backdoor)
//    9. SIDT trick (IDT base address in VM vs bare metal)
//   10. Hardware-assisted virtualization CPU flag checks
// ============================================================

class HypervisorPlugin final : public IPlugin {
public:
    HypervisorPlugin();
    ~HypervisorPlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 50; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkCpuidHypervisorBit();
    DetectionIndicator checkHypervisorVendorString();
    DetectionIndicator checkHypervisorInterface();
    DetectionIndicator checkNtHypervisorInfo();
    DetectionIndicator checkVmwareBackdoor();
    DetectionIndicator checkIdtBaseAddress();
    DetectionIndicator checkVirtualBoxCpuid();
    DetectionIndicator checkHyperVEnlightenments();
    DetectionIndicator checkKvmPvClock();
    DetectionIndicator checkParallelsCpuid();

    bool m_seenVendor = false;
    std::string m_hvVendor;
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_HYPERVISOR_PLUGIN_HPP
