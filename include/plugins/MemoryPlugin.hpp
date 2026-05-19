#pragma once

#ifndef SANDBOX_DETECTOR_MEMORY_PLUGIN_HPP
#define SANDBOX_DETECTOR_MEMORY_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <windows.h>
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  MemoryPlugin
//
//  Detects sandbox/VM via memory anomalies:
//    1.  Physical memory < 2 GB (GlobalMemoryStatusEx)
//    2.  VirtualAlloc NX page execution test (DEP enforcement oddities)
//    3.  Guard page exception response (sandbox hook detection)
//    4.  Heap spray detection via VirtualQuery region type analysis
//    5.  Hook detection in ntdll.dll — inline patches (jmp/push-ret)
//    6.  Hook detection in kernel32.dll
//    7.  Manual PE header in-memory vs on-disk comparison (patched ntdll)
//    8.  Suspicious loaded module list (injected DLLs)
//    9.  Abnormal module base addresses (relocation artifacts)
//   10.  PEB.NtGlobalFlag heap tail check vs flags (double check)
//   11.  Working set size anomaly (huge or zero)
//   12.  Page file total size < 100 MB (VMs often disable)
//   13.  Committed memory > physical (excessive over-commit = container)
//   14.  VirtualQuery hole count in process VA space
//   15.  Shared section detection (interprocess monitoring hooks)
// ============================================================

class MemoryPlugin final : public IPlugin {
public:
    MemoryPlugin();
    ~MemoryPlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 200; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkPhysicalMemorySize();
    DetectionIndicator checkPageFileSize();
    DetectionIndicator checkNtdllHooks();
    DetectionIndicator checkKernel32Hooks();
    DetectionIndicator checkSuspiciousModules();
    DetectionIndicator checkHeapFlags();
    DetectionIndicator checkVirtualMemoryRegions();
    DetectionIndicator checkWorkingSetAnomaly();
    DetectionIndicator checkMemoryCommitRatio();
    DetectionIndicator checkGuardPageBehavior();

    // Check if an export function has been inline-hooked
    static bool isFunctionHooked(FARPROC fn) noexcept;
    // Count executable private regions in VA space
    static uint32_t countExecutablePrivateRegions() noexcept;
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_MEMORY_PLUGIN_HPP
