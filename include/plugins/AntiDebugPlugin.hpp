#pragma once

#ifndef SANDBOX_DETECTOR_ANTIDEBUG_PLUGIN_HPP
#define SANDBOX_DETECTOR_ANTIDEBUG_PLUGIN_HPP

#include "core/IPlugin.hpp"

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  AntiDebugPlugin
//
//  Detects debuggers and analysis tools via:
//    1. IsDebuggerPresent() — PEB.BeingDebugged byte
//    2. CheckRemoteDebuggerPresent()
//    3. NtQueryInformationProcess (ProcessDebugPort)
//    4. NtQueryInformationProcess (ProcessDebugFlags)
//    5. NtQueryInformationProcess (ProcessDebugObjectHandle)
//    6. CloseHandle(invalid) — raises exception if debugger present
//    7. OutputDebugString timing trick
//    8. Heap flag checks (PEB.NtGlobalFlag, heap headers)
//    9. DR register check via GetThreadContext
//   10. NtSetInformationThread (ThreadHideFromDebugger)
//   11. Hardware breakpoint detection
//   12. Parent process name check (should not be a debugger)
//   13. EXCEPTION_SINGLE_STEP trap flag trick
//   14. INT 2D / INT 3 breakpoint detection
// ============================================================

class AntiDebugPlugin final : public IPlugin {
public:
    AntiDebugPlugin();
    ~AntiDebugPlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 100; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkIsDebuggerPresent();
    DetectionIndicator checkRemoteDebuggerPresent();
    DetectionIndicator checkNtDebugPort();
    DetectionIndicator checkNtDebugFlags();
    DetectionIndicator checkNtDebugObjectHandle();
    DetectionIndicator checkHeapFlags();
    DetectionIndicator checkNtGlobalFlag();
    DetectionIndicator checkHardwareBreakpoints();
    DetectionIndicator checkOutputDebugStringTiming();
    DetectionIndicator checkParentProcessName();
    DetectionIndicator checkCloseHandleTrick();
    DetectionIndicator checkDebuggerWindowClass();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_ANTIDEBUG_PLUGIN_HPP
