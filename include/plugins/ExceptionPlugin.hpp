#pragma once

#ifndef SANDBOX_DETECTOR_EXCEPTION_PLUGIN_HPP
#define SANDBOX_DETECTOR_EXCEPTION_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  ExceptionPlugin
//
//  Detects sandbox/VM via exception handling behavior:
//    1.  VEH (Vectored Exception Handler) invocation order anomaly
//    2.  SEH chain walk — sandbox hooks RtlDispatchException
//    3.  INT 2D instruction: debugger trap vs EXCEPTION_BREAKPOINT
//    4.  INT 3 (0xCC) single-byte breakpoint delivery test
//    5.  Trap flag (TF) delivery test via EXCEPTION_SINGLE_STEP
//    6.  EXCEPTION_INVALID_HANDLE from CloseHandle(invalid)
//    7.  UnhandledExceptionFilter hooking detection
//    8.  RaiseException → sandbox counts & intercepts
//    9.  RtlAddVectoredExceptionHandler: duplicate registration test
//   10.  NtRaiseException direct syscall delivery comparison
//   11.  Stack unwind consistency: RtlUnwindEx correctness
//   12.  EXCEPTION_BREAKPOINT on execution of NOP sled test
//   13.  KiUserExceptionDispatcher hook detection (first bytes)
//   14.  Wow64 exception redirection (32-bit on 64-bit OS)
// ============================================================

class ExceptionPlugin final : public IPlugin {
public:
    ExceptionPlugin();
    ~ExceptionPlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 150; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkVehOrder();
    DetectionIndicator checkInt2d();
    DetectionIndicator checkTrapFlag();
    DetectionIndicator checkCloseHandleException();
    DetectionIndicator checkUnhandledExceptionFilter();
    DetectionIndicator checkKiUserExceptionDispatcherHook();
    DetectionIndicator checkRaiseExceptionInterception();
    DetectionIndicator checkInt3Delivery();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_EXCEPTION_PLUGIN_HPP
