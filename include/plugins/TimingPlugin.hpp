#pragma once

#ifndef SANDBOX_DETECTOR_TIMING_PLUGIN_HPP
#define SANDBOX_DETECTOR_TIMING_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  TimingPlugin
//
//  Detects sandbox acceleration/deceleration by measuring:
//    1. CPUID instruction latency (hypervisors trap it)
//    2. RDTSC delta across Sleep() calls
//    3. GetTickCount vs QueryPerformanceCounter drift
//    4. NtDelayExecution accuracy
//    5. SetTimer + callback round-trip
//    6. __rdtscp consistency check
//    7. UserTimerResolution manipulation detection
// ============================================================

class TimingPlugin final : public IPlugin {
public:
    TimingPlugin();
    ~TimingPlugin() override;

    const PluginMetadata&   getMetadata()   const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()      noexcept override;
    PluginResult            run()           override;
    bool                    isSupported()   const noexcept override;
    uint32_t                estimatedRunTimeMs() const noexcept override { return 500; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    // Individual timing checks
    DetectionIndicator checkCpuidLatency();
    DetectionIndicator checkRdtscSleepDrift();
    DetectionIndicator checkTickCountConsistency();
    DetectionIndicator checkNtDelayAccuracy();
    DetectionIndicator checkRdtscpMonotonicity();
    DetectionIndicator checkTimerResolutionManipulation();
    DetectionIndicator checkQueryPerformanceCounterJitter();

    // Threshold parameters (configurable)
    uint64_t m_cpuidLatencyThresholdNs = 1000;   // >1µs CPUID = suspicious
    uint32_t m_rdtscDriftThresholdPct  = 20;      // >20% RDTSC/wall-clock drift
    uint32_t m_sleepMs                 = 100;
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_TIMING_PLUGIN_HPP
