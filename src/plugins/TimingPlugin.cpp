#include "plugins/TimingPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>

#include <chrono>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <sstream>
#include <vector>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Construction
// ============================================================

TimingPlugin::TimingPlugin() {
    m_meta.id           = "com.sandboxdetector.timing";
    m_meta.name         = "Timing & RDTSC Plugin";
    m_meta.version      = "1.2.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandboxes via timing anomalies: RDTSC drift, "
                           "CPUID latency spikes, Sleep accuracy, and timer jitter.";
    m_meta.categories   = DetectionCategory::Timing;
    m_meta.priority     = 10;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

TimingPlugin::~TimingPlugin() {
    shutdown();
}

const PluginMetadata& TimingPlugin::getMetadata() const noexcept {
    return m_meta;
}

bool TimingPlugin::isSupported() const noexcept {
    return true;  // RDTSC always available on x86-64
}

bool TimingPlugin::initialize(const PluginConfig& config) {
    m_config = config;

    if (auto val = config.getParameter("cpuid_latency_ns"))
        m_cpuidLatencyThresholdNs = std::stoull(*val);

    if (auto val = config.getParameter("rdtsc_drift_pct"))
        m_rdtscDriftThresholdPct = std::stoul(*val);

    if (auto val = config.getParameter("sleep_ms"))
        m_sleepMs = std::stoul(*val);

    return true;
}

void TimingPlugin::shutdown() noexcept {}

// ============================================================
//  Main run()
// ============================================================

PluginResult TimingPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkCpuidLatency());
    push(checkRdtscSleepDrift());
    push(checkTickCountConsistency());
    push(checkNtDelayAccuracy());
    push(checkRdtscpMonotonicity());
    push(checkTimerResolutionManipulation());
    push(checkQueryPerformanceCounterJitter());

    result.sandboxDetected   = !result.indicators.empty();
    result.overallConfidence  = result.computeAggregateConfidence();
    result.executionTime      = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Check: CPUID Instruction Latency
//
//  On bare metal, CPUID takes ~50–200 CPU cycles.
//  Under a hypervisor that traps CPUID, it can take 1000+ cycles.
//  We run it 50 times and take the median to filter noise.
// ============================================================

DetectionIndicator TimingPlugin::checkCpuidLatency() {
    DetectionIndicator ind;
    ind.name     = "CPUID Instruction Latency";
    ind.category = DetectionCategory::Timing;

    // Warm up
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);

    const int SAMPLES = 50;
    std::vector<uint64_t> deltas;
    deltas.reserve(SAMPLES);

    for (int i = 0; i < SAMPLES; ++i) {
        // Serialize with CPUID, then measure
        __cpuid(cpuInfo, 0);
        uint64_t before = __rdtsc();
        __cpuid(cpuInfo, 0);
        uint64_t after  = __rdtsc();
        if (after > before) deltas.push_back(after - before);
    }

    if (deltas.empty()) {
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    std::sort(deltas.begin(), deltas.end());
    uint64_t median = deltas[deltas.size() / 2];

    // Estimate cycles → nanoseconds via CPU frequency
    // Use QPC as reference for frequency estimate
    LARGE_INTEGER freq{}, t1{}, t2{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    volatile int dummy = 0;
    for (int i = 0; i < 1'000'000; ++i) dummy += i;
    QueryPerformanceCounter(&t2);
    // Rough TSC frequency estimation
    uint64_t tscBefore = __rdtsc();
    Sleep(50);
    uint64_t tscAfter  = __rdtsc();
    LARGE_INTEGER qt2{};
    QueryPerformanceCounter(&qt2);
    // GHz estimate won't be precise but good enough
    double tscHz = static_cast<double>(tscAfter - tscBefore) / 0.05;
    double nsPerCycle = 1e9 / tscHz;
    uint64_t latencyNs = static_cast<uint64_t>(median * nsPerCycle);

    ind.rawValue = latencyNs;

    std::ostringstream detail;
    detail << "Median CPUID latency: " << latencyNs << " ns "
           << "(threshold: " << m_cpuidLatencyThresholdNs << " ns)";
    ind.detail = detail.str();

    if (latencyNs > m_cpuidLatencyThresholdNs * 5)
        ind.confidence = SandboxConfidence::High;
    else if (latencyNs > m_cpuidLatencyThresholdNs * 2)
        ind.confidence = SandboxConfidence::Medium;
    else if (latencyNs > m_cpuidLatencyThresholdNs)
        ind.confidence = SandboxConfidence::Low;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: RDTSC vs Wall-Clock Sleep Drift
//
//  We Sleep(N ms) and measure TSC delta.
//  Sandboxes often speed up or slow down TSC relative to wall time.
// ============================================================

DetectionIndicator TimingPlugin::checkRdtscSleepDrift() {
    DetectionIndicator ind;
    ind.name     = "RDTSC/Sleep Drift";
    ind.category = DetectionCategory::Timing;

    LARGE_INTEGER freq{}, before{}, after{};
    QueryPerformanceFrequency(&freq);

    const int ITERATIONS = 5;
    std::vector<double> driftPct;

    for (int iter = 0; iter < ITERATIONS; ++iter) {
        QueryPerformanceCounter(&before);
        uint64_t tscBefore = __rdtsc();

        Sleep(m_sleepMs);

        uint64_t tscAfter = __rdtsc();
        QueryPerformanceCounter(&after);

        double wallMs = (static_cast<double>(after.QuadPart - before.QuadPart)
                         / freq.QuadPart) * 1000.0;

        // QPC is reliable; use it to compute expected TSC delta
        // We need CPU frequency: derive from a calibration
        // For drift check, compare Sleep(100) wall time vs requested
        double drift = std::abs(wallMs - m_sleepMs) / m_sleepMs * 100.0;
        driftPct.push_back(drift);
        (void)tscBefore;
        (void)tscAfter;
    }

    double avgDrift = std::accumulate(driftPct.begin(), driftPct.end(), 0.0)
                      / driftPct.size();
    ind.rawValue = static_cast<uint64_t>(avgDrift * 100);  // in basis points

    std::ostringstream detail;
    detail << "Average Sleep drift: " << avgDrift << "% "
           << "(threshold: " << m_rdtscDriftThresholdPct << "%)";
    ind.detail = detail.str();

    if (avgDrift > m_rdtscDriftThresholdPct * 3)
        ind.confidence = SandboxConfidence::Certain;
    else if (avgDrift > m_rdtscDriftThresholdPct * 2)
        ind.confidence = SandboxConfidence::High;
    else if (avgDrift > m_rdtscDriftThresholdPct)
        ind.confidence = SandboxConfidence::Medium;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: GetTickCount vs QPC Consistency
//
//  Both should agree within ~15ms per 100ms interval.
//  Sandboxes frequently forge one but not both.
// ============================================================

DetectionIndicator TimingPlugin::checkTickCountConsistency() {
    DetectionIndicator ind;
    ind.name     = "GetTickCount/QPC Consistency";
    ind.category = DetectionCategory::Timing;

    LARGE_INTEGER freq{}, qpc1{}, qpc2{};
    QueryPerformanceFrequency(&freq);

    DWORD gtc1 = GetTickCount();
    QueryPerformanceCounter(&qpc1);
    Sleep(100);
    DWORD gtc2 = GetTickCount();
    QueryPerformanceCounter(&qpc2);

    double gtcDeltaMs = static_cast<double>(gtc2 - gtc1);
    double qpcDeltaMs = (static_cast<double>(qpc2.QuadPart - qpc1.QuadPart)
                          / freq.QuadPart) * 1000.0;

    double discrepancyMs = std::abs(gtcDeltaMs - qpcDeltaMs);
    ind.rawValue = static_cast<uint64_t>(discrepancyMs * 1000);  // stored in µs

    std::ostringstream detail;
    detail << "GTC delta=" << gtcDeltaMs << " ms, QPC delta=" << qpcDeltaMs
           << " ms, discrepancy=" << discrepancyMs << " ms";
    ind.detail = detail.str();

    if (discrepancyMs > 50.0)
        ind.confidence = SandboxConfidence::High;
    else if (discrepancyMs > 25.0)
        ind.confidence = SandboxConfidence::Medium;
    else if (discrepancyMs > 15.0)
        ind.confidence = SandboxConfidence::Low;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: NtDelayExecution Accuracy
//
//  NtDelayExecution with a 1ms delay should return within 2–20ms
//  on real systems. Sandboxes may return instantly (0ms) indicating
//  time acceleration or hook bypass.
// ============================================================

DetectionIndicator TimingPlugin::checkNtDelayAccuracy() {
    DetectionIndicator ind;
    ind.name     = "NtDelayExecution Accuracy";
    ind.category = DetectionCategory::Timing;

    using PFN_NtDelayExecution = NTSTATUS(WINAPI*)(BOOLEAN, PLARGE_INTEGER);
    static auto pfnDelay = WinUtils::getNtdllExport<PFN_NtDelayExecution>(
        "NtDelayExecution");

    if (!pfnDelay) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "NtDelayExecution not available";
        return ind;
    }

    // Delay 5ms
    LARGE_INTEGER delayInterval;
    delayInterval.QuadPart = -50'000LL;  // 100ns units, negative = relative

    LARGE_INTEGER freq{}, before{}, after{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&before);
    pfnDelay(FALSE, &delayInterval);
    QueryPerformanceCounter(&after);

    double actualMs = (static_cast<double>(after.QuadPart - before.QuadPart)
                        / freq.QuadPart) * 1000.0;
    ind.rawValue = static_cast<uint64_t>(actualMs * 1000);

    std::ostringstream detail;
    detail << "NtDelayExecution(5ms) returned in " << actualMs << " ms";
    ind.detail = detail.str();

    // <0.5ms = accelerated; >50ms = extremely slow (paused sandbox)
    if (actualMs < 0.5 || actualMs > 50.0)
        ind.confidence = SandboxConfidence::High;
    else if (actualMs < 1.0 || actualMs > 30.0)
        ind.confidence = SandboxConfidence::Medium;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: __rdtscp Monotonicity
//
//  __rdtscp must always be strictly increasing.
//  Some sandbox TSC forgers reset or wrap the counter.
// ============================================================

DetectionIndicator TimingPlugin::checkRdtscpMonotonicity() {
    DetectionIndicator ind;
    ind.name     = "RDTSCP Monotonicity";
    ind.category = DetectionCategory::Timing;

    const int N = 1000;
    uint32_t aux = 0;
    uint32_t backwards = 0;
    uint64_t prev = __rdtscp(&aux);

    for (int i = 0; i < N; ++i) {
        uint64_t cur = __rdtscp(&aux);
        if (cur <= prev) ++backwards;
        prev = cur;
    }

    ind.rawValue = backwards;

    std::ostringstream detail;
    detail << backwards << "/" << N << " RDTSCP samples went backwards or stalled";
    ind.detail = detail.str();

    if (backwards > 10)
        ind.confidence = SandboxConfidence::Certain;
    else if (backwards > 5)
        ind.confidence = SandboxConfidence::High;
    else if (backwards > 0)
        ind.confidence = SandboxConfidence::Medium;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Timer Resolution Manipulation
//
//  Sandboxes may set the system timer resolution to 1ms (the min
//  for accurate tracing), revealing themselves via NtQueryTimerResolution.
// ============================================================

DetectionIndicator TimingPlugin::checkTimerResolutionManipulation() {
    DetectionIndicator ind;
    ind.name     = "Timer Resolution Manipulation";
    ind.category = DetectionCategory::Timing;

    using PFN_NtQueryTimerResolution = NTSTATUS(WINAPI*)(PULONG, PULONG, PULONG);
    static auto pfnQuery = WinUtils::getNtdllExport<PFN_NtQueryTimerResolution>(
        "NtQueryTimerResolution");

    if (!pfnQuery) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "NtQueryTimerResolution not available";
        return ind;
    }

    ULONG minRes = 0, maxRes = 0, curRes = 0;
    NTSTATUS status = pfnQuery(&maxRes, &minRes, &curRes);
    if (!NT_SUCCESS(status)) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "NtQueryTimerResolution failed";
        return ind;
    }

    // Resolution in 100ns units: 156250 = 15.625ms (default), 10000 = 1ms
    ind.rawValue = curRes;

    std::ostringstream detail;
    detail << "Current timer resolution: " << (curRes / 10000.0) << " ms "
           << "(min: " << (minRes / 10000.0) << " ms, "
           << "max: " << (maxRes / 10000.0) << " ms)";
    ind.detail = detail.str();

    // If current resolution is at minimum (1ms), something is forcing high-res timing
    if (curRes == minRes && minRes <= 10000)
        ind.confidence = SandboxConfidence::Medium;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: QPC Jitter Analysis
//
//  Consecutive QPC calls should have very consistent small deltas.
//  Sandboxes that fake QPC may show 0-delta or uniform deltas.
// ============================================================

DetectionIndicator TimingPlugin::checkQueryPerformanceCounterJitter() {
    DetectionIndicator ind;
    ind.name     = "QPC Jitter Analysis";
    ind.category = DetectionCategory::Timing;

    LARGE_INTEGER freq{};
    QueryPerformanceFrequency(&freq);

    const int N = 500;
    std::vector<uint64_t> deltas;
    deltas.reserve(N);

    LARGE_INTEGER prev{}, cur{};
    QueryPerformanceCounter(&prev);
    for (int i = 0; i < N; ++i) {
        QueryPerformanceCounter(&cur);
        uint64_t delta = static_cast<uint64_t>(cur.QuadPart - prev.QuadPart);
        deltas.push_back(delta);
        prev = cur;
    }

    // Count zero-deltas (QPC returned same value twice = fake/virtualized)
    uint64_t zeroes = std::count(deltas.begin(), deltas.end(), 0ULL);

    // Count uniform deltas (all exactly the same = quantized fake QPC)
    std::sort(deltas.begin(), deltas.end());
    uint64_t uniqueDeltas = static_cast<uint64_t>(
        std::unique(deltas.begin(), deltas.end()) - deltas.begin());

    ind.rawValue = zeroes;

    std::ostringstream detail;
    detail << "QPC zero-deltas: " << zeroes << "/" << N
           << ", unique delta values: " << uniqueDeltas;
    ind.detail = detail.str();

    if (zeroes > N / 5 || uniqueDeltas < 3)
        ind.confidence = SandboxConfidence::High;
    else if (zeroes > N / 20 || uniqueDeltas < 10)
        ind.confidence = SandboxConfidence::Medium;
    else if (zeroes > 0)
        ind.confidence = SandboxConfidence::Low;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
