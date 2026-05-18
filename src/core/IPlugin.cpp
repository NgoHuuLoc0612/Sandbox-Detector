#include "core/IPlugin.hpp"
#include <numeric>
#include <algorithm>

namespace SandboxDetector {

// ============================================================
//  PluginResult
// ============================================================

SandboxConfidence PluginResult::computeAggregateConfidence() const noexcept {
    if (indicators.empty()) return SandboxConfidence::None;

    // Weighted average: high-confidence indicators contribute more
    uint64_t weightedSum = 0;
    uint64_t totalWeight = 0;

    for (const auto& ind : indicators) {
        uint64_t weight = static_cast<uint64_t>(ind.confidence);
        weightedSum += weight * weight;   // square weighting — outliers dominate
        totalWeight += weight;
    }

    if (totalWeight == 0) return SandboxConfidence::None;
    uint64_t avg = weightedSum / totalWeight;

    if (avg >= static_cast<uint64_t>(SandboxConfidence::Certain))
        return SandboxConfidence::Certain;
    if (avg >= static_cast<uint64_t>(SandboxConfidence::High))
        return SandboxConfidence::High;
    if (avg >= static_cast<uint64_t>(SandboxConfidence::Medium))
        return SandboxConfidence::Medium;
    if (avg >= static_cast<uint64_t>(SandboxConfidence::Low))
        return SandboxConfidence::Low;
    return SandboxConfidence::None;
}

// ============================================================
//  PluginConfig
// ============================================================

std::optional<std::string> PluginConfig::getParameter(const std::string& key) const noexcept {
    for (const auto& [k, v] : parameters) {
        if (k == key) return v;
    }
    return std::nullopt;
}

} // namespace SandboxDetector
