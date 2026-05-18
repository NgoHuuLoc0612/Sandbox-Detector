#pragma once

#ifndef SANDBOX_DETECTOR_IPLUGIN_HPP
#define SANDBOX_DETECTOR_IPLUGIN_HPP

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>
#include <optional>
#include <chrono>

namespace SandboxDetector {

// ============================================================
//  Enumerations
// ============================================================

enum class SandboxConfidence : uint8_t {
    None     = 0,
    Low      = 25,
    Medium   = 50,
    High     = 75,
    Certain  = 100
};

enum class DetectionCategory : uint16_t {
    None                    = 0x0000,
    Timing                  = 0x0001,
    Hardware                = 0x0002,
    Registry                = 0x0004,
    Process                 = 0x0008,
    Network                 = 0x0010,
    FileSystem              = 0x0020,
    UserBehavior            = 0x0040,
    Hypervisor              = 0x0080,
    WMI                     = 0x0100,
    AntiDebug               = 0x0200,
    EnvironmentVariables    = 0x0400,
    Memory                  = 0x0800,
    NativeAPI               = 0x1000,
    GraphicsDevice          = 0x2000,
    Exception               = 0x4000,
    All                     = 0xFFFF
};

inline DetectionCategory operator|(DetectionCategory a, DetectionCategory b) {
    return static_cast<DetectionCategory>(
        static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}

inline DetectionCategory operator&(DetectionCategory a, DetectionCategory b) {
    return static_cast<DetectionCategory>(
        static_cast<uint16_t>(a) & static_cast<uint16_t>(b));
}

// ============================================================
//  Detection Result
// ============================================================

struct DetectionIndicator {
    std::string         name;           // e.g. "CPUID Hypervisor Bit"
    std::string         detail;         // human-readable evidence
    SandboxConfidence   confidence;
    DetectionCategory   category;
    uint64_t            rawValue;       // optional raw numeric evidence
};

struct PluginResult {
    std::string                         pluginId;
    std::string                         pluginVersion;
    bool                                executed;
    bool                                sandboxDetected;
    SandboxConfidence                   overallConfidence;
    std::vector<DetectionIndicator>     indicators;
    std::chrono::microseconds           executionTime;
    std::optional<std::string>          errorMessage;

    // Aggregate confidence from all indicators
    SandboxConfidence computeAggregateConfidence() const noexcept;
};

// ============================================================
//  Plugin Metadata
// ============================================================

struct PluginMetadata {
    std::string         id;             // unique reverse-DNS style: "com.vendor.timing"
    std::string         name;           // display name
    std::string         version;        // semver "1.2.3"
    std::string         author;
    std::string         description;
    DetectionCategory   categories;     // bitmask of categories this plugin covers
    uint32_t            priority;       // lower = runs first
    bool                requiresAdmin;  // needs elevated privileges
    bool                isDestructive;  // modifies system state
};

// ============================================================
//  Plugin Configuration
// ============================================================

struct PluginConfig {
    bool        enabled             = true;
    uint32_t    timeoutMilliseconds = 5000;
    bool        verbose             = false;
    // Extended config via key-value pairs
    std::vector<std::pair<std::string, std::string>> parameters;

    std::optional<std::string> getParameter(const std::string& key) const noexcept;
};

// ============================================================
//  IPlugin Interface
// ============================================================

class IPlugin {
public:
    virtual ~IPlugin() = default;

    // Metadata & lifecycle
    virtual const PluginMetadata&   getMetadata()   const noexcept = 0;
    virtual bool                    initialize(const PluginConfig& config) = 0;
    virtual void                    shutdown() noexcept = 0;

    // Core detection entry point
    virtual PluginResult            run() = 0;

    // Optional: quick pre-check (e.g. OS version gate)
    virtual bool                    isSupported()   const noexcept { return true; }

    // Optional: estimated run time hint (ms)
    virtual uint32_t                estimatedRunTimeMs() const noexcept { return 100; }
};

// ============================================================
//  Plugin Factory
// ============================================================

using PluginFactory = std::function<std::unique_ptr<IPlugin>()>;

// C-ABI export symbol each plugin DLL must expose:
//   extern "C" __declspec(dllexport) SandboxDetector::IPlugin* CreatePlugin();
//   extern "C" __declspec(dllexport) void DestroyPlugin(SandboxDetector::IPlugin*);
//   extern "C" __declspec(dllexport) const char* GetPluginApiVersion();

constexpr const char* PLUGIN_API_VERSION = "1.0.0";

} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_IPLUGIN_HPP
