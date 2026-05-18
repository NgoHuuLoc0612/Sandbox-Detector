#pragma once

#ifndef SANDBOX_DETECTOR_PLUGIN_MANAGER_HPP
#define SANDBOX_DETECTOR_PLUGIN_MANAGER_HPP

#include "IPlugin.hpp"
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <filesystem>
#include <atomic>

namespace SandboxDetector {

// ============================================================
//  Scan Configuration
// ============================================================

struct ScanConfig {
    DetectionCategory   categoryFilter      = DetectionCategory::All;
    uint32_t            globalTimeoutMs     = 30000;
    bool                runParallel         = false;   // single-threaded by default (safer)
    bool                stopOnFirstDetect   = false;
    bool                includeDisabled     = false;
    uint32_t            minimumPriority     = 0;       // 0 = run all
    bool                verboseLogging      = false;
};

// ============================================================
//  Aggregate Scan Report
// ============================================================

struct ScanReport {
    bool                                overallSandboxDetected;
    SandboxConfidence                   overallConfidence;
    uint32_t                            pluginsRun;
    uint32_t                            pluginsDetected;
    uint32_t                            pluginsErrored;
    std::vector<PluginResult>           results;
    std::chrono::milliseconds           totalScanTime;
    std::string                         systemFingerprint;  // hash of detection context

    // Helper: get all indicators sorted by confidence descending
    std::vector<DetectionIndicator>     getAllIndicators() const;

    // Helper: filter results by category
    std::vector<PluginResult>           getResultsByCategory(DetectionCategory cat) const;

    // Generate a JSON report string
    std::string                         toJson(bool pretty = true) const;

    // Generate a human-readable text report
    std::string                         toText() const;
};

// ============================================================
//  Plugin Loader (handles DLL/so lifetime)
// ============================================================

struct LoadedPlugin {
    std::shared_ptr<IPlugin>            instance;
    void*                               moduleHandle;   // HMODULE on Windows
    std::filesystem::path               sourcePath;
    PluginConfig                        config;
    bool                                ownsModule;
};

// ============================================================
//  PluginManager
// ============================================================

class PluginManager {
public:
    // Progress callback: (pluginId, current, total)
    using ProgressCallback = std::function<void(const std::string&, uint32_t, uint32_t)>;

    explicit PluginManager();
    ~PluginManager();

    // Non-copyable, movable
    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;
    PluginManager(PluginManager&&) noexcept;
    PluginManager& operator=(PluginManager&&) noexcept;

    // ── Plugin Registration ───────────────────────────────────

    // Register a built-in plugin directly (takes ownership)
    bool registerPlugin(std::unique_ptr<IPlugin> plugin,
                        const PluginConfig& config = {});

    // Load a plugin from a DLL/SO file
    bool loadPluginFromFile(const std::filesystem::path& dllPath,
                            const PluginConfig& config = {});

    // Scan a directory and auto-load all plugin DLLs matching pattern
    uint32_t loadPluginsFromDirectory(const std::filesystem::path& dir,
                                      const std::string& pattern = "sd_plugin_*.dll");

    // Unregister by ID
    bool unregisterPlugin(const std::string& pluginId);

    // Unregister all
    void unregisterAll();

    // ── Configuration ─────────────────────────────────────────

    void setPluginConfig(const std::string& pluginId, const PluginConfig& config);
    void enablePlugin(const std::string& pluginId, bool enabled);
    PluginConfig getPluginConfig(const std::string& pluginId) const;

    // ── Query ─────────────────────────────────────────────────

    std::vector<PluginMetadata> listPlugins() const;
    bool hasPlugin(const std::string& pluginId) const noexcept;
    uint32_t pluginCount() const noexcept;

    // ── Execution ─────────────────────────────────────────────

    ScanReport runScan(const ScanConfig& config = {},
                       ProgressCallback callback = nullptr);

    // Run a single plugin by ID
    std::optional<PluginResult> runPlugin(const std::string& pluginId);

    // ── Callbacks ─────────────────────────────────────────────

    using DetectionCallback = std::function<void(const PluginResult&)>;
    void setDetectionCallback(DetectionCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void sortPluginsByPriority();
    PluginResult executePluginSafe(LoadedPlugin& lp, const ScanConfig& cfg);
    std::string computeSystemFingerprint() const;
};

} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_PLUGIN_MANAGER_HPP
