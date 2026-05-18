//
// ExamplePlugin.cpp — Template for an external plugin DLL
//
// Build with CMake: the sd_plugin_example target produces
// sd_plugin_example.dll which PluginManager can load at runtime.
//
// To create your own plugin:
//   1. Copy this file, rename class and metadata
//   2. Implement run() with your detection logic
//   3. Build as DLL: dllexport CreatePlugin / DestroyPlugin / GetPluginApiVersion
//   4. Name the output file sd_plugin_<name>.dll
//   5. Drop into the --plugin-dir directory
//

#include "core/IPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <sstream>
#include <chrono>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  ExamplePlugin — Template demonstrating the plugin API
// ============================================================

class ExamplePlugin final : public IPlugin {
public:
    ExamplePlugin() {
        m_meta.id           = "com.example.customplugin";
        m_meta.name         = "Example Custom Plugin";
        m_meta.version      = "1.0.0";
        m_meta.author       = "Your Name";
        m_meta.description  = "Example plugin demonstrating the SandboxDetector plugin API.";
        m_meta.categories   = DetectionCategory::FileSystem;
        m_meta.priority     = 100;
        m_meta.requiresAdmin = false;
        m_meta.isDestructive = false;
    }

    ~ExamplePlugin() override { shutdown(); }

    const PluginMetadata& getMetadata() const noexcept override {
        return m_meta;
    }

    bool initialize(const PluginConfig& config) override {
        m_config = config;
        return true;
    }

    void shutdown() noexcept override {}

    bool isSupported() const noexcept override {
        return true;
    }

    uint32_t estimatedRunTimeMs() const noexcept override {
        return 50;
    }

    PluginResult run() override {
        PluginResult result;
        result.pluginId      = m_meta.id;
        result.pluginVersion = m_meta.version;
        result.executed      = true;

        auto t0 = std::chrono::steady_clock::now();

        // ── Example: Check for sandbox artifact files ────────
        static const std::vector<std::wstring> sandboxFiles = {
            L"C:\\agent.py",
            L"C:\\sandbox\\agent.py",
            L"C:\\cuckoo\\agent.py",
            L"C:\\windows\\system32\\drivers\\vboxdrv.sys",
            L"C:\\windows\\system32\\drivers\\vm3dmp.sys",
            L"C:\\windows\\system32\\vboxhook.dll",
        };

        std::vector<std::wstring> found;
        for (const auto& path : sandboxFiles) {
            if (WinUtils::fileExists(path))
                found.push_back(path);
        }

        if (!found.empty()) {
            DetectionIndicator ind;
            ind.name     = "Sandbox Artifact Files";
            ind.category = DetectionCategory::FileSystem;
            ind.rawValue = found.size();

            std::ostringstream detail;
            detail << found.size() << " sandbox file(s) found: ";
            for (const auto& f : found)
                detail << "\"" << WinUtils::toNarrow(f) << "\" ";
            ind.detail = detail.str();

            ind.confidence = (found.size() >= 2)
                             ? SandboxConfidence::Certain
                             : SandboxConfidence::High;

            result.indicators.push_back(std::move(ind));
        }

        result.sandboxDetected  = !result.indicators.empty();
        result.overallConfidence = result.computeAggregateConfidence();
        result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                       std::chrono::steady_clock::now() - t0);
        return result;
    }

private:
    PluginMetadata m_meta;
    PluginConfig   m_config;
};

} // namespace Plugins
} // namespace SandboxDetector

// ============================================================
//  DLL export symbols — required by PluginManager::loadPluginFromFile
// ============================================================

extern "C" {

__declspec(dllexport)
SandboxDetector::IPlugin* CreatePlugin() {
    return new SandboxDetector::Plugins::ExamplePlugin();
}

__declspec(dllexport)
void DestroyPlugin(SandboxDetector::IPlugin* plugin) {
    delete plugin;
}

__declspec(dllexport)
const char* GetPluginApiVersion() {
    return SandboxDetector::PLUGIN_API_VERSION;
}

} // extern "C"
