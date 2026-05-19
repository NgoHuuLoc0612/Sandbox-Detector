// plugin_test.cpp — SandboxDetector v3.0.0 full plugin test harness
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX
#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <windows.h>

#include "core/IPlugin.hpp"
#include "core/PluginManager.hpp"
#include "plugins/AntiDebugPlugin.hpp"
#include "plugins/EnvironmentPlugin.hpp"
#include "plugins/ExceptionPlugin.hpp"
#include "plugins/FileSystemPlugin.hpp"
#include "plugins/HardwarePlugin.hpp"
#include "plugins/HypervisorPlugin.hpp"
#include "plugins/MemoryPlugin.hpp"
#include "plugins/NativeApiPlugin.hpp"
#include "plugins/NetworkPlugin.hpp"
#include "plugins/ProcessPlugin.hpp"
#include "plugins/RegistryPlugin.hpp"
#include "plugins/ServicePlugin.hpp"
#include "plugins/TimingPlugin.hpp"
#include "plugins/TokenPrivilegePlugin.hpp"
#include "plugins/WmiPlugin.hpp"

#include <iostream>
#include <memory>
#include <string>
#include <functional>

using namespace SandboxDetector;
using namespace SandboxDetector::Plugins;

// ---- helpers ----
static PluginConfig defaultCfg() {
    PluginConfig c;
    c.enabled              = true;
    c.timeoutMilliseconds  = 500;
    return c;
}

static void registerAll(PluginManager& mgr) {
    auto cfg = defaultCfg();
    mgr.registerPlugin(std::make_unique<AntiDebugPlugin>(),      cfg);
    mgr.registerPlugin(std::make_unique<EnvironmentPlugin>(),    cfg);
    mgr.registerPlugin(std::make_unique<ExceptionPlugin>(),      cfg);
    mgr.registerPlugin(std::make_unique<FileSystemPlugin>(),     cfg);
    mgr.registerPlugin(std::make_unique<HardwarePlugin>(),       cfg);
    mgr.registerPlugin(std::make_unique<HypervisorPlugin>(),     cfg);
    mgr.registerPlugin(std::make_unique<MemoryPlugin>(),         cfg);
    mgr.registerPlugin(std::make_unique<NativeApiPlugin>(),      cfg);
    mgr.registerPlugin(std::make_unique<NetworkPlugin>(),        cfg);
    mgr.registerPlugin(std::make_unique<ProcessPlugin>(),        cfg);
    mgr.registerPlugin(std::make_unique<RegistryPlugin>(),       cfg);
    mgr.registerPlugin(std::make_unique<ServicePlugin>(),        cfg);
    mgr.registerPlugin(std::make_unique<TimingPlugin>(),         cfg);
    mgr.registerPlugin(std::make_unique<TokenPrivilegePlugin>(), cfg);
    mgr.registerPlugin(std::make_unique<WmiPlugin>(),            cfg);
}

// ---- test runner ----
static int g_passed = 0, g_failed = 0;
static void runTest(const char* name, std::function<bool()> fn) {
    std::cout << "--- Test: " << name << " ---\n";
    bool ok = false;
    try { ok = fn(); }
    catch (std::exception& e) { std::cout << "  EXCEPTION: " << e.what() << "\n"; }
    catch (...)                { std::cout << "  UNKNOWN EXCEPTION\n"; }
    if (ok) { ++g_passed; std::cout << "  [PASS]\n\n"; }
    else    { ++g_failed; std::cout << "  [FAIL]\n\n"; }
}

// ===============================================================
int main() {
    std::cout << "==== SandboxDetector v3.0.0 Plugin Test Harness ====\n\n";

    // T1
    runTest("PluginManager construction", []() -> bool {
        PluginManager mgr;
        std::cout << "  Default-constructed OK\n";
        return true;
    });

    // T2
    runTest("Register all 15 plugins", []() -> bool {
        PluginManager mgr;
        registerAll(mgr);
        std::cout << "  All 15 plugins registered without exception\n";
        return true;
    });

    // T3
    runTest("Plugin metadata non-empty", []() -> bool {
        bool ok = true;
        auto check = [&](const char* label, std::unique_ptr<IPlugin> p) {
            auto m = p->getMetadata();
            if (m.name.empty()) {
                std::cout << "  " << label << ": EMPTY name!\n"; ok = false;
            } else {
                std::cout << "  " << label << "  name=\"" << m.name
                          << "\"  ver=" << m.version << "\n";
            }
        };
        check("AntiDebugPlugin",  std::make_unique<AntiDebugPlugin>());
        check("HypervisorPlugin", std::make_unique<HypervisorPlugin>());
        check("MemoryPlugin",     std::make_unique<MemoryPlugin>());
        check("TimingPlugin",     std::make_unique<TimingPlugin>());
        check("ProcessPlugin",    std::make_unique<ProcessPlugin>());
        check("RegistryPlugin",   std::make_unique<RegistryPlugin>());
        check("NetworkPlugin",    std::make_unique<NetworkPlugin>());
        return ok;
    });

    // T4
    runTest("enablePlugin toggle", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        mgr.enablePlugin("AntiDebugPlugin", false);
        mgr.enablePlugin("AntiDebugPlugin", true);
        std::cout << "  Toggle AntiDebugPlugin off/on: no crash\n";
        return true;
    });

    // T5
    runTest("setPluginConfig", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        PluginConfig cfg = defaultCfg();
        cfg.timeoutMilliseconds = 2000;
        mgr.setPluginConfig("MemoryPlugin", cfg);
        std::cout << "  Set MemoryPlugin timeoutMilliseconds=2000: OK\n";
        return true;
    });

    // T6
    runTest("unregisterPlugin", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        mgr.unregisterPlugin("WmiPlugin");
        std::cout << "  Unregistered WmiPlugin: no crash\n";
        return true;
    });

    // T7
    runTest("unregisterAll", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        mgr.unregisterAll();
        std::cout << "  Cleared all 15 plugins: no crash\n";
        return true;
    });

    // T8
    runTest("runPlugin(TimingPlugin)", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        auto r = mgr.runPlugin("TimingPlugin");
        if (!r.has_value()) {
            std::cout << "  runPlugin returned nullopt\n"; return false;
        }
        std::cout << "  executed=" << r->executed
                  << "  indicators=" << r->indicators.size() << "\n";
        for (auto& ind : r->indicators) {
            std::cout << "    [" << ind.name
                      << "] confidence=" << static_cast<int>(ind.confidence)
                      << " raw=" << ind.rawValue << "\n";
            if (!ind.detail.empty())
                std::cout << "      " << ind.detail << "\n";
        }
        return true;
    });

    // T9
    runTest("runPlugin(HypervisorPlugin)", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        auto r = mgr.runPlugin("HypervisorPlugin");
        if (!r.has_value()) { std::cout << "  nullopt\n"; return false; }
        std::cout << "  executed=" << r->executed
                  << "  indicators=" << r->indicators.size() << "\n";
        for (auto& ind : r->indicators) {
            std::cout << "    [" << ind.name
                      << "] confidence=" << static_cast<int>(ind.confidence)
                      << " raw=" << ind.rawValue << "\n";
        }
        return true;
    });

    // T10
    runTest("runPlugin(EnvironmentPlugin)", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        auto r = mgr.runPlugin("EnvironmentPlugin");
        if (!r.has_value()) { std::cout << "  nullopt\n"; return false; }
        std::cout << "  executed=" << r->executed
                  << "  indicators=" << r->indicators.size() << "\n";
        for (auto& ind : r->indicators) {
            std::cout << "    [" << ind.name
                      << "] confidence=" << static_cast<int>(ind.confidence) << "\n";
            if (!ind.detail.empty()) std::cout << "      " << ind.detail << "\n";
        }
        return true;
    });

    // T11 — Full scan
    runTest("runScan all plugins", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        ScanConfig sc;
        sc.runParallel      = false;
        sc.globalTimeoutMs  = 15000;

        uint32_t progCount = 0;
        auto report = mgr.runScan(sc,
            [&](const std::string& pluginName, uint32_t done, uint32_t total) {
                std::cout << "  [" << done << "/" << total << "] " << pluginName << "\n";
                ++progCount;
            });

        std::cout << "\n  === Scan Report ===\n";
        std::cout << "  sandboxDetected : " << report.overallSandboxDetected << "\n";
        std::cout << "  overallConfidence:" << static_cast<int>(report.overallConfidence) << "\n";
        std::cout << "  pluginsRun      : " << report.pluginsRun << "\n";
        std::cout << "  pluginsDetected : " << report.pluginsDetected << "\n";
        std::cout << "  pluginsErrored  : " << report.pluginsErrored << "\n";
        std::cout << "  totalScanTime   : " << report.totalScanTime.count() << " ms\n";
        std::cout << "  progressCallbacks:" << progCount << "\n";

        auto allInds = report.getAllIndicators();
        int suspicious = 0;
        std::cout << "\n  --- Non-zero confidence indicators ---\n";
        for (auto& ind : allInds) {
            if (static_cast<int>(ind.confidence) > 0) {
                ++suspicious;
                std::cout << "  [conf=" << static_cast<int>(ind.confidence)
                          << "] " << ind.name << "\n";
                if (!ind.detail.empty())
                    std::cout << "      " << ind.detail << "\n";
            }
        }
        std::cout << "  Total suspicious: " << suspicious
                  << " / " << allInds.size() << " indicators\n";
        return true;
    });

    // T12 — JSON report
    runTest("ScanReport::toJson()", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        ScanConfig sc; sc.globalTimeoutMs = 8000;
        auto report = mgr.runScan(sc);
        std::string json = report.toJson(true);
        if (json.empty()) {
            std::cout << "  toJson() returned empty!\n"; return false;
        }
        std::cout << "  JSON size: " << json.size() << " bytes\n";
        std::cout << "  Preview (first 500 chars):\n";
        std::cout << json.substr(0, 500) << "\n  ...\n";
        return true;
    });

    // T13 — Text report
    runTest("ScanReport::toText()", []() -> bool {
        PluginManager mgr; registerAll(mgr);
        ScanConfig sc; sc.globalTimeoutMs = 8000;
        auto report = mgr.runScan(sc);
        std::string txt = report.toText();
        if (txt.empty()) {
            std::cout << "  toText() returned empty!\n"; return false;
        }
        std::cout << "  Text size: " << txt.size() << " bytes\n";
        std::cout << "  Preview:\n" << txt.substr(0, 500) << "\n  ...\n";
        return true;
    });

    // ---- summary ----
    std::cout << "============================================\n";
    std::cout << "RESULT: " << g_passed << " passed, "
              << g_failed << " failed  (total=" << (g_passed+g_failed) << ")\n";
    return (g_failed == 0) ? 0 : 1;
}
