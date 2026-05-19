//
// SandboxDetector — Command-Line Entry Point
// Production-grade sandbox detection with plugin architecture
//

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>

#include "core/PluginManager.hpp"
#include "plugins/TimingPlugin.hpp"
#include "plugins/HypervisorPlugin.hpp"
#include "plugins/RegistryPlugin.hpp"
#include "plugins/ProcessPlugin.hpp"
#include "plugins/AntiDebugPlugin.hpp"
#include "plugins/HardwarePlugin.hpp"
#include "plugins/WmiPlugin.hpp"
#include "plugins/NetworkPlugin.hpp"
#include "plugins/FileSystemPlugin.hpp"
#include "plugins/EnvironmentPlugin.hpp"
#include "plugins/MemoryPlugin.hpp"
#include "plugins/NativeApiPlugin.hpp"
#include "plugins/ExceptionPlugin.hpp"
#include "plugins/TokenPrivilegePlugin.hpp"
#include "plugins/ServicePlugin.hpp"

#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <csignal>
#include <algorithm>
#include <chrono>

namespace fs = std::filesystem;
using namespace SandboxDetector;

// ============================================================
//  ANSI Console Colors (Windows 10+)
// ============================================================

static void enableAnsiConsole() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static const char* RED     = "\033[1;31m";
static const char* GREEN   = "\033[1;32m";
static const char* YELLOW  = "\033[1;33m";
static const char* CYAN    = "\033[1;36m";
static const char* WHITE   = "\033[1;37m";
static const char* RESET   = "\033[0m";

// ============================================================
//  Banner
// ============================================================

static void printBanner() {
    std::cout << WHITE
              << "  ╔═══════════════════════════════════════════════════╗\n"
              << "  ║          SANDBOX DETECTOR  v3.0.0                 ║\n"
              << "  ║   Plugin-Based Virtualization & Sandbox Detector  ║\n"
              << "  ║   Plugins: Timing | Hypervisor | Registry |       ║\n"
              << "  ║            Process | AntiDebug | HW | WMI |       ║\n"
              << "  ║            Network | FileSystem | Env | Memory |  ║\n"
              << "  ║            NativeAPI | Exception | Token | Svc    ║\n"
              << "  ╚═══════════════════════════════════════════════════╝\n"
              << RESET << "\n";
}

// ============================================================
//  CLI Arguments
// ============================================================

struct CliArgs {
    bool        verbose       = false;
    bool        jsonOutput    = false;
    bool        parallel      = false;
    bool        stopOnFirst   = false;
    bool        listPlugins   = false;
    bool        noColor       = false;
    std::string outputFile;
    std::string pluginDir;
    std::string categoryFilter = "all";
    uint32_t    timeout        = 30000;
};

static void printUsage(const char* exe) {
    std::cout << "Usage: " << exe << " [options]\n\n"
              << "Options:\n"
              << "  -v, --verbose         Verbose output\n"
              << "  -j, --json            Output JSON report\n"
              << "  -o, --output FILE     Write report to FILE\n"
              << "  -p, --parallel        Run plugins in parallel\n"
              << "  -s, --stop-first      Stop after first detection\n"
              << "  -l, --list-plugins    List loaded plugins and exit\n"
              << "  --plugin-dir DIR      Load plugins from DIR\n"
              << "  --no-color            Disable ANSI color output\n"
              << "  --timeout MS          Global timeout in ms (default: 30000)\n"
              << "  --category CATS       Filter categories (comma-separated):\n"
              << "                        timing,hypervisor,registry,process,\n"
              << "                        antidebug,hardware,wmi,network,\n"
              << "                        filesystem,environment,memory,\n"
              << "                        nativeapi,exception,token,all\n"
              << "  -h, --help            Show this help\n\n";
}

static CliArgs parseArgs(int argc, char* argv[]) {
    CliArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose")      args.verbose      = true;
        else if (arg == "-j" || arg == "--json")    args.jsonOutput   = true;
        else if (arg == "-p" || arg == "--parallel") args.parallel    = true;
        else if (arg == "-s" || arg == "--stop-first") args.stopOnFirst = true;
        else if (arg == "-l" || arg == "--list-plugins") args.listPlugins = true;
        else if (arg == "--no-color")               args.noColor      = true;
        else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc)
            args.outputFile = argv[++i];
        else if (arg == "--plugin-dir" && i + 1 < argc)
            args.pluginDir = argv[++i];
        else if (arg == "--timeout" && i + 1 < argc)
            args.timeout = static_cast<uint32_t>(std::stoul(argv[++i]));
        else if (arg == "--category" && i + 1 < argc)
            args.categoryFilter = argv[++i];
    }
    return args;
}

// ============================================================
//  Category string parser
// ============================================================

static DetectionCategory parseCategoryFilter(const std::string& filter) {
    if (filter == "all") return DetectionCategory::All;

    DetectionCategory result = DetectionCategory::None;
    std::istringstream ss(filter);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);

        if      (token == "timing")        result = result | DetectionCategory::Timing;
        else if (token == "hypervisor")    result = result | DetectionCategory::Hypervisor;
        else if (token == "registry")      result = result | DetectionCategory::Registry;
        else if (token == "process")       result = result | DetectionCategory::Process;
        else if (token == "antidebug")     result = result | DetectionCategory::AntiDebug;
        else if (token == "hardware")      result = result | DetectionCategory::Hardware;
        else if (token == "wmi")           result = result | DetectionCategory::WMI;
        else if (token == "network")       result = result | DetectionCategory::Network;
        else if (token == "filesystem")    result = result | DetectionCategory::FileSystem;
        else if (token == "environment")   result = result | DetectionCategory::EnvironmentVariables;
        else if (token == "memory")        result = result | DetectionCategory::Memory;
        else if (token == "nativeapi")     result = result | DetectionCategory::NativeAPI;
        else if (token == "exception")     result = result | DetectionCategory::Exception;
        else if (token == "token")         result = result | DetectionCategory::NativeAPI;
        else if (token == "all")           result = result | DetectionCategory::All;
        else {
            std::cerr << "Unknown category: " << token << "\n";
        }
    }
    return result;
}

// ============================================================
//  Confidence label
// ============================================================

static const char* confidenceStr(SandboxConfidence c) {
    switch (c) {
    case SandboxConfidence::None:    return "NONE   ";
    case SandboxConfidence::Low:     return "LOW    ";
    case SandboxConfidence::Medium:  return "MEDIUM ";
    case SandboxConfidence::High:    return "HIGH   ";
    case SandboxConfidence::Certain: return "CERTAIN";
    default: return "???????";
    }
}

static const char* confidenceColor(SandboxConfidence c, bool color) {
    if (!color) return "";
    switch (c) {
    case SandboxConfidence::None:    return GREEN;
    case SandboxConfidence::Low:     return YELLOW;
    case SandboxConfidence::Medium:  return YELLOW;
    case SandboxConfidence::High:    return RED;
    case SandboxConfidence::Certain: return RED;
    default: return RESET;
    }
}

// ============================================================
//  Console report renderer
// ============================================================

static void printConsoleReport(const ScanReport& report,
                                const CliArgs& args)
{
    bool useColor = !args.noColor;

    std::cout << "\n";
    std::cout << WHITE << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
              << "  SCAN RESULTS\n"
              << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
              << RESET;

    const char* overallColor = useColor
        ? (report.overallSandboxDetected ? RED : GREEN)
        : "";

    std::cout << "\n  Sandbox Detected : "
              << overallColor
              << (report.overallSandboxDetected ? "[ YES ]" : "[ NO  ]")
              << RESET << "\n";

    std::cout << "  Confidence       : "
              << confidenceColor(report.overallConfidence, useColor)
              << confidenceStr(report.overallConfidence)
              << RESET << "\n";

    std::cout << "  Plugins Run      : " << report.pluginsRun      << "\n";
    std::cout << "  Detections       : " << report.pluginsDetected  << "\n";
    std::cout << "  Errors           : " << report.pluginsErrored   << "\n";
    std::cout << "  Scan Time        : " << report.totalScanTime.count() << " ms\n";
    std::cout << "  System FP        : " << report.systemFingerprint.substr(0, 16) << "…\n";

    std::cout << "\n" << WHITE
              << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
              << "  PLUGIN DETAILS\n"
              << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
              << RESET;

    for (const auto& r : report.results) {
        const char* pluginColor = useColor
            ? (r.sandboxDetected ? RED : GREEN)
            : "";

        std::cout << "\n  ┌─ " << CYAN << r.pluginId
                  << " v" << r.pluginVersion << RESET << "\n";
        std::cout << "  │  Status    : "
                  << pluginColor
                  << (r.sandboxDetected ? "DETECTED" : "clean")
                  << RESET << "\n";
        std::cout << "  │  Exec Time : " << r.executionTime.count() << " µs\n";

        if (r.errorMessage)
            std::cout << "  │  Error     : " << RED << *r.errorMessage << RESET << "\n";

        if (args.verbose || r.sandboxDetected) {
            for (const auto& ind : r.indicators) {
                std::cout << "  │  ["
                          << confidenceColor(ind.confidence, useColor)
                          << confidenceStr(ind.confidence)
                          << RESET << "] "
                          << ind.name << "\n"
                          << "  │           → " << ind.detail << "\n";
            }
        }
        std::cout << "  └─────────────────────────────────────────────\n";
    }

    std::cout << "\n";
}

// ============================================================
//  main()
// ============================================================

int main(int argc, char* argv[]) {
    enableAnsiConsole();
    SetConsoleOutputCP(CP_UTF8);

    CliArgs args = parseArgs(argc, argv);

    if (!args.noColor) printBanner();

    // ── Build Plugin Manager ─────────────────────────────────
    PluginManager mgr;

    // Register all built-in plugins
    {
        PluginConfig cfg;
        cfg.verbose = args.verbose;
        cfg.timeoutMilliseconds = args.timeout;

        mgr.registerPlugin(std::make_unique<Plugins::HypervisorPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::AntiDebugPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::TimingPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::RegistryPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::ProcessPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::HardwarePlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::WmiPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::NetworkPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::FileSystemPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::EnvironmentPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::MemoryPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::NativeApiPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::ExceptionPlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::TokenPrivilegePlugin>(), cfg);
        mgr.registerPlugin(std::make_unique<Plugins::ServicePlugin>(), cfg);
    }

    // Load external plugins from directory
    if (!args.pluginDir.empty()) {
        fs::path dir(args.pluginDir);
        uint32_t loaded = mgr.loadPluginsFromDirectory(dir);
        std::cout << CYAN << "[+] Loaded " << loaded
                  << " external plugin(s) from " << args.pluginDir
                  << RESET << "\n\n";
    }

    // ── List plugins ─────────────────────────────────────────
    if (args.listPlugins) {
        auto plugins = mgr.listPlugins();
        std::cout << WHITE << "Loaded Plugins (" << plugins.size() << "):\n" << RESET;
        for (const auto& m : plugins) {
            std::cout << "  [" << std::setw(3) << m.priority << "] "
                      << CYAN << m.id << RESET
                      << " v" << m.version
                      << " — " << m.description << "\n";
        }
        return 0;
    }

    // ── Build Scan Config ────────────────────────────────────
    ScanConfig scanCfg;
    scanCfg.categoryFilter   = parseCategoryFilter(args.categoryFilter);
    scanCfg.globalTimeoutMs  = args.timeout;
    scanCfg.runParallel      = args.parallel;
    scanCfg.stopOnFirstDetect = args.stopOnFirst;
    scanCfg.verboseLogging   = args.verbose;

    std::cout << CYAN << "[*] Starting scan with "
              << mgr.pluginCount() << " plugin(s)…\n" << RESET;

    // Progress callback
    auto progress = [&](const std::string& pluginId,
                         uint32_t current, uint32_t total)
    {
        if (!args.noColor) {
            std::cout << "  [" << current << "/" << total << "] Running: "
                      << pluginId << "…\r" << std::flush;
        }
    };

    // ── Detection callback ───────────────────────────────────
    mgr.setDetectionCallback([&](const PluginResult& r) {
        std::cout << "\n" << RED
                  << "  *** DETECTION: " << r.pluginId << " — "
                  << static_cast<int>(r.overallConfidence) << "% confidence ***"
                  << RESET << "\n";
    });

    // ── Execute Scan ─────────────────────────────────────────
    auto tStart = std::chrono::steady_clock::now();
    ScanReport report = mgr.runScan(scanCfg, progress);
    auto tEnd   = std::chrono::steady_clock::now();

    std::cout << "                                               \r"; // Clear progress line

    // ── Print Report ─────────────────────────────────────────
    if (args.jsonOutput) {
        std::string json = report.toJson(true);
        std::cout << json;
        if (!args.outputFile.empty()) {
            std::ofstream f(args.outputFile);
            if (f) f << json;
        }
    } else {
        printConsoleReport(report, args);
        if (!args.outputFile.empty()) {
            std::ofstream f(args.outputFile);
            if (f) f << report.toText();
            std::cout << GREEN << "[+] Report saved to: "
                      << args.outputFile << RESET << "\n\n";
        }
    }

    // ── Exit Code: 1 if sandbox detected ─────────────────────
    return report.overallSandboxDetected ? 1 : 0;
}
