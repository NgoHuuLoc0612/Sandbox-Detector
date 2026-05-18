#include "core/PluginManager.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>
#include <cassert>
#include <chrono>
#include <ctime>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace SandboxDetector {

// ============================================================
//  C-ABI function pointer types for plugin DLLs
// ============================================================

using PFN_CreatePlugin       = IPlugin* (*)();
using PFN_DestroyPlugin      = void     (*)(IPlugin*);
using PFN_GetPluginApiVersion= const char* (*)();

// ============================================================
//  PluginManager::Impl
// ============================================================

struct PluginManager::Impl {
    std::vector<LoadedPlugin>               plugins;
    mutable std::mutex                      mutex;
    PluginManager::DetectionCallback        detectionCallback;
    std::atomic<bool>                       scanRunning{ false };

    LoadedPlugin* findById(const std::string& id) noexcept {
        for (auto& lp : plugins) {
            if (lp.instance && lp.instance->getMetadata().id == id)
                return &lp;
        }
        return nullptr;
    }

    const LoadedPlugin* findById(const std::string& id) const noexcept {
        for (const auto& lp : plugins) {
            if (lp.instance && lp.instance->getMetadata().id == id)
                return &lp;
        }
        return nullptr;
    }
};

// ============================================================
//  PluginManager — Construction / Destruction
// ============================================================

PluginManager::PluginManager()
    : m_impl(std::make_unique<Impl>()) {}

PluginManager::~PluginManager() {
    unregisterAll();
}

PluginManager::PluginManager(PluginManager&&) noexcept = default;
PluginManager& PluginManager::operator=(PluginManager&&) noexcept = default;

// ============================================================
//  Plugin Registration
// ============================================================

bool PluginManager::registerPlugin(std::unique_ptr<IPlugin> plugin,
                                    const PluginConfig& config)
{
    if (!plugin) return false;

    const auto& meta = plugin->getMetadata();
    std::lock_guard<std::mutex> lock(m_impl->mutex);

    // Check for duplicate ID
    if (m_impl->findById(meta.id)) return false;

    LoadedPlugin lp;
    lp.instance    = std::move(plugin);
    lp.moduleHandle = nullptr;
    lp.config       = config;
    lp.ownsModule   = false;

    if (lp.instance->isSupported()) {
        if (!lp.instance->initialize(lp.config)) return false;
    }

    m_impl->plugins.push_back(std::move(lp));
    sortPluginsByPriority();
    return true;
}

bool PluginManager::loadPluginFromFile(const std::filesystem::path& dllPath,
                                        const PluginConfig& config)
{
    HMODULE hMod = LoadLibraryW(dllPath.wstring().c_str());
    if (!hMod) return false;

    // Verify API version compatibility
    auto pfnVersion = reinterpret_cast<PFN_GetPluginApiVersion>(
        GetProcAddress(hMod, "GetPluginApiVersion"));
    if (!pfnVersion || std::string(pfnVersion()) != PLUGIN_API_VERSION) {
        FreeLibrary(hMod);
        return false;
    }

    auto pfnCreate = reinterpret_cast<PFN_CreatePlugin>(
        GetProcAddress(hMod, "CreatePlugin"));
    if (!pfnCreate) {
        FreeLibrary(hMod);
        return false;
    }

    IPlugin* rawPtr = pfnCreate();
    if (!rawPtr) {
        FreeLibrary(hMod);
        return false;
    }

    auto pfnDestroy = reinterpret_cast<PFN_DestroyPlugin>(
        GetProcAddress(hMod, "DestroyPlugin"));

    // Wrap in unique_ptr with custom deleter
    auto deleter = [pfnDestroy](IPlugin* p) {
        if (pfnDestroy && p) pfnDestroy(p);
    };
    std::unique_ptr<IPlugin, decltype(deleter)> plugin(rawPtr, std::move(deleter));

    std::lock_guard<std::mutex> lock(m_impl->mutex);
    const auto& meta = plugin->getMetadata();
    if (m_impl->findById(meta.id)) {
        FreeLibrary(hMod);
        return false;
    }

    if (plugin->isSupported()) {
        if (!plugin->initialize(config)) {
            FreeLibrary(hMod);
            return false;
        }
    }

    LoadedPlugin lp;
    lp.instance     = std::move(plugin);
    lp.moduleHandle = static_cast<void*>(hMod);
    lp.sourcePath   = dllPath;
    lp.config       = config;
    lp.ownsModule   = true;

    m_impl->plugins.push_back(std::move(lp));
    sortPluginsByPriority();
    return true;
}

uint32_t PluginManager::loadPluginsFromDirectory(const std::filesystem::path& dir,
                                                   const std::string& pattern)
{
    if (!std::filesystem::is_directory(dir)) return 0;
    uint32_t loaded = 0;

    // Convert pattern to wide string for matching
    std::wstring wPattern = std::wstring(pattern.begin(), pattern.end());

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        const auto& p = entry.path();

        // Simple wildcard match on filename only
        std::wstring fname = p.filename().wstring();
        // Match prefix "sd_plugin_" and suffix ".dll"
        const std::wstring prefix = L"sd_plugin_";
        const std::wstring suffix = L".dll";
        if (fname.size() >= prefix.size() + suffix.size() &&
            fname.substr(0, prefix.size()) == prefix &&
            fname.substr(fname.size() - suffix.size()) == suffix)
        {
            if (loadPluginFromFile(p)) ++loaded;
        }
    }
    return loaded;
}

bool PluginManager::unregisterPlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    auto it = std::find_if(m_impl->plugins.begin(), m_impl->plugins.end(),
        [&](const LoadedPlugin& lp) {
            return lp.instance && lp.instance->getMetadata().id == pluginId;
        });

    if (it == m_impl->plugins.end()) return false;

    it->instance->shutdown();
    it->instance.reset();

    if (it->ownsModule && it->moduleHandle) {
        FreeLibrary(static_cast<HMODULE>(it->moduleHandle));
    }

    m_impl->plugins.erase(it);
    return true;
}

void PluginManager::unregisterAll() {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    for (auto& lp : m_impl->plugins) {
        if (lp.instance) lp.instance->shutdown();
        if (lp.ownsModule && lp.moduleHandle)
            FreeLibrary(static_cast<HMODULE>(lp.moduleHandle));
    }
    m_impl->plugins.clear();
}

// ============================================================
//  Configuration
// ============================================================

void PluginManager::setPluginConfig(const std::string& pluginId,
                                     const PluginConfig& config) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (auto* lp = m_impl->findById(pluginId)) {
        lp->config = config;
    }
}

void PluginManager::enablePlugin(const std::string& pluginId, bool enabled) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (auto* lp = m_impl->findById(pluginId)) {
        lp->config.enabled = enabled;
    }
}

PluginConfig PluginManager::getPluginConfig(const std::string& pluginId) const {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    if (const auto* lp = m_impl->findById(pluginId)) {
        return lp->config;
    }
    return {};
}

// ============================================================
//  Query
// ============================================================

std::vector<PluginMetadata> PluginManager::listPlugins() const {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    std::vector<PluginMetadata> result;
    result.reserve(m_impl->plugins.size());
    for (const auto& lp : m_impl->plugins) {
        if (lp.instance) result.push_back(lp.instance->getMetadata());
    }
    return result;
}

bool PluginManager::hasPlugin(const std::string& pluginId) const noexcept {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->findById(pluginId) != nullptr;
}

uint32_t PluginManager::pluginCount() const noexcept {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->plugins.size());
}

void PluginManager::setDetectionCallback(DetectionCallback cb) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->detectionCallback = std::move(cb);
}

// ============================================================
//  Execution
// ============================================================

// Forward declaration of SEH helper (defined in PluginManagerSEH.cpp,
// compiled without /EHa to satisfy MSVC C2712)
struct SehRunResult { bool succeeded; DWORD exceptionCode; };
SehRunResult runPluginWithSEH(IPlugin* plugin, PluginResult* outResult);

PluginResult PluginManager::executePluginSafe(LoadedPlugin& lp,
                                               const ScanConfig& cfg)
{
    (void)cfg; // reserved for future per-scan timeout/config use
    PluginResult result;
    result.pluginId      = lp.instance->getMetadata().id;
    result.pluginVersion = lp.instance->getMetadata().version;
    result.executed      = false;

    auto start = std::chrono::steady_clock::now();

    auto seh = runPluginWithSEH(lp.instance.get(), &result);
    if (!seh.succeeded) {
        result.executed      = false;
        result.errorMessage  = "SEH exception during plugin execution (code: "
            + std::to_string(seh.exceptionCode) + ")";
        result.pluginId      = lp.instance->getMetadata().id;
        result.pluginVersion = lp.instance->getMetadata().version;
    }

    auto end = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    return result;
}

ScanReport PluginManager::runScan(const ScanConfig& config,
                                   ProgressCallback progressCallback)
{
    // Snapshot plugins under lock, then run without holding lock
    std::vector<LoadedPlugin*> toRun;
    {
        std::lock_guard<std::mutex> lock(m_impl->mutex);
        for (auto& lp : m_impl->plugins) {
            if (!lp.instance || !lp.instance->isSupported()) continue;
            if (!lp.config.enabled && !config.includeDisabled) continue;
            if (lp.instance->getMetadata().priority < config.minimumPriority) continue;

            // Category filter
            auto cats = lp.instance->getMetadata().categories;
            if ((cats & config.categoryFilter) == DetectionCategory::None) continue;

            toRun.push_back(&lp);
        }
    }

    ScanReport report{};
    auto scanStart = std::chrono::steady_clock::now();

    uint32_t total   = static_cast<uint32_t>(toRun.size());
    uint32_t current = 0;

    if (config.runParallel) {
        // Parallel execution via std::async
        std::vector<std::future<PluginResult>> futures;
        futures.reserve(toRun.size());

        for (auto* lpPtr : toRun) {
            futures.push_back(std::async(std::launch::async,
                [this, lpPtr, &config]() {
                    return executePluginSafe(*lpPtr, config);
                }));
        }

        for (auto& fut : futures) {
            if (fut.valid()) {
                auto result = fut.get();
                ++current;
                if (progressCallback)
                    progressCallback(result.pluginId, current, total);

                if (!result.errorMessage.has_value() && result.executed) {
                    ++report.pluginsRun;
                    if (result.sandboxDetected) {
                        ++report.pluginsDetected;
                        std::lock_guard<std::mutex> lock(m_impl->mutex);
                        if (m_impl->detectionCallback)
                            m_impl->detectionCallback(result);
                    }
                } else {
                    ++report.pluginsErrored;
                }
                report.results.push_back(std::move(result));
            }
        }
    } else {
        // Sequential execution
        for (auto* lpPtr : toRun) {
            auto result = executePluginSafe(*lpPtr, config);
            ++current;

            if (progressCallback)
                progressCallback(result.pluginId, current, total);

            if (result.executed && !result.errorMessage.has_value()) {
                ++report.pluginsRun;
                if (result.sandboxDetected) {
                    ++report.pluginsDetected;
                    std::lock_guard<std::mutex> lock(m_impl->mutex);
                    if (m_impl->detectionCallback)
                        m_impl->detectionCallback(result);

                    if (config.stopOnFirstDetect) {
                        report.results.push_back(std::move(result));
                        break;
                    }
                }
            } else {
                ++report.pluginsErrored;
            }

            report.results.push_back(std::move(result));
        }
    }

    // Compute aggregate results
    report.overallSandboxDetected = (report.pluginsDetected > 0);
    report.systemFingerprint      = computeSystemFingerprint();

    // Overall confidence = max confidence across all detecting plugins
    SandboxConfidence maxConf = SandboxConfidence::None;
    for (const auto& r : report.results) {
        if (r.sandboxDetected &&
            static_cast<uint8_t>(r.overallConfidence) > static_cast<uint8_t>(maxConf))
        {
            maxConf = r.overallConfidence;
        }
    }
    report.overallConfidence = maxConf;

    auto scanEnd = std::chrono::steady_clock::now();
    report.totalScanTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        scanEnd - scanStart);

    return report;
}

std::optional<PluginResult> PluginManager::runPlugin(const std::string& pluginId) {
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    auto* lp = m_impl->findById(pluginId);
    if (!lp || !lp->instance || !lp->instance->isSupported()) return std::nullopt;

    ScanConfig dummy{};
    return executePluginSafe(*lp, dummy);
}

// ============================================================
//  Internal helpers
// ============================================================

void PluginManager::sortPluginsByPriority() {
    // Already under lock when called
    std::stable_sort(m_impl->plugins.begin(), m_impl->plugins.end(),
        [](const LoadedPlugin& a, const LoadedPlugin& b) {
            if (!a.instance) return false;
            if (!b.instance) return true;
            return a.instance->getMetadata().priority <
                   b.instance->getMetadata().priority;
        });
}

std::string PluginManager::computeSystemFingerprint() const {
    // Concatenate hardware identifiers and hash with SHA-256
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    MEMORYSTATUSEX ms{ sizeof(ms) };
    GlobalMemoryStatusEx(&ms);

    std::ostringstream oss;
    oss << si.dwNumberOfProcessors
        << si.wProcessorArchitecture
        << ms.ullTotalPhys
        << ms.ullTotalVirtual;

    // Get machine GUID
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        wchar_t guid[64]{};
        DWORD sz = sizeof(guid);
        RegQueryValueExW(hKey, L"MachineGuid", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(guid), &sz);
        RegCloseKey(hKey);
        oss << guid;
    }

    std::string raw = oss.str();

    // SHA-256 via CryptoAPI
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES,
                               CRYPT_VERIFYCONTEXT))
        return "fingerprint_error";

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "fingerprint_error";
    }

    CryptHashData(hHash,
                  reinterpret_cast<const BYTE*>(raw.data()),
                  static_cast<DWORD>(raw.size()), 0);

    DWORD hashSize = 32;
    std::vector<BYTE> digest(hashSize);
    CryptGetHashParam(hHash, HP_HASHVAL, digest.data(), &hashSize, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (BYTE b : digest) hex << std::setw(2) << static_cast<int>(b);
    return hex.str();
}

// ============================================================
//  ScanReport helpers
// ============================================================

std::vector<DetectionIndicator> ScanReport::getAllIndicators() const {
    std::vector<DetectionIndicator> all;
    for (const auto& r : results) {
        all.insert(all.end(), r.indicators.begin(), r.indicators.end());
    }
    std::sort(all.begin(), all.end(), [](const DetectionIndicator& a,
                                          const DetectionIndicator& b) {
        return static_cast<uint8_t>(a.confidence) >
               static_cast<uint8_t>(b.confidence);
    });
    return all;
}

std::vector<PluginResult> ScanReport::getResultsByCategory(DetectionCategory cat) const {
    std::vector<PluginResult> out;
    for (const auto& r : results) {
        for (const auto& ind : r.indicators) {
            if ((ind.category & cat) != DetectionCategory::None) {
                out.push_back(r);
                break;
            }
        }
    }
    return out;
}

std::string ScanReport::toText() const {
    std::ostringstream os;
    os << "====================================================\n";
    os << "  SANDBOX DETECTOR — SCAN REPORT\n";
    os << "====================================================\n";
    os << "Overall Sandbox Detected : " << (overallSandboxDetected ? "YES" : "NO") << "\n";

    const char* confStr = "None";
    switch (overallConfidence) {
    case SandboxConfidence::Low:     confStr = "Low";     break;
    case SandboxConfidence::Medium:  confStr = "Medium";  break;
    case SandboxConfidence::High:    confStr = "High";    break;
    case SandboxConfidence::Certain: confStr = "Certain"; break;
    default: break;
    }
    os << "Overall Confidence       : " << confStr << "\n";
    os << "Plugins Run              : " << pluginsRun << "\n";
    os << "Plugins Detected         : " << pluginsDetected << "\n";
    os << "Plugins Errored          : " << pluginsErrored << "\n";
    os << "Total Scan Time          : " << totalScanTime.count() << " ms\n";
    os << "System Fingerprint       : " << systemFingerprint << "\n";
    os << "----------------------------------------------------\n";

    for (const auto& r : results) {
        os << "\n[" << r.pluginId << " v" << r.pluginVersion << "]\n";
        os << "  Detected  : " << (r.sandboxDetected ? "YES" : "NO") << "\n";
        os << "  Exec Time : " << r.executionTime.count() << " µs\n";
        if (r.errorMessage)
            os << "  Error     : " << *r.errorMessage << "\n";
        for (const auto& ind : r.indicators) {
            os << "  [";
            switch (ind.confidence) {
            case SandboxConfidence::Low:     os << "LOW    "; break;
            case SandboxConfidence::Medium:  os << "MEDIUM "; break;
            case SandboxConfidence::High:    os << "HIGH   "; break;
            case SandboxConfidence::Certain: os << "CERTAIN"; break;
            default:                         os << "NONE   "; break;
            }
            os << "] " << ind.name << " — " << ind.detail << "\n";
        }
    }
    os << "====================================================\n";
    return os.str();
}

std::string ScanReport::toJson(bool pretty) const {
    const char* sep = pretty ? "\n" : "";
    const char* ind = pretty ? "  " : "";
    const char* ind2 = pretty ? "    " : "";
    const char* ind3 = pretty ? "      " : "";

    std::ostringstream os;
    os << "{" << sep;
    os << ind << "\"sandbox_detected\": " << (overallSandboxDetected ? "true" : "false") << "," << sep;
    os << ind << "\"confidence\": " << static_cast<int>(overallConfidence) << "," << sep;
    os << ind << "\"plugins_run\": " << pluginsRun << "," << sep;
    os << ind << "\"plugins_detected\": " << pluginsDetected << "," << sep;
    os << ind << "\"plugins_errored\": " << pluginsErrored << "," << sep;
    os << ind << "\"total_scan_time_ms\": " << totalScanTime.count() << "," << sep;
    os << ind << "\"system_fingerprint\": \"" << systemFingerprint << "\"," << sep;
    os << ind << "\"plugin_results\": [" << sep;

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        os << ind2 << "{" << sep;
        os << ind3 << "\"plugin_id\": \"" << r.pluginId << "\"," << sep;
        os << ind3 << "\"plugin_version\": \"" << r.pluginVersion << "\"," << sep;
        os << ind3 << "\"detected\": " << (r.sandboxDetected ? "true" : "false") << "," << sep;
        os << ind3 << "\"confidence\": " << static_cast<int>(r.overallConfidence) << "," << sep;
        os << ind3 << "\"exec_time_us\": " << r.executionTime.count() << "," << sep;
        if (r.errorMessage)
            os << ind3 << "\"error\": \"" << *r.errorMessage << "\"," << sep;
        os << ind3 << "\"indicators\": [";
        for (size_t j = 0; j < r.indicators.size(); ++j) {
            const auto& ind_ = r.indicators[j];
            os << "{\"name\":\"" << ind_.name << "\","
               << "\"detail\":\"" << ind_.detail << "\","
               << "\"confidence\":" << static_cast<int>(ind_.confidence) << "}";
            if (j + 1 < r.indicators.size()) os << ",";
        }
        os << "]" << sep;
        os << ind2 << "}";
        if (i + 1 < results.size()) os << ",";
        os << sep;
    }

    os << ind << "]" << sep << "}" << sep;
    return os.str();
}

} // namespace SandboxDetector
