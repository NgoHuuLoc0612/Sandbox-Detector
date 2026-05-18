#include "plugins/WmiPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <ctime>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Construction
// ============================================================

WmiPlugin::WmiPlugin()
    : m_wmi(std::make_unique<WinUtils::WmiSession>())
{
    m_meta.id           = "com.sandboxdetector.wmi";
    m_meta.name         = "WMI Query Plugin";
    m_meta.version      = "1.3.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Uses WMI queries to detect VM artifacts: computer model, "
                           "manufacturer, BIOS version/serial, disk model, network MAC, "
                           "video controller, registered user, processor name, OS install date.";
    m_meta.categories   = DetectionCategory::WMI;
    m_meta.priority     = 50;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

WmiPlugin::~WmiPlugin() { shutdown(); }

const PluginMetadata& WmiPlugin::getMetadata() const noexcept { return m_meta; }
bool WmiPlugin::isSupported() const noexcept { return true; }

bool WmiPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return m_wmi->initialize();
}

void WmiPlugin::shutdown() noexcept {
    if (m_wmi) m_wmi->shutdown();
}

// ============================================================
//  run()
// ============================================================

PluginResult WmiPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    // Re-initialize WMI if needed (run() may be called multiple times)
    if (!m_wmi->initialize()) {
        result.errorMessage = "WMI session initialization failed";
        result.executed     = false;
        return result;
    }

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkComputerSystemModel());
    push(checkComputerSystemManufacturer());
    push(checkBiosVersion());
    push(checkBiosSerialNumber());
    push(checkBaseBoardProduct());
    push(checkDiskDriveModel());
    push(checkNetworkAdapterMac());
    push(checkVideoControllerCaption());
    push(checkRegisteredUser());
    push(checkProcessorName());
    push(checkOsInstallDate());
    push(checkPhysicalMemoryAbsence());

    result.sandboxDetected  = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();
    result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Helpers
// ============================================================

std::vector<std::wstring> WmiPlugin::queryColumn(const std::wstring& wql,
                                                   const std::wstring& column)
{
    std::vector<std::wstring> results;
    auto rows = m_wmi->query(wql);
    for (const auto& row : rows) {
        auto it = row.columns.find(column);
        if (it != row.columns.end() && !it->second.empty())
            results.push_back(it->second);
    }
    return results;
}

bool WmiPlugin::anyContainsSubstring(const std::vector<std::wstring>& values,
                                      const std::vector<std::wstring>& needles,
                                      bool caseInsensitive)
{
    for (auto val : values) {
        if (caseInsensitive)
            std::transform(val.begin(), val.end(), val.begin(), ::towlower);

        for (auto needle : needles) {
            if (caseInsensitive)
                std::transform(needle.begin(), needle.end(), needle.begin(), ::towlower);
            if (val.find(needle) != std::wstring::npos)
                return true;
        }
    }
    return false;
}

// ============================================================
//  Check: Win32_ComputerSystem.Model
// ============================================================

DetectionIndicator WmiPlugin::checkComputerSystemModel() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_ComputerSystem Model";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT Model FROM Win32_ComputerSystem", L"Model");

    static const std::vector<std::wstring> vmModels = {
        L"VirtualBox", L"VMware", L"Virtual Machine",
        L"Bochs", L"QEMU", L"KVM", L"Parallels", L"Xen",
        L"HVM domU", L"Standard PC"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, vmModels);
    ind.rawValue = found ? 1 : 0;

    if (!vals.empty()) {
        ind.detail = "Win32_ComputerSystem.Model = \"" + combined + "\"";
    } else {
        ind.detail = "Win32_ComputerSystem.Model not available";
    }

    if (found) {
        ind.detail    += " — VM model string detected";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_ComputerSystem.Manufacturer
// ============================================================

DetectionIndicator WmiPlugin::checkComputerSystemManufacturer() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_ComputerSystem Manufacturer";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer");

    static const std::vector<std::wstring> vmManufacturers = {
        L"innotek", L"VMware, Inc.", L"VMware",
        L"Microsoft Corporation",   // often Hyper-V
        L"QEMU", L"Bochs", L"Parallels", L"Xen"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, vmManufacturers);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_ComputerSystem.Manufacturer = \"" + combined + "\"";

    // "Microsoft Corporation" alone is ambiguous (Hyper-V AND Surface/OEM)
    // Only flag if combined with other indicators, so use Low confidence
    if (found) {
        bool definite = anyContainsSubstring(vals,
            { L"innotek", L"VMware", L"QEMU", L"Bochs", L"Parallels", L"Xen" });
        ind.confidence = definite ? SandboxConfidence::High : SandboxConfidence::Low;
        ind.detail    += " — VM manufacturer";
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_BIOS.SMBIOSBIOSVersion
// ============================================================

DetectionIndicator WmiPlugin::checkBiosVersion() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_BIOS Version";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT SMBIOSBIOSVersion,Version FROM Win32_BIOS",
        L"SMBIOSBIOSVersion");

    static const std::vector<std::wstring> vmBios = {
        L"VBOX", L"VirtualBox", L"BOCHS", L"QEMU",
        L"SEABIOS", L"OVMF", L"innotek", L"VMware"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, vmBios);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_BIOS.SMBIOSBIOSVersion = \"" + combined + "\"";

    if (found) {
        ind.detail    += " — VM BIOS";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_BIOS.SerialNumber
// ============================================================

DetectionIndicator WmiPlugin::checkBiosSerialNumber() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_BIOS SerialNumber";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT SerialNumber FROM Win32_BIOS", L"SerialNumber");

    static const std::vector<std::wstring> invalidSerials = {
        L"0", L"None", L"Not Specified", L"To Be Filled By O.E.M.",
        L"Default string", L"System Serial Number", L"N/A",
        L"00000000", L"INVALID"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, invalidSerials);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_BIOS.SerialNumber = \"" + combined + "\"";

    if (found) {
        ind.detail    += " — placeholder/invalid serial (VM or blank OEM)";
        ind.confidence = SandboxConfidence::Medium;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_BaseBoard.Product
// ============================================================

DetectionIndicator WmiPlugin::checkBaseBoardProduct() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_BaseBoard Product";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT Product FROM Win32_BaseBoard", L"Product");

    static const std::vector<std::wstring> vmBoards = {
        L"VirtualBox", L"VMware", L"440BX", L"BOCHS",
        L"KVM", L"Parallels", L"Virtual Machine"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, vmBoards);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_BaseBoard.Product = \"" + combined + "\"";

    if (found) {
        ind.detail    += " — VM baseboard product";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_DiskDrive.Model
// ============================================================

DetectionIndicator WmiPlugin::checkDiskDriveModel() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_DiskDrive Model";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT Model FROM Win32_DiskDrive", L"Model");

    static const std::vector<std::wstring> vmDisks = {
        L"VBOX", L"VirtualBox", L"VMware", L"QEMU", L"Virtual",
        L"HARDDISK", L"Msft Virtual", L"BOCHS"
    };

    std::string combined;
    for (const auto& v : vals) combined += "\"" + WinUtils::toNarrow(v) + "\" ";

    bool found = anyContainsSubstring(vals, vmDisks);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_DiskDrive Models: " + combined;

    if (found) {
        ind.detail    += " — VM disk model";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_NetworkAdapter.MACAddress
// ============================================================

DetectionIndicator WmiPlugin::checkNetworkAdapterMac() {
    DetectionIndicator ind;
    ind.name     = "WMI Network Adapter MAC OUI";
    ind.category = DetectionCategory::WMI;

    auto rows = m_wmi->query(
        L"SELECT MACAddress, Name FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL");

    static const std::vector<std::wstring> vmOuis = {
        L"08:00:27",  // VirtualBox
        L"00:0C:29",  // VMware
        L"00:50:56",  // VMware
        L"52:54:00",  // QEMU/KVM
        L"00:16:3E",  // Xen
        L"00:1C:42",  // Parallels
        L"00:15:5D",  // Hyper-V
        L"00:03:FF",  // Hyper-V
    };

    uint32_t hits = 0;
    std::vector<std::string> found;

    for (const auto& row : rows) {
        auto macIt = row.columns.find(L"MACAddress");
        if (macIt == row.columns.end()) continue;

        std::wstring mac = macIt->second;
        std::transform(mac.begin(), mac.end(), mac.begin(), ::towupper);

        for (const auto& oui : vmOuis) {
            std::wstring ouiUpper = oui;
            std::transform(ouiUpper.begin(), ouiUpper.end(),
                           ouiUpper.begin(), ::towupper);
            if (mac.substr(0, 8) == ouiUpper) {
                ++hits;
                found.push_back(WinUtils::toNarrow(mac));
                break;
            }
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << " VM MAC OUI(s) found via WMI";
    for (const auto& f : found) detail << "; " << f;
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Win32_VideoController.Caption
// ============================================================

DetectionIndicator WmiPlugin::checkVideoControllerCaption() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_VideoController Caption";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT Caption FROM Win32_VideoController", L"Caption");

    static const std::vector<std::wstring> vmGpu = {
        L"VirtualBox", L"VMware", L"SVGA", L"QEMU",
        L"Microsoft Basic Display", L"Basic Render", L"Parallels",
        L"RedHat QXL", L"Remote Desktop"
    };

    std::string combined;
    for (const auto& v : vals) combined += "\"" + WinUtils::toNarrow(v) + "\" ";

    bool found = anyContainsSubstring(vals, vmGpu);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_VideoController: " + combined;

    if (found) {
        ind.detail    += " — VM video adapter";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_OperatingSystem.RegisteredUser
// ============================================================

DetectionIndicator WmiPlugin::checkRegisteredUser() {
    DetectionIndicator ind;
    ind.name     = "WMI Registered User Name";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT RegisteredUser FROM Win32_OperatingSystem", L"RegisteredUser");

    static const std::vector<std::wstring> suspiciousUsers = {
        L"sandbox", L"malware", L"virus", L"analysis",
        L"cuckoo", L"triage", L"user", L"test",
        L"john", L"admin", L"administrator",
        L"VIRUS", L"MALWARE", L"SANDBOX"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, suspiciousUsers);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "RegisteredUser = \"" + combined + "\"";

    if (found) {
        ind.detail    += " — suspicious username (analysis environment)";
        ind.confidence = SandboxConfidence::Medium;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_Processor.Name
// ============================================================

DetectionIndicator WmiPlugin::checkProcessorName() {
    DetectionIndicator ind;
    ind.name     = "WMI Processor Name";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT Name FROM Win32_Processor", L"Name");

    static const std::vector<std::wstring> vmCpus = {
        L"QEMU", L"KVM", L"Virtual", L"Bochs"
    };

    std::string combined;
    for (const auto& v : vals) combined += WinUtils::toNarrow(v) + " ";

    bool found = anyContainsSubstring(vals, vmCpus);
    ind.rawValue = found ? 1 : 0;

    ind.detail = "Win32_Processor.Name = \"" + combined + "\"";

    if (found) {
        ind.detail    += " — VM CPU string";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Win32_OperatingSystem.InstallDate
//
//  If the OS was installed very recently (< 7 days ago),
//  it may be a freshly-deployed sandbox VM.
// ============================================================

DetectionIndicator WmiPlugin::checkOsInstallDate() {
    DetectionIndicator ind;
    ind.name     = "OS Install Date (Freshness)";
    ind.category = DetectionCategory::WMI;

    auto vals = queryColumn(
        L"SELECT InstallDate FROM Win32_OperatingSystem", L"InstallDate");

    if (vals.empty()) {
        ind.detail     = "InstallDate not available";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    // WMI date format: "YYYYMMDDHHMMSS.mmmmmm+UUU"
    const std::wstring& dateStr = vals[0];
    if (dateStr.size() < 8) {
        ind.detail     = "InstallDate format unrecognized";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    int year  = std::stoi(std::wstring(dateStr, 0, 4));
    int month = std::stoi(std::wstring(dateStr, 4, 2));
    int day   = std::stoi(std::wstring(dateStr, 6, 2));

    std::tm installTm{};
    installTm.tm_year = year - 1900;
    installTm.tm_mon  = month - 1;
    installTm.tm_mday = day;
    std::time_t installTime = _mkgmtime(&installTm);

    std::time_t now = std::time(nullptr);
    double daysSinceInstall = std::difftime(now, installTime) / 86400.0;

    ind.rawValue = static_cast<uint64_t>(daysSinceInstall);

    std::ostringstream detail;
    detail << "OS installed " << static_cast<int>(daysSinceInstall)
           << " days ago (" << year << "-"
           << std::setfill('0') << std::setw(2) << month << "-"
           << std::setw(2) << day << ")";
    ind.detail = detail.str();

    if (daysSinceInstall < 1)        ind.confidence = SandboxConfidence::High;
    else if (daysSinceInstall < 3)   ind.confidence = SandboxConfidence::Medium;
    else if (daysSinceInstall < 7)   ind.confidence = SandboxConfidence::Low;
    else                             ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Win32_PhysicalMemory absence
//
//  Many sandboxes/VMs don't expose individual DIMM information.
// ============================================================

DetectionIndicator WmiPlugin::checkPhysicalMemoryAbsence() {
    DetectionIndicator ind;
    ind.name     = "WMI Win32_PhysicalMemory Absence";
    ind.category = DetectionCategory::WMI;

    auto rows = m_wmi->query(L"SELECT Capacity FROM Win32_PhysicalMemory");
    uint32_t dimmCount = static_cast<uint32_t>(rows.size());
    ind.rawValue = dimmCount;

    std::ostringstream detail;
    detail << dimmCount << " Win32_PhysicalMemory DIMM record(s)";
    ind.detail = detail.str();

    if (dimmCount == 0) {
        ind.detail    += " — no DIMM data (common in VMs)";
        ind.confidence = SandboxConfidence::Medium;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
