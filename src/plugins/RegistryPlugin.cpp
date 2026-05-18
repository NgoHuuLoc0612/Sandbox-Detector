#include "plugins/RegistryPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <sstream>
#include <algorithm>
#include <cctype>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Static check tables
// ============================================================

const std::vector<RegistryPlugin::KeyCheck> RegistryPlugin::s_vboxChecks = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VirtualBox Guest Additions", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\VBOX__", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\RSDT\\VBOX__", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxGuest", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxMouse", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxService", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxVideo", L"", L"" },
};

const std::vector<RegistryPlugin::KeyCheck> RegistryPlugin::s_vmwareChecks = {
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmhgfs", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmci", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmmouse", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmrawdsk", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmusbmouse", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmvss", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmx_svga", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmxnet", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VMTools", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", L"InstallPath", L"" },
};

const std::vector<RegistryPlugin::KeyCheck> RegistryPlugin::s_qemuChecks = {
    { HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
      L"Identifier", L"QEMU" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vioscsi", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\viostor", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\BALLOON", L"", L"" },
    { HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\BalloonService", L"", L"" },
};

// ============================================================
//  Construction
// ============================================================

RegistryPlugin::RegistryPlugin() {
    m_meta.id           = "com.sandboxdetector.registry";
    m_meta.name         = "Registry Artifact Plugin";
    m_meta.version      = "1.4.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects VM/sandbox artifacts in the Windows Registry: "
                           "VirtualBox, VMware, Hyper-V, QEMU, Sandboxie, Wine, "
                           "disk model strings, BIOS strings, and ACPI tables.";
    m_meta.categories   = DetectionCategory::Registry;
    m_meta.priority     = 20;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

RegistryPlugin::~RegistryPlugin() { shutdown(); }

const PluginMetadata& RegistryPlugin::getMetadata() const noexcept { return m_meta; }
bool RegistryPlugin::isSupported() const noexcept { return true; }

bool RegistryPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void RegistryPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult RegistryPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkVirtualBoxKeys());
    push(checkVMwareKeys());
    push(checkHyperVKeys());
    push(checkQemuKeys());
    push(checkSandboxieKeys());
    push(checkWinePresence());
    push(checkDiskModelStrings());
    push(checkBiosVersionStrings());
    push(checkAcpiTables());
    push(checkAnalysisToolKeys());
    push(checkSystemServiceCount());
    push(checkVideoDriverStrings());

    result.sandboxDetected  = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();
    result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Helper: run a table of KeyCheck entries, return hit count
// ============================================================

static uint32_t runKeyCheckTable(const std::vector<RegistryPlugin::KeyCheck>& table) {
    uint32_t hits = 0;
    for (const auto& kc : table) {
        if (kc.valueName.empty()) {
            // Key existence check
            if (WinUtils::regKeyExists(kc.rootKey, kc.subKey)) ++hits;
        } else {
            // Value check, optionally with substring match
            auto val = WinUtils::regQueryValue(kc.rootKey, kc.subKey, kc.valueName);
            if (!val) continue;

            if (kc.expectedSubstring.empty()) {
                ++hits;
            } else {
                std::wstring valStr;
                if (val->type == REG_SZ || val->type == REG_EXPAND_SZ) {
                    valStr = std::wstring(
                        reinterpret_cast<const wchar_t*>(val->data.data()),
                        val->data.size() / sizeof(wchar_t));
                }
                // Case-insensitive search
                auto lowerVal = valStr;
                auto lowerNeedle = kc.expectedSubstring;
                std::transform(lowerVal.begin(), lowerVal.end(),
                               lowerVal.begin(), ::towlower);
                std::transform(lowerNeedle.begin(), lowerNeedle.end(),
                               lowerNeedle.begin(), ::towlower);
                if (lowerVal.find(lowerNeedle) != std::wstring::npos) ++hits;
            }
        }
    }
    return hits;
}

// ============================================================
//  Check: VirtualBox Registry Keys
// ============================================================

DetectionIndicator RegistryPlugin::checkVirtualBoxKeys() {
    DetectionIndicator ind;
    ind.name     = "VirtualBox Registry Keys";
    ind.category = DetectionCategory::Registry;

    uint32_t hits = runKeyCheckTable(s_vboxChecks);
    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << "/" << s_vboxChecks.size() << " VirtualBox registry keys found";
    ind.detail = detail.str();

    if (hits >= 3)       ind.confidence = SandboxConfidence::Certain;
    else if (hits == 2)  ind.confidence = SandboxConfidence::High;
    else if (hits == 1)  ind.confidence = SandboxConfidence::Medium;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: VMware Registry Keys
// ============================================================

DetectionIndicator RegistryPlugin::checkVMwareKeys() {
    DetectionIndicator ind;
    ind.name     = "VMware Registry Keys";
    ind.category = DetectionCategory::Registry;

    uint32_t hits = runKeyCheckTable(s_vmwareChecks);
    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << "/" << s_vmwareChecks.size() << " VMware registry keys found";
    ind.detail = detail.str();

    if (hits >= 3)       ind.confidence = SandboxConfidence::Certain;
    else if (hits == 2)  ind.confidence = SandboxConfidence::High;
    else if (hits == 1)  ind.confidence = SandboxConfidence::Medium;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Hyper-V Registry Keys
// ============================================================

DetectionIndicator RegistryPlugin::checkHyperVKeys() {
    DetectionIndicator ind;
    ind.name     = "Hyper-V Registry Keys";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::wstring> hvKeys = {
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"SYSTEM\\ControlSet001\\Services\\vmbus",
        L"SYSTEM\\ControlSet001\\Services\\VMBusHID",
        L"SYSTEM\\ControlSet001\\Services\\hyperkbd",
        L"SYSTEM\\ControlSet001\\Services\\hvsocket",
        L"SYSTEM\\ControlSet001\\Services\\hv_vmbus",
    };

    uint32_t hits = 0;
    for (const auto& key : hvKeys) {
        if (WinUtils::regKeyExists(HKEY_LOCAL_MACHINE, key)) ++hits;
    }

    // Check guest hostname parameter
    auto hostName = WinUtils::regQueryValue(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        L"VirtualMachineName");
    bool hasVmName = hostName.has_value();
    if (hasVmName) ++hits;

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << "/" << (hvKeys.size() + 1) << " Hyper-V registry entries found";
    if (hasVmName && hostName)
        detail << "; VM name: \"" << hostName->asString() << "\"";
    ind.detail = detail.str();

    if (hits >= 2)       ind.confidence = SandboxConfidence::Certain;
    else if (hits == 1)  ind.confidence = SandboxConfidence::High;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: QEMU Registry Keys
// ============================================================

DetectionIndicator RegistryPlugin::checkQemuKeys() {
    DetectionIndicator ind;
    ind.name     = "QEMU/KVM Registry Keys";
    ind.category = DetectionCategory::Registry;

    uint32_t hits = runKeyCheckTable(s_qemuChecks);
    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << "/" << s_qemuChecks.size() << " QEMU/KVM registry entries found";
    ind.detail = detail.str();

    if (hits >= 2)       ind.confidence = SandboxConfidence::Certain;
    else if (hits == 1)  ind.confidence = SandboxConfidence::High;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Sandboxie Registry Keys
// ============================================================

DetectionIndicator RegistryPlugin::checkSandboxieKeys() {
    DetectionIndicator ind;
    ind.name     = "Sandboxie Registry Keys";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::wstring> sbieKeys = {
        L"SYSTEM\\CurrentControlSet\\Services\\SbieDrv",
        L"SYSTEM\\CurrentControlSet\\Services\\SandboxieDrv",
        L"SOFTWARE\\Sandboxie-Plus",
        L"SOFTWARE\\Sandboxie",
        L"SYSTEM\\CurrentControlSet\\Services\\SbieHide",
    };

    uint32_t hits = 0;
    for (const auto& key : sbieKeys) {
        if (WinUtils::regKeyExists(HKEY_LOCAL_MACHINE, key)) ++hits;
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << "/" << sbieKeys.size() << " Sandboxie registry keys found";
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::Certain;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Wine Presence
// ============================================================

DetectionIndicator RegistryPlugin::checkWinePresence() {
    DetectionIndicator ind;
    ind.name     = "Wine Registry Presence";
    ind.category = DetectionCategory::Registry;

    bool wineKey  = WinUtils::regKeyExists(HKEY_CURRENT_USER, L"Software\\Wine");
    bool wineKey2 = WinUtils::regKeyExists(HKEY_LOCAL_MACHINE, L"Software\\Wine");

    ind.rawValue = (wineKey || wineKey2) ? 1 : 0;

    if (wineKey || wineKey2) {
        ind.detail     = "Wine registry key found (HKCU or HKLM \\Software\\Wine)";
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail     = "Wine registry key not found";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Disk Model Strings
// ============================================================

DetectionIndicator RegistryPlugin::checkDiskModelStrings() {
    DetectionIndicator ind;
    ind.name     = "Disk Model Strings";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::wstring> vmDiskStrings = {
        L"VBOX", L"VMWARE", L"QEMU", L"VIRTUAL", L"BOCHS",
        L"HARDDISK", L"MSFT VIRTUAL", L"Msft Virtual"
    };

    // Enumerate SCSI adapters
    const std::wstring scsiBase = L"HARDWARE\\DEVICEMAP\\Scsi";
    auto ports = WinUtils::regEnumSubKeys(HKEY_LOCAL_MACHINE, scsiBase);

    uint32_t hits = 0;
    std::vector<std::string> foundModels;

    for (const auto& port : ports) {
        std::wstring busBase = scsiBase + L"\\" + port;
        auto buses = WinUtils::regEnumSubKeys(HKEY_LOCAL_MACHINE, busBase);
        for (const auto& bus : buses) {
            std::wstring targetBase = busBase + L"\\" + bus;
            auto targets = WinUtils::regEnumSubKeys(HKEY_LOCAL_MACHINE, targetBase);
            for (const auto& target : targets) {
                std::wstring luBase = targetBase + L"\\" + target;
                auto luns = WinUtils::regEnumSubKeys(HKEY_LOCAL_MACHINE, luBase);
                for (const auto& lun : luns) {
                    std::wstring luKey = luBase + L"\\" + lun;
                    auto id = WinUtils::regQueryValue(HKEY_LOCAL_MACHINE,
                                                      luKey, L"Identifier");
                    if (!id) continue;
                    std::wstring idStr = std::wstring(
                        reinterpret_cast<const wchar_t*>(id->data.data()),
                        id->data.size() / sizeof(wchar_t));

                    // Uppercase for comparison
                    std::wstring idUpper = idStr;
                    std::transform(idUpper.begin(), idUpper.end(),
                                   idUpper.begin(), ::towupper);

                    for (const auto& vmStr : vmDiskStrings) {
                        std::wstring vmUpper = vmStr;
                        std::transform(vmUpper.begin(), vmUpper.end(),
                                       vmUpper.begin(), ::towupper);
                        if (idUpper.find(vmUpper) != std::wstring::npos) {
                            ++hits;
                            foundModels.push_back(WinUtils::toNarrow(idStr));
                            break;
                        }
                    }
                }
            }
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << " VM disk model string(s) found";
    for (const auto& m : foundModels)
        detail << "; \"" << m << "\"";
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: BIOS Version Strings
// ============================================================

DetectionIndicator RegistryPlugin::checkBiosVersionStrings() {
    DetectionIndicator ind;
    ind.name     = "BIOS Version Strings";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::wstring> vmBiosStrings = {
        L"VBOX", L"VIRTUALBOX", L"VMWARE", L"BOCHS", L"QEMU",
        L"SEABIOS", L"OVMF", L"XENSOURCE", L"INNOTEK"
    };

    const std::wstring biosKey = L"HARDWARE\\DESCRIPTION\\System";
    auto biosVersion = WinUtils::regQueryValue(HKEY_LOCAL_MACHINE, biosKey,
                                               L"SystemBiosVersion");
    auto videoVersion = WinUtils::regQueryValue(HKEY_LOCAL_MACHINE, biosKey,
                                                L"VideoBiosVersion");

    std::vector<std::string> found;
    uint32_t hits = 0;

    auto checkString = [&](const std::optional<WinUtils::RegValueResult>& val,
                            const std::string& fieldName)
    {
        if (!val) return;
        std::wstring s = std::wstring(
            reinterpret_cast<const wchar_t*>(val->data.data()),
            val->data.size() / sizeof(wchar_t));
        std::wstring sUpper = s;
        std::transform(sUpper.begin(), sUpper.end(), sUpper.begin(), ::towupper);

        for (const auto& vm : vmBiosStrings) {
            if (sUpper.find(vm) != std::wstring::npos) {
                ++hits;
                found.push_back(fieldName + "=\"" + WinUtils::toNarrow(s) + "\"");
                break;
            }
        }
    };

    checkString(biosVersion,  "SystemBiosVersion");
    checkString(videoVersion, "VideoBiosVersion");

    ind.rawValue = hits;

    std::ostringstream detail;
    if (!found.empty()) {
        detail << "VM BIOS strings: ";
        for (size_t i = 0; i < found.size(); ++i) {
            if (i) detail << ", ";
            detail << found[i];
        }
    } else {
        detail << "No suspicious BIOS version strings found";
    }
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: ACPI Table Vendor Strings
// ============================================================

DetectionIndicator RegistryPlugin::checkAcpiTables() {
    DetectionIndicator ind;
    ind.name     = "ACPI Table Vendor";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::wstring> acpiPaths = {
        L"HARDWARE\\ACPI\\DSDT\\VBOX__",
        L"HARDWARE\\ACPI\\FADT\\VBOX__",
        L"HARDWARE\\ACPI\\RSDT\\VBOX__",
        L"HARDWARE\\ACPI\\DSDT\\BOCHS_",
        L"HARDWARE\\ACPI\\DSDT\\BXPC",
    };

    uint32_t hits = 0;
    std::vector<std::string> foundAcpi;
    for (const auto& path : acpiPaths) {
        if (WinUtils::regKeyExists(HKEY_LOCAL_MACHINE, path)) {
            ++hits;
            foundAcpi.push_back(WinUtils::toNarrow(path));
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    if (hits > 0) {
        detail << hits << " VM ACPI table(s) found: ";
        for (const auto& a : foundAcpi) detail << "\"" << a << "\" ";
    } else {
        detail << "No VM-specific ACPI tables found in registry";
    }
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::Certain;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Known Analysis Tool Registry Keys
// ============================================================

DetectionIndicator RegistryPlugin::checkAnalysisToolKeys() {
    DetectionIndicator ind;
    ind.name     = "Analysis Tool Registry Keys";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::pair<HKEY, std::wstring>> toolKeys = {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wireshark" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Wireshark.exe" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Sysinternals\\Process Monitor" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Sysinternals\\Process Explorer" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Sysinternals\\Autoruns" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\OllyDbg" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\de.sysinternals.procmon" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\x64dbg" },
    };

    uint32_t hits = 0;
    std::vector<std::string> found;
    for (const auto& [root, key] : toolKeys) {
        if (WinUtils::regKeyExists(root, key)) {
            ++hits;
            found.push_back(WinUtils::toNarrow(key));
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << "/" << toolKeys.size() << " analysis tool registry keys found";
    for (const auto& f : found) detail << "; \"" << f << "\"";
    ind.detail = detail.str();

    if (hits >= 3)       ind.confidence = SandboxConfidence::High;
    else if (hits >= 1)  ind.confidence = SandboxConfidence::Medium;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: System Service Count (sandboxes have very few services)
// ============================================================

DetectionIndicator RegistryPlugin::checkSystemServiceCount() {
    DetectionIndicator ind;
    ind.name     = "System Service Count";
    ind.category = DetectionCategory::Registry;

    auto services = WinUtils::regEnumSubKeys(HKEY_LOCAL_MACHINE,
                                              L"SYSTEM\\CurrentControlSet\\Services");
    uint32_t count = static_cast<uint32_t>(services.size());
    ind.rawValue = count;

    std::ostringstream detail;
    detail << count << " services in HKLM\\SYSTEM\\CurrentControlSet\\Services";
    ind.detail = detail.str();

    // Real Windows installations typically have 200+ services
    // Sandboxes may have as few as 30–80
    if (count < 50)        ind.confidence = SandboxConfidence::High;
    else if (count < 100)  ind.confidence = SandboxConfidence::Medium;
    else if (count < 150)  ind.confidence = SandboxConfidence::Low;
    else                   ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Video Driver Strings
// ============================================================

DetectionIndicator RegistryPlugin::checkVideoDriverStrings() {
    DetectionIndicator ind;
    ind.name     = "Video Driver Strings";
    ind.category = DetectionCategory::Registry;

    static const std::vector<std::wstring> vmVideoStrings = {
        L"VBoxVideo", L"vmsvga", L"vm3dmp", L"qxl",
        L"Standard VGA", L"Microsoft Basic Display"
    };

    // Check Video class drivers
    const std::wstring videoKey =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}";
    auto subKeys = WinUtils::regEnumSubKeys(HKEY_LOCAL_MACHINE, videoKey);

    uint32_t hits = 0;
    std::vector<std::string> found;

    for (const auto& sub : subKeys) {
        auto driverDesc = WinUtils::regQueryValue(HKEY_LOCAL_MACHINE,
                                                   videoKey + L"\\" + sub,
                                                   L"DriverDesc");
        if (!driverDesc) continue;

        std::wstring desc = std::wstring(
            reinterpret_cast<const wchar_t*>(driverDesc->data.data()),
            driverDesc->data.size() / sizeof(wchar_t));

        std::wstring descUpper = desc;
        std::transform(descUpper.begin(), descUpper.end(),
                       descUpper.begin(), ::towupper);

        for (const auto& vm : vmVideoStrings) {
            std::wstring vmUpper = vm;
            std::transform(vmUpper.begin(), vmUpper.end(),
                           vmUpper.begin(), ::towupper);
            if (descUpper.find(vmUpper) != std::wstring::npos) {
                ++hits;
                found.push_back(WinUtils::toNarrow(desc));
                break;
            }
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << " VM video driver(s) found";
    for (const auto& f : found) detail << "; \"" << f << "\"";
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
