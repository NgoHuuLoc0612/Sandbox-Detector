#include "plugins/HardwarePlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <initguid.h>
#include <dxgi.h>

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "dxgi.lib")

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Construction
// ============================================================

HardwarePlugin::HardwarePlugin() {
    m_meta.id           = "com.sandboxdetector.hardware";
    m_meta.name         = "Hardware Fingerprint Plugin";
    m_meta.version      = "1.3.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects VM/sandbox via hardware anomalies: RAM, CPU count, "
                           "disk size, screen resolution, MAC OUI, GPU name, "
                           "sound device, monitors, battery, firmware strings.";
    m_meta.categories   = DetectionCategory::Hardware;
    m_meta.priority     = 25;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

HardwarePlugin::~HardwarePlugin() { shutdown(); }

const PluginMetadata& HardwarePlugin::getMetadata() const noexcept { return m_meta; }
bool HardwarePlugin::isSupported() const noexcept { return true; }

bool HardwarePlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void HardwarePlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult HardwarePlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkPhysicalRam());
    push(checkCpuCount());
    push(checkDiskSize());
    push(checkScreenResolution());
    push(checkMacAddressOui());
    push(checkDiskSerialNumber());
    push(checkGpuName());
    push(checkSoundDevice());
    push(checkMonitorCount());
    push(checkBatteryPresence());
    push(checkFirmwareStrings());
    push(checkUsbControllers());

    result.sandboxDetected  = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();
    result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Check: Physical RAM
// ============================================================

DetectionIndicator HardwarePlugin::checkPhysicalRam() {
    DetectionIndicator ind;
    ind.name     = "Physical RAM Size";
    ind.category = DetectionCategory::Hardware;

    auto mem = WinUtils::getMemoryStats();
    uint64_t ramGb = mem.totalPhysicalBytes / (1024ULL * 1024 * 1024);
    ind.rawValue = mem.totalPhysicalBytes;

    std::ostringstream detail;
    detail << "Physical RAM: " << ramGb << " GB ("
           << (mem.totalPhysicalBytes / (1024 * 1024)) << " MB)";
    ind.detail = detail.str();

    if (ramGb < 1)       ind.confidence = SandboxConfidence::Certain;
    else if (ramGb < 2)  ind.confidence = SandboxConfidence::High;
    else if (ramGb < 3)  ind.confidence = SandboxConfidence::Medium;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: CPU Core Count
// ============================================================

DetectionIndicator HardwarePlugin::checkCpuCount() {
    DetectionIndicator ind;
    ind.name     = "Logical CPU Count";
    ind.category = DetectionCategory::Hardware;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uint32_t cores = si.dwNumberOfProcessors;
    ind.rawValue   = cores;

    std::ostringstream detail;
    detail << cores << " logical processor(s) reported by GetSystemInfo";
    ind.detail = detail.str();

    if (cores == 1)      ind.confidence = SandboxConfidence::High;
    else if (cores == 0) ind.confidence = SandboxConfidence::Certain;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Primary Disk Size
// ============================================================

DetectionIndicator HardwarePlugin::checkDiskSize() {
    DetectionIndicator ind;
    ind.name     = "Primary Disk Size";
    ind.category = DetectionCategory::Hardware;

    ULARGE_INTEGER freeBytesAvailable{}, totalBytes{}, freeBytes{};
    if (!GetDiskFreeSpaceExW(L"C:\\", &freeBytesAvailable,
                              &totalBytes, &freeBytes))
    {
        ind.detail     = "GetDiskFreeSpaceEx failed";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    uint64_t totalGb = totalBytes.QuadPart / (1024ULL * 1024 * 1024);
    ind.rawValue = totalBytes.QuadPart;

    std::ostringstream detail;
    detail << "C:\\ total size: " << totalGb << " GB";
    ind.detail = detail.str();

    if (totalGb < 20)        ind.confidence = SandboxConfidence::Certain;
    else if (totalGb < 40)   ind.confidence = SandboxConfidence::High;
    else if (totalGb < 60)   ind.confidence = SandboxConfidence::Medium;
    else                     ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Screen Resolution
// ============================================================

DetectionIndicator HardwarePlugin::checkScreenResolution() {
    DetectionIndicator ind;
    ind.name     = "Screen Resolution";
    ind.category = DetectionCategory::Hardware;

    int width  = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    ind.rawValue = (static_cast<uint64_t>(width) << 32) | height;

    std::ostringstream detail;
    detail << width << "x" << height;
    ind.detail = detail.str();

    // Common VM default resolutions: 800x600, 1024x768, 640x480
    struct SuspRes { int w, h; SandboxConfidence conf; };
    static const SuspRes suspRes[] = {
        { 640,  480,  SandboxConfidence::Certain },
        { 800,  600,  SandboxConfidence::High    },
        { 1024, 768,  SandboxConfidence::Medium  },
        { 1152, 864,  SandboxConfidence::Low     },
    };

    for (const auto& r : suspRes) {
        if (width == r.w && height == r.h) {
            ind.detail    += " — typical VM default resolution";
            ind.confidence = r.conf;
            return ind;
        }
    }

    ind.confidence = SandboxConfidence::None;
    return ind;
}

// ============================================================
//  Check: MAC Address OUI (Organizationally Unique Identifier)
// ============================================================

DetectionIndicator HardwarePlugin::checkMacAddressOui() {
    DetectionIndicator ind;
    ind.name     = "MAC Address OUI (VM Vendor)";
    ind.category = DetectionCategory::Hardware;

    // Known VM vendor OUI prefixes (first 3 bytes of MAC)
    static const std::vector<std::pair<std::string, std::string>> vmOuis = {
        { "08:00:27", "VirtualBox"     },
        { "00:0C:29", "VMware"         },
        { "00:50:56", "VMware"         },
        { "00:05:69", "VMware"         },
        { "00:1C:14", "VMware"         },
        { "00:16:3E", "Xen"            },
        { "52:54:00", "QEMU/KVM"       },
        { "00:1C:42", "Parallels"      },
        { "00:03:FF", "Hyper-V"        },
        { "00:15:5D", "Hyper-V"        },
        { "00:E0:4C", "Realtek (VM)"   },
    };

    auto macs = WinUtils::getNetworkAdapterMacAddresses();
    uint32_t hits = 0;
    std::vector<std::string> found;

    for (const auto& mac : macs) {
        std::string macStr = WinUtils::toNarrow(mac);
        // Normalize to uppercase colon format
        std::transform(macStr.begin(), macStr.end(), macStr.begin(),
                       [](unsigned char c) { return static_cast<char>(::toupper(c)); });

        for (const auto& [oui, vendor] : vmOuis) {
            std::string ouiUpper = oui;
            std::transform(ouiUpper.begin(), ouiUpper.end(),
                           ouiUpper.begin(), [](unsigned char c) { return static_cast<char>(::toupper(c)); });
            if (macStr.substr(0, 8) == ouiUpper) {
                ++hits;
                found.push_back(macStr + " [" + vendor + "]");
                break;
            }
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << " VM MAC address(es) found";
    for (const auto& f : found) detail << "; " << f;
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Disk Serial Number Patterns
// ============================================================

DetectionIndicator HardwarePlugin::checkDiskSerialNumber() {
    DetectionIndicator ind;
    ind.name     = "Disk Serial Number";
    ind.category = DetectionCategory::Hardware;

    // Query the C: drive serial number via DeviceIoControl
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0",
                                0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDisk == INVALID_HANDLE_VALUE) {
        // Fall back to volume serial
        DWORD volSerial = 0;
        GetVolumeInformationW(L"C:\\", nullptr, 0, &volSerial,
                               nullptr, nullptr, nullptr, 0);
        ind.rawValue = volSerial;

        // Serial numbers of exactly 0 or 0xFFFFFFFF = suspicious
        if (volSerial == 0 || volSerial == 0xFFFFFFFF) {
            ind.detail     = "C:\\ volume serial number is zero or FFFFFFFF — suspicious";
            ind.confidence = SandboxConfidence::Medium;
        } else {
            std::ostringstream detail;
            detail << "C:\\ volume serial: 0x" << std::hex << volSerial;
            ind.detail     = detail.str();
            ind.confidence = SandboxConfidence::None;
        }
        return ind;
    }

    // Use STORAGE_PROPERTY_QUERY to get disk descriptor
    STORAGE_PROPERTY_QUERY spq{};
    spq.PropertyId = StorageDeviceProperty;
    spq.QueryType  = PropertyStandardQuery;

    std::vector<uint8_t> buf(2048);
    DWORD bytesReturned = 0;
    bool ok = DeviceIoControl(hDisk,
                               IOCTL_STORAGE_QUERY_PROPERTY,
                               &spq, sizeof(spq),
                               buf.data(), static_cast<DWORD>(buf.size()),
                               &bytesReturned, nullptr) != FALSE;
    CloseHandle(hDisk);

    if (!ok || bytesReturned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        ind.detail     = "DeviceIoControl STORAGE_QUERY_PROPERTY failed";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf.data());

    auto getString = [&](DWORD offset) -> std::string {
        if (offset == 0 || offset >= bytesReturned) return {};
        const char* ptr = reinterpret_cast<const char*>(buf.data()) + offset;
        size_t maxLen = bytesReturned - offset;
        size_t len = strnlen(ptr, maxLen);
        return std::string(ptr, len);
    };

    std::string vendorId  = getString(desc->VendorIdOffset);
    std::string productId = getString(desc->ProductIdOffset);
    std::string serialNum = getString(desc->SerialNumberOffset);

    std::string combined = vendorId + " " + productId + " " + serialNum;
    std::string combinedUpper = combined;
    std::transform(combinedUpper.begin(), combinedUpper.end(),
                   combinedUpper.begin(), [](unsigned char c){ return static_cast<char>(::toupper(c)); });

    static const std::vector<std::string> vmStrings = {
        "VBOX", "VIRTUALBOX", "VMWARE", "QEMU", "VIRTUAL HD",
        "MSFT VIRTUAL", "VIRTUAL DISK", "BOCHS"
    };

    uint32_t hits = 0;
    std::string foundStr;
    for (const auto& vm : vmStrings) {
        if (combinedUpper.find(vm) != std::string::npos) {
            ++hits;
            foundStr = vm;
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << "Disk: \"" << vendorId << " " << productId << "\" serial=\"" << serialNum << "\"";
    if (!foundStr.empty()) detail << " — VM string \"" << foundStr << "\" detected";
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: GPU Name via DXGI
// ============================================================

DetectionIndicator HardwarePlugin::checkGpuName() {
    DetectionIndicator ind;
    ind.name     = "GPU Name (DXGI Adapter)";
    ind.category = DetectionCategory::Hardware;

    static const std::vector<std::string> vmGpuStrings = {
        "VIRTUALBOX", "VMWARE", "SVGA", "MICROSOFT BASIC",
        "BASIC RENDER", "QEMU", "BOCHS", "PARALLELS",
        "REMOTE DESKTOP", "RDP"
    };

    IDXGIFactory* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory(__uuidof(IDXGIFactory),
                                    reinterpret_cast<void**>(&pFactory));
    if (FAILED(hr) || !pFactory) {
        ind.detail     = "DXGI not available";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    std::vector<std::string> gpuNames;
    UINT i = 0;
    IDXGIAdapter* pAdapter = nullptr;
    while (pFactory->EnumAdapters(i++, &pAdapter) != DXGI_ERROR_NOT_FOUND) {
        DXGI_ADAPTER_DESC desc{};
        if (SUCCEEDED(pAdapter->GetDesc(&desc))) {
            char narrow[128]{};
            WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1,
                                narrow, sizeof(narrow) - 1, nullptr, nullptr);
            gpuNames.emplace_back(narrow);
        }
        pAdapter->Release();
    }
    pFactory->Release();

    uint32_t hits = 0;
    std::vector<std::string> found;

    for (const auto& name : gpuNames) {
        std::string nameUpper = name;
        std::transform(nameUpper.begin(), nameUpper.end(),
                       nameUpper.begin(), [](unsigned char c){ return static_cast<char>(::toupper(c)); });
        for (const auto& vm : vmGpuStrings) {
            if (nameUpper.find(vm) != std::string::npos) {
                ++hits;
                found.push_back(name);
                break;
            }
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << "GPU(s): ";
    for (size_t j = 0; j < gpuNames.size(); ++j) {
        if (j) detail << ", ";
        detail << "\"" << gpuNames[j] << "\"";
    }
    if (hits > 0) detail << " — VM GPU detected";
    ind.detail = detail.str();

    if (hits >= 1)  ind.confidence = SandboxConfidence::High;
    else            ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Sound Device Presence
// ============================================================

DetectionIndicator HardwarePlugin::checkSoundDevice() {
    DetectionIndicator ind;
    ind.name     = "Sound Device Absence";
    ind.category = DetectionCategory::Hardware;

    // Use SetupAPI to enumerate sound devices
    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_MEDIA,
                                              nullptr, nullptr,
                                              DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        ind.detail     = "SetupDiGetClassDevs(MEDIA) failed";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    SP_DEVINFO_DATA devInfoData{ sizeof(SP_DEVINFO_DATA) };
    uint32_t count = 0;
    for (DWORD idx = 0;
         SetupDiEnumDeviceInfo(hDevInfo, idx, &devInfoData);
         ++idx)
    {
        ++count;
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);

    ind.rawValue = count;

    std::ostringstream detail;
    detail << count << " sound/media device(s) present";
    ind.detail = detail.str();

    if (count == 0)  ind.confidence = SandboxConfidence::Medium;
    else             ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Monitor Count
// ============================================================

DetectionIndicator HardwarePlugin::checkMonitorCount() {
    DetectionIndicator ind;
    ind.name     = "Monitor Count";
    ind.category = DetectionCategory::Hardware;

    int count = GetSystemMetrics(SM_CMONITORS);
    ind.rawValue = count;

    std::ostringstream detail;
    detail << count << " monitor(s) detected";
    ind.detail = detail.str();

    // Sandboxes typically have 0 or 1 monitor
    // Physical workstations commonly have 1-3, but 0 is very suspicious
    if (count == 0)  ind.confidence = SandboxConfidence::High;
    else             ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Battery Presence (via SetupAPI GUID_DEVCLASS_BATTERY)
// ============================================================

DetectionIndicator HardwarePlugin::checkBatteryPresence() {
    DetectionIndicator ind;
    ind.name     = "Battery Device Presence";
    ind.category = DetectionCategory::Hardware;

    // GUID_DEVCLASS_BATTERY = {72631E54-78A4-11D0-BCF7-00AA00B7B32A}
    static const GUID BATTERY_GUID = {
        0x72631E54, 0x78A4, 0x11D0,
        { 0xBC, 0xF7, 0x00, 0xAA, 0x00, 0xB7, 0xB3, 0x2A }
    };

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&BATTERY_GUID, nullptr, nullptr,
                                              DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        ind.detail     = "Could not enumerate battery devices";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    SP_DEVINFO_DATA devInfoData{ sizeof(SP_DEVINFO_DATA) };
    uint32_t batteryCount = 0;
    for (DWORD idx = 0;
         SetupDiEnumDeviceInfo(hDevInfo, idx, &devInfoData);
         ++idx)
    {
        ++batteryCount;
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);

    ind.rawValue = batteryCount;

    std::ostringstream detail;
    detail << batteryCount << " battery device(s) found";
    ind.detail = detail.str();

    // Note: desktops/servers also have no battery.
    // This is only a weak signal by itself, used in combination.
    if (batteryCount == 0) ind.confidence = SandboxConfidence::Low;
    else                   ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: Firmware OEM Strings (via SMBIOS / registry fallback)
// ============================================================

DetectionIndicator HardwarePlugin::checkFirmwareStrings() {
    DetectionIndicator ind;
    ind.name     = "Firmware OEM Strings";
    ind.category = DetectionCategory::Hardware;

    // Read SMBIOS data via GetSystemFirmwareTable
    UINT fwSize = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (fwSize == 0) {
        ind.detail     = "GetSystemFirmwareTable returned 0";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    std::vector<uint8_t> fwData(fwSize);
    GetSystemFirmwareTable('RSMB', 0, fwData.data(), fwSize);

    // Search raw SMBIOS data for VM strings
    static const std::vector<std::string> vmFwStrings = {
        "VirtualBox", "VBOX", "VMware", "QEMU", "Bochs",
        "Parallels", "innotek", "SeaBIOS", "OVMF", "Xen"
    };

    std::string fwStr(reinterpret_cast<const char*>(fwData.data()),
                      fwData.size());

    uint32_t hits = 0;
    std::vector<std::string> found;
    for (const auto& vm : vmFwStrings) {
        if (fwStr.find(vm) != std::string::npos) {
            ++hits;
            found.push_back(vm);
        }
    }

    ind.rawValue = hits;

    std::ostringstream detail;
    detail << hits << " VM string(s) in SMBIOS firmware data";
    for (const auto& f : found) detail << "; \"" << f << "\"";
    ind.detail = detail.str();

    if (hits >= 2)       ind.confidence = SandboxConfidence::Certain;
    else if (hits == 1)  ind.confidence = SandboxConfidence::High;
    else                 ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: USB Controller Count
// ============================================================

DetectionIndicator HardwarePlugin::checkUsbControllers() {
    DetectionIndicator ind;
    ind.name     = "USB Controller Count";
    ind.category = DetectionCategory::Hardware;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_USB,
                                              nullptr, nullptr,
                                              DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        ind.detail     = "Could not enumerate USB devices";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    SP_DEVINFO_DATA devInfoData{ sizeof(SP_DEVINFO_DATA) };
    uint32_t count = 0;
    for (DWORD idx = 0;
         SetupDiEnumDeviceInfo(hDevInfo, idx, &devInfoData);
         ++idx)
    {
        ++count;
    }
    SetupDiDestroyDeviceInfoList(hDevInfo);

    ind.rawValue = count;

    std::ostringstream detail;
    detail << count << " USB controller(s)/device(s) present";
    ind.detail = detail.str();

    // Sandboxes commonly have 0 USB controllers
    if (count == 0)  ind.confidence = SandboxConfidence::Medium;
    else             ind.confidence = SandboxConfidence::None;

    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
