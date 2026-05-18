# SandboxDetector

**Plugin-based sandbox and virtualization detector for Windows.**

A C++17 library and CLI tool that detects analysis environments (VMs, sandboxes, debuggers)
using a rich plugin architecture. Every detection technique is fully implemented —
no stubs, no placeholders.

---

## Architecture

```
sandbox_detector/
├── include/
│   ├── core/
│   │   ├── IPlugin.hpp          ← Plugin interface, result types, metadata
│   │   └── PluginManager.hpp    ← Plugin loader, registry, scan orchestrator
│   ├── plugins/
│   │   ├── TimingPlugin.hpp
│   │   ├── HypervisorPlugin.hpp
│   │   ├── RegistryPlugin.hpp
│   │   ├── ProcessPlugin.hpp
│   │   ├── AntiDebugPlugin.hpp
│   │   ├── HardwarePlugin.hpp
│   │   └── WmiPlugin.hpp
│   └── utils/
│       └── WinApiUtils.hpp      ← WinAPI helpers, WMI session, CPUID, NtApi
├── src/
│   ├── core/                    ← Core implementations
│   ├── plugins/                 ← Built-in plugin implementations
│   ├── utils/                   ← Utility implementations
│   └── main.cpp                 ← CLI entry point
├── examples/
│   └── ExamplePlugin.cpp        ← External plugin DLL template
└── CMakeLists.txt
```

---

## Built-in Plugins

### 1. `TimingPlugin` (Priority 10)
Detects timing manipulation used by sandbox accelerators:

| Check | Technique |
|---|---|
| CPUID Latency | Median over 50 samples; hypervisor trap overhead |
| RDTSC/Sleep Drift | Sleep(N) vs wall-clock consistency |
| GetTickCount/QPC | Cross-timer agreement check |
| NtDelayExecution | 5ms delay accuracy measurement |
| RDTSCP Monotonicity | Detects TSC counter wrap/reset |
| Timer Resolution | NtQueryTimerResolution manipulation |
| QPC Jitter | Zero-delta and uniform-delta detection |

### 2. `HypervisorPlugin` (Priority 5)
CPUID-based hypervisor fingerprinting:

| Check | Detection |
|---|---|
| CPUID bit 31 ECX | Standard hypervisor present bit |
| Leaf 0x40000000 | Vendor: VMwareVMware, KVMKVMKVM, VBoxVBoxVBox, prl hyperv… |
| Leaf 0x40000001 | Interface ID: Hv#1, KVMK, XenV |
| NtQuerySystemInformation | `SystemHypervisorQueryInformation` |
| VMware Backdoor | CPUID/vendor confirmation |
| IDT Base Address | SIDT base address anomaly |
| VirtualBox CPUID | Leaf 0x40000010 |
| Hyper-V Enlightenments | Leaf 0x40000003 feature bits |
| KVM PV Clock | Feature bits EAX steal-time, pv-unhalt |
| Parallels | Vendor string matching |

### 3. `RegistryPlugin` (Priority 20)
Registry artifact scanning (10+ tables):

- VirtualBox: 10 key checks (Guest Additions, ACPI/VBOX__, services)
- VMware: 11 key checks (VMware Tools, vmhgfs, vmci, vmxnet…)
- Hyper-V: 6 key checks + VirtualMachineName parameter
- QEMU/KVM: vioscsi, viostor, BALLOON, VirtIO-FS
- Sandboxie: SbieDrv, SandboxieDrv, Sandboxie-Plus
- Wine: HKCU/HKLM `\Software\Wine`
- Disk model strings: SCSI enumeration for VBOX/VMWARE/QEMU
- BIOS strings: SystemBiosVersion / VideoBiosVersion
- ACPI tables: VBOX__, BOCHS_, BXPC
- Analysis tools: Wireshark, ProcMon, OllyDbg, x64dbg, IDA
- Service count: <50 services = suspicious
- Video drivers: VBoxVideo, vmsvga, qxl, Microsoft Basic Display

### 4. `ProcessPlugin` (Priority 30)
Running process inspection:

- Sandbox agents: Cuckoo, Sandboxie, Joe Sandbox, VxStream
- VM guest tools: VBoxService, vmtoolsd, vmwaretray, prl_tools, xenservice
- Analysis tools: Wireshark, Fiddler, x64dbg, IDA, OllyDbg, ProcMon, ProcExp
- Process count: <20 processes total
- Missing user processes: explorer, chrome, firefox, etc.
- Sandboxie service: SCM query for running SbieDrv

### 5. `AntiDebugPlugin` (Priority 8)
Debugger detection via 12 techniques:

| Technique | API / Method |
|---|---|
| PEB.BeingDebugged | `IsDebuggerPresent()` |
| Remote debugger | `CheckRemoteDebuggerPresent()` |
| Debug port | `NtQueryInformationProcess(ProcessDebugPort)` |
| Debug flags | `NtQueryInformationProcess(ProcessDebugFlags)` |
| Debug object handle | `NtQueryInformationProcess(ProcessDebugObjectHandle)` |
| Heap flags | PEB → ProcessHeap → Flags/ForceFlags |
| NtGlobalFlag | PEB.NtGlobalFlag 0x70 mask |
| Hardware BPs | `GetThreadContext` DR0–DR3 |
| OutputDebugString | Error code preservation trick |
| Parent process | Name vs debugger blacklist |
| CloseHandle | EXCEPTION_INVALID_HANDLE SEH trick |
| Window classes | FindWindow(OLLYDBG, WinDbgFrameClass…) |

### 6. `HardwarePlugin` (Priority 25)
Hardware fingerprint anomaly detection:

| Check | Threshold |
|---|---|
| Physical RAM | <2 GB suspicious, <1 GB certain |
| CPU count | 1 core = high confidence |
| Disk size | <60 GB suspicious |
| Screen resolution | 800×600, 1024×768 = VM defaults |
| MAC OUI | 10 VM vendor prefixes |
| Disk serial | STORAGE_PROPERTY_QUERY for VM strings |
| GPU name | DXGI adapter: VMware SVGA, Microsoft Basic Display |
| Sound device | SetupAPI GUID_DEVCLASS_MEDIA |
| Monitor count | 0 monitors |
| Battery | SetupAPI GUID_DEVCLASS_BATTERY |
| Firmware strings | GetSystemFirmwareTable SMBIOS raw scan |
| USB controllers | SetupAPI GUID_DEVCLASS_USB |

### 7. `WmiPlugin` (Priority 50)
WMI-based system property interrogation:

| WMI Class | Property | VM Strings |
|---|---|---|
| Win32_ComputerSystem | Model | VirtualBox, VMware, QEMU |
| Win32_ComputerSystem | Manufacturer | innotek, VMware Inc. |
| Win32_BIOS | SMBIOSBIOSVersion | VBOX, BOCHS, SEABIOS |
| Win32_BIOS | SerialNumber | 0, None, Not Specified |
| Win32_BaseBoard | Product | VirtualBox, 440BX |
| Win32_DiskDrive | Model | VBOX HARDDISK, VMware Virtual |
| Win32_NetworkAdapter | MACAddress | 6 VM OUI prefixes |
| Win32_VideoController | Caption | VMware SVGA, Microsoft Basic |
| Win32_OperatingSystem | RegisteredUser | sandbox, malware, cuckoo |
| Win32_Processor | Name | QEMU, KVM |
| Win32_OperatingSystem | InstallDate | <7 days old |
| Win32_PhysicalMemory | (absence) | No DIMM records |

---

## Building

### Requirements
- Windows 10+ SDK
- MSVC 2019 or 2022 (with C++17)
- CMake 3.20+

### Build

```bat
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Output
- `sandbox_detector.exe` — CLI tool
- `sd_core.lib` — core library
- `sd_plugins.lib` — built-in plugins
- `sd_plugin_example.dll` — example external plugin DLL

---

## CLI Usage

```
sandbox_detector.exe [options]

Options:
  -v, --verbose          Show all indicators, not just detections
  -j, --json             Output JSON report to stdout
  -o, --output FILE      Save text/JSON report to FILE
  -p, --parallel         Run plugins in parallel (faster, less stable)
  -s, --stop-first       Stop after first positive detection
  -l, --list-plugins     List all loaded plugins and exit
  --plugin-dir DIR       Load sd_plugin_*.dll files from DIR
  --no-color             Disable ANSI color output
  --timeout MS           Per-scan global timeout (default: 30000)
  --category CATS        Filter by category (default: all)
                         timing,hypervisor,registry,process,
                         antidebug,hardware,wmi
  -h, --help             Show help

Exit Codes:
  0 = No sandbox detected
  1 = Sandbox detected
```

### Examples

```bat
# Full scan, verbose, save JSON
sandbox_detector.exe -v -j -o report.json

# Quick hypervisor check only
sandbox_detector.exe --category hypervisor,timing

# Load custom plugins
sandbox_detector.exe --plugin-dir C:\my_plugins -v

# Non-interactive (CI/CD gate)
sandbox_detector.exe --no-color -j -o scan.json
if %errorlevel% equ 1 exit /b 1
```

---

## Writing an External Plugin

Copy `examples/ExamplePlugin.cpp` and implement three symbols:

```cpp
extern "C" {
    __declspec(dllexport) SandboxDetector::IPlugin* CreatePlugin();
    __declspec(dllexport) void DestroyPlugin(SandboxDetector::IPlugin*);
    __declspec(dllexport) const char* GetPluginApiVersion();  // return "1.0.0"
}
```

Your plugin class must implement `IPlugin`:

```cpp
class MyPlugin final : public SandboxDetector::IPlugin {
    const PluginMetadata& getMetadata() const noexcept override;
    bool                  initialize(const PluginConfig&) override;
    void                  shutdown() noexcept override;
    PluginResult          run() override;
};
```

Name the DLL `sd_plugin_<name>.dll` and place in `--plugin-dir`.

---

## Detection Confidence Scale

| Level | Value | Meaning |
|---|---|---|
| None | 0 | Not detected |
| Low | 25 | Possible indicator, easily false-positive |
| Medium | 50 | Probable indicator |
| High | 75 | Strong indicator (rare on bare metal) |
| Certain | 100 | Definitive evidence |

The overall confidence is computed as a weighted average (squared weighting)
across all active `DetectionIndicator` entries from all plugins.

---

## Embedding as a Library

```cpp
#include "core/PluginManager.hpp"
#include "plugins/HypervisorPlugin.hpp"
// ...

SandboxDetector::PluginManager mgr;
mgr.registerPlugin(std::make_unique<Plugins::HypervisorPlugin>());
mgr.registerPlugin(std::make_unique<Plugins::TimingPlugin>());
mgr.registerPlugin(std::make_unique<Plugins::AntiDebugPlugin>());

SandboxDetector::ScanConfig cfg;
cfg.categoryFilter = SandboxDetector::DetectionCategory::All;

auto report = mgr.runScan(cfg);
if (report.overallSandboxDetected) {
    // handle detection
    for (auto& ind : report.getAllIndicators()) {
        printf("[%d] %s: %s\n",
               (int)ind.confidence, ind.name.c_str(), ind.detail.c_str());
    }
}

// Export as JSON
std::string json = report.toJson();
```

---

## License

MIT License. See `LICENSE` for details.
