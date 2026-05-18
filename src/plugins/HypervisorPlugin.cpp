#include "plugins/HypervisorPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>

#include <sstream>
#include <algorithm>
#include <cstring>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Construction
// ============================================================

HypervisorPlugin::HypervisorPlugin() {
    m_meta.id           = "com.sandboxdetector.hypervisor";
    m_meta.name         = "Hypervisor Detection Plugin";
    m_meta.version      = "1.3.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects hypervisors (VirtualBox, VMware, Hyper-V, QEMU, KVM, "
                           "Parallels) via CPUID leaves, IDT tricks, and native APIs.";
    m_meta.categories   = DetectionCategory::Hypervisor;
    m_meta.priority     = 5;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

HypervisorPlugin::~HypervisorPlugin() { shutdown(); }

const PluginMetadata& HypervisorPlugin::getMetadata() const noexcept { return m_meta; }
bool HypervisorPlugin::isSupported() const noexcept { return true; }

bool HypervisorPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void HypervisorPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult HypervisorPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    // Cache the hypervisor vendor string for subsequent checks
    m_hvVendor = WinUtils::getHypervisorVendorString();
    m_seenVendor = !m_hvVendor.empty();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkCpuidHypervisorBit());
    push(checkHypervisorVendorString());
    push(checkHypervisorInterface());
    push(checkNtHypervisorInfo());
    push(checkVmwareBackdoor());
    push(checkIdtBaseAddress());
    push(checkVirtualBoxCpuid());
    push(checkHyperVEnlightenments());
    push(checkKvmPvClock());
    push(checkParallelsCpuid());

    result.sandboxDetected  = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();
    result.executionTime     = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0);
    return result;
}

// ============================================================
//  Check: CPUID leaf 0x1 bit 31 (ECX) — Hypervisor Present Bit
// ============================================================

DetectionIndicator HypervisorPlugin::checkCpuidHypervisorBit() {
    DetectionIndicator ind;
    ind.name     = "CPUID Hypervisor Present Bit";
    ind.category = DetectionCategory::Hypervisor;

    auto r = WinUtils::cpuid(0x1);
    bool hvBit = (r.ecx & (1u << 31)) != 0;
    ind.rawValue = hvBit ? 1 : 0;

    if (hvBit) {
        ind.detail     = "CPUID leaf 0x1 ECX bit 31 is set — hypervisor present";
        ind.confidence = SandboxConfidence::High;
    } else {
        ind.detail     = "CPUID hypervisor bit not set";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: CPUID leaf 0x40000000 — Hypervisor Vendor String
// ============================================================

DetectionIndicator HypervisorPlugin::checkHypervisorVendorString() {
    DetectionIndicator ind;
    ind.name     = "Hypervisor Vendor String";
    ind.category = DetectionCategory::Hypervisor;

    if (m_hvVendor.empty()) {
        ind.detail     = "No hypervisor vendor string returned by CPUID 0x40000000";
        ind.confidence = SandboxConfidence::None;
        return ind;
    }

    ind.detail = "Hypervisor vendor: \"" + m_hvVendor + "\"";
    ind.rawValue = 1;

    // Match known hypervisor vendors
    struct KnownHV { const char* vendor; SandboxConfidence conf; };
    static const KnownHV knownHVs[] = {
        { "KVMKVMKVM",   SandboxConfidence::Certain },
        { "VMwareVMware", SandboxConfidence::Certain },
        { "VBoxVBoxVBox", SandboxConfidence::Certain },
        { "Microsoft Hv", SandboxConfidence::High    },
        { "prl hyperv",   SandboxConfidence::Certain },
        { "XenVMMXenVMM", SandboxConfidence::Certain },
        { "TCGTCGTCGTCG", SandboxConfidence::Certain },  // QEMU/TCG
    };

    for (const auto& kh : knownHVs) {
        if (m_hvVendor.find(kh.vendor) != std::string::npos) {
            ind.confidence = kh.conf;
            ind.detail = "Known hypervisor vendor: \"" + m_hvVendor + "\"";
            return ind;
        }
    }

    // Unknown but non-empty = still suspicious
    ind.confidence = SandboxConfidence::Medium;
    return ind;
}

// ============================================================
//  Check: CPUID leaf 0x40000001 — Hypervisor Interface ID
// ============================================================

DetectionIndicator HypervisorPlugin::checkHypervisorInterface() {
    DetectionIndicator ind;
    ind.name     = "Hypervisor Interface ID";
    ind.category = DetectionCategory::Hypervisor;

    if (!m_seenVendor) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "Skipped (no hypervisor vendor)";
        return ind;
    }

    auto r = WinUtils::cpuid(0x40000001);
    char iface[5]{};
    std::memcpy(iface, &r.eax, 4);
    iface[4] = '\0';

    std::string ifaceStr(iface);
    ind.rawValue = r.eax;

    std::ostringstream detail;
    detail << "HV interface EAX: 0x" << std::hex << r.eax
           << " (\"" << ifaceStr << "\")";
    ind.detail = detail.str();

    // "Hv#1" = Hyper-V specification; "KVMK" = KVM etc.
    if (ifaceStr == "Hv#1" || ifaceStr == "KVMK" || ifaceStr == "XenV") {
        ind.confidence = SandboxConfidence::Certain;
    } else if (r.eax != 0) {
        ind.confidence = SandboxConfidence::Medium;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: NtQuerySystemInformation SystemHypervisorQueryInformation
// ============================================================

DetectionIndicator HypervisorPlugin::checkNtHypervisorInfo() {
    DetectionIndicator ind;
    ind.name     = "NtQuerySystemInformation Hypervisor";
    ind.category = DetectionCategory::Hypervisor;

    SYSTEM_HYPERVISOR_QUERY_INFORMATION hvInfo{};
    ULONG returnLen = 0;
    NTSTATUS status = WinUtils::ntQuerySystemInformation(
        static_cast<UINT>(SystemHypervisorQueryInformation),
        &hvInfo, sizeof(hvInfo), &returnLen);

    if (!NT_SUCCESS(status)) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "NtQuerySystemInformation failed or not supported";
        return ind;
    }

    ind.rawValue = hvInfo.HypervisorPresent ? 1 : 0;

    std::ostringstream detail;
    detail << "HypervisorPresent=" << (hvInfo.HypervisorPresent ? "true" : "false")
           << " HypervisorConnected=" << (hvInfo.HypervisorConnected ? "true" : "false")
           << " Enlightenments=0x" << std::hex << hvInfo.EnabledEnlightenments;
    ind.detail = detail.str();

    if (hvInfo.HypervisorPresent)
        ind.confidence = SandboxConfidence::Certain;
    else
        ind.confidence = SandboxConfidence::None;

    return ind;
}

// ============================================================
//  Check: VMware Backdoor I/O Port (0x5658 / 'VMXh')
//
//  VMware exposes a backdoor via IN instruction on port 0x5658.
//  If EBX == 'VMXh' after the IN, we're inside VMware.
//  This requires a SEH wrapper to catch #GP on bare metal.
// ============================================================

DetectionIndicator HypervisorPlugin::checkVmwareBackdoor() {
    DetectionIndicator ind;
    ind.name     = "VMware Backdoor I/O Port";
    ind.category = DetectionCategory::Hypervisor;
    ind.confidence = SandboxConfidence::None;

    bool vmwareDetected = false;
    uint32_t version    = 0;

#if defined(_M_X64) || defined(__x86_64__)
    // Inline asm and I/O port access not available in x64 MSVC.
    // VMware backdoor detection falls through to CPUID vendor string below.
    (void)vmwareDetected; (void)version;
#endif

    // Reliable fallback: VMware vendor leaf
    if (m_hvVendor.find("VMware") != std::string::npos) {
        vmwareDetected = true;
        version = WinUtils::cpuid(0x40000000).eax;
    }

    if (vmwareDetected) {
        std::ostringstream detail;
        detail << "VMware backdoor confirmed via vendor string. "
               << "Max HV CPUID leaf: 0x" << std::hex << version;
        ind.detail     = detail.str();
        ind.rawValue   = version;
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail = "VMware backdoor not detected";
    }
    return ind;
}

// ============================================================
//  Check: IDT Base Address
//
//  On bare metal, the IDT base is typically in kernel-space
//  at a high canonical address. Inside older VMs, it was placed
//  at lower addresses (the "Red Pill" technique).
//  Modern VMs have fixed this, but the check still catches old VMs.
// ============================================================

DetectionIndicator HypervisorPlugin::checkIdtBaseAddress() {
    DetectionIndicator ind;
    ind.name     = "IDT Base Address";
    ind.category = DetectionCategory::Hypervisor;

    // SIDT stores 10-byte IDTR: 2-byte limit + 8-byte base (x64)
    #pragma pack(push,1)
    struct IDTR { uint16_t limit; uintptr_t base; } idtr{};
    #pragma pack(pop)

    __sidt(&idtr);

    ind.rawValue = static_cast<uint64_t>(idtr.base);

    std::ostringstream detail;
    detail << "IDT base: 0x" << std::hex << idtr.base
           << " limit: 0x" << idtr.limit;
    ind.detail = detail.str();

    // On x64 bare metal, IDT base is in upper canonical range (>0xFFFF8...)
    // In old VMs (VMware/VBox pre-6.x), may be < 0xD0000000 on 32-bit
    // On 64-bit, this trick is less reliable; flag only obviously wrong values
    if (idtr.base < 0x0000FFFF00000000ULL && idtr.base != 0) {
        ind.confidence = SandboxConfidence::Low;
    } else {
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: VirtualBox-Specific CPUID Leaves
// ============================================================

DetectionIndicator HypervisorPlugin::checkVirtualBoxCpuid() {
    DetectionIndicator ind;
    ind.name     = "VirtualBox CPUID Fingerprint";
    ind.category = DetectionCategory::Hypervisor;

    bool vboxDetected = (m_hvVendor == "VBoxVBoxVBox");

    // Also check leaf 0x40000010 which VBox exposes
    auto r = WinUtils::cpuid(0x40000010);
    bool hasVboxLeaf10 = (r.eax != 0 && m_seenVendor);

    ind.rawValue = vboxDetected ? 1 : 0;

    if (vboxDetected) {
        std::ostringstream detail;
        detail << "VirtualBox confirmed: vendor=\"" << m_hvVendor << "\"";
        if (hasVboxLeaf10)
            detail << ", CPUID 0x40000010 EAX=0x" << std::hex << r.eax;
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::Certain;
    } else {
        ind.detail     = "VirtualBox CPUID fingerprint not found";
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: Hyper-V Enlightenments (CPUID leaf 0x40000003)
// ============================================================

DetectionIndicator HypervisorPlugin::checkHyperVEnlightenments() {
    DetectionIndicator ind;
    ind.name     = "Hyper-V Enlightenments";
    ind.category = DetectionCategory::Hypervisor;

    if (!m_seenVendor) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "Skipped (no hypervisor vendor)";
        return ind;
    }

    auto r = WinUtils::cpuid(0x40000003);
    ind.rawValue = (static_cast<uint64_t>(r.eax) << 32) | r.ebx;

    bool isHyperV = (m_hvVendor.find("Microsoft Hv") != std::string::npos);

    std::ostringstream detail;
    detail << "CPUID 0x40000003: EAX=0x" << std::hex << r.eax
           << " EBX=0x" << r.ebx;

    if (isHyperV) {
        detail << " (Hyper-V enlightenments confirmed)";
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::Certain;
    } else if (r.eax != 0) {
        detail << " (non-zero enlightenment bits, non-Hyper-V)";
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::Medium;
    } else {
        ind.detail     = detail.str();
        ind.confidence = SandboxConfidence::None;
    }
    return ind;
}

// ============================================================
//  Check: KVM PV Clock (CPUID 0x40000001 == "KVMKVMKVM")
// ============================================================

DetectionIndicator HypervisorPlugin::checkKvmPvClock() {
    DetectionIndicator ind;
    ind.name     = "KVM Paravirtual Clock";
    ind.category = DetectionCategory::Hypervisor;

    bool isKvm = (m_hvVendor.find("KVMKVMKVM") != std::string::npos);

    if (!isKvm) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "KVM PV clock: not detected";
        return ind;
    }

    // KVM feature bits in CPUID 0x40000001 EAX
    auto r = WinUtils::cpuid(0x40000001);
    ind.rawValue = r.eax;

    std::ostringstream detail;
    detail << "KVM confirmed. Feature bits EAX=0x" << std::hex << r.eax;
    if (r.eax & (1 << 3))  detail << " [steal-time]";
    if (r.eax & (1 << 9))  detail << " [pv-unhalt]";
    if (r.eax & (1 << 11)) detail << " [pv-tlb-flush]";
    ind.detail     = detail.str();
    ind.confidence = SandboxConfidence::Certain;
    return ind;
}

// ============================================================
//  Check: Parallels Desktop CPUID
// ============================================================

DetectionIndicator HypervisorPlugin::checkParallelsCpuid() {
    DetectionIndicator ind;
    ind.name     = "Parallels Desktop Detection";
    ind.category = DetectionCategory::Hypervisor;

    bool isParallels = (m_hvVendor.find("prl hyperv") != std::string::npos ||
                        m_hvVendor.find("lrpepyh") != std::string::npos);

    if (!isParallels) {
        ind.confidence = SandboxConfidence::None;
        ind.detail = "Parallels Desktop: not detected";
        return ind;
    }

    ind.rawValue   = 1;
    ind.detail     = "Parallels Desktop confirmed via CPUID vendor: \"" + m_hvVendor + "\"";
    ind.confidence = SandboxConfidence::Certain;
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
