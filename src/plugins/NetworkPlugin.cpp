#include "plugins/NetworkPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <tcpmib.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <sstream>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <array>
#include <cctype>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Known VM vendor MAC OUI prefixes (3 bytes, uppercase hex colon-separated)
// ============================================================

static constexpr std::array<const char*, 22> VM_MAC_OUIS = {{
    "00:05:69",  // VMware
    "00:0C:29",  // VMware
    "00:50:56",  // VMware vSphere
    "00:1C:14",  // VMware
    "08:00:27",  // VirtualBox / Oracle
    "52:54:00",  // QEMU/KVM (libvirt)
    "00:16:3E",  // Xen
    "00:1C:42",  // Parallels
    "00:21:F6",  // Virtual Iron
    "00:14:4F",  // Sun xVM / Oracle VM
    "00:0F:4B",  // Virtual Iron
    "00:03:FF",  // Microsoft Hyper-V
    "00:15:5D",  // Microsoft Hyper-V
    "00:E0:C8",  // AKIMBI Systems
    "00:25:AE",  // Microsoft
    "28:D2:44",  // Microsoft Hyper-V
    "00:17:FA",  // Microsoft Hyper-V
    "00:BD:FF",  // Microsoft
    "00:1D:D8",  // Microsoft
    "00:12:3F",  // Vmware Workstation
    "06:00:27",  // VirtualBox NAT
    "0A:00:27",  // VirtualBox Host-Only
}};

// Well-known VM NAT IP ranges
static constexpr std::array<const char*, 6> VM_IP_PREFIXES = {{
    "192.168.56.",  // VirtualBox Host-Only
    "10.0.2.",      // VirtualBox NAT
    "192.168.122.", // QEMU/KVM NAT
    "172.16.0.",    // VMware NAT
    "192.168.0.",   // VMware NAT (common)
    "192.168.1.",   // Hyper-V NAT
}};

// VM-related adapter description substrings (lowercase for comparison)
static constexpr std::array<const char*, 18> VM_ADAPTER_STRINGS = {{
    "virtualbox",
    "vmware",
    "virtual ethernet",
    "hyper-v virtual",
    "qemu",
    "virt",
    "tap-windows",
    "ndis virtual",
    "wan miniport",
    "vboxnet",
    "vmnet",
    "virtio",
    "vmxnet",
    "parallels",
    "xen",
    "realtek pcie fe",   // common VirtualBox NAT fake
    "intel(r) 82574",    // common VMware emulation
    "vmsmp",
}};

// ============================================================
//  Helpers
// ============================================================

static std::string toUpper(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return (char)std::toupper(c); });
    return out;
}

static std::string toLower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return out;
}

static std::string formatMac(const BYTE* addr, DWORD len) {
    if (len < 6) return "";
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return std::string(buf);
}

// ============================================================
//  Construction / lifecycle
// ============================================================

NetworkPlugin::NetworkPlugin() {
    m_meta.id           = "com.sandboxdetector.network";
    m_meta.name         = "Network Stack Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox/VM via network adapter enumeration, "
                          "MAC OUI fingerprinting, IP range analysis, ARP table "
                          "size, active connections, hostname, and DNS suffix checks.";
    m_meta.categories   = DetectionCategory::Network;
    m_meta.priority     = 35;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

NetworkPlugin::~NetworkPlugin() { shutdown(); }

const PluginMetadata& NetworkPlugin::getMetadata() const noexcept { return m_meta; }
bool NetworkPlugin::isSupported() const noexcept { return true; }

bool NetworkPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void NetworkPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult NetworkPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkMacAddressOui());
    push(checkAdapterCount());
    push(checkAdapterDescriptions());
    push(checkVmNatIpRanges());
    push(checkHostname());
    push(checkDnsSuffix());
    push(checkArpTableSize());
    push(checkActiveTcpConnections());
    push(checkDefaultGateway());
    push(checkIpv6Presence());
    push(checkLoopbackOnly());
    push(checkNetworkInterfaces());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Check: MAC Address OUI
// ============================================================

DetectionIndicator NetworkPlugin::checkMacAddressOui() {
    DetectionIndicator ind;
    ind.name     = "VM MAC Address OUI";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }

    DWORD rc = GetAdaptersAddresses(AF_UNSPEC,
                                     GAA_FLAG_INCLUDE_ALL_INTERFACES |
                                     GAA_FLAG_SKIP_FRIENDLY_NAME,
                                     nullptr, pAddrs, &bufLen);
    if (rc != NO_ERROR) {
        ind.detail = "GetAdaptersAddresses failed: " + std::to_string(rc);
        return ind;
    }

    std::vector<std::string> matchedMacs;
    for (auto* p = pAddrs; p != nullptr; p = p->Next) {
        if (p->PhysicalAddressLength == 0) continue;
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        std::string mac = formatMac(p->PhysicalAddress, p->PhysicalAddressLength);
        std::string oui = mac.substr(0, 8);
        std::string ouiUp = toUpper(oui);
        for (const char* vmOui : VM_MAC_OUIS) {
            if (ouiUp == std::string(vmOui)) {
                matchedMacs.push_back(mac + " (" + vmOui + ")");
                break;
            }
        }
    }

    if (!matchedMacs.empty()) {
        std::ostringstream ss;
        ss << "VM vendor MAC OUI detected: ";
        for (size_t i = 0; i < matchedMacs.size(); ++i) {
            if (i) ss << ", ";
            ss << matchedMacs[i];
        }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::High;
        ind.rawValue   = static_cast<uint64_t>(matchedMacs.size());
    }
    return ind;
}

// ============================================================
//  Check: Adapter Count
// ============================================================

DetectionIndicator NetworkPlugin::checkAdapterCount() {
    DetectionIndicator ind;
    ind.name     = "Network Adapter Count Anomaly";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
                             GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                             nullptr, pAddrs, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }
    DWORD rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
                                    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                    nullptr, pAddrs, &bufLen);
    if (rc != NO_ERROR) return ind;

    uint32_t real = 0, loopback = 0;
    for (auto* p = pAddrs; p != nullptr; p = p->Next) {
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) loopback++;
        else real++;
    }
    ind.rawValue = real;

    if (real == 0) {
        ind.detail     = "No real network adapters found (loopback-only). Likely headless sandbox.";
        ind.confidence = SandboxConfidence::High;
    } else if (real > 8) {
        ind.detail     = "Unusually high adapter count: " + std::to_string(real)
                         + " (> 8). Possible virtual/tap adapter injection.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: Adapter Descriptions
// ============================================================

DetectionIndicator NetworkPlugin::checkAdapterDescriptions() {
    DetectionIndicator ind;
    ind.name     = "VM Network Adapter Description";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) != NO_ERROR) return ind;

    std::vector<std::string> hits;
    for (auto* p = pAddrs; p != nullptr; p = p->Next) {
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        std::string desc = WinUtils::toNarrow(std::wstring(p->Description ? p->Description : L""));
        std::string descLo = toLower(desc);
        for (const char* vmStr : VM_ADAPTER_STRINGS) {
            if (descLo.find(vmStr) != std::string::npos) {
                hits.push_back(desc);
                break;
            }
        }
    }

    if (!hits.empty()) {
        std::ostringstream ss;
        ss << "VM adapter description(s): ";
        for (size_t i = 0; i < hits.size(); ++i) { if (i) ss << ", "; ss << hits[i]; }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::High;
        ind.rawValue   = static_cast<uint64_t>(hits.size());
    }
    return ind;
}

// ============================================================
//  Check: VM NAT IP Ranges
// ============================================================

DetectionIndicator NetworkPlugin::checkVmNatIpRanges() {
    DetectionIndicator ind;
    ind.name     = "VM NAT IP Range";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAddrs, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAddrs, &bufLen) != NO_ERROR) return ind;

    std::vector<std::string> hits;
    for (auto* p = pAddrs; p != nullptr; p = p->Next) {
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* ua = p->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            char ipBuf[INET_ADDRSTRLEN] = {};
            auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
            inet_ntop(AF_INET, &sa->sin_addr, ipBuf, sizeof(ipBuf));
            std::string ip(ipBuf);
            for (const char* prefix : VM_IP_PREFIXES) {
                if (ip.rfind(prefix, 0) == 0) {
                    hits.push_back(ip + " [" + prefix + "...]");
                    break;
                }
            }
        }
    }

    if (!hits.empty()) {
        std::ostringstream ss;
        ss << "IP address(es) in known VM NAT range: ";
        for (size_t i = 0; i < hits.size(); ++i) { if (i) ss << ", "; ss << hits[i]; }
        ind.detail     = ss.str();
        ind.confidence = SandboxConfidence::Medium;
        ind.rawValue   = static_cast<uint64_t>(hits.size());
    }
    return ind;
}

// ============================================================
//  Check: Hostname
// ============================================================

DetectionIndicator NetworkPlugin::checkHostname() {
    DetectionIndicator ind;
    ind.name     = "Suspicious Hostname";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    static constexpr std::array<const char*, 16> SUSPECT_NAMES = {{
        "sandbox", "malware", "cuckoo", "virus", "analysis",
        "maltest", "test", "sample", "honeypot", "lab",
        "anyrun", "joesandbox", "cape", "hybrid", "vmware", "vbox"
    }};

    char hostname[MAX_COMPUTERNAME_LENGTH + 2] = {};
    DWORD len = sizeof(hostname);
    if (!GetComputerNameExA(ComputerNameDnsHostname, hostname, &len)) {
        GetComputerNameA(hostname, &len);
    }

    std::string host(hostname);
    std::string hostLo = toLower(host);
    ind.rawValue = static_cast<uint64_t>(host.size());

    for (const char* s : SUSPECT_NAMES) {
        if (hostLo.find(s) != std::string::npos) {
            ind.detail     = "Hostname contains sandbox keyword: '" + host + "'";
            ind.confidence = SandboxConfidence::High;
            return ind;
        }
    }

    // DESKTOP-XXXXXXX with exactly 7 uppercase alphanum suffix is default Windows OOBE name
    // while not conclusive alone, combined with other indicators it matters
    if (host.rfind("DESKTOP-", 0) == 0 && host.size() == 15) {
        // Not flagged alone — too common. Return None.
    }
    return ind;
}

// ============================================================
//  Check: DNS Suffix
// ============================================================

DetectionIndicator NetworkPlugin::checkDnsSuffix() {
    DetectionIndicator ind;
    ind.name     = "Suspicious DNS Suffix";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    static constexpr std::array<const char*, 6> SUSPECT_SUFFIXES = {{
        "sandbox", "localdomain", "malware", "cuckoo", "anyrun", "lab"
    }};

    char suffix[256] = {};
    DWORD len = sizeof(suffix);
    if (GetComputerNameExA(ComputerNameDnsDomain, suffix, &len) && len > 0) {
        std::string sfx(suffix);
        std::string sfxLo = toLower(sfx);
        for (const char* s : SUSPECT_SUFFIXES) {
            if (sfxLo.find(s) != std::string::npos) {
                ind.detail     = "DNS suffix indicates sandbox environment: '" + sfx + "'";
                ind.confidence = SandboxConfidence::Medium;
                return ind;
            }
        }
    }
    return ind;
}

// ============================================================
//  Check: ARP Table Size
// ============================================================

DetectionIndicator NetworkPlugin::checkArpTableSize() {
    DetectionIndicator ind;
    ind.name     = "ARP Table Anomaly";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 0;
    GetIpNetTable(nullptr, &bufLen, FALSE);
    if (bufLen == 0) {
        ind.detail     = "ARP table unavailable (empty). Isolated network environment.";
        ind.confidence = SandboxConfidence::Low;
        return ind;
    }

    std::vector<BYTE> buf(bufLen);
    auto* pTable = reinterpret_cast<PMIB_IPNETTABLE>(buf.data());
    DWORD rc = GetIpNetTable(pTable, &bufLen, FALSE);
    if (rc != NO_ERROR && rc != ERROR_NO_DATA) return ind;

    DWORD count = (rc == ERROR_NO_DATA) ? 0 : pTable->dwNumEntries;
    ind.rawValue = count;

    if (count == 0) {
        ind.detail     = "ARP table is empty (0 entries). Typical of isolated sandbox.";
        ind.confidence = SandboxConfidence::Medium;
    } else if (count < 2) {
        ind.detail     = "ARP table has only " + std::to_string(count)
                         + " entries. Minimal network activity suggests sandbox.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: Active TCP Connections
// ============================================================

DetectionIndicator NetworkPlugin::checkActiveTcpConnections() {
    DetectionIndicator ind;
    ind.name     = "Active TCP Connection Count";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 0;
    GetExtendedTcpTable(nullptr, &bufLen, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (bufLen == 0) return ind;

    std::vector<BYTE> buf(bufLen);
    auto* pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buf.data());
    if (GetExtendedTcpTable(pTable, &bufLen, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return ind;

    uint32_t established = 0;
    for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
        if (pTable->table[i].dwState == MIB_TCP_STATE_ESTAB)
            established++;
    }
    ind.rawValue = established;

    // Sandboxes typically have 0 or 1 external connections
    if (established == 0) {
        ind.detail     = "No established TCP connections. Network-isolated sandbox.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: Default Gateway
// ============================================================

DetectionIndicator NetworkPlugin::checkDefaultGateway() {
    DetectionIndicator ind;
    ind.name     = "Default Gateway Presence";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 0;
    GetIpForwardTable(nullptr, &bufLen, FALSE);
    if (bufLen == 0) return ind;

    std::vector<BYTE> buf(bufLen);
    auto* pTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buf.data());
    if (GetIpForwardTable(pTable, &bufLen, FALSE) != NO_ERROR) return ind;

    bool hasDefault = false;
    for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
        if (pTable->table[i].dwForwardDest == 0 &&
            pTable->table[i].dwForwardMask == 0) {
            hasDefault = true;
            break;
        }
    }
    ind.rawValue = hasDefault ? 1 : 0;

    if (!hasDefault) {
        ind.detail     = "No default gateway in routing table. Network-isolated sandbox.";
        ind.confidence = SandboxConfidence::Medium;
    }
    return ind;
}

// ============================================================
//  Check: IPv6 Link-Local Presence
// ============================================================

DetectionIndicator NetworkPlugin::checkIpv6Presence() {
    DetectionIndicator ind;
    ind.name     = "IPv6 Absence on Physical Adapter";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) != NO_ERROR) return ind;

    uint32_t realAdapters = 0;
    uint32_t ipv6Adapters = 0;
    for (auto* p = pAddrs; p != nullptr; p = p->Next) {
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (p->PhysicalAddressLength == 0) continue;
        realAdapters++;
        for (auto* ua = p->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                ipv6Adapters++;
                break;
            }
        }
    }
    ind.rawValue = ipv6Adapters;

    if (realAdapters > 0 && ipv6Adapters == 0) {
        ind.detail     = "No IPv6 addresses on " + std::to_string(realAdapters)
                         + " real adapter(s). VMs often lack IPv6 link-local.";
        ind.confidence = SandboxConfidence::Low;
    }
    return ind;
}

// ============================================================
//  Check: Loopback Only
// ============================================================

DetectionIndicator NetworkPlugin::checkLoopbackOnly() {
    DetectionIndicator ind;
    ind.name     = "Loopback-Only Network Stack";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    PIP_ADAPTER_ADDRESSES pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        pAddrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                             nullptr, pAddrs, &bufLen) != NO_ERROR) return ind;

    uint32_t realAdapters = 0;
    for (auto* p = pAddrs; p != nullptr; p = p->Next) {
        if (p->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
            p->IfType != IF_TYPE_TUNNEL)
            realAdapters++;
    }
    ind.rawValue = realAdapters;

    if (realAdapters == 0) {
        ind.detail     = "Only loopback adapter present. Network-isolated/headless sandbox.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

// ============================================================
//  Check: Network Interfaces (detailed cross-check)
// ============================================================

DetectionIndicator NetworkPlugin::checkNetworkInterfaces() {
    DetectionIndicator ind;
    ind.name     = "Virtual Network Interface Fingerprint";
    ind.category = DetectionCategory::Network;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Use MIB_IF_TABLE2 for richer interface data (Vista+)
    PMIB_IF_TABLE2 pTable = nullptr;
    if (GetIfTable2(&pTable) != NO_ERROR || !pTable) return ind;

    struct TableGuard {
        PMIB_IF_TABLE2 t;
        ~TableGuard() { if (t) FreeMibTable(t); }
    } guard{pTable};

    uint32_t vmInterfaces = 0;
    std::ostringstream ss;

    for (ULONG i = 0; i < pTable->NumEntries; ++i) {
        const auto& row = pTable->Table[i];
        if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (row.PhysicalAddressLength == 0) continue;

        std::wstring alias(row.Alias);
        std::wstring desc(row.Description);
        std::string aliasN = WinUtils::toNarrow(alias);
        std::string descN  = WinUtils::toNarrow(desc);
        std::string aliasLo = toLower(aliasN);
        std::string descLo  = toLower(descN);

        for (const char* vmStr : VM_ADAPTER_STRINGS) {
            if (aliasLo.find(vmStr) != std::string::npos ||
                descLo.find(vmStr)  != std::string::npos) {
                vmInterfaces++;
                if (vmInterfaces > 1) ss << ", ";
                ss << aliasN;
                break;
            }
        }
    }

    ind.rawValue = vmInterfaces;
    if (vmInterfaces > 0) {
        ind.detail     = "Virtual interface(s) identified: " + ss.str();
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
