#pragma once

#ifndef SANDBOX_DETECTOR_NETWORK_PLUGIN_HPP
#define SANDBOX_DETECTOR_NETWORK_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  NetworkPlugin
//
//  Detects sandbox/VM via network stack fingerprinting:
//    1.  MAC address OUI matching known VM vendors
//    2.  Total adapter count anomalies (0 or >8 adapters)
//    3.  Loopback-only connectivity (no real adapter)
//    4.  IP address in well-known VM NAT ranges (192.168.56.x, 10.0.2.x)
//    5.  Hostname patterns (DESKTOP-XXXXXXX length, or sandbox/malware/cuckoo)
//    6.  DNS suffix anomalies (localdomain, .sandbox, no suffix)
//    7.  ARP table size (sandboxes often have 0 entries)
//    8.  Active TCP/UDP connection count (<3 = isolated sandbox)
//    9.  Adapter description strings matching VM vendors
//   10.  NetBIOS name resolution anomalies
//   11.  WINS server presence check
//   12.  Adapter type: IFT_OTHER / software loopback only
//   13.  IPv6 link-local address presence (VMs often lack)
//   14.  Routing table: default gateway presence
// ============================================================

class NetworkPlugin final : public IPlugin {
public:
    NetworkPlugin();
    ~NetworkPlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 400; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkMacAddressOui();
    DetectionIndicator checkAdapterCount();
    DetectionIndicator checkAdapterDescriptions();
    DetectionIndicator checkVmNatIpRanges();
    DetectionIndicator checkHostname();
    DetectionIndicator checkDnsSuffix();
    DetectionIndicator checkArpTableSize();
    DetectionIndicator checkActiveTcpConnections();
    DetectionIndicator checkDefaultGateway();
    DetectionIndicator checkIpv6Presence();
    DetectionIndicator checkLoopbackOnly();
    DetectionIndicator checkNetworkInterfaces();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_NETWORK_PLUGIN_HPP
