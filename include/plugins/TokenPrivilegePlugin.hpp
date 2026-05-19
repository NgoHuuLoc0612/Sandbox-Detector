#pragma once

#ifndef SANDBOX_DETECTOR_TOKEN_PLUGIN_HPP
#define SANDBOX_DETECTOR_TOKEN_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  TokenPrivilegePlugin
//
//  Detects sandbox/VM via access token & privilege anomalies:
//    1.  Token integrity level < Medium (sandbox downgrade)
//    2.  Token is AppContainer (sandboxed UWP/Win32 app)
//    3.  Token has SeDebugPrivilege already enabled (AV/EDR hook)
//    4.  Token privilege count anomaly (<5 or >30)
//    5.  Missing SeShutdownPrivilege (restricted sandbox token)
//    6.  Mandatory label: Low integrity = highly sandboxed
//    7.  Token restricted SIDs present (CreateRestrictedToken)
//    8.  Token session ID = 0 (running in Session 0 = service context)
//    9.  NtQueryInformationToken(TokenVirtualizationEnabled) = true
//   10.  Impersonation token on primary thread (credential sandbox)
//   11.  LogonSID check: sandboxes often use same logon for all processes
//   12.  Token source: unusual logon type (Network = automated sandbox)
// ============================================================

class TokenPrivilegePlugin final : public IPlugin {
public:
    TokenPrivilegePlugin();
    ~TokenPrivilegePlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 100; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkIntegrityLevel();
    DetectionIndicator checkAppContainerToken();
    DetectionIndicator checkPrivilegeCount();
    DetectionIndicator checkSeDebugEnabled();
    DetectionIndicator checkMandatoryLabel();
    DetectionIndicator checkRestrictedSids();
    DetectionIndicator checkSessionId();
    DetectionIndicator checkVirtualizationEnabled();
    DetectionIndicator checkTokenSource();
    DetectionIndicator checkLogonType();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_TOKEN_PLUGIN_HPP
