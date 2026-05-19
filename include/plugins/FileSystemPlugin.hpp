#pragma once

#ifndef SANDBOX_DETECTOR_FILESYSTEM_PLUGIN_HPP
#define SANDBOX_DETECTOR_FILESYSTEM_PLUGIN_HPP

#include "core/IPlugin.hpp"
#include <vector>
#include <string>

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  FileSystemPlugin
//
//  Detects sandbox/VM via file system artifacts and anomalies:
//    1.  VM guest addition directories (C:\Program Files\Oracle\VirtualBox Guest Additions)
//    2.  VMware tools installation paths
//    3.  Sandbox agent files (agent.exe, cuckoo_agent.py, etc.)
//    4.  Analysis tool artifacts (.pcap files, sandbox logs)
//    5.  Suspicious %TEMP% content (malware sample drops)
//    6.  Recent file count anomaly (new install = <100 files in C:\Users)
//    7.  Drive count anomaly (only C: = suspicious)
//    8.  System32 driver files for VM drivers
//    9.  C:\ root directory file count (<15 = minimal install)
//   10.  Wine filesystem artifacts (Z:\ → Unix paths)
//   11.  Sandbox-specific DLLs loaded in system32
//   12.  Alternate data streams anomaly (sandboxes often strip them)
//   13.  Prefetch directory absence/minimal content
//   14.  Pagefile.sys size (VMs often set very small or zero paging)
//   15.  NTFS journal presence and size
// ============================================================

class FileSystemPlugin final : public IPlugin {
public:
    FileSystemPlugin();
    ~FileSystemPlugin() override;

    const PluginMetadata&   getMetadata()           const noexcept override;
    bool                    initialize(const PluginConfig& config) override;
    void                    shutdown()              noexcept override;
    PluginResult            run()                   override;
    bool                    isSupported()           const noexcept override;
    uint32_t                estimatedRunTimeMs()    const noexcept override { return 500; }

private:
    PluginMetadata  m_meta;
    PluginConfig    m_config;

    DetectionIndicator checkVmGuestAdditionPaths();
    DetectionIndicator checkSandboxAgentFiles();
    DetectionIndicator checkAnalysisToolArtifacts();
    DetectionIndicator checkDriveCount();
    DetectionIndicator checkVmDriverFiles();
    DetectionIndicator checkRootDirectoryFileCount();
    DetectionIndicator checkWineArtifacts();
    DetectionIndicator checkSandboxDlls();
    DetectionIndicator checkPrefetchDirectory();
    DetectionIndicator checkPagefileSizeRegistry();
    DetectionIndicator checkUserDirectoryDepth();
    DetectionIndicator checkRecentDocumentsCount();
};

} // namespace Plugins
} // namespace SandboxDetector

#endif // SANDBOX_DETECTOR_FILESYSTEM_PLUGIN_HPP
