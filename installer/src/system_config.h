/**
 * AegisGate Installer — System Configuration
 * Developer: Nik
 *
 * Handles all system-level changes:
 *   - Disable Hyper-V, VBS, Core Isolation, Device Guard
 *   - Mount/unmount EFI System Partition
 *   - Create/remove BCD boot entry
 *   - Copy EFI binary to ESP
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>

namespace aegis::installer {

// Status callback for progress UI
using ProgressCallback = void(*)(const wchar_t* message, int percent);

struct InstallConfig {
    bool        IsTester;          // Temporary (1-boot) install
    bool        DisableHyperV;
    bool        DisableVbs;
    bool        DisableCoreIsolation;
    bool        InstallAgent;
    bool        AddAutostart;
    const wchar_t* EfiSourcePath;  // Path to aegisgate.efi
    const wchar_t* AgentSourcePath;// Path to AegisGate.exe
    ProgressCallback Progress;
};

struct InstallResult {
    bool    Success;
    wchar_t BootEntryGuid[64];     // BCD GUID of created entry
    wchar_t EspDriveLetter;        // Assigned drive letter (e.g., 'S')
    wchar_t ErrorMessage[512];
};

// ── Main Install/Uninstall ─────────────────────────────────────────────
bool PerformInstall(const InstallConfig* config, InstallResult* result);
bool PerformUninstall(const wchar_t* bootEntryGuid);

// ── Individual Operations ──────────────────────────────────────────────
bool DisableHyperV();
bool DisableVirtualizationBasedSecurity();
bool DisableCoreIsolation();
bool MountEsp(wchar_t* outDriveLetter);
bool UnmountEsp(wchar_t driveLetter);
bool CopyEfiToEsp(wchar_t espDrive, const wchar_t* efiSourcePath);
bool CreateBootEntry(wchar_t espDrive, wchar_t* outGuid, size_t guidLen, bool firstBoot);
bool RemoveBootEntry(const wchar_t* guid);
bool InstallTrayAgent(const wchar_t* agentPath);
bool AddToAutostart();
bool RegisterCleanupTask(const wchar_t* bootEntryGuid);

} // namespace aegis::installer
