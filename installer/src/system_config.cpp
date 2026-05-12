/**
 * AegisGate Installer — System Configuration Implementation
 * Developer: Nik
 */

#include "system_config.h"
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

namespace aegis::installer {

// Helper: Run a command and return exit code
static int RunCmd(const wchar_t* cmd) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    wchar_t cmdBuf[1024];
    wcscpy_s(cmdBuf, cmd);

    if (!CreateProcessW(nullptr, cmdBuf, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)exitCode;
}

// Helper: Run command and capture stdout
static bool RunCmdCapture(const wchar_t* cmd, wchar_t* output, size_t outLen) {
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE hRead, hWrite;
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};

    wchar_t cmdBuf[1024];
    wcscpy_s(cmdBuf, cmd);

    bool ok = CreateProcessW(nullptr, cmdBuf, nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);

    if (ok) {
        char buf[2048] = {};
        DWORD read = 0;
        ReadFile(hRead, buf, sizeof(buf) - 1, &read, nullptr);
        WaitForSingleObject(pi.hProcess, 10000);
        // Convert to wchar
        MultiByteToWideChar(CP_UTF8, 0, buf, -1, output, (int)outLen);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hRead);
    return ok;
}

// ============================================================================
//  Hyper-V / VBS / Core Isolation
// ============================================================================

bool DisableHyperV() {
    return RunCmd(L"bcdedit /set hypervisorlaunchtype off") == 0;
}

bool DisableVirtualizationBasedSecurity() {
    HKEY key;
    DWORD val = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_WRITE, &key) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"EnableVirtualizationBasedSecurity",
            0, REG_DWORD, (LPBYTE)&val, sizeof(val));
        RegCloseKey(key);
        return true;
    }
    return false;
}

bool DisableCoreIsolation() {
    HKEY key;
    DWORD val = 0;
    DWORD disp;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, nullptr, 0, KEY_WRITE, nullptr, &key, &disp) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"Enabled", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
        RegCloseKey(key);
        return true;
    }
    return false;
}

// ============================================================================
//  EFI System Partition
// ============================================================================

bool MountEsp(wchar_t* outDriveLetter) {
    // Try S: first, then T:, U:, etc.
    const wchar_t candidates[] = L"STUVWXYZ";
    for (int i = 0; candidates[i]; i++) {
        wchar_t drive[4] = { candidates[i], L':', L'\\', 0 };
        if (GetDriveTypeW(drive) == DRIVE_NO_ROOT_DIR) {
            // This drive letter is free
            wchar_t cmd[64];
            swprintf_s(cmd, L"mountvol %c: /S", candidates[i]);
            if (RunCmd(cmd) == 0) {
                *outDriveLetter = candidates[i];
                return true;
            }
        }
    }
    return false;
}

bool UnmountEsp(wchar_t driveLetter) {
    wchar_t cmd[64];
    swprintf_s(cmd, L"mountvol %c: /D", driveLetter);
    return RunCmd(cmd) == 0;
}

bool CopyEfiToEsp(wchar_t espDrive, const wchar_t* efiSourcePath) {
    // Create directory: X:\EFI\AegisGate\ 
    wchar_t dir[MAX_PATH];
    swprintf_s(dir, L"%c:\\EFI\\AegisGate", espDrive);
    SHCreateDirectoryExW(nullptr, dir, nullptr);

    // Copy the .efi file
    wchar_t dest[MAX_PATH];
    swprintf_s(dest, L"%c:\\EFI\\AegisGate\\aegisgate.efi", espDrive);
    return CopyFileW(efiSourcePath, dest, FALSE) != 0;
}

// ============================================================================
//  BCD Boot Entry
// ============================================================================

bool CreateBootEntry(wchar_t espDrive, wchar_t* outGuid, size_t guidLen, bool firstBoot) {
    // Step 1: Copy {bootmgr} to create a new entry
    wchar_t output[2048] = {};
    RunCmdCapture(L"bcdedit /copy \"{bootmgr}\" /d \"AegisGate Security Gate\"", output, 2048);

    // Parse GUID from output: "...{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}..."
    wchar_t* start = wcschr(output, L'{');
    wchar_t* end = wcschr(output, L'}');
    if (!start || !end || end <= start) return false;

    size_t len = (size_t)(end - start + 1);
    if (len >= guidLen) return false;
    wcsncpy_s(outGuid, guidLen, start, len);

    // Step 2: Set device to ESP
    wchar_t cmd[512];
    swprintf_s(cmd, L"bcdedit /set \"%s\" device partition=%c:", outGuid, espDrive);
    RunCmd(cmd);

    // Step 3: Set path to our EFI
    swprintf_s(cmd, L"bcdedit /set \"%s\" path \\EFI\\AegisGate\\aegisgate.efi", outGuid);
    RunCmd(cmd);

    // Step 4: Add to boot order (FIRST = boots before Windows)
    swprintf_s(cmd, L"bcdedit /displayorder \"%s\" /addfirst", outGuid);
    RunCmd(cmd);

    // For tester: set to boot only once using bcdedit /bootsequence
    if (firstBoot) {
        swprintf_s(cmd, L"bcdedit /bootsequence \"%s\"", outGuid);
        RunCmd(cmd);
    }

    return true;
}

bool RemoveBootEntry(const wchar_t* guid) {
    wchar_t cmd[256];
    swprintf_s(cmd, L"bcdedit /delete \"%s\"", guid);
    return RunCmd(cmd) == 0;
}

// ============================================================================
//  Tray Agent
// ============================================================================

bool InstallTrayAgent(const wchar_t* agentPath) {
    wchar_t destDir[MAX_PATH];
    swprintf_s(destDir, L"%s\\AegisGate", _wgetenv(L"ProgramFiles"));
    SHCreateDirectoryExW(nullptr, destDir, nullptr);

    wchar_t dest[MAX_PATH];
    swprintf_s(dest, L"%s\\AegisGate.exe", destDir);
    return CopyFileW(agentPath, dest, FALSE) != 0;
}

bool AddToAutostart() {
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &key) == ERROR_SUCCESS) {
        wchar_t path[MAX_PATH];
        swprintf_s(path, L"\"%s\\AegisGate\\AegisGate.exe\"", _wgetenv(L"ProgramFiles"));
        RegSetValueExW(key, L"AegisGate", 0, REG_SZ,
            (LPBYTE)path, (DWORD)(wcslen(path) + 1) * sizeof(wchar_t));
        RegCloseKey(key);
        return true;
    }
    return false;
}

// ============================================================================
//  Tester Cleanup Task
// ============================================================================

bool RegisterCleanupTask(const wchar_t* bootEntryGuid) {
    // Create a scheduled task that runs at next logon to clean up
    wchar_t cmd[1024];
    swprintf_s(cmd,
        L"schtasks /create /tn \"AegisGateCleanup\" /tr "
        L"\"bcdedit /delete \\\"%s\\\"\" "
        L"/sc ONLOGON /rl HIGHEST /f",
        bootEntryGuid);
    RunCmd(cmd);

    // Also schedule removal of the cleanup task itself
    wchar_t cmd2[256];
    swprintf_s(cmd2, L"schtasks /create /tn \"AegisGateCleanup2\" /tr "
        L"\"schtasks /delete /tn AegisGateCleanup /f\" "
        L"/sc ONLOGON /delay 0001:00 /rl HIGHEST /f");
    RunCmd(cmd2);

    return true;
}

// ============================================================================
//  Full Install Orchestration
// ============================================================================

bool PerformInstall(const InstallConfig* config, InstallResult* result) {
    memset(result, 0, sizeof(*result));

    auto progress = [&](const wchar_t* msg, int pct) {
        if (config->Progress) config->Progress(msg, pct);
    };

    // Step 1: Disable conflicting features
    progress(L"Disabling Hyper-V...", 10);
    if (config->DisableHyperV) DisableHyperV();

    progress(L"Disabling VBS...", 20);
    if (config->DisableVbs) DisableVirtualizationBasedSecurity();

    progress(L"Disabling Core Isolation...", 25);
    if (config->DisableCoreIsolation) DisableCoreIsolation();

    // Step 2: Mount ESP
    progress(L"Mounting EFI System Partition...", 30);
    wchar_t espDrive = 0;
    if (!MountEsp(&espDrive)) {
        wcscpy_s(result->ErrorMessage, L"Failed to mount EFI System Partition.");
        return false;
    }
    result->EspDriveLetter = espDrive;

    // Step 3: Copy EFI
    progress(L"Copying AegisGate bootloader...", 50);
    if (!CopyEfiToEsp(espDrive, config->EfiSourcePath)) {
        UnmountEsp(espDrive);
        wcscpy_s(result->ErrorMessage, L"Failed to copy EFI binary to ESP.");
        return false;
    }

    // Step 4: Create boot entry
    progress(L"Creating boot entry...", 65);
    if (!CreateBootEntry(espDrive, result->BootEntryGuid, 64, config->IsTester)) {
        UnmountEsp(espDrive);
        wcscpy_s(result->ErrorMessage, L"Failed to create BCD boot entry.");
        return false;
    }

    // Step 5: Install agent (full install only)
    if (config->InstallAgent && config->AgentSourcePath) {
        progress(L"Installing AegisGate Agent...", 80);
        InstallTrayAgent(config->AgentSourcePath);
        if (config->AddAutostart) AddToAutostart();
    }

    // Step 6: Tester cleanup
    if (config->IsTester) {
        progress(L"Registering cleanup task...", 90);
        RegisterCleanupTask(result->BootEntryGuid);
    }

    // Step 7: Unmount ESP
    progress(L"Finishing up...", 95);
    UnmountEsp(espDrive);

    progress(L"Installation complete!", 100);
    result->Success = true;
    return true;
}

bool PerformUninstall(const wchar_t* bootEntryGuid) {
    // Remove boot entry
    if (bootEntryGuid && bootEntryGuid[0]) {
        RemoveBootEntry(bootEntryGuid);
    }

    // Remove EFI from ESP
    wchar_t espDrive = 0;
    if (MountEsp(&espDrive)) {
        wchar_t path[MAX_PATH];
        swprintf_s(path, L"%c:\\EFI\\AegisGate\\aegisgate.efi", espDrive);
        DeleteFileW(path);
        swprintf_s(path, L"%c:\\EFI\\AegisGate", espDrive);
        RemoveDirectoryW(path);
        UnmountEsp(espDrive);
    }

    // Remove autostart
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &key) == ERROR_SUCCESS) {
        RegDeleteValueW(key, L"AegisGate");
        RegCloseKey(key);
    }

    // Remove program files
    wchar_t dir[MAX_PATH];
    swprintf_s(dir, L"%s\\AegisGate\\AegisGate.exe", _wgetenv(L"ProgramFiles"));
    DeleteFileW(dir);
    swprintf_s(dir, L"%s\\AegisGate", _wgetenv(L"ProgramFiles"));
    RemoveDirectoryW(dir);

    // Remove registry
    RegDeleteKeyW(HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisGate");
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"Software\\AegisGate");

    return true;
}

} // namespace aegis::installer
