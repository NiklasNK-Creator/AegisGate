/**
 * AegisGate Installer — Main GUI Application
 * Developer: Nik
 *
 * One-click installer with hardware check, system configuration,
 * Secure Boot signing, and boot entry creation.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>

#include "hardware_check.h"
#include "system_config.h"
#include "secure_boot.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

using namespace aegis::installer;

// ============================================================================
//  Global State
// ============================================================================

static HWND g_hWnd        = nullptr;
static HWND g_hProgress   = nullptr;
static HWND g_hStatus     = nullptr;
static HWND g_hLogBox     = nullptr;
static HWND g_hInstallBtn = nullptr;
static HWND g_hCloseBtn   = nullptr;
static bool g_IsTester    = false;
static HardwareReport g_HwReport = {};

// IDs
#define IDC_PROGRESS   101
#define IDC_STATUS     102
#define IDC_LOG        103
#define IDC_INSTALL    104
#define IDC_CLOSE      105
#define IDC_HWINFO     106

// ============================================================================
//  Logging
// ============================================================================

static void Log(const wchar_t* msg) {
    if (!g_hLogBox) return;
    int len = GetWindowTextLengthW(g_hLogBox);
    SendMessageW(g_hLogBox, EM_SETSEL, len, len);
    SendMessageW(g_hLogBox, EM_REPLACESEL, FALSE, (LPARAM)msg);
    SendMessageW(g_hLogBox, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    SendMessageW(g_hLogBox, EM_SCROLLCARET, 0, 0);
}

static void LogFmt(const wchar_t* fmt, ...) {
    wchar_t buf[512];
    va_list args;
    va_start(args, fmt);
    vswprintf_s(buf, fmt, args);
    va_end(args);
    Log(buf);
}

static void SetStatus(const wchar_t* msg) {
    SetWindowTextW(g_hStatus, msg);
}

static void InstallerProgress(const wchar_t* message, int percent) {
    SetStatus(message);
    SendMessageW(g_hProgress, PBM_SETPOS, percent, 0);
    Log(message);
    // Process messages to keep UI responsive
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

// ============================================================================
//  Hardware Check UI
// ============================================================================

static void ShowHardwareReport() {
    CheckHardware(&g_HwReport);

    LogFmt(L"═══ Hardware Report ═══");
    LogFmt(L"CPU: %hs", g_HwReport.BrandString);
    LogFmt(L"Vendor: %hs", g_HwReport.VendorString);
    LogFmt(L"AMD SVM: %s", g_HwReport.HasSvm ? L"✓ Supported" : L"✗ Not available");
    LogFmt(L"Intel VT-x: %s", g_HwReport.HasVtx ? L"✓ Supported" : L"✗ Not available");
    LogFmt(L"AES-NI: %s", g_HwReport.HasAesNi ? L"✓ Yes" : L"✗ No (software fallback)");
    LogFmt(L"Phys Addr Bits: %u", g_HwReport.PhysAddrBits);
    LogFmt(L"Boot Mode: %s",
        g_HwReport.Boot == BootMode::UEFI ? L"✓ UEFI" : L"✗ Legacy BIOS");
    LogFmt(L"Secure Boot: %s",
        g_HwReport.SecureBootEnabled ? L"Enabled (will sign locally)" : L"Disabled");
    LogFmt(L"Hyper-V: %s",
        g_HwReport.HyperVEnabled ? L"⚠ Active (will be disabled)" : L"✓ Not active");
    LogFmt(L"VBS: %s",
        g_HwReport.VbsEnabled ? L"⚠ Enabled (will be disabled)" : L"✓ Disabled");
    LogFmt(L"Core Isolation: %s",
        g_HwReport.CoreIsolationEnabled ? L"⚠ Enabled (will be disabled)" : L"✓ Disabled");
    LogFmt(L"RAM: %llu MB", g_HwReport.TotalRamMB);
    LogFmt(L"");

    if (g_HwReport.Compatible) {
        LogFmt(L"✅ System is compatible with AegisGate!");
        SetStatus(L"Ready to install. Click 'Install' to begin.");
        EnableWindow(g_hInstallBtn, TRUE);
    } else {
        LogFmt(L"❌ System is NOT compatible:");
        Log(g_HwReport.ErrorMessage);
        SetStatus(L"System not compatible. See log for details.");
        EnableWindow(g_hInstallBtn, FALSE);
    }
}

// ============================================================================
//  Install Thread
// ============================================================================

static DWORD WINAPI InstallThread(LPVOID param) {
    (void)param;
    EnableWindow(g_hInstallBtn, FALSE);

    // Get paths relative to installer executable
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(exePath, L'\\');
    if (lastSlash) *(lastSlash + 1) = 0;

    wchar_t efiPath[MAX_PATH], agentPath[MAX_PATH];
    swprintf_s(efiPath, L"%saegisgate.efi", exePath);
    swprintf_s(agentPath, L"%sAegisGate.exe", exePath);

    // Check if EFI file exists
    if (GetFileAttributesW(efiPath) == INVALID_FILE_ATTRIBUTES) {
        Log(L"❌ aegisgate.efi not found next to installer!");
        SetStatus(L"Error: Missing aegisgate.efi");
        EnableWindow(g_hInstallBtn, TRUE);
        return 1;
    }

    // Configure install
    InstallConfig config = {};
    config.IsTester = g_IsTester;
    config.DisableHyperV = g_HwReport.HyperVEnabled;
    config.DisableVbs = g_HwReport.VbsEnabled;
    config.DisableCoreIsolation = g_HwReport.CoreIsolationEnabled;
    config.InstallAgent = !g_IsTester;
    config.AddAutostart = !g_IsTester;
    config.EfiSourcePath = efiPath;
    config.AgentSourcePath = agentPath;
    config.Progress = InstallerProgress;

    InstallResult result = {};

    Log(L"");
    LogFmt(L"═══ Starting %s Installation ═══",
        g_IsTester ? L"TEST (one-boot)" : L"FULL");

    bool ok = PerformInstall(&config, &result);

    if (!ok) {
        LogFmt(L"❌ Installation failed: %s", result.ErrorMessage);
        SetStatus(L"Installation failed!");
        EnableWindow(g_hInstallBtn, TRUE);
        return 1;
    }

    // Secure Boot signing (if Secure Boot is on)
    if (g_HwReport.SecureBootEnabled) {
        Log(L"");
        Log(L"═══ Secure Boot: Signing with local certificate ═══");

        SecureBootConfig sbConfig = {};
        wcscpy_s(sbConfig.CertSubject, L"AegisGate Local Signing Key");
        swprintf_s(sbConfig.CertStorePath, L"%saegisgate_key.pfx", exePath);
        swprintf_s(sbConfig.CerExportPath, L"%saegisgate_key.cer", exePath);
        wcscpy_s(sbConfig.EfiPath, efiPath);

        SecureBootResult sbResult = {};

        // Re-mount ESP for cert export
        wchar_t espDrive = 0;
        MountEsp(&espDrive);
        SetupSecureBoot(&sbConfig, espDrive, &sbResult);

        if (sbResult.CertGenerated) Log(L"  ✓ Certificate generated");
        else Log(L"  ✗ Certificate generation failed");

        if (sbResult.EfiSigned) Log(L"  ✓ EFI binary signed");
        else Log(L"  ✗ EFI signing failed (signtool/SDK may be needed)");

        if (sbResult.CerExportedToEsp) Log(L"  ✓ Public key exported to ESP");

        if (sbResult.NeedsManualEnrollment) {
            Log(L"");
            Log(L"  ⚠ To complete Secure Boot setup:");
            Log(L"    1. Restart → Enter BIOS (DEL/F2)");
            Log(L"    2. Security → Secure Boot → Key Management");
            Log(L"    3. 'Append DB' or 'Enroll Signature'");
            Log(L"    4. Select: EFI\\AegisGate\\keys\\aegisgate.cer");
            Log(L"    5. Save & Exit");
        }

        if (espDrive) UnmountEsp(espDrive);
    }

    Log(L"");
    if (g_IsTester) {
        Log(L"✅ Test installation complete!");
        Log(L"   AegisGate will boot ONCE on next restart.");
        Log(L"   After the test, it will auto-remove itself.");
    } else {
        Log(L"✅ Full installation complete!");
        Log(L"   AegisGate will boot before Windows on every start.");
        LogFmt(L"   Boot entry GUID: %s", result.BootEntryGuid);
    }

    SetStatus(L"Installation complete! Restart to activate AegisGate.");

    // Ask for reboot
    int answer = MessageBoxW(g_hWnd,
        L"AegisGate has been installed successfully!\n\n"
        L"A restart is required to activate protection.\n\n"
        L"Restart now?",
        L"AegisGate — Installation Complete",
        MB_YESNO | MB_ICONQUESTION);

    if (answer == IDYES) {
        // Initiate system restart
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
        ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_SOFTWARE);
    }

    EnableWindow(g_hCloseBtn, TRUE);
    return 0;
}

// ============================================================================
//  Window Procedure
// ============================================================================

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Title label
        HWND hTitle = CreateWindowW(L"STATIC",
            g_IsTester ? L"🛡️ AegisGate — Test Installer" : L"🛡️ AegisGate — Installer",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 10, 540, 30, hWnd, nullptr, nullptr, nullptr);
        SendMessageW(hTitle, WM_SETFONT,
            (WPARAM)CreateFontW(22, 0, 0, 0, FW_BOLD, 0, 0, 0,
                DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI"), TRUE);

        // Subtitle
        CreateWindowW(L"STATIC",
            g_IsTester
                ? L"Temporary installation — boots AegisGate once for testing"
                : L"Full installation — permanent Ring -1 protection",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 40, 540, 20, hWnd, nullptr, nullptr, nullptr);

        // Log box
        g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            20, 70, 540, 280, hWnd, (HMENU)IDC_LOG, nullptr, nullptr);
        SendMessageW(g_hLogBox, WM_SETFONT,
            (WPARAM)CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Consolas"), TRUE);

        // Progress bar
        g_hProgress = CreateWindowW(PROGRESS_CLASSW, L"",
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
            20, 360, 540, 22, hWnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
        SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

        // Status label
        g_hStatus = CreateWindowW(L"STATIC", L"Checking hardware...",
            WS_CHILD | WS_VISIBLE,
            20, 390, 540, 20, hWnd, (HMENU)IDC_STATUS, nullptr, nullptr);

        // Buttons
        g_hInstallBtn = CreateWindowW(L"BUTTON", L"Install",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_DISABLED,
            310, 420, 120, 35, hWnd, (HMENU)IDC_INSTALL, nullptr, nullptr);

        g_hCloseBtn = CreateWindowW(L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE,
            440, 420, 120, 35, hWnd, (HMENU)IDC_CLOSE, nullptr, nullptr);

        // Run hardware check after window is created
        PostMessageW(hWnd, WM_USER + 1, 0, 0);
        return 0;
    }

    case WM_USER + 1:
        ShowHardwareReport();
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_INSTALL:
            CreateThread(nullptr, 0, InstallThread, nullptr, 0, nullptr);
            break;
        case IDC_CLOSE:
            DestroyWindow(hWnd);
            break;
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
//  WinMain
// ============================================================================

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR cmdLine, int) {
    // Check for admin
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup);
    CheckTokenMembership(nullptr, adminGroup, &isAdmin);
    FreeSid(adminGroup);

    if (!isAdmin) {
        // Re-launch as admin
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        ShellExecuteW(nullptr, L"runas", exePath, cmdLine, nullptr, SW_SHOWNORMAL);
        return 0;
    }

    // Check if this is the tester version
    g_IsTester = (wcsstr(cmdLine, L"--test") != nullptr);

    // Init common controls
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    // Register window class
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AegisGateInstaller";
    RegisterClassExW(&wc);

    // Create window
    g_hWnd = CreateWindowExW(0, L"AegisGateInstaller",
        g_IsTester ? L"AegisGate Test Installer" : L"AegisGate Installer",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 500,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
