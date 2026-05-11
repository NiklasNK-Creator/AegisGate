/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * main.cpp — Windows Agent entry point.
 *            System tray application that communicates with the hypervisor
 *            via direct VMCALL (no kernel driver needed).
 */

#define _AEGISGATE_WIN 1
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>

#include "vmcall_direct.h"

using namespace aegis;
using namespace aegis::agent;

// ============================================================================
//  Constants
// ============================================================================

static const wchar_t* APP_NAME      = L"AegisGate";
static const wchar_t* WND_CLASS     = L"AegisGateTrayWnd";
static const UINT WM_TRAYICON      = WM_USER + 1;
static const UINT IDI_TRAY         = 1;
static const UINT IDM_STATUS       = 1001;
static const UINT IDM_SETTINGS     = 1002;
static const UINT IDM_ABOUT        = 1003;
static const UINT IDM_EXIT         = 1004;
static const UINT TIMER_HEARTBEAT  = 1;

// ============================================================================
//  Global state
// ============================================================================

static HWND           g_hWnd = NULL;
static NOTIFYICONDATAW g_nid = {};
static UINT64         g_SessionToken = 0;
static bool           g_HvActive = false;
static HINSTANCE      g_hInstance = NULL;

// ============================================================================
//  System Tray Icon
// ============================================================================

static void CreateTrayIcon(HWND hWnd) {
    g_nid.cbSize = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd = hWnd;
    g_nid.uID = IDI_TRAY;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIconW(NULL, IDI_SHIELD);
    wcscpy_s(g_nid.szTip, L"AegisGate - The Gate Below");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

static void UpdateTrayTooltip(const wchar_t* text) {
    wcscpy_s(g_nid.szTip, text);
    g_nid.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// ============================================================================
//  Context Menu
// ============================================================================

static void ShowContextMenu(HWND hWnd) {
    HMENU hMenu = CreatePopupMenu();
    
    // Status line (disabled, just for display)
    if (g_HvActive) {
        AppendMenuW(hMenu, MF_STRING | MF_DISABLED, 0, L"✅ Hypervisor ACTIVE");
    } else {
        AppendMenuW(hMenu, MF_STRING | MF_DISABLED, 0, L"❌ Hypervisor INACTIVE");
    }
    
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_STATUS, L"Status...");
    AppendMenuW(hMenu, MF_STRING, IDM_ABOUT, L"About AegisGate");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"Exit");
    
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
}

// ============================================================================
//  Status Dialog
// ============================================================================

static void ShowStatusDialog() {
    wchar_t msg[512];
    
    if (g_HvActive) {
        UINT32 ver = GetHypervisorVersion();
        UINT32 major = (ver >> 16) & 0xFF;
        UINT32 minor = (ver >> 8) & 0xFF;
        UINT32 patch = ver & 0xFF;
        
        HypervisorStatus status = {};
        QueryStatus(g_SessionToken, &status);
        
        wsprintfW(msg,
            L"AegisGate Hypervisor Status\n"
            L"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            L"Status:    ACTIVE ✅\n"
            L"Version:   %d.%d.%d\n"
            L"Stealth:   %s\n"
            L"Uptime:    %llu seconds\n\n"
            L"Developer: Nik\n"
            L"\"The Gate Below\"",
            major, minor, patch,
            status.StealthEnabled ? L"Enabled" : L"Disabled",
            status.UptimeSeconds
        );
    } else {
        wcscpy_s(msg,
            L"AegisGate Hypervisor Status\n"
            L"━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            L"Status: INACTIVE ❌\n\n"
            L"The hypervisor is not running.\n"
            L"Please boot from the AegisGate USB\n"
            L"to activate protection."
        );
    }
    
    MessageBoxW(NULL, msg, L"AegisGate", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
//  Window Procedure
// ============================================================================

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_TRAYICON:
            if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU) {
                ShowContextMenu(hWnd);
            }
            else if (LOWORD(lParam) == WM_LBUTTONDBLCLK) {
                ShowStatusDialog();
            }
            return 0;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDM_STATUS:   ShowStatusDialog(); break;
                case IDM_ABOUT:
                    MessageBoxW(NULL,
                        L"AegisGate v1.0.0\n\n"
                        L"Ring -1 Hypervisor Security Gate\n"
                        L"Developer: Nik\n\n"
                        L"\"The Gate Below\"",
                        L"About AegisGate", MB_OK | MB_ICONINFORMATION);
                    break;
                case IDM_EXIT:
                    RemoveTrayIcon();
                    PostQuitMessage(0);
                    break;
            }
            return 0;
            
        case WM_TIMER:
            if (wParam == TIMER_HEARTBEAT && g_HvActive) {
                HvStatus status = SendHeartbeat(g_SessionToken);
                if (HvIsError(status)) {
                    // Lost connection to hypervisor
                    g_HvActive = false;
                    UpdateTrayTooltip(L"AegisGate - Hypervisor LOST");
                    KillTimer(hWnd, TIMER_HEARTBEAT);
                }
            }
            return 0;
            
        case WM_DESTROY:
            RemoveTrayIcon();
            PostQuitMessage(0);
            return 0;
    }
    
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
//  Entry Point
// ============================================================================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    g_hInstance = hInstance;
    
    // Prevent multiple instances
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"AegisGate_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"AegisGate is already running.", APP_NAME, MB_ICONWARNING);
        return 0;
    }
    
    // Check if hypervisor is active
    g_HvActive = IsHypervisorActive();
    
    if (g_HvActive) {
        // Perform handshake
        HvStatus hvs = PerformHandshake(&g_SessionToken);
        if (HvIsError(hvs)) {
            g_HvActive = false;
        }
    }
    
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = WND_CLASS;
    RegisterClassExW(&wc);
    
    // Create hidden message window
    g_hWnd = CreateWindowExW(0, WND_CLASS, APP_NAME, 0,
        0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
    
    // Create tray icon
    CreateTrayIcon(g_hWnd);
    
    if (g_HvActive) {
        UpdateTrayTooltip(L"AegisGate - Protection ACTIVE ✅");
        // Start heartbeat timer
        SetTimer(g_hWnd, TIMER_HEARTBEAT, 3000, NULL);  // Every 3 seconds
    } else {
        UpdateTrayTooltip(L"AegisGate - Hypervisor not detected");
    }
    
    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    
    if (hMutex) CloseHandle(hMutex);
    return 0;
}
