/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * main.cpp — UEFI Application entry point.
 *            Orchestrates: Hardware Probe → Logo → Settings → Hypervisor Init → Chain Boot
 */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>

#include "../include/efi_cpp_runtime.h"
#include "../../common/include/types.h"
#include "../../common/include/aegis_config.h"
#include "../../common/include/aegis_status.h"
#include "hardware_probe.h"
#include "settings.h"

using namespace aegis;

// ============================================================================
//  External declarations
// ============================================================================

// Logo & UI (logo.cpp)
extern EFI_STATUS DisplayLogo(EFI_SYSTEM_TABLE* ST);
extern void DisplayError(EFI_SYSTEM_TABLE* ST, const CHAR16* message);

// Hotkey detection (hotkey.cpp)
extern BOOLEAN WaitForHotkey(EFI_SYSTEM_TABLE* ST, UINT32 timeoutMs);
extern void StallSeconds(EFI_SYSTEM_TABLE* ST, UINT32 seconds);

// Chain boot (chain_boot.cpp)
extern EFI_STATUS ChainBootToWindows(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable);

// Hypervisor initialization (from hypervisor/core — linked at build time)
// This will be the entry point into the hypervisor core module
extern "C" HvStatus AegisHypervisorInit(
    EFI_HANDLE        ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable,
    const HardwareCapabilities* hwCaps
);

// ============================================================================
//  UEFI Application Entry Point
// ============================================================================

extern "C" EFI_STATUS EFIAPI AegisGateMain(
    EFI_HANDLE        ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable
) {
    // ════════════════════════════════════════════════════════════════════════
    //  Phase 1: Hardware Compatibility Check
    // ════════════════════════════════════════════════════════════════════════

    HardwareCapabilities hwCaps{};
    HvStatus hvStatus = ProbeHardware(&hwCaps);

    if (HvIsError(hvStatus)) {
        // Hardware not compatible — show error and boot Windows anyway
        DisplayError(SystemTable, 
            (hvStatus == HV_BOOT_VIRT_DISABLED) 
                ? L"AMD-V/VT-x is DISABLED in BIOS. Please enable SVM/VT-x in BIOS settings."
                : L"CPU does not support hardware virtualization (AMD-V/VT-x)."
        );
        PrintHardwareInfo(SystemTable, &hwCaps);
        StallSeconds(SystemTable, 5);
        return ChainBootToWindows(ImageHandle, SystemTable);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 2: Load Settings from UEFI NVRAM
    // ════════════════════════════════════════════════════════════════════════

    AegisSettings settings{};
    LoadSettings(SystemTable, &settings);

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 3: Display Logo + Hotkey Detection (2 seconds)
    // ════════════════════════════════════════════════════════════════════════

    DisplayLogo(SystemTable);
    BOOLEAN hotkeyPressed = WaitForHotkey(SystemTable, config::BOOT_LOGO_TIMEOUT_MS);

    if (hotkeyPressed) {
        // User pressed a key → show settings menu
        ShowSettingsMenu(SystemTable, &settings);
        SaveSettings(SystemTable, &settings);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 4: Conditional Hypervisor Initialization
    // ════════════════════════════════════════════════════════════════════════

    if (settings.Enabled) {
        // Show brief initialization message
        SystemTable->ConOut->SetAttribute(SystemTable->ConOut, EFI_LIGHTGREEN | EFI_BACKGROUND_BLACK);
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        SystemTable->ConOut->OutputString(SystemTable->ConOut, 
            (CHAR16*)L"\r\n  AegisGate: Initializing hypervisor...\r\n");
        
        // Print hardware info
        PrintHardwareInfo(SystemTable, &hwCaps);

        // Initialize the hypervisor core
        hvStatus = AegisHypervisorInit(ImageHandle, SystemTable, &hwCaps);

        if (HvIsError(hvStatus)) {
            // Hypervisor failed to initialize — warn but still boot Windows
            DisplayError(SystemTable, L"Hypervisor initialization failed! Booting without protection.");

            // Show error code for debugging
            SystemTable->ConOut->SetAttribute(SystemTable->ConOut, EFI_YELLOW | EFI_BACKGROUND_BLACK);
            // Manual hex print since we don't have PrintLib format easily
            SystemTable->ConOut->OutputString(SystemTable->ConOut, 
                (CHAR16*)L"  Error module: ");
            // Simple numeric display
            CHAR16 numBuf[20];
            UINT32 module = HvGetModule(hvStatus);
            UINT32 code = HvGetCode(hvStatus);
            // We'd need a proper IntToStr here — simplified for now
            numBuf[0] = L'0' + (CHAR16)(module / 10);
            numBuf[1] = L'0' + (CHAR16)(module % 10);
            numBuf[2] = L':';
            numBuf[3] = L'0' + (CHAR16)(code / 10);
            numBuf[4] = L'0' + (CHAR16)(code % 10);
            numBuf[5] = L'\0';
            SystemTable->ConOut->OutputString(SystemTable->ConOut, numBuf);
            SystemTable->ConOut->OutputString(SystemTable->ConOut, (CHAR16*)L"\r\n");

            StallSeconds(SystemTable, 3);
        } else {
            // Success!
            SystemTable->ConOut->SetAttribute(SystemTable->ConOut, EFI_LIGHTGREEN | EFI_BACKGROUND_BLACK);
            SystemTable->ConOut->OutputString(SystemTable->ConOut, 
                (CHAR16*)L"\r\n  AegisGate: Hypervisor ACTIVE. Booting Windows as guest...\r\n");
            StallSeconds(SystemTable, 1);
        }
    } else {
        // Protection disabled — just boot Windows normally
        SystemTable->ConOut->SetAttribute(SystemTable->ConOut, EFI_YELLOW | EFI_BACKGROUND_BLACK);
        SystemTable->ConOut->ClearScreen(SystemTable->ConOut);
        SystemTable->ConOut->OutputString(SystemTable->ConOut, 
            (CHAR16*)L"\r\n  AegisGate: Protection DISABLED. Booting Windows normally...\r\n");
        StallSeconds(SystemTable, 1);
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Phase 5: Chain-Boot to Windows
    // ════════════════════════════════════════════════════════════════════════

    SystemTable->ConOut->SetAttribute(SystemTable->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
    return ChainBootToWindows(ImageHandle, SystemTable);
}
