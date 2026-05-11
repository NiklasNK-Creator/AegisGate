/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * settings.h — UEFI NVRAM settings persistence structures.
 */

#pragma once

#include <Uefi.h>
#include "../../common/include/types.h"

// ============================================================================
//  NVRAM Variable GUID for AegisGate Settings
//  {A3E1B2C4-D5F6-7890-ABCD-EF1234567890}
// ============================================================================

#define AEGISGATE_SETTINGS_GUID \
    { 0xA3E1B2C4, 0xD5F6, 0x7890, \
      { 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90 } }

// ============================================================================
//  Settings Structure (stored in UEFI NVRAM)
// ============================================================================

#pragma pack(push, 1)
struct AegisSettings {
    UINT32  Magic;          // Must be SETTINGS_MAGIC (0x54534741 = 'AGST')
    UINT8   Version;        // Settings format version (for future migration)
    BOOLEAN Enabled;        // Protection ON / OFF
    BOOLEAN AutoStart;      // AUTO start on boot / MANUAL (ask each time)
    UINT8   Reserved[25];   // Reserved for future settings, padded to 32 bytes
};
#pragma pack(pop)

static_assert(sizeof(AegisSettings) == 32, "AegisSettings must be exactly 32 bytes");

// ============================================================================
//  Settings API
// ============================================================================

/**
 * Load settings from UEFI NVRAM. If not found or corrupt, creates defaults.
 */
EFI_STATUS LoadSettings(EFI_SYSTEM_TABLE* ST, AegisSettings* settings);

/**
 * Save settings to UEFI NVRAM (non-volatile, persists across reboots).
 */
EFI_STATUS SaveSettings(EFI_SYSTEM_TABLE* ST, const AegisSettings* settings);

/**
 * Display interactive settings menu (text-mode UI).
 * User navigates with arrow keys, toggles with Enter/Space, confirms with OK.
 */
void ShowSettingsMenu(EFI_SYSTEM_TABLE* ST, AegisSettings* settings);
