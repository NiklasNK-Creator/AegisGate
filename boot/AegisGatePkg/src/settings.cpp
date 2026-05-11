/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * settings.cpp — UEFI NVRAM settings persistence and interactive settings menu.
 */

#include "settings.h"
#include "../include/efi_cpp_runtime.h"
#include "../../common/include/aegis_config.h"
#include <Library/UefiRuntimeServicesTableLib.h>

using namespace aegis;

// ============================================================================
//  Static data
// ============================================================================

static EFI_GUID gAegisSettingsGuid = AEGISGATE_SETTINGS_GUID;
static CHAR16*  gSettingsVarName   = (CHAR16*)L"AegisGateSettings";

// ============================================================================
//  LoadSettings — Read from UEFI NVRAM or create defaults
// ============================================================================

EFI_STATUS LoadSettings(EFI_SYSTEM_TABLE* ST, AegisSettings* settings) {
    if (!settings) return EFI_INVALID_PARAMETER;

    UINTN dataSize = sizeof(AegisSettings);
    EFI_STATUS status = ST->RuntimeServices->GetVariable(
        gSettingsVarName,
        &gAegisSettingsGuid,
        NULL,       // Attributes (don't care when reading)
        &dataSize,
        settings
    );

    // If variable doesn't exist or is corrupt, use defaults
    if (EFI_ERROR(status) || settings->Magic != config::SETTINGS_MAGIC || dataSize != sizeof(AegisSettings)) {
        settings->Magic     = config::SETTINGS_MAGIC;
        settings->Version   = 1;
        settings->Enabled   = TRUE;
        settings->AutoStart = TRUE;
        MemZero(settings->Reserved, sizeof(settings->Reserved));

        // Persist defaults immediately
        SaveSettings(ST, settings);
    }

    return EFI_SUCCESS;
}

// ============================================================================
//  SaveSettings — Write to UEFI NVRAM (non-volatile)
// ============================================================================

EFI_STATUS SaveSettings(EFI_SYSTEM_TABLE* ST, const AegisSettings* settings) {
    if (!settings) return EFI_INVALID_PARAMETER;

    return ST->RuntimeServices->SetVariable(
        gSettingsVarName,
        &gAegisSettingsGuid,
        EFI_VARIABLE_NON_VOLATILE |
        EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS,
        sizeof(AegisSettings),
        (VOID*)settings
    );
}

// ============================================================================
//  ShowSettingsMenu — Interactive text-mode settings UI
// ============================================================================

// Helper: Print a menu line with optional highlight
static void PrintMenuLine(
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* con,
    const CHAR16* label,
    const CHAR16* value,
    BOOLEAN isSelected,
    BOOLEAN isEnabled
) {
    // Highlight selected row
    if (isSelected) {
        con->SetAttribute(con, EFI_BLACK | EFI_BACKGROUND_LIGHTGRAY);
    } else {
        con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);
    }

    con->OutputString(con, (CHAR16*)L"    ");
    con->OutputString(con, (CHAR16*)label);
    con->OutputString(con, (CHAR16*)L"  ");

    // Value with color coding
    if (!isSelected) {
        if (isEnabled) {
            con->SetAttribute(con, EFI_LIGHTGREEN | EFI_BACKGROUND_BLACK);
        } else {
            con->SetAttribute(con, EFI_LIGHTRED | EFI_BACKGROUND_BLACK);
        }
    }

    con->OutputString(con, (CHAR16*)value);

    // Clear rest of line
    con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);
    con->OutputString(con, (CHAR16*)L"          \r\n");
}

void ShowSettingsMenu(EFI_SYSTEM_TABLE* ST, AegisSettings* settings) {
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* con = ST->ConOut;
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL*  input = ST->ConIn;

    con->ClearScreen(con);

    UINT8 selection = 0;  // 0 = Protection, 1 = AutoStart, 2 = OK button
    BOOLEAN running = TRUE;

    while (running) {
        // Reset cursor to menu start
        con->SetCursorPosition(con, 0, 2);

        // ── Header ─────────────────────────────────────────────────────────
        con->SetAttribute(con, EFI_LIGHTCYAN | EFI_BACKGROUND_BLACK);
        con->OutputString(con, (CHAR16*)L"    +----------------------------------+\r\n");
        con->OutputString(con, (CHAR16*)L"    |     AegisGate Settings v1.0      |\r\n");
        con->OutputString(con, (CHAR16*)L"    +----------------------------------+\r\n\r\n");

        // ── Protection toggle ──────────────────────────────────────────────
        PrintMenuLine(con,
            L"Protection: ",
            settings->Enabled ? L"[  AN  ]" : L"[ AUS  ]",
            (selection == 0),
            settings->Enabled
        );
        con->OutputString(con, (CHAR16*)L"\r\n");

        // ── AutoStart toggle ───────────────────────────────────────────────
        PrintMenuLine(con,
            L"Auto-Start: ",
            settings->AutoStart ? L"[ AUTO ]" : L"[MANUAL]",
            (selection == 1),
            settings->AutoStart
        );
        con->OutputString(con, (CHAR16*)L"\r\n");

        // ── OK Button ──────────────────────────────────────────────────────
        if (selection == 2) {
            con->SetAttribute(con, EFI_BLACK | EFI_BACKGROUND_LIGHTGREEN);
        } else {
            con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);
        }
        con->OutputString(con, (CHAR16*)L"              [  OK  ]             \r\n");
        con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);

        // ── Controls hint ──────────────────────────────────────────────────
        con->OutputString(con, (CHAR16*)L"\r\n\r\n");
        con->SetAttribute(con, EFI_DARKGRAY | EFI_BACKGROUND_BLACK);
        con->OutputString(con, (CHAR16*)L"    Arrow Keys: Navigate  |  Enter: Toggle/Confirm\r\n");
        con->OutputString(con, (CHAR16*)L"    ESC: Cancel (keep previous settings)\r\n");
        con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);

        // ── Wait for keypress ──────────────────────────────────────────────
        EFI_INPUT_KEY key;
        UINTN index;
        ST->BootServices->WaitForEvent(1, &input->WaitForKey, &index);
        input->ReadKeyStroke(input, &key);

        // ── Handle input ───────────────────────────────────────────────────
        switch (key.ScanCode) {
            case 0x01:  // Up arrow
                if (selection > 0) selection--;
                break;
            case 0x02:  // Down arrow
                if (selection < 2) selection++;
                break;
            case 0x17:  // ESC — cancel without saving
                running = FALSE;
                break;
        }

        // Enter or Space — toggle or confirm
        if (key.UnicodeChar == CHAR_CARRIAGE_RETURN || key.UnicodeChar == L' ') {
            switch (selection) {
                case 0:
                    settings->Enabled = !settings->Enabled;
                    break;
                case 1:
                    settings->AutoStart = !settings->AutoStart;
                    break;
                case 2:
                    running = FALSE;  // OK pressed → save and exit
                    break;
            }
        }
    }

    con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);
    con->ClearScreen(con);
}
