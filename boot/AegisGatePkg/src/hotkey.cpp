/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * hotkey.cpp — Boot-time hotkey detection with timer.
 *              Waits for a keypress during logo display (default 2 seconds).
 */

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include "../../common/include/aegis_config.h"

/**
 * Wait for any keypress within the specified timeout.
 * 
 * @param ST          UEFI System Table
 * @param timeoutMs   Maximum time to wait in milliseconds
 * @return            TRUE if a key was pressed, FALSE if timeout elapsed
 */
BOOLEAN WaitForHotkey(EFI_SYSTEM_TABLE* ST, UINT32 timeoutMs) {
    EFI_SIMPLE_TEXT_INPUT_PROTOCOL* input = ST->ConIn;
    EFI_STATUS status;

    // Flush any queued keystrokes from before
    input->Reset(input, FALSE);

    // Create a timer event
    EFI_EVENT timerEvent;
    status = ST->BootServices->CreateEvent(
        EVT_TIMER,
        TPL_CALLBACK,
        NULL,
        NULL,
        &timerEvent
    );
    if (EFI_ERROR(status)) {
        // Timer creation failed — fallback: just stall and check once
        ST->BootServices->Stall(timeoutMs * 1000);  // Stall in microseconds
        EFI_INPUT_KEY key;
        return (input->ReadKeyStroke(input, &key) == EFI_SUCCESS) ? TRUE : FALSE;
    }

    // Set timer: relative, in 100ns units
    UINT64 timerValue = (UINT64)timeoutMs * 10000ULL;  // ms → 100ns
    ST->BootServices->SetTimer(timerEvent, TimerRelative, timerValue);

    // Wait for either: keyboard input OR timer expiration
    EFI_EVENT waitEvents[2] = {
        input->WaitForKey,
        timerEvent
    };

    UINTN eventIndex = 0;
    status = ST->BootServices->WaitForEvent(2, waitEvents, &eventIndex);

    // Clean up timer
    ST->BootServices->CloseEvent(timerEvent);

    if (EFI_ERROR(status)) {
        return FALSE;
    }

    if (eventIndex == 0) {
        // Keyboard event fired first — a key was pressed
        EFI_INPUT_KEY key;
        input->ReadKeyStroke(input, &key);  // Consume the keystroke
        return TRUE;
    }

    // Timer expired — no key pressed
    return FALSE;
}

/**
 * Stall execution for a given number of seconds.
 * Used for error message display before chain-booting.
 */
void StallSeconds(EFI_SYSTEM_TABLE* ST, UINT32 seconds) {
    ST->BootServices->Stall((UINT64)seconds * 1000000ULL);
}
