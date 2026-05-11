/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * chain_boot.cpp — Chain-boot to Windows Boot Manager after AegisGate initialization.
 *                  Locates bootmgfw.efi on the ESP and starts it.
 */

#include <Uefi.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiLib.h>
#include "../../common/include/types.h"

// Standard path to Windows Boot Manager on ESP
static CHAR16* gWindowsBootPath = (CHAR16*)L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";

/**
 * Chain-boot to Windows Boot Manager.
 * 
 * Strategy:
 * 1. Find our own device handle (the ESP partition we booted from)
 * 2. Construct device path to \EFI\Microsoft\Boot\bootmgfw.efi
 * 3. Load and start the Windows boot manager image
 * 
 * If the hypervisor is active, Windows will boot as a VM guest.
 * The hypervisor intercepts ExitBootServices to adjust EPT/NPT state.
 */
EFI_STATUS ChainBootToWindows(
    EFI_HANDLE        ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable
) {
    EFI_STATUS status;

    // ── Step 1: Get our own loaded image to find the ESP device ────────────
    EFI_LOADED_IMAGE_PROTOCOL* loadedImage = NULL;
    status = SystemTable->BootServices->HandleProtocol(
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID**)&loadedImage
    );
    if (EFI_ERROR(status)) {
        return status;
    }

    // ── Step 2: Build device path to Windows Boot Manager ──────────────────
    EFI_DEVICE_PATH_PROTOCOL* windowsPath = FileDevicePath(
        loadedImage->DeviceHandle,
        gWindowsBootPath
    );
    if (!windowsPath) {
        return EFI_NOT_FOUND;
    }

    // ── Step 3: Load the Windows Boot Manager image ────────────────────────
    EFI_HANDLE windowsHandle = NULL;
    status = SystemTable->BootServices->LoadImage(
        FALSE,              // BootPolicy = FALSE (not from boot option)
        ImageHandle,        // ParentImageHandle
        windowsPath,        // DevicePath to bootmgfw.efi
        NULL,               // SourceBuffer = NULL (load from disk)
        0,                  // SourceSize = 0
        &windowsHandle      // Output: loaded image handle
    );

    if (EFI_ERROR(status)) {
        // bootmgfw.efi not found at standard path
        // TODO: Fallback — iterate UEFI boot variables (Boot0001, Boot0002, ...)
        //       to find alternative Windows boot entries
        return status;
    }

    // ── Step 4: Start Windows Boot Manager ─────────────────────────────────
    // NOTE: If hypervisor is active, Windows will run as a guest VM.
    // The hypervisor hooks ExitBootServices via VM-Exit to transition
    // from UEFI boot-time to runtime mode without losing control.
    status = SystemTable->BootServices->StartImage(
        windowsHandle,
        NULL,   // ExitDataSize — don't need it
        NULL    // ExitData — don't need it
    );

    // If we reach here, StartImage returned (unusual — means Windows exited?)
    // Unload the image and return error
    SystemTable->BootServices->UnloadImage(windowsHandle);
    return status;
}
