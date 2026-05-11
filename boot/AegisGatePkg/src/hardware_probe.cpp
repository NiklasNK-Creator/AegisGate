/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * hardware_probe.cpp — CPU vendor detection and virtualization feature probing.
 *                      Calls ASM functions for CPUID queries.
 */

#include "hardware_probe.h"
#include "../include/efi_cpp_runtime.h"
#include <Library/UefiLib.h>

using namespace aegis;

HvStatus ProbeHardware(HardwareCapabilities* caps) {
    if (!caps) return HV_INVALID_PARAMETER;

    // Zero-init
    MemZero(caps, sizeof(HardwareCapabilities));

    // ── Step 1: Identify CPU Vendor ────────────────────────────────────────
    UINT32 vendorId = AsmCheckCpuVendor();
    caps->Vendor = static_cast<CpuVendor>(vendorId);

    // ── Step 2: Check virtualization support per vendor ─────────────────────
    switch (caps->Vendor) {
        case CpuVendor::Intel:
            caps->Technology = VirtTech::VTx;
            caps->VirtualizationSupported = AsmCheckVtxSupport();
            
            if (caps->VirtualizationSupported) {
                caps->VirtualizationEnabled = AsmCheckVtxEnabled();
                // Intel EPT support is checked later during VMX init
                // (requires VMX to be active to read VMX capability MSRs)
                caps->EptNptSupported = TRUE;  // Assumed for Haswell+
            }
            break;

        case CpuVendor::AMD:
            caps->Technology = VirtTech::SVM;
            caps->VirtualizationSupported = AsmCheckSvmSupport();
            
            if (caps->VirtualizationSupported) {
                // AMD doesn't have a lock bit like Intel — check VM_CR MSR
                BOOLEAN svmDisabled = AsmCheckSvmDisabledByBios();
                caps->VirtualizationEnabled = !svmDisabled;
                
                // Check NPT (Nested Page Tables) support
                caps->EptNptSupported = AsmCheckNptSupport();
            }
            break;

        default:
            return HV_BOOT_NO_VIRT_SUPPORT;
    }

    // ── Step 3: Check crypto hardware ──────────────────────────────────────
    caps->AesNiSupported = AsmCheckAesNiSupport();
    // SHA Extensions: less critical, software fallback available
    caps->ShaExtSupported = FALSE;  // TODO: Add CPUID check

    // ── Step 4: Physical address width ─────────────────────────────────────
    caps->MaxPhysAddrBits = AsmGetMaxPhysAddrBits();

    // ── Step 5: Processor count (filled in by caller via MP Services) ──────
    // caps->NumLogicalProcessors and NumPhysicalCores set elsewhere

    // ── Validation ─────────────────────────────────────────────────────────
    if (!caps->VirtualizationSupported) {
        return HV_BOOT_NO_VIRT_SUPPORT;
    }
    if (!caps->VirtualizationEnabled) {
        return HV_BOOT_VIRT_DISABLED;
    }

    return HV_SUCCESS;
}

void PrintHardwareInfo(EFI_SYSTEM_TABLE* ST, const HardwareCapabilities* caps) {
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* con = ST->ConOut;

    con->SetAttribute(con, EFI_LIGHTCYAN | EFI_BACKGROUND_BLACK);
    con->OutputString(con, L"\r\n  AegisGate Hardware Probe Results:\r\n");
    con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);

    // Vendor
    con->OutputString(con, L"  CPU Vendor:       ");
    switch (caps->Vendor) {
        case CpuVendor::Intel: con->OutputString(con, L"Intel\r\n"); break;
        case CpuVendor::AMD:   con->OutputString(con, L"AMD\r\n"); break;
        default:               con->OutputString(con, L"Unknown\r\n"); break;
    }

    // Virtualization
    con->OutputString(con, L"  Virtualization:   ");
    switch (caps->Technology) {
        case VirtTech::VTx: con->OutputString(con, L"VT-x (VMX)"); break;
        case VirtTech::SVM: con->OutputString(con, L"AMD-V (SVM)"); break;
        default:            con->OutputString(con, L"None"); break;
    }
    con->OutputString(con, caps->VirtualizationSupported ? L" [Supported]" : L" [NOT Supported]");
    con->OutputString(con, caps->VirtualizationEnabled ? L" [Enabled]\r\n" : L" [DISABLED in BIOS]\r\n");

    // EPT/NPT
    con->OutputString(con, L"  EPT/NPT:          ");
    con->OutputString(con, caps->EptNptSupported ? L"Supported\r\n" : L"NOT Supported\r\n");

    // AES-NI
    con->OutputString(con, L"  AES-NI:           ");
    if (caps->AesNiSupported) {
        con->SetAttribute(con, EFI_LIGHTGREEN | EFI_BACKGROUND_BLACK);
        con->OutputString(con, L"Available (Hardware Crypto)\r\n");
    } else {
        con->SetAttribute(con, EFI_YELLOW | EFI_BACKGROUND_BLACK);
        con->OutputString(con, L"Not Available (Software Fallback)\r\n");
    }
    con->SetAttribute(con, EFI_WHITE | EFI_BACKGROUND_BLACK);

    con->OutputString(con, L"\r\n");
}
