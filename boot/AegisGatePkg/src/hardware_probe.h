/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * hardware_probe.h — Hardware capability detection interface.
 */

#pragma once

#include <Uefi.h>
#include "../../common/include/types.h"
#include "../../common/include/aegis_status.h"

// ============================================================================
//  ASM function declarations (from cpuid_check.asm)
// ============================================================================

extern "C" {
    UINT32  AsmCheckCpuVendor(void);
    BOOLEAN AsmCheckVtxSupport(void);
    BOOLEAN AsmCheckSvmSupport(void);
    BOOLEAN AsmCheckVtxEnabled(void);
    BOOLEAN AsmCheckSvmDisabledByBios(void);
    BOOLEAN AsmCheckNptSupport(void);
    BOOLEAN AsmCheckAesNiSupport(void);
    UINT32  AsmGetMaxPhysAddrBits(void);
}

// ============================================================================
//  Hardware Probe API
// ============================================================================

/**
 * Probe all hardware capabilities needed for AegisGate.
 * 
 * @param caps  Output structure filled with detection results.
 * @return      HV_SUCCESS if hardware is compatible,
 *              HV_BOOT_NO_VIRT_SUPPORT if VT-x/AMD-V is not available,
 *              HV_BOOT_VIRT_DISABLED if virtualization is disabled in BIOS.
 */
aegis::HvStatus ProbeHardware(aegis::HardwareCapabilities* caps);

/**
 * Display hardware probe results to the console (for debugging/info).
 */
void PrintHardwareInfo(EFI_SYSTEM_TABLE* ST, const aegis::HardwareCapabilities* caps);
