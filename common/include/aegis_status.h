/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * aegis_status.h — Unified status/error codes across all components.
 */

#pragma once
#include "types.h"

namespace aegis {

// ============================================================================
//  Status Codes
//  Bit layout: [31] = Error flag, [30:16] = Module, [15:0] = Code
// ============================================================================

using HvStatus = UINT32;

constexpr HvStatus HV_STATUS_ERROR_BIT = (1u << 31);

// Module identifiers (bits 30:16)
constexpr UINT32 MODULE_GENERAL    = (0x00 << 16);
constexpr UINT32 MODULE_BOOT       = (0x01 << 16);
constexpr UINT32 MODULE_VMX        = (0x02 << 16);
constexpr UINT32 MODULE_SVM        = (0x03 << 16);
constexpr UINT32 MODULE_EPT        = (0x04 << 16);
constexpr UINT32 MODULE_CRYPTO     = (0x05 << 16);
constexpr UINT32 MODULE_SESSION    = (0x06 << 16);
constexpr UINT32 MODULE_PROTECT    = (0x07 << 16);
constexpr UINT32 MODULE_STEALTH    = (0x08 << 16);

// ── Success Codes ──────────────────────────────────────────────────────────

constexpr HvStatus HV_SUCCESS              = 0x00000000;
constexpr HvStatus HV_ALREADY_INITIALIZED  = 0x00000001;
constexpr HvStatus HV_ALREADY_DISABLED     = 0x00000002;

// ── General Errors ─────────────────────────────────────────────────────────

constexpr HvStatus HV_ERROR_GENERIC        = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0001;
constexpr HvStatus HV_OUT_OF_MEMORY        = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0002;
constexpr HvStatus HV_INVALID_PARAMETER    = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0003;
constexpr HvStatus HV_NOT_SUPPORTED        = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0004;
constexpr HvStatus HV_NOT_INITIALIZED      = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0005;
constexpr HvStatus HV_ACCESS_DENIED        = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0006;
constexpr HvStatus HV_TIMEOUT              = HV_STATUS_ERROR_BIT | MODULE_GENERAL | 0x0007;

// ── Boot Errors ────────────────────────────────────────────────────────────

constexpr HvStatus HV_BOOT_NO_VIRT_SUPPORT = HV_STATUS_ERROR_BIT | MODULE_BOOT | 0x0001;
constexpr HvStatus HV_BOOT_VIRT_DISABLED   = HV_STATUS_ERROR_BIT | MODULE_BOOT | 0x0002;
constexpr HvStatus HV_BOOT_CHAIN_FAILED    = HV_STATUS_ERROR_BIT | MODULE_BOOT | 0x0003;
constexpr HvStatus HV_BOOT_SETTINGS_CORRUPT= HV_STATUS_ERROR_BIT | MODULE_BOOT | 0x0004;

// ── SVM Errors (AMD-V) ────────────────────────────────────────────────────

constexpr HvStatus HV_SVM_VMRUN_FAILED     = HV_STATUS_ERROR_BIT | MODULE_SVM | 0x0001;
constexpr HvStatus HV_SVM_VMCB_INVALID     = HV_STATUS_ERROR_BIT | MODULE_SVM | 0x0002;
constexpr HvStatus HV_SVM_DISABLED_BY_BIOS = HV_STATUS_ERROR_BIT | MODULE_SVM | 0x0003;
constexpr HvStatus HV_SVM_NESTED_CONFLICT  = HV_STATUS_ERROR_BIT | MODULE_SVM | 0x0004;

// ── VMX Errors (Intel VT-x) ───────────────────────────────────────────────

constexpr HvStatus HV_VMX_VMXON_FAILED     = HV_STATUS_ERROR_BIT | MODULE_VMX | 0x0001;
constexpr HvStatus HV_VMX_VMLAUNCH_FAILED  = HV_STATUS_ERROR_BIT | MODULE_VMX | 0x0002;
constexpr HvStatus HV_VMX_VMCS_INVALID     = HV_STATUS_ERROR_BIT | MODULE_VMX | 0x0003;
constexpr HvStatus HV_VMX_LOCKED_OFF       = HV_STATUS_ERROR_BIT | MODULE_VMX | 0x0004;

// ── EPT/NPT Errors ────────────────────────────────────────────────────────

constexpr HvStatus HV_EPT_SETUP_FAILED     = HV_STATUS_ERROR_BIT | MODULE_EPT | 0x0001;
constexpr HvStatus HV_EPT_VIOLATION        = HV_STATUS_ERROR_BIT | MODULE_EPT | 0x0002;
constexpr HvStatus HV_EPT_MISCONFIG        = HV_STATUS_ERROR_BIT | MODULE_EPT | 0x0003;

// ── Crypto Errors ──────────────────────────────────────────────────────────

constexpr HvStatus HV_CRYPTO_NO_AESNI      = HV_STATUS_ERROR_BIT | MODULE_CRYPTO | 0x0001;
constexpr HvStatus HV_CRYPTO_AUTH_FAILED   = HV_STATUS_ERROR_BIT | MODULE_CRYPTO | 0x0002;
constexpr HvStatus HV_CRYPTO_KEY_EXPIRED   = HV_STATUS_ERROR_BIT | MODULE_CRYPTO | 0x0003;
constexpr HvStatus HV_CRYPTO_REPLAY_ATTACK = HV_STATUS_ERROR_BIT | MODULE_CRYPTO | 0x0004;

// ── Session Errors ─────────────────────────────────────────────────────────

constexpr HvStatus HV_SESSION_INVALID      = HV_STATUS_ERROR_BIT | MODULE_SESSION | 0x0001;
constexpr HvStatus HV_SESSION_EXPIRED      = HV_STATUS_ERROR_BIT | MODULE_SESSION | 0x0002;
constexpr HvStatus HV_SESSION_AUTH_FAILED  = HV_STATUS_ERROR_BIT | MODULE_SESSION | 0x0003;
constexpr HvStatus HV_SESSION_LIMIT        = HV_STATUS_ERROR_BIT | MODULE_SESSION | 0x0004;

// ── Protection Errors ──────────────────────────────────────────────────────

constexpr HvStatus HV_PROTECT_USB_BLOCKED  = HV_STATUS_ERROR_BIT | MODULE_PROTECT | 0x0001;
constexpr HvStatus HV_PROTECT_INTEGRITY    = HV_STATUS_ERROR_BIT | MODULE_PROTECT | 0x0002;

// ============================================================================
//  Helper Functions
// ============================================================================

inline constexpr bool HvIsError(HvStatus status) {
    return (status & HV_STATUS_ERROR_BIT) != 0;
}

inline constexpr bool HvIsSuccess(HvStatus status) {
    return !HvIsError(status);
}

inline constexpr UINT32 HvGetModule(HvStatus status) {
    return (status >> 16) & 0x7FFF;
}

inline constexpr UINT16 HvGetCode(HvStatus status) {
    return static_cast<UINT16>(status & 0xFFFF);
}

} // namespace aegis
