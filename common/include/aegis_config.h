/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * aegis_config.h — Compile-time configuration constants.
 *                  Tune these for performance vs. security tradeoffs.
 */

#pragma once
#include "types.h"

namespace aegis::config {

// ============================================================================
//  Version Info
// ============================================================================

constexpr UINT32 VERSION_MAJOR = 1;
constexpr UINT32 VERSION_MINOR = 0;
constexpr UINT32 VERSION_PATCH = 0;
constexpr const char* VERSION_STRING = "1.0.0-alpha";
constexpr const char* PROJECT_NAME   = "AegisGate";
constexpr const char* DEVELOPER      = "Nik";

// ============================================================================
//  Boot Configuration
// ============================================================================

/// Time in milliseconds to show logo and wait for hotkey
constexpr UINT32 BOOT_LOGO_TIMEOUT_MS = 2000;

/// Hotkey scan code to enter settings menu (F2)
constexpr UINT16 BOOT_HOTKEY_SCANCODE = 0x0C;  // EFI Scan Code for F2

/// NVRAM variable magic to detect corrupted settings
constexpr UINT32 SETTINGS_MAGIC = 0x54534741;  // 'AGST'

// ============================================================================
//  Hypervisor Configuration
// ============================================================================

/// Maximum number of logical processors supported
constexpr UINT32 MAX_PROCESSOR_COUNT = 256;

/// Host stack size per VCPU (bytes) — needs to be sufficient for VM-Exit handling
constexpr UINT64 VCPU_HOST_STACK_SIZE = 0x6000;  // 24 KB

/// Use 2MB large pages for NPT/EPT identity mapping (much faster TLB)
constexpr bool USE_LARGE_PAGES = true;

/// Maximum physical address space to map (0 = auto-detect via CPUID)
constexpr UINT64 MAX_PHYS_ADDR_OVERRIDE = 0;

// ============================================================================
//  Session & Communication Configuration
// ============================================================================

/// Maximum concurrent agent sessions
constexpr UINT32 MAX_SESSIONS = 4;

/// Session token rotation interval (milliseconds)
constexpr UINT32 TOKEN_ROTATION_MS = 30000;  // 30 seconds

/// Heartbeat timeout — if no heartbeat in this time, session expires
constexpr UINT32 HEARTBEAT_TIMEOUT_MS = 10000;  // 10 seconds

/// Required heartbeat interval for Agent
constexpr UINT32 HEARTBEAT_INTERVAL_MS = 3000;  // 3 seconds

/// Maximum sequence number gap allowed (anti-replay window)
constexpr UINT64 MAX_SEQUENCE_GAP = 1000;

// ============================================================================
//  Crypto Configuration
// ============================================================================

/// AES key size in bytes (32 = AES-256)
constexpr UINT32 AES_KEY_SIZE = 32;

/// AES-GCM nonce size (12 bytes = 96 bits, standard)
constexpr UINT32 AES_GCM_NONCE_SIZE = 12;

/// AES-GCM tag size (16 bytes = 128 bits, full security)
constexpr UINT32 AES_GCM_TAG_SIZE = 16;

/// Curve25519 key size
constexpr UINT32 ECDH_KEY_SIZE = 32;

/// Hardware fingerprint hash size (SHA-256)
constexpr UINT32 HW_FINGERPRINT_SIZE = 32;

// ============================================================================
//  Stealth Configuration
// ============================================================================

/// Enable CPUID hypervisor-present bit masking (bit 31 of ECX in leaf 1)
constexpr bool STEALTH_HIDE_CPUID_HV_BIT = true;

/// Enable CPUID VMX/SVM bit masking
constexpr bool STEALTH_HIDE_CPUID_VIRT_BIT = true;

/// Enable TSC offsetting to prevent timing-based detection
constexpr bool STEALTH_TSC_OFFSETTING = true;

/// TSC cycles to subtract from VM-Exit overhead (calibrated at boot)
constexpr UINT64 STEALTH_TSC_OFFSET_DEFAULT = 0;  // Auto-calibrated

// ============================================================================
//  Protection Configuration
// ============================================================================

/// Enable USB I/O port monitoring
constexpr bool PROTECT_USB_ENABLED_DEFAULT = true;

/// Enable kernel code integrity monitoring via NPT
constexpr bool PROTECT_KERNEL_INTEGRITY_DEFAULT = true;

/// Kernel integrity scan interval (milliseconds)
constexpr UINT32 INTEGRITY_SCAN_INTERVAL_MS = 5000;  // 5 seconds

// ============================================================================
//  Debug Configuration
// ============================================================================

/// Enable serial port debug output (COM1, 0x3F8)
#ifdef _DEBUG
    constexpr bool DEBUG_SERIAL_ENABLED = true;
#else
    constexpr bool DEBUG_SERIAL_ENABLED = false;
#endif

/// Serial port base address (COM1)
constexpr UINT16 DEBUG_SERIAL_PORT = 0x3F8;

/// Serial baud rate
constexpr UINT32 DEBUG_SERIAL_BAUD = 115200;

} // namespace aegis::config
