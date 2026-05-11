/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * aegis_hypercalls.h — Hypercall protocol definitions.
 *                      Used by both the Hypervisor (Ring -1) and the Agent (Ring 3).
 *                      
 * Communication: Agent.exe → VMCALL → Hypervisor (driverless, no kernel driver needed)
 */

#pragma once
#include "types.h"

namespace aegis {

// ============================================================================
//  Magic Numbers & Signatures
// ============================================================================

/// Magic value in RAX to identify AegisGate hypercalls (vs random VMCALL)
constexpr UINT64 AEGIS_HYPERCALL_MAGIC = 0xAE6157A7E0000000ULL;

/// Mask to extract the command from RAX
constexpr UINT64 AEGIS_COMMAND_MASK    = 0x00000000FFFFFFFFULL;

/// Custom CPUID leaf for hypervisor detection by the Agent
/// Leaf 0x41454700 = "AEG\0" — Agent queries this to detect AegisGate
constexpr UINT32 AEGIS_CPUID_SIGNATURE_LEAF = 0x41454700;

/// Expected CPUID response
/// EAX = "Aegi", EBX = "sGat", ECX = "eHV!", EDX = version
constexpr UINT32 AEGIS_CPUID_SIG_EAX = 0x69676541;  // "Aegi"
constexpr UINT32 AEGIS_CPUID_SIG_EBX = 0x74614773;  // "sGat"
constexpr UINT32 AEGIS_CPUID_SIG_ECX = 0x21564865;  // "eHV!"

/// Current hypervisor version (major.minor.patch packed into UINT32)
constexpr UINT32 AEGIS_HV_VERSION = (1 << 16) | (0 << 8) | 0;  // v1.0.0

// ============================================================================
//  Hypercall IDs
//  
//  Usage from Agent (Ring 3):
//    MOV RAX, AEGIS_HYPERCALL_MAGIC | <HypercallId>
//    MOV RBX, <param1>
//    MOV RCX, <param2>
//    MOV RDX, <session_token>
//    VMCALL
//    ; Result in RAX (HvStatus), RBX (return1), RCX (return2)
// ============================================================================

enum class Hypercall : UINT32 {

    // ── Session Management (0x0001 - 0x00FF) ───────────────────────────────
    
    /// Initial handshake — Agent proves it's legitimate
    /// RBX = pointer to handshake challenge (shared mem)
    /// RCX = size of challenge data
    /// Returns: RAX = HvStatus, RBX = session token
    Handshake       = 0x0001,
    
    /// ECDH key exchange for session encryption
    /// RBX = pointer to public key (shared mem)
    /// RCX = key length
    /// Returns: RAX = HvStatus, RBX = pointer to HV public key
    KeyExchange     = 0x0002,
    
    /// Refresh session token (rotation)
    /// RDX = current session token
    /// Returns: RAX = HvStatus, RBX = new session token
    TokenRefresh    = 0x0003,
    
    /// Keep-alive ping
    /// RDX = session token
    /// Returns: RAX = HV_SUCCESS
    Heartbeat       = 0x0004,
    
    /// Graceful session disconnect
    /// RDX = session token
    Disconnect      = 0x0005,

    // ── Information Queries (0x0100 - 0x01FF) ──────────────────────────────
    
    /// Get hypervisor status (active, protection level, uptime)
    /// Returns: RBX = status flags, RCX = uptime in seconds
    GetStatus       = 0x0100,
    
    /// Get hypervisor version
    /// Returns: RBX = version (packed), RCX = build number
    GetVersion      = 0x0101,
    
    /// Get performance metrics (VM-Exit count, avg latency)
    /// RBX = pointer to metrics struct (shared mem)
    GetMetrics      = 0x0102,
    
    /// Get protection module status
    /// Returns: RBX = active modules bitmask
    GetProtection   = 0x0103,

    // ── Security Operations (0x0200 - 0x02FF) ─────────────────────────────
    
    /// Set NPT/EPT protection on a memory page
    /// RBX = guest physical address
    /// RCX = MemPermissions flags
    ProtectPage     = 0x0200,
    
    /// Remove NPT/EPT protection from a page
    /// RBX = guest physical address
    UnprotectPage   = 0x0201,
    
    /// Trigger kernel integrity scan
    /// Returns: RAX = HvStatus (HV_SUCCESS or HV_PROTECT_INTEGRITY)
    ScanIntegrity   = 0x0202,
    
    /// Enable/disable USB monitoring
    /// RBX = 1 (enable) or 0 (disable)
    SetUsbMonitor   = 0x0203,

    // ── Control (0xFF00 - 0xFFFF) ──────────────────────────────────────────
    
    /// Request hypervisor shutdown (devirtualize all CPUs)
    /// RDX = session token (must be authenticated)
    /// RBX = confirmation code (prevents accidental shutdown)
    Shutdown        = 0xFF00,
    
    /// Toggle stealth mode
    /// RBX = 1 (enable) or 0 (disable)
    SetStealth      = 0xFF01,
};

// ============================================================================
//  Shared Memory Communication Structures
// ============================================================================

/// Shared memory page header (encrypted payload follows)
#pragma pack(push, 1)
struct SharedMemHeader {
    UINT32 Magic;              // Must be 0xAE61C0DE         (4)
    UINT32 Version;            // Protocol version            (4)
    UINT64 SequenceNumber;     // Monotonically increasing    (8)
    UINT32 PayloadLength;      // Length of encrypted data     (4)
    UINT32 Command;            // Hypercall command echo       (4)
    UINT8  Nonce[12];          // AES-GCM nonce               (12)
    UINT8  AuthTag[16];        // AES-GCM authentication tag  (16)
    // Total: 52 bytes. Encrypted payload starts at offset 52.
};
#pragma pack(pop)

constexpr UINT32 SHARED_MEM_MAGIC   = 0xAE61C0DE;
constexpr UINT32 SHARED_MEM_VERSION = 1;
constexpr UINT32 SHARED_MEM_HEADER_SIZE = sizeof(SharedMemHeader);
constexpr UINT32 SHARED_MEM_MAX_PAYLOAD = PAGE_SIZE_4K - SHARED_MEM_HEADER_SIZE;

static_assert(SHARED_MEM_HEADER_SIZE == 52, "Header must be 52 bytes");

// ============================================================================
//  Handshake Challenge Structure
// ============================================================================

#pragma pack(push, 1)
struct HandshakeChallenge {
    UINT8  AgentPublicKey[32];    // Curve25519 public key from Agent
    UINT64 Timestamp;             // Milliseconds since boot (anti-replay)
    UINT8  HwFingerprint[32];     // SHA-256 of hardware IDs
    UINT8  Padding[56];           // Pad to 128 bytes
};
#pragma pack(pop)

static_assert(sizeof(HandshakeChallenge) == 128, "Challenge must be 128 bytes");

#pragma pack(push, 1)
struct HandshakeResponse {
    UINT8  HvPublicKey[32];       // Curve25519 public key from Hypervisor
    UINT64 SessionToken;          // Initial session token
    UINT32 TokenLifetimeMs;       // Token validity in milliseconds
    UINT32 HeartbeatIntervalMs;   // Required heartbeat interval
    UINT8  Padding[48];           // Pad to 96 bytes
};
#pragma pack(pop)

static_assert(sizeof(HandshakeResponse) == 96, "Response must be 96 bytes");

// ============================================================================
//  Status & Metrics Structures
// ============================================================================

struct HypervisorStatus {
    BOOLEAN Active;               // Hypervisor is running
    BOOLEAN StealthEnabled;       // Stealth mode active
    BOOLEAN UsbMonitorEnabled;    // USB monitoring active
    BOOLEAN IntegrityOk;          // Last integrity check passed
    UINT64  UptimeSeconds;        // Seconds since hypervisor started
    UINT32  ActiveSessions;       // Number of connected agents
    UINT32  ProtectedPages;       // Number of EPT/NPT protected pages
};

struct PerformanceMetrics {
    UINT64 TotalVmExits;          // Total VM-Exits since boot
    UINT64 HypercallCount;        // Total hypercalls processed
    UINT64 AvgExitLatencyNs;      // Average VM-Exit handling time (nanoseconds)
    UINT64 MaxExitLatencyNs;      // Worst-case VM-Exit latency
    UINT64 UsbEventsBlocked;      // USB events intercepted
    UINT64 IntegrityViolations;   // Kernel integrity violations detected
};

// ============================================================================
//  Helper: Build hypercall RAX value
// ============================================================================

inline constexpr UINT64 MakeHypercallId(Hypercall cmd) {
    return AEGIS_HYPERCALL_MAGIC | static_cast<UINT32>(cmd);
}

inline constexpr bool IsAegisHypercall(UINT64 rax) {
    return (rax & ~AEGIS_COMMAND_MASK) == AEGIS_HYPERCALL_MAGIC;
}

inline constexpr Hypercall ExtractCommand(UINT64 rax) {
    return static_cast<Hypercall>(rax & AEGIS_COMMAND_MASK);
}

} // namespace aegis
