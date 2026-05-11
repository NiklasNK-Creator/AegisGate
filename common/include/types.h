/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * types.h — Fundamental type definitions for the entire project.
 *           Works in freestanding (UEFI/Hypervisor) and hosted (Windows) environments.
 */

#pragma once

// ============================================================================
//  Environment Detection
// ============================================================================

#if defined(_AEGISGATE_UEFI)
    #define AEGIS_ENV_UEFI      1
    #define AEGIS_ENV_HYPERVISOR 0
    #define AEGIS_ENV_WINDOWS    0
#elif defined(_AEGISGATE_HV)
    #define AEGIS_ENV_UEFI      0
    #define AEGIS_ENV_HYPERVISOR 1
    #define AEGIS_ENV_WINDOWS    0
#elif defined(_AEGISGATE_WIN)
    #define AEGIS_ENV_UEFI      0
    #define AEGIS_ENV_HYPERVISOR 0
    #define AEGIS_ENV_WINDOWS    1
#else
    #error "Define _AEGISGATE_UEFI, _AEGISGATE_HV, or _AEGISGATE_WIN"
#endif

// ============================================================================
//  Compiler Detection
// ============================================================================

#if defined(_MSC_VER)
    #define AEGIS_COMPILER_MSVC  1
    #define AEGIS_FORCEINLINE    __forceinline
    #define AEGIS_NOINLINE       __declspec(noinline)
    #define AEGIS_ALIGN(x)       __declspec(align(x))
    #define AEGIS_PACKED_BEGIN   __pragma(pack(push, 1))
    #define AEGIS_PACKED_END     __pragma(pack(pop))
    #define AEGIS_UNREACHABLE()  __assume(0)
#elif defined(__GNUC__) || defined(__clang__)
    #define AEGIS_COMPILER_MSVC  0
    #define AEGIS_FORCEINLINE    __attribute__((always_inline)) inline
    #define AEGIS_NOINLINE       __attribute__((noinline))
    #define AEGIS_ALIGN(x)       __attribute__((aligned(x)))
    #define AEGIS_PACKED_BEGIN
    #define AEGIS_PACKED_END     __attribute__((packed))
    #define AEGIS_UNREACHABLE()  __builtin_unreachable()
#endif

// ============================================================================
//  Fundamental Integer Types (Freestanding — no <cstdint>)
// ============================================================================

#if AEGIS_ENV_UEFI
    // UEFI already defines these via ProcessorBind.h
    #include <Uefi.h>
#else
    // Freestanding definitions for Hypervisor and Windows Agent
    using UINT8   = unsigned char;
    using UINT16  = unsigned short;
    using UINT32  = unsigned int;
    using UINT64  = unsigned long long;
    using INT8    = signed char;
    using INT16   = signed short;
    using INT32   = signed int;
    using INT64   = signed long long;
    using UINTN   = UINT64;   // Always 64-bit (x86-64 only)
    using INTN    = INT64;
    using BOOLEAN = UINT8;
    using CHAR16  = unsigned short;

    #ifndef TRUE
        #define TRUE  ((BOOLEAN)1)
    #endif
    #ifndef FALSE
        #define FALSE ((BOOLEAN)0)
    #endif
    #ifndef NULL
        #define NULL  ((void*)0)
    #endif
#endif

// ============================================================================
//  AegisGate-Specific Types
// ============================================================================

namespace aegis {

/// Physical memory address (GPA or HPA)
using PhysicalAddress = UINT64;

/// Virtual memory address
using VirtualAddress = UINT64;

/// Guest Physical Address
using Gpa = UINT64;

/// Host Physical Address
using Hpa = UINT64;

/// Guest Virtual Address
using Gva = UINT64;

/// Page-aligned size (always in bytes)
using PageSize = UINT64;

/// CPU core index
using CpuIndex = UINT32;

/// Hypercall ID
using HypercallId = UINT64;

/// Session token for Agent ↔ Hypervisor communication
using SessionToken = UINT64;

// ============================================================================
//  CPU Vendor Identification
// ============================================================================

enum class CpuVendor : UINT8 {
    Unknown = 0,
    Intel   = 1,    // "GenuineIntel"
    AMD     = 2,    // "AuthenticAMD"
};

// ============================================================================
//  Virtualization Technology
// ============================================================================

enum class VirtTech : UINT8 {
    None = 0,
    VTx  = 1,    // Intel VT-x (VMX)
    SVM  = 2,    // AMD-V (SVM)
};

// ============================================================================
//  Hardware Capabilities (filled by boot-time probe)
// ============================================================================

struct HardwareCapabilities {
    CpuVendor Vendor;
    VirtTech  Technology;
    BOOLEAN   VirtualizationSupported;
    BOOLEAN   VirtualizationEnabled;
    BOOLEAN   EptNptSupported;          // EPT (Intel) or NPT (AMD)
    BOOLEAN   AesNiSupported;           // AES-NI hardware crypto
    BOOLEAN   ShaExtSupported;          // SHA Extensions
    UINT32    MaxPhysAddrBits;          // CPUID.80000008:EAX[7:0]
    UINT32    NumLogicalProcessors;
    UINT32    NumPhysicalCores;
};

// ============================================================================
//  Page Constants
// ============================================================================

constexpr UINT64 PAGE_SIZE_4K  = 0x1000ULL;          // 4 KB
constexpr UINT64 PAGE_SIZE_2M  = 0x200000ULL;        // 2 MB
constexpr UINT64 PAGE_SIZE_1G  = 0x40000000ULL;      // 1 GB
constexpr UINT64 PAGE_MASK_4K  = ~(PAGE_SIZE_4K - 1);
constexpr UINT64 PAGE_MASK_2M  = ~(PAGE_SIZE_2M - 1);

// ============================================================================
//  Memory Permission Flags (for EPT/NPT)
// ============================================================================

enum class MemPermissions : UINT8 {
    None          = 0,
    Read          = (1 << 0),
    Write         = (1 << 1),
    Execute       = (1 << 2),
    ReadWrite     = Read | Write,
    ReadExecute   = Read | Execute,
    ReadWriteExec = Read | Write | Execute,
};

// Bitwise operators for MemPermissions
inline MemPermissions operator|(MemPermissions a, MemPermissions b) {
    return static_cast<MemPermissions>(static_cast<UINT8>(a) | static_cast<UINT8>(b));
}
inline MemPermissions operator&(MemPermissions a, MemPermissions b) {
    return static_cast<MemPermissions>(static_cast<UINT8>(a) & static_cast<UINT8>(b));
}
inline bool HasFlag(MemPermissions perms, MemPermissions flag) {
    return (static_cast<UINT8>(perms) & static_cast<UINT8>(flag)) != 0;
}

// ============================================================================
//  Guest Register Context (saved/restored on VM-Exit)
// ============================================================================

struct GuestRegisters {
    // Layout MUST match the SAVE_GUEST_REGS / RESTORE_GUEST_REGS macro order!
    // Stack grows down, so first push = highest address = first struct field
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
    
    // NOTE: Rip, Rsp, Rflags are NOT here — they live in VMCB State Area
    // Access them via vcpu->GuestVmcb.State.Rip / .Rsp / .Rflags
};

// Verify layout matches ASM push order (15 GPRs × 8 bytes = 120 bytes)
static_assert(sizeof(GuestRegisters) == 15 * 8, "GuestRegisters must be 120 bytes");

// ============================================================================
//  Utility: Compile-time assertions & helpers
// ============================================================================

template<typename T>
constexpr T AlignUp(T value, T alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

template<typename T>
constexpr T AlignDown(T value, T alignment) {
    return value & ~(alignment - 1);
}

template<typename T>
constexpr bool IsAligned(T value, T alignment) {
    return (value & (alignment - 1)) == 0;
}

} // namespace aegis
