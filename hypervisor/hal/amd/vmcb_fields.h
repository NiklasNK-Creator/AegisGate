/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vmcb_fields.h — AMD SVM VMCB (Virtual Machine Control Block) layout.
 *                 Complete field definitions for the 4KB VMCB structure.
 *                 Reference: AMD64 Architecture Programmer's Manual, Volume 2, Chapter 15.
 */

#pragma once

#include "../../../common/include/types.h"

namespace aegis::svm {

// ============================================================================
//  VMCB Control Area (Offset 0x000 - 0x3FF)
// ============================================================================

#pragma pack(push, 1)

/// Intercept control fields for CR reads/writes
struct CrInterceptControl {
    UINT16 ReadCr;      // Bits 0-15: Intercept reads of CR0-CR15
    UINT16 WriteCr;     // Bits 0-15: Intercept writes of CR0-CR15
};

/// Intercept control fields for DR reads/writes
struct DrInterceptControl {
    UINT16 ReadDr;      // Bits 0-15: Intercept reads of DR0-DR15
    UINT16 WriteDr;     // Bits 0-15: Intercept writes of DR0-DR15
};

/// Exception intercepts (bitmap for exceptions 0-31)
struct ExceptionInterceptControl {
    UINT32 Vector;      // Bit N: intercept exception #N (#DE=0, #DB=1, ..., #SX=30)
};

/// Main intercept control word 1
struct InterceptMisc1 {
    UINT32 InterceptIntr        : 1;  // Bit 0:  Physical INTR
    UINT32 InterceptNmi         : 1;  // Bit 1:  NMI
    UINT32 InterceptSmi         : 1;  // Bit 2:  SMI
    UINT32 InterceptInit        : 1;  // Bit 3:  INIT
    UINT32 InterceptVintr       : 1;  // Bit 4:  Virtual INTR
    UINT32 InterceptCr0Write    : 1;  // Bit 5:  CR0 writes that change bits other than CR0.TS or CR0.MP
    UINT32 InterceptIdtrRead    : 1;  // Bit 6:  IDTR reads
    UINT32 InterceptGdtrRead    : 1;  // Bit 7:  GDTR reads
    UINT32 InterceptLdtrRead    : 1;  // Bit 8:  LDTR reads
    UINT32 InterceptTrRead      : 1;  // Bit 9:  TR reads
    UINT32 InterceptIdtrWrite   : 1;  // Bit 10: IDTR writes
    UINT32 InterceptGdtrWrite   : 1;  // Bit 11: GDTR writes
    UINT32 InterceptLdtrWrite   : 1;  // Bit 12: LDTR writes
    UINT32 InterceptTrWrite     : 1;  // Bit 13: TR writes
    UINT32 InterceptRdtsc       : 1;  // Bit 14: RDTSC
    UINT32 InterceptRdpmc       : 1;  // Bit 15: RDPMC
    UINT32 InterceptPushf       : 1;  // Bit 16: PUSHF
    UINT32 InterceptPopf        : 1;  // Bit 17: POPF
    UINT32 InterceptCpuid       : 1;  // Bit 18: CPUID
    UINT32 InterceptRsm         : 1;  // Bit 19: RSM
    UINT32 InterceptIret        : 1;  // Bit 20: IRET
    UINT32 InterceptInt         : 1;  // Bit 21: INTn
    UINT32 InterceptInvd        : 1;  // Bit 22: INVD
    UINT32 InterceptPause       : 1;  // Bit 23: PAUSE
    UINT32 InterceptHlt         : 1;  // Bit 24: HLT
    UINT32 InterceptInvlpg      : 1;  // Bit 25: INVLPG
    UINT32 InterceptInvlpga     : 1;  // Bit 26: INVLPGA
    UINT32 InterceptIoio        : 1;  // Bit 27: IOIO (IN/OUT)
    UINT32 InterceptMsr         : 1;  // Bit 28: MSR (use MSR permission map)
    UINT32 InterceptTaskSwitch  : 1;  // Bit 29: Task switches
    UINT32 InterceptFerrFreeze  : 1;  // Bit 30: FERR_FREEZE
    UINT32 InterceptShutdown    : 1;  // Bit 31: Shutdown events
};

/// Main intercept control word 2
struct InterceptMisc2 {
    UINT32 InterceptVmrun       : 1;  // Bit 0:  VMRUN
    UINT32 InterceptVmcall      : 1;  // Bit 1:  VMCALL  <-- KEY: needed for Agent communication
    UINT32 InterceptVmload      : 1;  // Bit 2:  VMLOAD
    UINT32 InterceptVmsave      : 1;  // Bit 3:  VMSAVE
    UINT32 InterceptStgi        : 1;  // Bit 4:  STGI
    UINT32 InterceptClgi        : 1;  // Bit 5:  CLGI
    UINT32 InterceptSkinit      : 1;  // Bit 6:  SKINIT
    UINT32 InterceptRdtscp      : 1;  // Bit 7:  RDTSCP
    UINT32 InterceptIcebp       : 1;  // Bit 8:  ICEBP
    UINT32 InterceptWbinvd      : 1;  // Bit 9:  WBINVD
    UINT32 InterceptMonitor     : 1;  // Bit 10: MONITOR
    UINT32 InterceptMwaitUncond : 1;  // Bit 11: MWAIT unconditionally
    UINT32 InterceptMwaitArmed  : 1;  // Bit 12: MWAIT if armed
    UINT32 InterceptXsetbv      : 1;  // Bit 13: XSETBV
    UINT32 InterceptRdpru       : 1;  // Bit 14: RDPRU
    UINT32 Reserved             : 17; // Bits 15-31
};

/// The complete VMCB Control Area layout
struct VmcbControlArea {
    // Offset 0x000
    CrInterceptControl CrIntercept;             // 0x000 (4 bytes)
    DrInterceptControl DrIntercept;             // 0x004 (4 bytes)
    ExceptionInterceptControl ExcIntercept;     // 0x008 (4 bytes)
    InterceptMisc1 Intercept1;                  // 0x00C (4 bytes)
    InterceptMisc2 Intercept2;                  // 0x010 (4 bytes)
    UINT8  Reserved1[0x028 - 0x014];            // 0x014 - 0x027

    // Offset 0x028
    UINT16 PauseFilterThreshold;                // 0x028
    UINT16 PauseFilterCount;                    // 0x02A
    UINT8  Reserved2[0x040 - 0x02C];            // 0x02C - 0x03F

    // Offset 0x040
    UINT64 IopmBasePa;                          // 0x040: I/O Permission Map base (physical)
    UINT64 MsrpmBasePa;                         // 0x048: MSR Permission Map base (physical)
    UINT64 TscOffset;                           // 0x050: TSC offset (for stealth)
    
    // Offset 0x058
    UINT32 GuestAsid;                           // 0x058: Guest ASID (must be != 0)
    UINT32 TlbControl;                          // 0x05C: TLB control
    //   0 = Do nothing
    //   1 = Flush entire TLB
    //   3 = Flush this guest's TLB entries
    //   7 = Flush non-global TLB entries

    // Offset 0x060
    UINT64 VIntr;                               // 0x060: Virtual interrupt control

    // Offset 0x068
    UINT64 InterruptShadow;                     // 0x068: Interrupt shadow

    // Offset 0x070
    UINT64 ExitCode;                            // 0x070: #VMEXIT code
    UINT64 ExitInfo1;                           // 0x078: Exit info 1
    UINT64 ExitInfo2;                           // 0x080: Exit info 2
    UINT64 ExitIntInfo;                         // 0x088: Exit interrupt info

    // Offset 0x090
    UINT64 NptEnable;                           // 0x090: Nested Paging enable
    //   Bit 0: NP_ENABLE — enable nested paging
    UINT8  Reserved3[0x0A8 - 0x098];            // 0x098 - 0x0A7

    // Offset 0x0A8
    UINT64 AvicApicBar;                         // 0x0A8: AVIC APIC BAR

    // Offset 0x0B0
    UINT64 NptCr3;                              // 0x0B0: Nested page table CR3 (nCR3)
    //   Host-level CR3 for nested page table walks

    // Offset 0x0B8
    UINT64 LbrVirtualizationEnable;             // 0x0B8: LBR virtualization

    // Offset 0x0C0
    UINT64 VmcbClean;                           // 0x0C0: VMCB clean bits (optimization)
    //   If a bit is set, the corresponding VMCB field has NOT changed
    //   since last VMRUN. CPU can skip reloading that state.

    UINT8  Reserved4[0x100 - 0x0C8];            // 0x0C8 - 0x0FF

    // Rest is reserved up to 0x3FF
    UINT8  ReservedControl[0x400 - 0x100];      // 0x100 - 0x3FF
};

static_assert(sizeof(VmcbControlArea) == 0x400, "VMCB Control Area must be 1024 bytes");

// ============================================================================
//  VMCB State Save Area (Offset 0x400 - 0xFFF)
// ============================================================================

/// Segment register state in VMCB
struct VmcbSegment {
    UINT16 Selector;
    UINT16 Attrib;          // Segment attributes (type, S, DPL, P, AVL, L, D/B, G)
    UINT32 Limit;
    UINT64 Base;
};

/// The complete VMCB State Save Area
struct VmcbStateSaveArea {
    // Segment registers
    VmcbSegment Es;                             // 0x400
    VmcbSegment Cs;                             // 0x410
    VmcbSegment Ss;                             // 0x420
    VmcbSegment Ds;                             // 0x430
    VmcbSegment Fs;                             // 0x440
    VmcbSegment Gs;                             // 0x450
    VmcbSegment Gdtr;                           // 0x460
    VmcbSegment Ldtr;                           // 0x470
    VmcbSegment Idtr;                           // 0x480
    VmcbSegment Tr;                             // 0x490

    UINT8  Reserved1[0x4CB - 0x4A0];            // 0x4A0 - 0x4CA
    UINT8  Cpl;                                 // 0x4CB: Current Privilege Level
    UINT32 Reserved2;                           // 0x4CC

    // Offset 0x4D0
    UINT64 Efer;                                // 0x4D0: EFER MSR
    UINT8  Reserved3[0x548 - 0x4D8];            // 0x4D8 - 0x547

    // Offset 0x548
    UINT64 Cr4;                                 // 0x548
    UINT64 Cr3;                                 // 0x550
    UINT64 Cr0;                                 // 0x558
    UINT64 Dr7;                                 // 0x560
    UINT64 Dr6;                                 // 0x568
    UINT64 Rflags;                              // 0x570
    UINT64 Rip;                                 // 0x578

    UINT8  Reserved4[0x5D8 - 0x580];            // 0x580 - 0x5D7

    UINT64 Rsp;                                 // 0x5D8
    UINT64 SSsp;                                // 0x5E0 (Shadow Stack Pointer)

    UINT8  Reserved5[0x5F8 - 0x5E8];            // 0x5E8 - 0x5F7 padding

    UINT64 Rax;                                 // 0x5F8 — NOTE: RAX is only here, not in GP area

    UINT64 Star;                                // 0x600
    UINT64 LStar;                               // 0x608
    UINT64 CStar;                               // 0x610
    UINT64 SfMask;                              // 0x618
    UINT64 KernelGsBase;                        // 0x620

    UINT64 SysenterCs;                          // 0x628
    UINT64 SysenterEsp;                         // 0x630
    UINT64 SysenterEip;                         // 0x638
    UINT64 Cr2;                                 // 0x640

    UINT8  Reserved6[0x668 - 0x648];            // 0x648 - 0x667

    UINT64 GPat;                                // 0x668: Guest PAT MSR
    UINT64 DbgCtl;                              // 0x670: DebugCtl MSR
    UINT64 BrFrom;                              // 0x678
    UINT64 BrTo;                                // 0x680
    UINT64 LastExcpFrom;                        // 0x688
    UINT64 LastExcpTo;                          // 0x690

    // Rest reserved to 0xFFF
    UINT8  ReservedState[0xC00 - 0x698];        // Pad to end
};

// ============================================================================
//  Complete VMCB (4KB page-aligned)
// ============================================================================

struct alignas(4096) Vmcb {
    VmcbControlArea  Control;                   // 0x000 - 0x3FF
    VmcbStateSaveArea State;                    // 0x400 - 0xFFF
};

static_assert(sizeof(Vmcb) == 4096, "VMCB must be exactly one 4KB page");

// ============================================================================
//  #VMEXIT Codes (AMD-specific)
// ============================================================================

enum class VmExitCode : UINT64 {
    // CR access (0x000 - 0x01F)
    CrRead0         = 0x000,
    CrRead3         = 0x003,
    CrRead4         = 0x004,
    CrWrite0        = 0x010,
    CrWrite3        = 0x013,
    CrWrite4        = 0x014,

    // DR access (0x020 - 0x03F)
    DrRead0         = 0x020,
    DrWrite0        = 0x030,

    // Exceptions (0x040 - 0x05F)
    Exception0      = 0x040,  // #DE
    Exception1      = 0x041,  // #DB
    Exception6      = 0x046,  // #UD
    Exception13     = 0x04D,  // #GP
    Exception14     = 0x04E,  // #PF
    Exception18     = 0x052,  // #MC

    // Instruction intercepts
    Intr            = 0x060,
    Nmi             = 0x061,
    Smi             = 0x062,
    Init            = 0x063,
    Vintr           = 0x064,
    Cpuid           = 0x072,
    Invd            = 0x076,
    Hlt             = 0x078,
    Invlpg          = 0x079,
    Invlpga         = 0x07A,
    IoIo            = 0x07B,
    Msr             = 0x07C,
    Shutdown        = 0x07F,
    Vmrun           = 0x080,
    Vmcall          = 0x081,  // <-- AegisGate hypercalls arrive here
    Vmload          = 0x082,
    Vmsave          = 0x083,
    Stgi            = 0x084,
    Clgi            = 0x085,
    Skinit          = 0x086,
    Rdtscp          = 0x087,
    Icebp           = 0x088,
    Wbinvd          = 0x089,
    Monitor         = 0x08A,
    MwaitUncond     = 0x08B,
    Xsetbv          = 0x08D,

    // NPT (Nested Page Table) violation
    Npf             = 0x400,  // Nested Page Fault

    // Invalid VMCB
    Invalid         = -1ULL,
};

// ============================================================================
//  VMCB Clean Bits (optimization flags for VMRUN)
// ============================================================================

enum class VmcbCleanBits : UINT64 {
    Intercepts  = (1ULL << 0),   // Intercept vectors
    Iopm        = (1ULL << 1),   // IOPM base address
    Asid        = (1ULL << 2),   // ASID
    Tpr         = (1ULL << 3),   // TPR/V_TPR
    Npt         = (1ULL << 4),   // NPT enable + nCR3
    Crx         = (1ULL << 5),   // CR0, CR3, CR4, EFER
    Drx         = (1ULL << 6),   // DR6, DR7
    Dt          = (1ULL << 7),   // GDT, IDT
    Seg         = (1ULL << 8),   // CS, DS, SS, ES segments
    Cr2         = (1ULL << 9),   // CR2
    Lbr         = (1ULL << 10),  // LBR, DbgCtl
    AvicState   = (1ULL << 11),  // AVIC
    All         = 0xFFF,         // All bits clean (nothing changed)
};

} // namespace aegis::svm
