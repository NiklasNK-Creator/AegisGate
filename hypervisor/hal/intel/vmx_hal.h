/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vmx_hal.h — Intel VT-x (VMX) backend header.
 *             Full VMX implementation with VMCS, EPT, and VM-Exit handling.
 */

#pragma once

#include "../hal_interface.h"
#include "../../../common/include/aegis_config.h"

namespace aegis::vmx {

// ============================================================================
//  VMCS Field Encodings (Intel SDM Vol 3, Appendix B)
// ============================================================================

enum class VmcsField : UINT32 {
    // ── 16-bit Guest State ────────────────────────────────────────────
    GuestEsSelector      = 0x0800,
    GuestCsSelector      = 0x0802,
    GuestSsSelector      = 0x0804,
    GuestDsSelector      = 0x0806,
    GuestFsSelector      = 0x0808,
    GuestGsSelector      = 0x080A,
    GuestLdtrSelector    = 0x080C,
    GuestTrSelector      = 0x080E,
    GuestInterruptStatus = 0x0810,

    // ── 16-bit Host State ─────────────────────────────────────────────
    HostEsSelector       = 0x0C00,
    HostCsSelector       = 0x0C02,
    HostSsSelector       = 0x0C04,
    HostDsSelector       = 0x0C06,
    HostFsSelector       = 0x0C08,
    HostGsSelector       = 0x0C0A,
    HostTrSelector       = 0x0C0C,

    // ── 64-bit Control Fields ─────────────────────────────────────────
    IoBitmapA            = 0x2000,
    IoBitmapB            = 0x2002,
    MsrBitmapAddr        = 0x2004,
    VmExitMsrStoreAddr   = 0x2006,
    VmExitMsrLoadAddr    = 0x2008,
    VmEntryMsrLoadAddr   = 0x200A,
    TscOffset            = 0x2010,
    EptPointer           = 0x201A,

    // ── 64-bit Guest State ────────────────────────────────────────────
    VmcsLinkPointer      = 0x2800,
    GuestIa32Debugctl    = 0x2802,
    GuestIa32Pat         = 0x2804,
    GuestIa32Efer        = 0x2806,

    // ── 64-bit Host State ─────────────────────────────────────────────
    HostIa32Pat          = 0x2C00,
    HostIa32Efer         = 0x2C02,

    // ── 32-bit Control Fields ─────────────────────────────────────────
    PinBasedVmExecCtrl   = 0x4000,
    ProcBasedVmExecCtrl  = 0x4002,
    ExceptionBitmap      = 0x4004,
    PageFaultErrorMask   = 0x4006,
    PageFaultErrorMatch  = 0x4008,
    Cr3TargetCount       = 0x400A,
    VmExitControls       = 0x400C,
    VmExitMsrStoreCount  = 0x400E,
    VmExitMsrLoadCount   = 0x4010,
    VmEntryControls      = 0x4012,
    VmEntryMsrLoadCount  = 0x4014,
    VmEntryIntrInfoField = 0x4016,
    ProcBasedVmExecCtrl2 = 0x401E,

    // ── 32-bit Read-Only Fields ───────────────────────────────────────
    VmInstructionError   = 0x4400,
    VmExitReason         = 0x4402,
    VmExitIntrInfo       = 0x4404,
    VmExitIntrErrorCode  = 0x4406,
    IdtVectoringInfoField= 0x4408,
    IdtVectoringErrorCode= 0x440A,
    VmExitInstrLen       = 0x440C,
    VmExitInstrInfo      = 0x440E,

    // ── 32-bit Guest State ────────────────────────────────────────────
    GuestEsLimit         = 0x4800,
    GuestCsLimit         = 0x4802,
    GuestSsLimit         = 0x4804,
    GuestDsLimit         = 0x4806,
    GuestFsLimit         = 0x4808,
    GuestGsLimit         = 0x480A,
    GuestLdtrLimit       = 0x480C,
    GuestTrLimit         = 0x480E,
    GuestGdtrLimit       = 0x4810,
    GuestIdtrLimit       = 0x4812,
    GuestEsAccessRights  = 0x4814,
    GuestCsAccessRights  = 0x4816,
    GuestSsAccessRights  = 0x4818,
    GuestDsAccessRights  = 0x481A,
    GuestFsAccessRights  = 0x481C,
    GuestGsAccessRights  = 0x481E,
    GuestLdtrAccessRights= 0x4820,
    GuestTrAccessRights  = 0x4822,
    GuestInterruptibility= 0x4824,
    GuestActivityState   = 0x4826,
    GuestSysenterCs      = 0x482A,

    // ── 32-bit Host State ─────────────────────────────────────────────
    HostIa32SysenterCs   = 0x4C00,

    // ── Natural-Width Control Fields ──────────────────────────────────
    Cr0GuestHostMask     = 0x6000,
    Cr4GuestHostMask     = 0x6002,
    Cr0ReadShadow        = 0x6004,
    Cr4ReadShadow        = 0x6006,

    // ── Natural-Width Read-Only ───────────────────────────────────────
    ExitQualification    = 0x6400,
    GuestLinearAddress   = 0x640A,

    // ── Natural-Width Guest State ─────────────────────────────────────
    GuestCr0             = 0x6800,
    GuestCr3             = 0x6802,
    GuestCr4             = 0x6804,
    GuestEsBase          = 0x6806,
    GuestCsBase          = 0x6808,
    GuestSsBase          = 0x680A,
    GuestDsBase          = 0x680C,
    GuestFsBase          = 0x680E,
    GuestGsBase          = 0x6810,
    GuestLdtrBase        = 0x6812,
    GuestTrBase          = 0x6814,
    GuestGdtrBase        = 0x6816,
    GuestIdtrBase        = 0x6818,
    GuestDr7             = 0x681A,
    GuestRsp             = 0x681C,
    GuestRip             = 0x681E,
    GuestRflags          = 0x6820,
    GuestSysenterEsp     = 0x6824,
    GuestSysenterEip     = 0x6826,

    // ── Natural-Width Host State ──────────────────────────────────────
    HostCr0              = 0x6C00,
    HostCr3              = 0x6C02,
    HostCr4              = 0x6C04,
    HostFsBase           = 0x6C06,
    HostGsBase           = 0x6C08,
    HostTrBase           = 0x6C0A,
    HostGdtrBase         = 0x6C0C,
    HostIdtrBase         = 0x6C0E,
    HostIa32SysenterEsp  = 0x6C10,
    HostIa32SysenterEip  = 0x6C12,
    HostRsp              = 0x6C14,
    HostRip              = 0x6C16,
};

// ============================================================================
//  VMX Exit Reasons (Intel SDM Vol 3, Appendix C)
// ============================================================================

enum class VmxExitReason : UINT32 {
    ExceptionNmi         = 0,
    ExternalInt          = 1,
    TripleFault          = 2,
    InitSignal           = 3,
    Sipi                 = 4,
    IoSmi                = 5,
    OtherSmi             = 6,
    InterruptWindow      = 7,
    NmiWindow            = 8,
    TaskSwitch           = 9,
    Cpuid                = 10,
    Getsec               = 11,
    Hlt                  = 12,
    Invd                 = 13,
    Invlpg               = 14,
    Rdpmc                = 15,
    Rdtsc                = 16,
    Rsm                  = 17,
    Vmcall               = 18,
    Vmclear              = 19,
    Vmlaunch             = 20,
    Vmptrld              = 21,
    Vmptrst              = 22,
    Vmread               = 23,
    Vmresume             = 24,
    Vmwrite              = 25,
    Vmxoff               = 26,
    Vmxon                = 27,
    CrAccess             = 28,
    DrAccess             = 29,
    IoInstruction        = 30,
    MsrRead              = 31,
    MsrWrite             = 32,
    InvalidGuestState    = 33,
    MsrLoading           = 34,
    Mwait                = 36,
    MonitorTrapFlag      = 37,
    Monitor              = 39,
    Pause                = 40,
    MachineCheckEntry    = 41,
    TprBelowThreshold    = 43,
    ApicAccess           = 44,
    VirtualEoi           = 45,
    GdtrIdtrAccess       = 46,
    LdtrTrAccess         = 47,
    EptViolation         = 48,
    EptMisconfig         = 49,
    Invept               = 50,
    Rdtscp               = 51,
    PreemptionTimer      = 52,
    Invvpid              = 53,
    Wbinvd               = 54,
    Xsetbv               = 55,
    ApicWrite            = 56,
    Rdrand               = 57,
    Invpcid              = 58,
    Vmfunc               = 59,
    Encls                = 60,
    Rdseed               = 61,
    PageModLog           = 62,
    Xsaves               = 63,
    Xrstors              = 64,
};

// ============================================================================
//  VMX Control Bit Definitions
// ============================================================================

// Pin-Based VM-Execution Controls
namespace PinBased {
    constexpr UINT32 ExtIntExiting     = (1u << 0);
    constexpr UINT32 NmiExiting        = (1u << 3);
    constexpr UINT32 VirtualNmis       = (1u << 5);
    constexpr UINT32 PreemptionTimer   = (1u << 6);
}

// Primary Processor-Based VM-Execution Controls
namespace ProcBased {
    constexpr UINT32 IntWindowExiting  = (1u << 2);
    constexpr UINT32 UseTscOffsetting  = (1u << 3);
    constexpr UINT32 HltExiting        = (1u << 7);
    constexpr UINT32 InvlpgExiting     = (1u << 9);
    constexpr UINT32 MwaitExiting      = (1u << 10);
    constexpr UINT32 RdpmcExiting      = (1u << 11);
    constexpr UINT32 RdtscExiting      = (1u << 12);
    constexpr UINT32 Cr3LoadExiting    = (1u << 15);
    constexpr UINT32 Cr3StoreExiting   = (1u << 16);
    constexpr UINT32 Cr8LoadExiting    = (1u << 19);
    constexpr UINT32 Cr8StoreExiting   = (1u << 20);
    constexpr UINT32 UseTprShadow      = (1u << 21);
    constexpr UINT32 NmiWindowExiting  = (1u << 22);
    constexpr UINT32 MovDrExiting      = (1u << 23);
    constexpr UINT32 UnconditionalIo   = (1u << 24);
    constexpr UINT32 UseIoBitmaps      = (1u << 25);
    constexpr UINT32 MonitorTrapFlag   = (1u << 27);
    constexpr UINT32 UseMsrBitmaps     = (1u << 28);
    constexpr UINT32 MonitorExiting    = (1u << 29);
    constexpr UINT32 PauseExiting      = (1u << 30);
    constexpr UINT32 ActivateSecondary = (1u << 31);
}

// Secondary Processor-Based VM-Execution Controls
namespace ProcBased2 {
    constexpr UINT32 VirtualizeApic    = (1u << 0);
    constexpr UINT32 EnableEpt         = (1u << 1);
    constexpr UINT32 DescTableExiting  = (1u << 2);
    constexpr UINT32 EnableRdtscp      = (1u << 3);
    constexpr UINT32 VirtualizeX2Apic  = (1u << 4);
    constexpr UINT32 EnableVpid        = (1u << 5);
    constexpr UINT32 WbinvdExiting     = (1u << 6);
    constexpr UINT32 UnrestrictedGuest = (1u << 7);
    constexpr UINT32 EnableInvpcid     = (1u << 12);
    constexpr UINT32 EnableVmFunctions = (1u << 13);
    constexpr UINT32 EnableXsaves      = (1u << 20);
}

// VM-Exit Controls
namespace ExitCtrl {
    constexpr UINT32 SaveDebugControls    = (1u << 2);
    constexpr UINT32 HostAddressSpace64   = (1u << 9);
    constexpr UINT32 AckIntOnExit         = (1u << 15);
    constexpr UINT32 SaveIa32Pat          = (1u << 18);
    constexpr UINT32 LoadIa32Pat          = (1u << 19);
    constexpr UINT32 SaveIa32Efer         = (1u << 20);
    constexpr UINT32 LoadIa32Efer         = (1u << 21);
}

// VM-Entry Controls
namespace EntryCtrl {
    constexpr UINT32 LoadDebugControls    = (1u << 2);
    constexpr UINT32 Ia32eModeGuest       = (1u << 9);
    constexpr UINT32 LoadIa32Pat          = (1u << 14);
    constexpr UINT32 LoadIa32Efer         = (1u << 15);
}

// ============================================================================
//  EPT (Extended Page Table) Structures
// ============================================================================

// EPT PML4/PDPT/PD/PT Entry flags
constexpr UINT64 EPT_READ    = (1ULL << 0);
constexpr UINT64 EPT_WRITE   = (1ULL << 1);
constexpr UINT64 EPT_EXECUTE = (1ULL << 2);
constexpr UINT64 EPT_RWX     = EPT_READ | EPT_WRITE | EPT_EXECUTE;
constexpr UINT64 EPT_LARGE   = (1ULL << 7);    // 2MB page
constexpr UINT64 EPT_MEM_WB  = (6ULL << 3);    // Write-back memory type
constexpr UINT64 EPT_ADDR_MASK = 0x000FFFFFFFFFF000ULL;

// EPT Pointer format
// Bits [2:0] = Memory type (6 = WB)
// Bit [6]    = Page walk length - 1 (3 = 4-level)
constexpr UINT64 EPT_POINTER_WB   = 6ULL;
constexpr UINT64 EPT_POINTER_4LVL = (3ULL << 3);

struct alignas(4096) EptPml4  { UINT64 Entries[512]; };
struct alignas(4096) EptPdpt  { UINT64 Entries[512]; };
struct alignas(4096) EptPd    { UINT64 Entries[512]; };
struct alignas(4096) EptPt    { UINT64 Entries[512]; };

// ============================================================================
//  Per-CPU VMX Data
// ============================================================================

/// VMXON region (must be 4KB aligned, revision ID in first 4 bytes)
struct alignas(4096) VmxonRegion {
    UINT32 RevisionId;
    UINT8  Data[4096 - sizeof(UINT32)];
};

/// VMCS region
struct alignas(4096) VmcsRegion {
    UINT32 RevisionId;
    UINT32 AbortIndicator;
    UINT8  Data[4096 - 2 * sizeof(UINT32)];
};

/// MSR Bitmap for VMX (4KB — covers MSR ranges)
struct alignas(4096) VmxMsrBitmap {
    UINT8 ReadLow[1024];   // MSRs 0x00000000 - 0x00001FFF
    UINT8 ReadHigh[1024];  // MSRs 0xC0000000 - 0xC0001FFF
    UINT8 WriteLow[1024];  // MSRs 0x00000000 - 0x00001FFF
    UINT8 WriteHigh[1024]; // MSRs 0xC0000000 - 0xC0001FFF
};

/// Per-CPU VCPU data for Intel VMX
struct alignas(4096) VmxVcpuData {
    VmxonRegion   VmxonRegion;                                     // 4KB
    VmcsRegion    GuestVmcs;                                       // 4KB
    VmxMsrBitmap  MsrBitmap;                                       // 4KB

    // Host stack for VM-Exit handling
    AEGIS_ALIGN(16) UINT8 HostStack[config::VCPU_HOST_STACK_SIZE]; // 24KB

    // Metadata
    CpuIndex   Index;
    BOOLEAN    IsVirtualized;
    VirtTech   Tech;
    Hpa        EptRoot;

    // Original host state
    UINT64     OriginalCr0;
    UINT64     OriginalCr4;

    UINT8      Padding[64];
};

// ============================================================================
//  ASM Function Declarations (vmx_ops.asm)
// ============================================================================

extern "C" {
    void     AsmVmxEnable(void);
    void     AsmVmxDisable(void);
    UINT64   AsmVmxon(UINT64* vmxonRegionPa);
    UINT64   AsmVmxoff(void);
    UINT64   AsmVmclear(UINT64* vmcsPa);
    UINT64   AsmVmptrld(UINT64* vmcsPa);
    UINT64   AsmVmwrite(UINT64 field, UINT64 value);
    UINT64   AsmVmread(UINT64 field);
    UINT64   AsmVmlaunch(void);
    UINT64   AsmVmresume(void);
    void     AsmVmxEntryLoop(VmxVcpuData* vcpu);
    UINT64   AsmVirtToPhys(void* virtualAddr);
    UINT64   AsmReadMsr(UINT32 msrIndex);
    void     AsmWriteMsr(UINT32 msrIndex, UINT64 value);
}

// ============================================================================
//  VMX HAL Implementation
// ============================================================================

class VmxHal final : public IHypervisorBackend {
public:
    VmxHal();
    ~VmxHal() override;

    // IHypervisorBackend interface
    HvStatus InitializeCpu(CpuIndex cpuIndex, VcpuData** vcpu) override;
    HvStatus VirtualizeCpu(VcpuData* vcpu) override;
    HvStatus DevirtualizeCpu(VcpuData* vcpu) override;

    HvStatus SetupIdentityNpt(UINT32 maxPhysAddrBits) override;
    HvStatus SetPagePermissions(Gpa guestPhys, MemPermissions perms) override;
    HvStatus InvalidateNpt() override;
    Hpa      GetNptRoot() const override;

    bool     HandleVmExit(VcpuData* vcpu, GuestRegisters* regs) override;

    const char* GetBackendName() const override { return "Intel VMX (VT-x)"; }
    VirtTech    GetVirtTech() const override { return VirtTech::VTx; }

private:
    // VMCS setup helpers
    UINT32 AdjustControls(UINT32 desired, UINT32 msrAddr);
    void   SetupVmcsControlFields(VmxVcpuData* vcpu);
    void   SetupVmcsGuestState(VmxVcpuData* vcpu);
    void   SetupVmcsHostState(VmxVcpuData* vcpu);

    // VM-Exit sub-handlers
    bool HandleCpuidExit(VmxVcpuData* vcpu, GuestRegisters* regs);
    bool HandleMsrReadExit(VmxVcpuData* vcpu, GuestRegisters* regs);
    bool HandleMsrWriteExit(VmxVcpuData* vcpu, GuestRegisters* regs);
    bool HandleVmcallExit(VmxVcpuData* vcpu, GuestRegisters* regs);
    bool HandleEptViolation(VmxVcpuData* vcpu, GuestRegisters* regs);

    // State
    VmxVcpuData*  m_Vcpus[config::MAX_PROCESSOR_COUNT];
    UINT32        m_CpuCount;
    Hpa           m_EptRoot;
    bool          m_Initialized;
};

} // namespace aegis::vmx
