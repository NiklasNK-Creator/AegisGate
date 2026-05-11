/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * svm_hal.cpp — AMD SVM backend implementation.
 */

#include "svm_hal.h"
#include "../../../common/include/aegis_hypercalls.h"

// UEFI memory services (available during boot)
#if AEGIS_ENV_UEFI
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#endif

namespace aegis::svm {

// ============================================================================
//  NPT (Nested Page Table) structures
// ============================================================================

struct alignas(4096) NptPml4  { UINT64 Entries[512]; };
struct alignas(4096) NptPdpt  { UINT64 Entries[512]; };
struct alignas(4096) NptPd    { UINT64 Entries[512]; };

// NPT Entry flags
constexpr UINT64 NPT_PRESENT  = (1ULL << 0);
constexpr UINT64 NPT_WRITE    = (1ULL << 1);
constexpr UINT64 NPT_USER     = (1ULL << 2);
constexpr UINT64 NPT_LARGE    = (1ULL << 7);  // 2MB page
constexpr UINT64 NPT_NX       = (0ULL);       // No NX for data pages
constexpr UINT64 NPT_ADDR_MASK = 0x000FFFFFFFFFF000ULL;

// ============================================================================
//  Memory helpers
// ============================================================================

static void* AllocPage() {
#if AEGIS_ENV_UEFI
    void* p = AllocateAlignedPages(1, 4096);
    if (p) ZeroMem(p, 4096);
    return p;
#else
    return nullptr;
#endif
}

static void* AllocPages(UINTN count) {
#if AEGIS_ENV_UEFI
    void* p = AllocateAlignedPages(count, 4096);
    if (p) ZeroMem(p, count * 4096);
    return p;
#else
    return nullptr;
#endif
}

static Hpa VirtToPhys(void* va) {
    return AsmVirtToPhys(va);
}

// ============================================================================
//  Constructor / Destructor
// ============================================================================

// Global instance pointer — set by SvmHal constructor, used by ASM callback
static SvmHal* g_SvmInstance = nullptr;

SvmHal::SvmHal()
    : m_CpuCount(0)
    , m_NptRoot(0)
    , m_SharedMsrPm(nullptr)
    , m_SharedIoPm(nullptr)
    , m_Initialized(false)
{
    for (UINT32 i = 0; i < config::MAX_PROCESSOR_COUNT; i++) {
        m_Vcpus[i] = nullptr;
    }
    g_SvmInstance = this;
}

SvmHal::~SvmHal() {
    // Devirtualize all CPUs if still active
    // In practice, this destructor may never run in a hypervisor context
}

// ============================================================================
//  InitializeCpu — Allocate and configure per-CPU structures
// ============================================================================

HvStatus SvmHal::InitializeCpu(CpuIndex cpuIndex, VcpuData** outVcpu) {
    if (cpuIndex >= config::MAX_PROCESSOR_COUNT || !outVcpu) {
        return HV_INVALID_PARAMETER;
    }

    // Allocate per-CPU data (must be page-aligned for VMCB)
    UINTN vcpuPages = (sizeof(VcpuData) + 4095) / 4096;
    auto* vcpu = static_cast<VcpuData*>(AllocPages(vcpuPages));
    if (!vcpu) return HV_OUT_OF_MEMORY;

    vcpu->Index = cpuIndex;
    vcpu->IsVirtualized = FALSE;
    vcpu->Tech = VirtTech::SVM;

    // Allocate shared MSR permission map (once, shared by all CPUs)
    if (!m_SharedMsrPm) {
        m_SharedMsrPm = static_cast<MsrPermissionMap*>(AllocPages(2));
        if (!m_SharedMsrPm) return HV_OUT_OF_MEMORY;
        SetupMsrPermissionMap(m_SharedMsrPm);
    }
    vcpu->MsrPm = m_SharedMsrPm;

    // Allocate shared I/O permission map (once)
    if (!m_SharedIoPm) {
        m_SharedIoPm = static_cast<IoPermissionMap*>(AllocPages(3));
        if (!m_SharedIoPm) return HV_OUT_OF_MEMORY;
        SetupIoPermissionMap(m_SharedIoPm);
    }
    vcpu->IoPm = m_SharedIoPm;

    m_Vcpus[cpuIndex] = vcpu;
    if (cpuIndex >= m_CpuCount) m_CpuCount = cpuIndex + 1;

    *outVcpu = vcpu;
    return HV_SUCCESS;
}

// ============================================================================
//  VirtualizeCpu — Enter SVM root mode on current CPU
// ============================================================================

HvStatus SvmHal::VirtualizeCpu(VcpuData* vcpu) {
    if (!vcpu || vcpu->IsVirtualized) return HV_INVALID_PARAMETER;

    // Save original EFER and VM_HSAVE_PA
    vcpu->OriginalEfer = AsmReadMsr(0xC0000080);
    vcpu->OriginalVmHsavePa = AsmGetVmHsavePa();

    // Enable SVM (EFER.SVME = 1)
    AsmSvmEnable();

    // Set VM_HSAVE_PA to our host save area
    Hpa hsavePa = VirtToPhys(vcpu->HostSaveArea);
    AsmSetVmHsavePa(hsavePa);

    // Configure VMCB
    SetupVmcbControlArea(&vcpu->GuestVmcb, vcpu);
    SetupVmcbStateSave(&vcpu->GuestVmcb);

    // Set NPT root CR3
    vcpu->NptRootCr3 = m_NptRoot;

    vcpu->IsVirtualized = TRUE;

    // Enter the guest loop — this function only returns when
    // the hypervisor is being shut down
    AsmSvmEntryLoop(vcpu);

    // If we get here, hypervisor has been shut down on this CPU
    vcpu->IsVirtualized = FALSE;
    return HV_SUCCESS;
}

// ============================================================================
//  DevirtualizeCpu — Exit SVM root mode
// ============================================================================

HvStatus SvmHal::DevirtualizeCpu(VcpuData* vcpu) {
    if (!vcpu) return HV_INVALID_PARAMETER;
    if (!vcpu->IsVirtualized) return HV_ALREADY_DISABLED;

    // Restore original VM_HSAVE_PA
    AsmSetVmHsavePa(vcpu->OriginalVmHsavePa);

    // Disable SVM
    AsmSvmDisable();

    vcpu->IsVirtualized = FALSE;
    return HV_SUCCESS;
}

// ============================================================================
//  VMCB Control Area Setup
// ============================================================================

void SvmHal::SetupVmcbControlArea(Vmcb* vmcb, VcpuData* vcpu) {
    auto& ctrl = vmcb->Control;

    // ── Intercepts ─────────────────────────────────────────────────────
    // Intercept CPUID — needed for stealth + hypervisor detection
    ctrl.Intercept1.InterceptCpuid = 1;

    // Intercept MSR access — controlled via MSR permission map
    ctrl.Intercept1.InterceptMsr = 1;

    // Intercept VMRUN/VMCALL/VMLOAD/VMSAVE — security critical
    ctrl.Intercept2.InterceptVmrun = 1;
    ctrl.Intercept2.InterceptVmcall = 1;  // Agent communication!
    ctrl.Intercept2.InterceptVmload = 1;
    ctrl.Intercept2.InterceptVmsave = 1;

    // Intercept INVD (cache invalidation) — required for correctness
    ctrl.Intercept1.InterceptInvd = 1;

    // Intercept XSETBV — needed for XCR0 management
    ctrl.Intercept2.InterceptXsetbv = 1;

    // Intercept shutdown events
    ctrl.Intercept1.InterceptShutdown = 1;

    // ── Guest ASID (must be non-zero) ──────────────────────────────────
    ctrl.GuestAsid = 1;

    // ── TLB Control ────────────────────────────────────────────────────
    ctrl.TlbControl = 1;  // Flush entire TLB on first VMRUN

    // ── MSR Permission Map ─────────────────────────────────────────────
    ctrl.MsrpmBasePa = VirtToPhys(vcpu->MsrPm);

    // ── I/O Permission Map ─────────────────────────────────────────────
    // Don't intercept I/O by default (too much overhead)
    // USB monitoring will selectively enable I/O intercepts later
    ctrl.Intercept1.InterceptIoio = 0;
    ctrl.IopmBasePa = VirtToPhys(vcpu->IoPm);

    // ── Nested Paging ──────────────────────────────────────────────────
    ctrl.NptEnable = 1;  // Enable NPT
    ctrl.NptCr3 = m_NptRoot;  // NPT page table root

    // ── TSC Offset (Stealth) ───────────────────────────────────────────
    if (config::STEALTH_TSC_OFFSETTING) {
        ctrl.TscOffset = 0;  // Will be calibrated at runtime
        ctrl.Intercept1.InterceptRdtsc = 0;  // Use offset instead of intercept
        ctrl.Intercept2.InterceptRdtscp = 0;
    }

    // ── VMCB Clean bits ────────────────────────────────────────────────
    // First VMRUN: all fields dirty (clean bits = 0)
    ctrl.VmcbClean = 0;
}

// ============================================================================
//  VMCB State Save Area Setup
// ============================================================================

void SvmHal::SetupVmcbStateSave(Vmcb* vmcb) {
    auto& state = vmcb->State;

    // Capture current CPU state as the initial guest state.
    // This means the guest starts executing right where we are now,
    // making the transition transparent.

    // Control registers
    UINT64 cr0, cr3, cr4;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    state.Cr0 = cr0;
    state.Cr3 = cr3;
    state.Cr4 = cr4;

    // EFER — keep current value but ensure SVME is set
    state.Efer = AsmReadMsr(0xC0000080) | (1ULL << 12);

    // RIP will be set by the ASM entry loop to resume after VMRUN
    // RSP will be captured by the ASM entry loop
    // RFLAGS will be captured automatically

    // Segment registers — capture current state
    // (In UEFI context, these are in a flat 64-bit configuration)
    state.Cs.Selector = 0x38;  // Typical UEFI code segment
    state.Cs.Attrib = 0x029B;  // Code, Read, Accessed, Long mode
    state.Cs.Limit = 0xFFFFFFFF;
    state.Cs.Base = 0;

    state.Ds.Selector = 0x30;
    state.Ds.Attrib = 0x0093;
    state.Ds.Limit = 0xFFFFFFFF;
    state.Ds.Base = 0;

    state.Es = state.Ds;
    state.Ss = state.Ds;

    // PAT MSR
    state.GPat = AsmReadMsr(0x277);

    // STAR/LSTAR/CSTAR/SFMASK for SYSCALL/SYSRET
    state.Star = AsmReadMsr(0xC0000081);
    state.LStar = AsmReadMsr(0xC0000082);
    state.CStar = AsmReadMsr(0xC0000083);
    state.SfMask = AsmReadMsr(0xC0000084);
    state.KernelGsBase = AsmReadMsr(0xC0000102);
}

// ============================================================================
//  MSR Permission Map Setup
// ============================================================================

void SvmHal::SetupMsrPermissionMap(MsrPermissionMap* msrpm) {
    // Default: allow all MSR access (0 = no intercept)
    // We only intercept specific MSRs for security

    // Zero = don't intercept any MSRs
    // The MSR permission map is 8KB and covers MSR ranges:
    //   0x0000_0000 - 0x0000_1FFF (first 2KB)
    //   0xC000_0000 - 0xC000_1FFF (second 2KB)
    //   0xC001_0000 - 0xC001_1FFF (third 2KB)
    //   Reserved (fourth 2KB)

    // For now, allow everything. Specific MSRs will be intercepted
    // as protection modules are enabled.
}

// ============================================================================
//  I/O Permission Map Setup
// ============================================================================

void SvmHal::SetupIoPermissionMap(IoPermissionMap* iopm) {
    // Default: don't intercept any I/O ports
    // USB monitoring will set specific port bits later
    // Bit = 1 means intercept, Bit = 0 means allow
}

// ============================================================================
//  NPT Setup — Identity mapping with 2MB large pages
// ============================================================================

HvStatus SvmHal::SetupIdentityNpt(UINT32 maxPhysAddrBits) {
    auto* pml4 = static_cast<NptPml4*>(AllocPage());
    if (!pml4) return HV_OUT_OF_MEMORY;

    // Calculate max physical address
    UINT64 maxPhysAddr = 1ULL << maxPhysAddrBits;
    UINT64 num2MBPages = maxPhysAddr / PAGE_SIZE_2M;

    for (UINT64 i = 0; i < num2MBPages; i++) {
        UINT64 physAddr = i * PAGE_SIZE_2M;

        UINT32 pml4Idx = (physAddr >> 39) & 0x1FF;
        UINT32 pdptIdx = (physAddr >> 30) & 0x1FF;
        UINT32 pdIdx   = (physAddr >> 21) & 0x1FF;

        // PML4 → PDPT (lazy allocate)
        if (!(pml4->Entries[pml4Idx] & NPT_PRESENT)) {
            auto* pdpt = static_cast<NptPdpt*>(AllocPage());
            if (!pdpt) return HV_OUT_OF_MEMORY;
            pml4->Entries[pml4Idx] = VirtToPhys(pdpt) | NPT_PRESENT | NPT_WRITE | NPT_USER;
        }
        auto* pdpt = reinterpret_cast<NptPdpt*>(
            pml4->Entries[pml4Idx] & NPT_ADDR_MASK);

        // PDPT → PD (lazy allocate)
        if (!(pdpt->Entries[pdptIdx] & NPT_PRESENT)) {
            auto* pd = static_cast<NptPd*>(AllocPage());
            if (!pd) return HV_OUT_OF_MEMORY;
            pdpt->Entries[pdptIdx] = VirtToPhys(pd) | NPT_PRESENT | NPT_WRITE | NPT_USER;
        }
        auto* pd = reinterpret_cast<NptPd*>(
            pdpt->Entries[pdptIdx] & NPT_ADDR_MASK);

        // PD entry → 2MB large page (identity: GPA = HPA)
        pd->Entries[pdIdx] = physAddr | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_LARGE;
    }

    m_NptRoot = VirtToPhys(pml4);
    m_Initialized = true;
    return HV_SUCCESS;
}

HvStatus SvmHal::SetPagePermissions(Gpa guestPhys, MemPermissions perms) {
    // Walk the NPT to find the PD entry for this address
    // and modify its permission bits
    // TODO: Implement 4KB page splitting when needed
    (void)guestPhys; (void)perms;
    return HV_SUCCESS;
}

HvStatus SvmHal::InvalidateNpt() {
    // For AMD SVM: flush TLB via VMCB TlbControl field
    // Set on next VMRUN
    for (UINT32 i = 0; i < m_CpuCount; i++) {
        if (m_Vcpus[i] && m_Vcpus[i]->IsVirtualized) {
            m_Vcpus[i]->GuestVmcb.Control.TlbControl = 1;
        }
    }
    return HV_SUCCESS;
}

Hpa SvmHal::GetNptRoot() const {
    return m_NptRoot;
}

// ============================================================================
//  VM-Exit Handler (called from ASM via HandleVmExitSvm)
// ============================================================================

bool SvmHal::HandleVmExit(VcpuData* vcpu, GuestRegisters* regs) {
    auto exitCode = static_cast<VmExitCode>(vcpu->GuestVmcb.Control.ExitCode);

    // After handling, mark VMCB clean bits for optimization
    vcpu->GuestVmcb.Control.VmcbClean = static_cast<UINT64>(VmcbCleanBits::All);

    switch (exitCode) {
        case VmExitCode::Cpuid:
            return HandleCpuidExit(vcpu, regs);

        case VmExitCode::Vmcall:
            return HandleVmcallExit(vcpu, regs);

        case VmExitCode::Msr:
            return HandleMsrExit(vcpu, regs,
                vcpu->GuestVmcb.Control.ExitInfo1 == 1);

        case VmExitCode::Npf:
            return HandleNpfExit(vcpu, regs);

        case VmExitCode::Vmrun:
        case VmExitCode::Vmload:
        case VmExitCode::Vmsave:
            // Inject #UD — guest should not use SVM instructions
            // (nested virtualization not supported)
            // For now, just skip the instruction
            vcpu->GuestVmcb.State.Rip += 3;  // SVM instructions are 3 bytes
            return true;

        case VmExitCode::Invd:
            // INVD → convert to WBINVD (safer)
            asm volatile("wbinvd");
            vcpu->GuestVmcb.State.Rip += 2;
            return true;

        case VmExitCode::Xsetbv:
            // Execute XSETBV on behalf of guest
            // ECX = XCR number, EDX:EAX = value
            asm volatile("xsetbv" :: "a"((UINT32)regs->Rax),
                         "d"((UINT32)regs->Rdx), "c"((UINT32)regs->Rcx));
            vcpu->GuestVmcb.State.Rip += 3;
            return true;

        case VmExitCode::Shutdown:
            // Triple fault or critical error
            return false;  // Stop hypervisor

        default:
            // Unhandled exit — advance RIP and continue
            // This is dangerous but prevents hangs during development
            vcpu->GuestVmcb.State.Rip += 1;
            return true;
    }
}

// ============================================================================
//  CPUID Handler (Stealth + Agent Detection)
// ============================================================================

bool SvmHal::HandleCpuidExit(VcpuData* vcpu, GuestRegisters* regs) {
    UINT32 leaf = static_cast<UINT32>(regs->Rax);
    UINT32 subleaf = static_cast<UINT32>(regs->Rcx);

    // Custom AegisGate detection leaf
    if (leaf == AEGIS_CPUID_SIGNATURE_LEAF) {
        regs->Rax = AEGIS_CPUID_SIG_EAX;
        regs->Rbx = AEGIS_CPUID_SIG_EBX;
        regs->Rcx = AEGIS_CPUID_SIG_ECX;
        regs->Rdx = AEGIS_HV_VERSION;
        vcpu->GuestVmcb.State.Rip += 2;  // CPUID is 2 bytes (0F A2)
        return true;
    }

    // Execute real CPUID
    UINT32 eax, ebx, ecx, edx;
    asm volatile("cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(leaf), "c"(subleaf));

    // Stealth: Hide hypervisor presence
    if (leaf == 1 && config::STEALTH_HIDE_CPUID_HV_BIT) {
        ecx &= ~(1u << 31);  // Clear Hypervisor Present bit
    }
    if (leaf == 1 && config::STEALTH_HIDE_CPUID_VIRT_BIT) {
        ecx &= ~(1u << 5);   // Clear VMX bit (Intel-style, some tools check)
    }

    regs->Rax = eax;
    regs->Rbx = ebx;
    regs->Rcx = ecx;
    regs->Rdx = edx;

    vcpu->GuestVmcb.State.Rip += 2;
    return true;
}

// ============================================================================
//  VMCALL Handler (Agent ↔ Hypervisor Communication)
// ============================================================================

bool SvmHal::HandleVmcallExit(VcpuData* vcpu, GuestRegisters* regs) {
    UINT64 rax = vcpu->GuestVmcb.State.Rax;

    // Check if this is an AegisGate hypercall
    if (!IsAegisHypercall(rax)) {
        // Not our hypercall — inject #UD to guest
        regs->Rax = static_cast<UINT64>(HV_ACCESS_DENIED);
        vcpu->GuestVmcb.State.Rip += 3;
        return true;
    }

    auto cmd = ExtractCommand(rax);

    switch (cmd) {
        case Hypercall::GetStatus:
            regs->Rax = HV_SUCCESS;
            regs->Rbx = 1;  // Active
            regs->Rcx = 0;  // Uptime (TODO)
            break;

        case Hypercall::GetVersion:
            regs->Rax = HV_SUCCESS;
            regs->Rbx = AEGIS_HV_VERSION;
            regs->Rcx = 0;  // Build number
            break;

        case Hypercall::Heartbeat:
            regs->Rax = HV_SUCCESS;
            break;

        case Hypercall::Shutdown: {
            // Verify session token (RDX)
            // TODO: Full session validation
            UINT64 confirmCode = regs->Rbx;
            if (confirmCode == 0xDEAD) {
                regs->Rax = HV_SUCCESS;
                vcpu->GuestVmcb.State.Rip += 3;
                return false;  // Stop the hypervisor
            }
            regs->Rax = static_cast<UINT64>(HV_ACCESS_DENIED);
            break;
        }

        case Hypercall::Handshake:
        case Hypercall::KeyExchange:
        case Hypercall::TokenRefresh:
            // TODO: Implement crypto handshake (Phase 5)
            regs->Rax = HV_SUCCESS;
            regs->Rbx = 0x1234567890ABCDEFULL;  // Temp session token
            break;

        default:
            regs->Rax = static_cast<UINT64>(HV_NOT_SUPPORTED);
            break;
    }

    vcpu->GuestVmcb.State.Rip += 3;  // VMCALL is 3 bytes
    return true;
}

// ============================================================================
//  MSR Exit Handler
// ============================================================================

bool SvmHal::HandleMsrExit(VcpuData* vcpu, GuestRegisters* regs, bool isWrite) {
    UINT32 msrIndex = static_cast<UINT32>(regs->Rcx);

    if (isWrite) {
        UINT64 value = (regs->Rdx << 32) | (regs->Rax & 0xFFFFFFFF);
        AsmWriteMsr(msrIndex, value);
    } else {
        UINT64 value = AsmReadMsr(msrIndex);
        regs->Rax = value & 0xFFFFFFFF;
        regs->Rdx = value >> 32;
    }

    vcpu->GuestVmcb.State.Rip += 2;
    return true;
}

// ============================================================================
//  NPT Fault Handler
// ============================================================================

bool SvmHal::HandleNpfExit(VcpuData* vcpu, GuestRegisters* regs) {
    UINT64 faultAddress = vcpu->GuestVmcb.Control.ExitInfo2;
    UINT64 errorCode = vcpu->GuestVmcb.Control.ExitInfo1;

    // TODO: Implement page protection violation handling
    // For now, inject #PF to guest
    (void)faultAddress;
    (void)errorCode;
    (void)regs;

    return true;
}

// ============================================================================
//  I/O Exit Handler (for USB monitoring)
// ============================================================================

bool SvmHal::HandleIoExit(VcpuData* vcpu, GuestRegisters* regs) {
    // TODO: Implement I/O port intercept for USB controllers
    (void)vcpu;
    (void)regs;
    return true;
}

// ============================================================================
//  C Linkage Entry Point (called from ASM)
// ============================================================================

} // namespace aegis::svm

// Global C entry point called from svm_ops.asm
extern "C" bool HandleVmExitSvm(
    aegis::svm::VcpuData* vcpu,
    aegis::GuestRegisters* regs
) {
    // Use the global instance set during SvmHal construction
    if (!aegis::svm::g_SvmInstance) {
        return false;  // Fatal: no backend initialized
    }
    return aegis::svm::g_SvmInstance->HandleVmExit(vcpu, regs);
}

// Factory function
namespace aegis {

IHypervisorBackend* CreateHypervisorBackend(CpuVendor vendor) {
    switch (vendor) {
        case CpuVendor::AMD:
            return new svm::SvmHal();
        // case CpuVendor::Intel:
        //     return new vmx::VmxHal();  // Phase 8
        default:
            return nullptr;
    }
}

} // namespace aegis
