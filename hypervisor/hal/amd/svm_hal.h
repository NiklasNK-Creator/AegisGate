/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * svm_hal.h — AMD SVM (Secure Virtual Machine) backend header.
 *             Implements IHypervisorBackend for AMD processors.
 */

#pragma once

#include "../hal_interface.h"
#include "vmcb_fields.h"
#include "../../../common/include/aegis_config.h"

namespace aegis::svm {

// ============================================================================
//  Per-CPU Data Structure for SVM
// ============================================================================

/// MSR Permission Map: 2 bits per MSR (read intercept, write intercept)
/// Total size: 8KB (2 pages) — covers all MSR ranges
struct alignas(4096) MsrPermissionMap {
    UINT8 Data[2 * 4096];  // 8KB
};

/// I/O Permission Map: 1 bit per I/O port (0 = no intercept, 1 = intercept)
/// 64KB address space / 8 bits per byte = 8KB + 1 extra byte
struct alignas(4096) IoPermissionMap {
    UINT8 Data[12 * 1024];  // 12KB (3 pages, AMD requires this alignment)
};

/// Per-CPU VCPU data for AMD SVM
struct alignas(4096) VcpuData {
    // Page-aligned structures (each must be on its own 4KB boundary)
    Vmcb              GuestVmcb;                                    // Guest VMCB (4KB)
    UINT8             HostSaveArea[4096];                            // Host state save (4KB)
    
    // MSR and I/O permission maps (shared across VCPUs to save memory)
    // These are pointers to shared allocations
    MsrPermissionMap* MsrPm;
    IoPermissionMap*  IoPm;
    
    // Host stack for VM-Exit handling
    AEGIS_ALIGN(16) UINT8 HostStack[config::VCPU_HOST_STACK_SIZE];  // 24KB
    
    // Metadata
    CpuIndex          Index;
    BOOLEAN           IsVirtualized;
    VirtTech          Tech;
    
    // NPT root (shared, same for all VCPUs)
    Hpa               NptRootCr3;
    
    // Original host state (saved before entering SVM)
    UINT64            OriginalEfer;
    UINT64            OriginalVmHsavePa;
    
    // Padding to ensure clean alignment
    UINT8             Padding[64];
};

// ============================================================================
//  ASM Function Declarations (svm_ops.asm)
// ============================================================================

extern "C" {
    /**
     * Enable SVM by setting EFER.SVME bit.
     */
    void AsmSvmEnable(void);
    
    /**
     * Disable SVM by clearing EFER.SVME bit.
     */
    void AsmSvmDisable(void);
    
    /**
     * Execute VMRUN instruction.
     * @param vmcbPhysAddr  Physical address of the VMCB
     */
    void AsmSvmVmrun(UINT64 vmcbPhysAddr);
    
    /**
     * Load host state from VMCB.
     * @param vmcbPhysAddr  Physical address of the VMCB
     */
    void AsmSvmVmload(UINT64 vmcbPhysAddr);
    
    /**
     * Save host state to VMCB.
     * @param vmcbPhysAddr  Physical address of the VMCB
     */
    void AsmSvmVmsave(UINT64 vmcbPhysAddr);
    
    /**
     * Set Global Interrupt Flag (re-enable interrupts after CLGI).
     */
    void AsmSvmStgi(void);
    
    /**
     * Clear Global Interrupt Flag (disable all interrupts including NMI).
     */
    void AsmSvmClgi(void);
    
    /**
     * Write the VM_HSAVE_PA MSR with the host save area physical address.
     */
    void AsmSetVmHsavePa(UINT64 physAddr);
    
    /**
     * Read the VM_HSAVE_PA MSR.
     */
    UINT64 AsmGetVmHsavePa(void);
    
    /**
     * The actual SVM guest entry/exit loop.
     * This function:
     *   1. Saves host GPRs
     *   2. Loads guest GPRs from VcpuData
     *   3. Executes VMRUN
     *   4. On #VMEXIT: saves guest GPRs, restores host GPRs
     *   5. Calls the C VM-Exit handler
     *   6. If handler returns "continue": loop back to step 2
     *   7. If handler returns "stop": return to caller
     * 
     * @param vcpu  Pointer to VcpuData (used for register save/restore area)
     */
    void AsmSvmEntryLoop(VcpuData* vcpu);
    
    /**
     * Get the physical address of a virtual address.
     * Uses the current page tables (CR3).
     */
    UINT64 AsmVirtToPhys(void* virtualAddr);
    
    /**
     * Read a Model-Specific Register.
     */
    UINT64 AsmReadMsr(UINT32 msrIndex);
    
    /**
     * Write a Model-Specific Register.
     */
    void AsmWriteMsr(UINT32 msrIndex, UINT64 value);
}

// ============================================================================
//  SVM HAL Implementation Class
// ============================================================================

class SvmHal final : public IHypervisorBackend {
public:
    SvmHal();
    ~SvmHal() override;

    // IHypervisorBackend interface
    HvStatus InitializeCpu(CpuIndex cpuIndex, VcpuData** vcpu) override;
    HvStatus VirtualizeCpu(VcpuData* vcpu) override;
    HvStatus DevirtualizeCpu(VcpuData* vcpu) override;
    
    HvStatus SetupIdentityNpt(UINT32 maxPhysAddrBits) override;
    HvStatus SetPagePermissions(Gpa guestPhys, MemPermissions perms) override;
    HvStatus InvalidateNpt() override;
    Hpa      GetNptRoot() const override;
    
    bool     HandleVmExit(VcpuData* vcpu, GuestRegisters* regs) override;
    
    const char* GetBackendName() const override { return "AMD SVM (AMD-V)"; }
    VirtTech    GetVirtTech() const override { return VirtTech::SVM; }

private:
    // Internal helpers
    void SetupVmcbControlArea(Vmcb* vmcb, VcpuData* vcpu);
    void SetupVmcbStateSave(Vmcb* vmcb);
    void SetupMsrPermissionMap(MsrPermissionMap* msrpm);
    void SetupIoPermissionMap(IoPermissionMap* iopm);
    
    // VM-Exit sub-handlers
    bool HandleCpuidExit(VcpuData* vcpu, GuestRegisters* regs);
    bool HandleMsrExit(VcpuData* vcpu, GuestRegisters* regs, bool isWrite);
    bool HandleVmcallExit(VcpuData* vcpu, GuestRegisters* regs);
    bool HandleNpfExit(VcpuData* vcpu, GuestRegisters* regs);
    bool HandleIoExit(VcpuData* vcpu, GuestRegisters* regs);
    
    // State
    VcpuData*          m_Vcpus[config::MAX_PROCESSOR_COUNT];
    UINT32             m_CpuCount;
    Hpa                m_NptRoot;
    MsrPermissionMap*  m_SharedMsrPm;
    IoPermissionMap*   m_SharedIoPm;
    bool               m_Initialized;
};

} // namespace aegis::svm
