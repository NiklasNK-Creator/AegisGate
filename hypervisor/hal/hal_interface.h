/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * hal_interface.h — Abstract Hardware Abstraction Layer interface.
 *                   Provides a vendor-agnostic API for Intel VMX and AMD SVM backends.
 *                   The hypervisor core programs against this interface exclusively.
 */

#pragma once

#include "../../common/include/types.h"
#include "../../common/include/aegis_status.h"

namespace aegis {

// ============================================================================
//  Forward declarations
// ============================================================================

struct VcpuData;  // Defined per-backend (vmx or svm specific)

// ============================================================================
//  Abstract HAL Interface
// ============================================================================

class IHypervisorBackend {
public:
    virtual ~IHypervisorBackend() = default;

    // ── Lifecycle ──────────────────────────────────────────────────────────

    /**
     * Initialize backend for a specific CPU core.
     * Allocates per-CPU structures (VMCS/VMCB, host stack, etc.)
     * Must be called ON the target CPU core.
     * 
     * @param cpuIndex  Logical processor index (0 = BSP)
     * @param vcpu      Output: pointer to allocated VCPU data
     */
    virtual HvStatus InitializeCpu(CpuIndex cpuIndex, VcpuData** vcpu) = 0;

    /**
     * Enter VMX/SVM root mode and virtualize the current CPU.
     * After this call, the calling code continues to run but is now
     * in VMX/SVM root mode (Ring -1), and the "guest" state is set up
     * to resume execution at the return address.
     * 
     * @param vcpu  VCPU data for this CPU core
     */
    virtual HvStatus VirtualizeCpu(VcpuData* vcpu) = 0;

    /**
     * Exit VMX/SVM root mode and return CPU to native operation.
     * Used for clean hypervisor shutdown.
     */
    virtual HvStatus DevirtualizeCpu(VcpuData* vcpu) = 0;

    // ── Nested Page Tables (NPT/EPT) ──────────────────────────────────────

    /**
     * Set up identity-mapped nested page tables covering all physical memory.
     * Guest Physical Address = Host Physical Address.
     * Uses 2MB large pages for performance.
     * 
     * @param maxPhysAddrBits  Physical address width (from CPUID)
     */
    virtual HvStatus SetupIdentityNpt(UINT32 maxPhysAddrBits) = 0;

    /**
     * Modify permissions on a specific guest physical page.
     * Used for memory protection (e.g., make kernel code read+execute only).
     * 
     * @param guestPhys  Guest physical address (page-aligned)
     * @param perms      New permissions (Read/Write/Execute flags)
     */
    virtual HvStatus SetPagePermissions(Gpa guestPhys, MemPermissions perms) = 0;

    /**
     * Invalidate NPT/EPT TLB entries.
     * Must be called after modifying page table entries.
     */
    virtual HvStatus InvalidateNpt() = 0;

    /**
     * Get the NPT/EPT root page table physical address.
     * Needed for VMCB/VMCS configuration.
     */
    virtual Hpa GetNptRoot() const = 0;

    // ── VM-Exit Handling ───────────────────────────────────────────────────

    /**
     * Handle a VM-Exit. Called from the ASM exit stub after registers are saved.
     * Dispatches to the appropriate handler based on exit reason.
     * 
     * @param vcpu  VCPU data for this CPU
     * @param regs  Guest register state (saved by ASM stub)
     * @return      true if guest should resume, false if hypervisor should shut down
     */
    virtual bool HandleVmExit(VcpuData* vcpu, GuestRegisters* regs) = 0;

    // ── Information ────────────────────────────────────────────────────────

    virtual const char* GetBackendName() const = 0;
    virtual VirtTech GetVirtTech() const = 0;
};

// ============================================================================
//  Factory: Create the appropriate backend based on CPU vendor
// ============================================================================

/**
 * Detect CPU vendor and create the matching backend.
 * Returns nullptr if no virtualization support is available.
 * Caller owns the returned pointer.
 */
IHypervisorBackend* CreateHypervisorBackend(CpuVendor vendor);

} // namespace aegis
