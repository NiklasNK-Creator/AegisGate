/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * kernel_integrity.cpp — Kernel code integrity monitoring implementation.
 */

#include "kernel_integrity.h"
#include "../../common/include/aegis_config.h"
#include "../hal/hal_interface.h"

namespace aegis::protection {

// Static members
KernelRegion KernelIntegrity::s_Regions[MAX_REGIONS] = {};
UINT32 KernelIntegrity::s_RegionCount = 0;
UINT64 KernelIntegrity::s_ViolationCount = 0;
BOOLEAN KernelIntegrity::s_Enabled = FALSE;

// ============================================================================
//  Initialization
// ============================================================================

HvStatus KernelIntegrity::Initialize() {
    s_Enabled = config::PROTECT_KERNEL_INTEGRITY_DEFAULT;
    s_RegionCount = 0;
    s_ViolationCount = 0;
    
    // Critical Windows kernel regions to protect:
    // 1. ntoskrnl.exe .text section (kernel code)
    // 2. hal.dll .text section
    // 3. CI.dll (Code Integrity module)
    // 4. SSDT (System Service Descriptor Table)
    // 5. IDT (Interrupt Descriptor Table)
    //
    // These addresses are discovered at runtime by scanning the
    // kernel's PE headers via guest physical memory access.
    // The Agent can also send region info via hypercall.
    
    return HV_SUCCESS;
}

// ============================================================================
//  Region Protection
// ============================================================================

HvStatus KernelIntegrity::ProtectRegion(Gpa physBase, UINT64 size, BOOLEAN isCode) {
    if (s_RegionCount >= MAX_REGIONS) return HV_OUT_OF_MEMORY;
    if (!s_Enabled) return HV_ALREADY_DISABLED;
    
    auto& region = s_Regions[s_RegionCount];
    region.PhysBase = physBase;
    region.Size = size;
    region.IsCode = isCode;
    region.IsProtected = TRUE;
    region.OriginalHash = nullptr;  // TODO: Compute and store SHA-256
    
    // Set NPT permissions:
    // Code regions: Read + Execute, NO Write
    // This means any attempt to patch kernel code triggers an NPT fault
    MemPermissions perms;
    if (isCode) {
        perms = MemPermissions::ReadExecute;   // RX only — blocks code patching
    } else {
        perms = MemPermissions::Read;          // Read-only data protection
    }
    
    // Apply NPT permissions for each page in the region
    UINT64 numPages = (size + 4095) / 4096;
    for (UINT64 i = 0; i < numPages; i++) {
        Gpa pageAddr = physBase + (i * 4096);
        // TODO: Call backend->SetPagePermissions(pageAddr, perms)
        // This requires splitting 2MB NPT pages into 4KB pages
        // for the specific kernel region
        (void)pageAddr;
        (void)perms;
    }
    
    s_RegionCount++;
    return HV_SUCCESS;
}

// ============================================================================
//  Violation Handler
// ============================================================================

bool KernelIntegrity::HandleViolation(Gpa faultAddr, BOOLEAN isWrite) {
    if (!s_Enabled) return false;
    
    // Find which protected region was accessed
    for (UINT32 i = 0; i < s_RegionCount; i++) {
        auto& region = s_Regions[i];
        if (!region.IsProtected) continue;
        
        if (faultAddr >= region.PhysBase &&
            faultAddr < region.PhysBase + region.Size) {
            
            if (isWrite) {
                // VIOLATION: Something tried to write to protected kernel code!
                s_ViolationCount++;
                
                // Log the violation (via serial debug or shared memory)
                // TODO: Detailed logging with RIP, faulting instruction, caller
                
                // Decision: Block the write
                // The guest will receive a #PF or the write is silently ignored
                // depending on our response:
                //   - Return true = we handled it (write blocked)
                //   - Inject #GP into guest for the offending code
                
                return true;  // Write blocked
            }
            
            // Read access to protected region — this shouldn't fault
            // unless we misconfigured NPT. Allow it.
            return false;
        }
    }
    
    return false;  // Not a protected region — let normal NPF handling proceed
}

// ============================================================================
//  Periodic Integrity Scan
// ============================================================================

HvStatus KernelIntegrity::PeriodicScan() {
    if (!s_Enabled) return HV_ALREADY_DISABLED;
    
    // Walk all protected regions and re-hash their contents
    // Compare against the stored original hashes
    // If mismatch → rootkit/patch detected!
    
    for (UINT32 i = 0; i < s_RegionCount; i++) {
        auto& region = s_Regions[i];
        if (!region.IsProtected || !region.OriginalHash) continue;
        
        // Read the current content via guest physical address
        // SHA-256 hash it
        // Compare with OriginalHash
        // If different → VIOLATION
        
        // TODO: Implement actual hash comparison
        // This requires reading guest memory from the hypervisor context
        // which is directly accessible via the identity-mapped NPT
    }
    
    return HV_SUCCESS;
}

// ============================================================================
//  Accessors
// ============================================================================

UINT64 KernelIntegrity::GetViolationCount() { return s_ViolationCount; }
void KernelIntegrity::SetEnabled(BOOLEAN enabled) { s_Enabled = enabled; }
BOOLEAN KernelIntegrity::IsEnabled() { return s_Enabled; }

} // namespace aegis::protection
