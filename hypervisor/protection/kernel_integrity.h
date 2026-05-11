/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * kernel_integrity.h — Windows kernel code integrity monitoring via NPT.
 *                      Detects unauthorized kernel memory modifications (rootkits).
 */

#pragma once

#include "../../../common/include/types.h"
#include "../../../common/include/aegis_status.h"

namespace aegis::protection {

// ============================================================================
//  Kernel Region Descriptor
// ============================================================================

struct KernelRegion {
    Gpa     PhysBase;        // Physical address of the region
    UINT64  Size;            // Size in bytes
    UINT8*  OriginalHash;    // SHA-256 of the original content
    BOOLEAN IsCode;          // true = executable code, false = data
    BOOLEAN IsProtected;     // Currently under NPT protection
};

// ============================================================================
//  Kernel Integrity Monitor
// ============================================================================

class KernelIntegrity {
public:
    /// Initialize: capture baseline hashes of critical kernel regions
    static HvStatus Initialize();
    
    /**
     * Register a kernel region for monitoring.
     * Sets NPT permissions to Read+Execute (no Write) for code regions.
     * Any write attempt triggers an NPT fault → violation alert.
     * 
     * @param physBase  Physical address of the region
     * @param size      Size in bytes
     * @param isCode    true if executable code (will be set RX-only)
     */
    static HvStatus ProtectRegion(Gpa physBase, UINT64 size, BOOLEAN isCode);
    
    /**
     * Handle an NPT violation on a protected kernel region.
     * Called from the NPF exit handler.
     * 
     * @param faultAddr  Faulting guest physical address
     * @param isWrite    Was this a write access?
     * @return           true if violation was handled (blocked), false if benign
     */
    static bool HandleViolation(Gpa faultAddr, BOOLEAN isWrite);
    
    /// Perform periodic integrity scan (compare hashes)
    static HvStatus PeriodicScan();
    
    /// Get violation count since last reset
    static UINT64 GetViolationCount();
    
    /// Enable/disable kernel integrity monitoring
    static void SetEnabled(BOOLEAN enabled);
    static BOOLEAN IsEnabled();

private:
    static constexpr UINT32 MAX_REGIONS = 64;
    static KernelRegion s_Regions[MAX_REGIONS];
    static UINT32 s_RegionCount;
    static UINT64 s_ViolationCount;
    static BOOLEAN s_Enabled;
};

} // namespace aegis::protection
