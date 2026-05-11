/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * stealth.cpp — Anti-detection engine.
 *               Hides hypervisor presence from anti-cheat (Vanguard, EAC, BattlEye)
 *               and security tools that scan for virtualization.
 */

#include "../../../common/include/types.h"
#include "../../../common/include/aegis_config.h"
#include "../../hal/amd/svm_hal.h"

namespace aegis::stealth {

// ============================================================================
//  TSC Calibration
//  Measures the average VM-Exit overhead in TSC cycles so we can
//  subtract it from RDTSC/RDTSCP results, preventing timing-based detection.
// ============================================================================

static UINT64 g_TscExitOverhead = 0;
static bool   g_Calibrated = false;

/// Read TSC via inline assembly
static inline UINT64 ReadTsc() {
    UINT32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<UINT64>(hi) << 32) | lo;
}

/**
 * Calibrate TSC offset by measuring VM-Exit round-trip time.
 * Should be called during hypervisor init on the BSP.
 * Takes the median of multiple measurements to filter noise.
 */
void CalibrateTscOffset() {
    constexpr UINT32 SAMPLES = 16;
    UINT64 measurements[SAMPLES];
    
    for (UINT32 i = 0; i < SAMPLES; i++) {
        UINT64 before = ReadTsc();
        // Force a VM-Exit (CPUID is the cheapest)
        UINT32 eax, ebx, ecx, edx;
        asm volatile("cpuid" 
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(0));
        UINT64 after = ReadTsc();
        measurements[i] = after - before;
    }
    
    // Simple bubble sort for median
    for (UINT32 i = 0; i < SAMPLES - 1; i++) {
        for (UINT32 j = 0; j < SAMPLES - i - 1; j++) {
            if (measurements[j] > measurements[j+1]) {
                UINT64 tmp = measurements[j];
                measurements[j] = measurements[j+1];
                measurements[j+1] = tmp;
            }
        }
    }
    
    // Use median value
    g_TscExitOverhead = measurements[SAMPLES / 2];
    g_Calibrated = true;
}

UINT64 GetTscOffset() {
    return g_Calibrated ? g_TscExitOverhead : 0;
}

// ============================================================================
//  CPUID Stealth Filters
//  Applied during CPUID VM-Exit handling to mask virtualization indicators.
// ============================================================================

/**
 * Filter CPUID results to hide hypervisor presence.
 * Called from the VM-Exit CPUID handler after executing real CPUID.
 * 
 * @param leaf    CPUID leaf number
 * @param subleaf CPUID sub-leaf
 * @param eax/ebx/ecx/edx — CPUID results to filter (modified in-place)
 */
void FilterCpuid(UINT32 leaf, UINT32 subleaf,
                 UINT32& eax, UINT32& ebx, UINT32& ecx, UINT32& edx) {
    (void)subleaf;
    
    switch (leaf) {
        case 0x00000001:
            // Bit 31 of ECX: Hypervisor Present — MUST hide from anti-cheat
            if (config::STEALTH_HIDE_CPUID_HV_BIT) {
                ecx &= ~(1u << 31);
            }
            // Bit 5 of ECX: VMX — hide to prevent detection tools
            if (config::STEALTH_HIDE_CPUID_VIRT_BIT) {
                ecx &= ~(1u << 5);
            }
            break;
            
        case 0x40000000:
            // Hypervisor vendor leaf — return zeros (no hypervisor)
            // Anti-cheat tools like Vanguard check this leaf
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
            break;
            
        case 0x40000001:
        case 0x40000002:
        case 0x40000003:
        case 0x40000004:
        case 0x40000005:
        case 0x40000006:
            // All hypervisor info leaves — return zeros
            eax = 0;
            ebx = 0;
            ecx = 0;
            edx = 0;
            break;
            
        case 0x80000001:
            // AMD: Bit 2 of ECX = SVM — hide
            if (config::STEALTH_HIDE_CPUID_VIRT_BIT) {
                ecx &= ~(1u << 2);
            }
            break;
    }
}

// ============================================================================
//  MSR Stealth Filters
//  Prevent detection via MSR reads that reveal virtualization state.
// ============================================================================

/**
 * Filter MSR read results to hide SVM/VMX indicators.
 * Returns true if the MSR was filtered (caller should use filtered value).
 * Returns false if the MSR should be passed through normally.
 */
bool FilterMsrRead(UINT32 msrIndex, UINT64& value) {
    switch (msrIndex) {
        case 0xC0010114:  // VM_CR — hide SVM lock status
            // Clear SVM_DISABLE and SVML bits to look like SVM isn't active
            value &= ~((1ULL << 3) | (1ULL << 4));
            return true;
            
        case 0xC0000080:  // EFER — hide SVME bit
            value &= ~(1ULL << 12);  // Clear SVME
            return true;
            
        case 0x3A:  // IA32_FEATURE_CONTROL (Intel) — hide VMX enabled
            value &= ~((1ULL << 0) | (1ULL << 2));  // Clear lock + VMX
            return true;
            
        default:
            return false;
    }
}

// ============================================================================
//  Timing attack mitigation
//  Adjusts TSC values in RDTSC/RDTSCP exits to hide VM-Exit overhead.
// ============================================================================

/**
 * Adjust a TSC value by subtracting accumulated VM-Exit overhead.
 * This prevents timing-based hypervisor detection where tools measure
 * RDTSC → CPUID → RDTSC and look for elevated cycle counts.
 */
UINT64 AdjustTsc(UINT64 rawTsc, UINT64 exitCount) {
    if (!config::STEALTH_TSC_OFFSETTING || !g_Calibrated) {
        return rawTsc;
    }
    
    // Subtract estimated overhead for all exits that occurred
    UINT64 overhead = exitCount * g_TscExitOverhead;
    if (overhead > rawTsc) return rawTsc;  // Underflow protection
    return rawTsc - overhead;
}

} // namespace aegis::stealth
