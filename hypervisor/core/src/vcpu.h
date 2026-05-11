/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vcpu.h — Per-CPU virtual processor management.
 */

#pragma once

#include "../../../common/include/types.h"
#include "../../../common/include/aegis_status.h"
#include "../../../common/include/aegis_config.h"

namespace aegis {

// ============================================================================
//  VCPU Manager — tracks all virtualized CPUs
// ============================================================================

class VcpuManager {
public:
    static VcpuManager& Instance();

    HvStatus RegisterVcpu(CpuIndex index, VcpuData* vcpu);
    VcpuData* GetVcpu(CpuIndex index);
    UINT32 GetActiveCount() const;
    
    /// Get VCPU for the currently executing CPU
    VcpuData* GetCurrentVcpu();

private:
    VcpuManager() : m_Count(0) {
        for (UINT32 i = 0; i < config::MAX_PROCESSOR_COUNT; i++)
            m_Vcpus[i] = nullptr;
    }

    VcpuData* m_Vcpus[config::MAX_PROCESSOR_COUNT];
    UINT32 m_Count;
};

// ============================================================================
//  Performance counters per VCPU
// ============================================================================

struct VcpuStats {
    UINT64 TotalExits;
    UINT64 CpuidExits;
    UINT64 VmcallExits;
    UINT64 MsrExits;
    UINT64 NpfExits;
    UINT64 IoExits;
    UINT64 LastExitTsc;       // TSC at last VM-Exit (for latency measurement)
    UINT64 TotalExitCycles;   // Accumulated cycles in exit handling
};

} // namespace aegis
