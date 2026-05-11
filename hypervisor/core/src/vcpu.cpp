/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vcpu.cpp — VCPU manager implementation.
 */

#include "vcpu.h"

namespace aegis {

VcpuManager& VcpuManager::Instance() {
    static VcpuManager instance;
    return instance;
}

HvStatus VcpuManager::RegisterVcpu(CpuIndex index, VcpuData* vcpu) {
    if (index >= config::MAX_PROCESSOR_COUNT) return HV_INVALID_PARAMETER;
    if (!vcpu) return HV_INVALID_PARAMETER;
    
    m_Vcpus[index] = vcpu;
    if (index >= m_Count) m_Count = index + 1;
    return HV_SUCCESS;
}

VcpuData* VcpuManager::GetVcpu(CpuIndex index) {
    if (index >= config::MAX_PROCESSOR_COUNT) return nullptr;
    return m_Vcpus[index];
}

UINT32 VcpuManager::GetActiveCount() const {
    UINT32 count = 0;
    for (UINT32 i = 0; i < m_Count; i++) {
        if (m_Vcpus[i]) count++;
    }
    return count;
}

VcpuData* VcpuManager::GetCurrentVcpu() {
    // In SVM, we can use the GS base or a per-CPU variable
    // For now, use CPU index 0 (BSP) as default
    // TODO: Use RDTSCP (ECX returns processor ID on AMD) or APIC ID
    return m_Vcpus[0];
}

} // namespace aegis
