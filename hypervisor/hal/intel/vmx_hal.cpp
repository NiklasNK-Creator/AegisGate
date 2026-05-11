/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vmx_hal.cpp — Intel VT-x (VMX) backend implementation.
 */

#include "vmx_hal.h"
#include "../../../common/include/aegis_status.h"
#include "../../core/src/vcpu.h"

namespace aegis::vmx {

// Global instance pointer for ASM callbacks
static VmxHal* g_VmxInstance = nullptr;

VmxHal::VmxHal() : m_CpuCount(0), m_EptRoot(0), m_Initialized(false) {
    for (UINT32 i = 0; i < config::MAX_PROCESSOR_COUNT; i++) {
        m_Vcpus[i] = nullptr;
    }
}

VmxHal::~VmxHal() {
    // Cleanup handled by DevirtualizeCpu
}

HvStatus VmxHal::InitializeCpu(CpuIndex cpuIndex, VcpuData** vcpu) {
    if (!vcpu) return HV_INVALID_PARAMETER;
    if (cpuIndex >= config::MAX_PROCESSOR_COUNT) return HV_INVALID_PARAMETER;
    
    // Allocate memory for VMX VCPU Data
    // TODO: Use actual memory allocator
    // auto* vmxVcpu = new VmxVcpuData();
    // m_Vcpus[cpuIndex] = vmxVcpu;
    // *vcpu = reinterpret_cast<VcpuData*>(vmxVcpu);
    
    g_VmxInstance = this;
    
    return HV_SUCCESS;
}

HvStatus VmxHal::VirtualizeCpu(VcpuData* vcpu) {
    if (!vcpu) return HV_INVALID_PARAMETER;
    auto* vmxVcpu = reinterpret_cast<VmxVcpuData*>(vcpu);
    
    // 1. Enable VMX operation in CR4
    UINT64 cr4 = AsmReadMsr(0); // TODO: Read actual CR4
    // cr4 |= (1ULL << 13); // VMXE
    // TODO: Write actual CR4
    
    // 2. Adjust CR0 and CR4 fixed bits
    // 3. Execute VMXON
    // UINT64 status = AsmVmxon(reinterpret_cast<UINT64*>(&vmxVcpu->VmxonRegion));
    
    // 4. Load VMCS
    // 5. Setup VMCS fields
    // SetupVmcsControlFields(vmxVcpu);
    // SetupVmcsHostState(vmxVcpu);
    // SetupVmcsGuestState(vmxVcpu);
    
    // 6. Launch VM
    // AsmVmlaunch();
    
    return HV_NOT_SUPPORTED; // Stub for now
}

HvStatus VmxHal::DevirtualizeCpu(VcpuData* vcpu) {
    (void)vcpu;
    return HV_NOT_SUPPORTED;
}

HvStatus VmxHal::SetupIdentityNpt(UINT32 maxPhysAddrBits) {
    (void)maxPhysAddrBits;
    // TODO: Implement EPT setup
    return HV_NOT_SUPPORTED;
}

HvStatus VmxHal::SetPagePermissions(Gpa guestPhys, MemPermissions perms) {
    (void)guestPhys; (void)perms;
    return HV_NOT_SUPPORTED;
}

HvStatus VmxHal::InvalidateNpt() {
    return HV_NOT_SUPPORTED;
}

Hpa VmxHal::GetNptRoot() const {
    return m_EptRoot;
}

bool VmxHal::HandleVmExit(VcpuData* vcpu, GuestRegisters* regs) {
    if (!vcpu || !regs) return false; // Stop hypervisor
    
    auto* vmxVcpu = reinterpret_cast<VmxVcpuData*>(vcpu);
    UINT64 exitReason = AsmVmread(static_cast<UINT64>(VmcsField::VmExitReason)) & 0xFFFF;
    
    bool continueVm = true;
    
    switch (static_cast<VmxExitReason>(exitReason)) {
        case VmxExitReason::Cpuid:
            continueVm = HandleCpuidExit(vmxVcpu, regs);
            break;
        case VmxExitReason::MsrRead:
            continueVm = HandleMsrReadExit(vmxVcpu, regs);
            break;
        case VmxExitReason::MsrWrite:
            continueVm = HandleMsrWriteExit(vmxVcpu, regs);
            break;
        case VmxExitReason::Vmcall:
            continueVm = HandleVmcallExit(vmxVcpu, regs);
            break;
        case VmxExitReason::EptViolation:
            continueVm = HandleEptViolation(vmxVcpu, regs);
            break;
        default:
            // Unhandled exit
            break;
    }
    
    // Advance RIP for non-faulting instructions
    if (continueVm) {
        UINT64 instrLen = AsmVmread(static_cast<UINT64>(VmcsField::VmExitInstrLen));
        UINT64 guestRip = AsmVmread(static_cast<UINT64>(VmcsField::GuestRip));
        AsmVmwrite(static_cast<UINT64>(VmcsField::GuestRip), guestRip + instrLen);
    }
    
    return continueVm;
}

// ----------------------------------------------------------------------------
// Internal Helpers
// ----------------------------------------------------------------------------

UINT32 VmxHal::AdjustControls(UINT32 desired, UINT32 msrAddr) {
    UINT64 msrValue = AsmReadMsr(msrAddr);
    desired &= static_cast<UINT32>(msrValue >> 32); // High 32 bits = allowed 1s
    desired |= static_cast<UINT32>(msrValue);       // Low 32 bits = forced 1s
    return desired;
}

void VmxHal::SetupVmcsControlFields(VmxVcpuData* vcpu) {
    (void)vcpu;
}

void VmxHal::SetupVmcsGuestState(VmxVcpuData* vcpu) {
    (void)vcpu;
}

void VmxHal::SetupVmcsHostState(VmxVcpuData* vcpu) {
    (void)vcpu;
}

bool VmxHal::HandleCpuidExit(VmxVcpuData* vcpu, GuestRegisters* regs) {
    (void)vcpu; (void)regs;
    return true; // Continue
}

bool VmxHal::HandleMsrReadExit(VmxVcpuData* vcpu, GuestRegisters* regs) {
    (void)vcpu; (void)regs;
    return true;
}

bool VmxHal::HandleMsrWriteExit(VmxVcpuData* vcpu, GuestRegisters* regs) {
    (void)vcpu; (void)regs;
    return true;
}

bool VmxHal::HandleVmcallExit(VmxVcpuData* vcpu, GuestRegisters* regs) {
    (void)vcpu; (void)regs;
    return true;
}

bool VmxHal::HandleEptViolation(VmxVcpuData* vcpu, GuestRegisters* regs) {
    (void)vcpu; (void)regs;
    return true;
}

} // namespace aegis::vmx
