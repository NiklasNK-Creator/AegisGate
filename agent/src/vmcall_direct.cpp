/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vmcall_direct.cpp — Direct VMCALL execution from Windows Ring 3.
 *                     Uses inline assembly / intrinsics to invoke VMCALL.
 */

#include "vmcall_direct.h"
#include <intrin.h>  // MSVC intrinsics

namespace aegis::agent {

// ============================================================================
//  Low-level VMCALL via inline assembly (MSVC x64)
// ============================================================================

// MSVC x64 doesn't support inline ASM, so we use a separate .asm file
// or the __vmx_vmcall intrinsic. However, __vmx_vmcall is only available
// in kernel mode. For user mode, we need a raw .asm stub.

// Declared in vmcall_stub.asm
extern "C" void AsmDoVmcall(
    UINT64 rax_val,   // Hypercall ID
    UINT64 rbx_val,   // Param 1
    UINT64 rcx_val,   // Param 2
    UINT64 rdx_val,   // Session token
    UINT64* out_rax,  // Return: status
    UINT64* out_rbx,  // Return: value 1
    UINT64* out_rcx   // Return: value 2
);

VmcallResult DoVmcall(UINT64 hypercallId, UINT64 param1, UINT64 param2, UINT64 token) {
    VmcallResult result = {};
    
    __try {
        AsmDoVmcall(
            hypercallId, param1, param2, token,
            &result.Status, &result.Value1, &result.Value2
        );
    } __except(1) {
        // VMCALL caused an exception — hypervisor is not active
        // This happens when no hypervisor is running (VMCALL = #UD)
        result.Status = static_cast<UINT64>(HV_NOT_INITIALIZED);
        result.Value1 = 0;
        result.Value2 = 0;
    }
    
    return result;
}

// ============================================================================
//  Hypervisor Detection via Custom CPUID Leaf
// ============================================================================

bool IsHypervisorActive() {
    int cpuInfo[4] = {};
    __cpuidex(cpuInfo, AEGIS_CPUID_SIGNATURE_LEAF, 0);
    
    return (static_cast<UINT32>(cpuInfo[0]) == AEGIS_CPUID_SIG_EAX &&
            static_cast<UINT32>(cpuInfo[1]) == AEGIS_CPUID_SIG_EBX &&
            static_cast<UINT32>(cpuInfo[2]) == AEGIS_CPUID_SIG_ECX);
}

UINT32 GetHypervisorVersion() {
    if (!IsHypervisorActive()) return 0;
    
    int cpuInfo[4] = {};
    __cpuidex(cpuInfo, AEGIS_CPUID_SIGNATURE_LEAF, 0);
    return static_cast<UINT32>(cpuInfo[3]);  // EDX = version
}

// ============================================================================
//  High-level Hypercall Wrappers
// ============================================================================

HvStatus PerformHandshake(UINT64* outSessionToken) {
    if (!outSessionToken) return HV_INVALID_PARAMETER;
    
    auto result = DoVmcall(
        MakeHypercallId(Hypercall::Handshake),
        0,  // TODO: pointer to handshake challenge
        0,
        0   // No session token yet
    );
    
    if (HvIsSuccess(static_cast<HvStatus>(result.Status))) {
        *outSessionToken = result.Value1;
    }
    
    return static_cast<HvStatus>(result.Status);
}

HvStatus SendHeartbeat(UINT64 sessionToken) {
    auto result = DoVmcall(
        MakeHypercallId(Hypercall::Heartbeat),
        0, 0, sessionToken
    );
    return static_cast<HvStatus>(result.Status);
}

HvStatus QueryStatus(UINT64 sessionToken, HypervisorStatus* status) {
    if (!status) return HV_INVALID_PARAMETER;
    
    auto result = DoVmcall(
        MakeHypercallId(Hypercall::GetStatus),
        0, 0, sessionToken
    );
    
    if (HvIsSuccess(static_cast<HvStatus>(result.Status))) {
        status->Active = static_cast<BOOLEAN>(result.Value1 & 1);
        status->StealthEnabled = static_cast<BOOLEAN>((result.Value1 >> 1) & 1);
        status->UptimeSeconds = result.Value2;
    }
    
    return static_cast<HvStatus>(result.Status);
}

HvStatus RequestShutdown(UINT64 sessionToken) {
    auto result = DoVmcall(
        MakeHypercallId(Hypercall::Shutdown),
        0xDEAD,  // Confirmation code
        0,
        sessionToken
    );
    return static_cast<HvStatus>(result.Status);
}

} // namespace aegis::agent
