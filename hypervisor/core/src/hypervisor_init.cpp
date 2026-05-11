/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * hypervisor_init.cpp — Main hypervisor initialization entry point.
 *                       Called from UEFI boot module after hardware probe.
 *                       Orchestrates: HAL creation → NPT setup → Per-CPU virtualization.
 */

#include "../../hal/hal_interface.h"
#include "../../hal/amd/svm_hal.h"
#include "../../../common/include/aegis_config.h"
#include "../../../common/include/aegis_hypercalls.h"

#if AEGIS_ENV_UEFI
#include <Uefi.h>
#include <Pi/PiMultiPhase.h>
#include <Protocol/MpService.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#endif

using namespace aegis;

// ============================================================================
//  Global hypervisor state
// ============================================================================

static IHypervisorBackend* g_Backend = nullptr;
static UINT32 g_CpuCount = 0;
static VcpuData* g_Vcpus[config::MAX_PROCESSOR_COUNT] = {};
static HardwareCapabilities g_HwCaps = {};

// ============================================================================
//  Per-AP (Application Processor) virtualization callback
// ============================================================================

#if AEGIS_ENV_UEFI

/// Data passed to each AP for virtualization
struct ApVirtualizeContext {
    IHypervisorBackend* Backend;
    CpuIndex            Index;
    HvStatus            Result;
    VcpuData*           Vcpu;
};

/// Callback executed on each AP via MP Services Protocol
static VOID EFIAPI ApVirtualizeCallback(VOID* context) {
    auto* ctx = static_cast<ApVirtualizeContext*>(context);
    
    // Initialize per-CPU structures
    ctx->Result = ctx->Backend->InitializeCpu(ctx->Index, &ctx->Vcpu);
    if (HvIsError(ctx->Result)) return;
    
    // Virtualize this CPU — enters the VMRUN loop
    // This function only returns when the hypervisor shuts down
    ctx->Result = ctx->Backend->VirtualizeCpu(ctx->Vcpu);
}

/// Get processor count via UEFI MP Services Protocol
static UINT32 GetProcessorCount(EFI_SYSTEM_TABLE* ST) {
    EFI_MP_SERVICES_PROTOCOL* mpServices = nullptr;
    EFI_GUID mpGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    
    EFI_STATUS status = ST->BootServices->LocateProtocol(
        &mpGuid, nullptr, (VOID**)&mpServices);
    
    if (EFI_ERROR(status) || !mpServices) {
        return 1;  // Assume single processor if MP Services unavailable
    }
    
    UINTN numProc = 0, numEnabled = 0;
    status = mpServices->GetNumberOfProcessors(mpServices, &numProc, &numEnabled);
    
    if (EFI_ERROR(status)) return 1;
    return static_cast<UINT32>(numEnabled);
}

/// Start a function on a specific AP
static EFI_STATUS StartOnAP(
    EFI_SYSTEM_TABLE* ST, 
    UINT32 apIndex,
    EFI_AP_PROCEDURE proc,
    VOID* context
) {
    EFI_MP_SERVICES_PROTOCOL* mpServices = nullptr;
    EFI_GUID mpGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
    
    EFI_STATUS status = ST->BootServices->LocateProtocol(
        &mpGuid, nullptr, (VOID**)&mpServices);
    if (EFI_ERROR(status)) return status;
    
    return mpServices->StartupThisAP(
        mpServices,
        proc,
        apIndex,
        nullptr,    // WaitEvent (synchronous)
        0,          // Timeout (infinite)
        context,
        nullptr     // Finished
    );
}

#endif // AEGIS_ENV_UEFI

// ============================================================================
//  Main hypervisor initialization — called from boot/main.cpp
// ============================================================================

extern "C" HvStatus AegisHypervisorInit(
    EFI_HANDLE        ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable,
    const HardwareCapabilities* hwCaps
) {
    (void)ImageHandle;
    
    if (!hwCaps) return HV_INVALID_PARAMETER;
    g_HwCaps = *hwCaps;
    
    // ── Step 1: Create the appropriate backend ─────────────────────────
    g_Backend = CreateHypervisorBackend(hwCaps->Vendor);
    if (!g_Backend) {
        return HV_NOT_SUPPORTED;
    }
    
    // Print backend info
    SystemTable->ConOut->OutputString(SystemTable->ConOut,
        (CHAR16*)L"  Backend: ");
    // Simple ASCII to CHAR16 print
    const char* name = g_Backend->GetBackendName();
    CHAR16 nameBuf[64];
    for (int i = 0; name[i] && i < 63; i++) {
        nameBuf[i] = (CHAR16)name[i];
        nameBuf[i+1] = 0;
    }
    SystemTable->ConOut->OutputString(SystemTable->ConOut, nameBuf);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, (CHAR16*)L"\r\n");
    
    // ── Step 2: Setup NPT/EPT identity mapping ────────────────────────
    HvStatus status = g_Backend->SetupIdentityNpt(hwCaps->MaxPhysAddrBits);
    if (HvIsError(status)) {
        return status;
    }
    
    SystemTable->ConOut->OutputString(SystemTable->ConOut,
        (CHAR16*)L"  NPT: Identity mapping established\r\n");
    
    // ── Step 3: Get CPU count ──────────────────────────────────────────
    g_CpuCount = GetProcessorCount(SystemTable);
    if (g_CpuCount > config::MAX_PROCESSOR_COUNT) {
        g_CpuCount = config::MAX_PROCESSOR_COUNT;
    }
    
    // Print CPU count
    CHAR16 cpuBuf[4] = {(CHAR16)(L'0' + g_CpuCount / 10), 
                         (CHAR16)(L'0' + g_CpuCount % 10), 0, 0};
    if (g_CpuCount < 10) { cpuBuf[0] = (CHAR16)(L'0' + g_CpuCount); cpuBuf[1] = 0; }
    SystemTable->ConOut->OutputString(SystemTable->ConOut,
        (CHAR16*)L"  CPUs: ");
    SystemTable->ConOut->OutputString(SystemTable->ConOut, cpuBuf);
    SystemTable->ConOut->OutputString(SystemTable->ConOut,
        (CHAR16*)L" logical processors\r\n");
    
    // ── Step 4: Initialize and virtualize BSP (Bootstrap Processor) ───
    status = g_Backend->InitializeCpu(0, &g_Vcpus[0]);
    if (HvIsError(status)) {
        return status;
    }
    
    SystemTable->ConOut->OutputString(SystemTable->ConOut,
        (CHAR16*)L"  BSP: Initialized\r\n");
    
    // ── Step 5: Initialize and virtualize APs ──────────────────────────
    for (UINT32 i = 1; i < g_CpuCount; i++) {
        ApVirtualizeContext ctx = {};
        ctx.Backend = g_Backend;
        ctx.Index = i;
        
        EFI_STATUS efiStatus = StartOnAP(
            SystemTable, i, ApVirtualizeCallback, &ctx);
        
        if (EFI_ERROR(efiStatus) || HvIsError(ctx.Result)) {
            // AP failed — continue with remaining CPUs
            SystemTable->ConOut->OutputString(SystemTable->ConOut,
                (CHAR16*)L"  WARNING: AP virtualization failed\r\n");
            continue;
        }
        
        g_Vcpus[i] = ctx.Vcpu;
    }
    
    // ── Step 6: Virtualize BSP (this enters the VMRUN loop) ────────────
    // NOTE: After this call, we are inside the hypervisor.
    // The function returns when execution continues as a guest,
    // but the hypervisor is now running underneath.
    SystemTable->ConOut->OutputString(SystemTable->ConOut,
        (CHAR16*)L"  BSP: Entering hypervisor mode...\r\n");
    
    status = g_Backend->VirtualizeCpu(g_Vcpus[0]);
    if (HvIsError(status)) {
        return status;
    }
    
    // If we reach here, the hypervisor is active and we're now
    // running as a guest. Execution continues normally.
    return HV_SUCCESS;
}

// ============================================================================
//  Hypervisor shutdown (called via hypercall or emergency)
// ============================================================================

extern "C" HvStatus AegisHypervisorShutdown() {
    if (!g_Backend) return HV_NOT_INITIALIZED;
    
    // Devirtualize all CPUs in reverse order
    for (INT32 i = static_cast<INT32>(g_CpuCount) - 1; i >= 0; i--) {
        if (g_Vcpus[i]) {
            g_Backend->DevirtualizeCpu(g_Vcpus[i]);
            g_Vcpus[i] = nullptr;
        }
    }
    
    delete g_Backend;
    g_Backend = nullptr;
    
    return HV_SUCCESS;
}
