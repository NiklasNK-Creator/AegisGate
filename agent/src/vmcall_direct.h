/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * vmcall_direct.h — Direct VMCALL from Ring 3 to Ring -1 (no kernel driver needed).
 */

#pragma once

#define _AEGISGATE_WIN 1
#include "../../common/include/types.h"
#include "../../common/include/aegis_hypercalls.h"
#include "../../common/include/aegis_status.h"

namespace aegis::agent {

// ============================================================================
//  VMCALL result from hypervisor
// ============================================================================

struct VmcallResult {
    UINT64 Status;   // RAX: HvStatus
    UINT64 Value1;   // RBX: return value 1
    UINT64 Value2;   // RCX: return value 2
};

// ============================================================================
//  Direct VMCALL Interface
// ============================================================================

/**
 * Execute a VMCALL instruction directly from Ring 3.
 * This works because VMCALL causes a VM-Exit regardless of current privilege level.
 * The hypervisor receives the call and checks authentication via session token.
 * 
 * @param hypercallId  Full hypercall ID (AEGIS_MAGIC | command)
 * @param param1       Parameter in RBX
 * @param param2       Parameter in RCX
 * @param token        Session token in RDX
 * @return             Result from hypervisor (RAX, RBX, RCX)
 */
VmcallResult DoVmcall(UINT64 hypercallId, UINT64 param1, UINT64 param2, UINT64 token);

/**
 * Check if AegisGate hypervisor is active by querying custom CPUID leaf.
 * @return true if hypervisor is running and responds with correct signature
 */
bool IsHypervisorActive();

/**
 * Get hypervisor version.
 * @return Version packed as (major << 16 | minor << 8 | patch), or 0 if not active
 */
UINT32 GetHypervisorVersion();

// ============================================================================
//  High-level Hypercall Wrappers
// ============================================================================

/// Perform initial handshake with hypervisor
HvStatus PerformHandshake(UINT64* outSessionToken);

/// Send heartbeat to keep session alive
HvStatus SendHeartbeat(UINT64 sessionToken);

/// Get hypervisor status
HvStatus QueryStatus(UINT64 sessionToken, HypervisorStatus* status);

/// Request hypervisor shutdown (requires confirmation code)
HvStatus RequestShutdown(UINT64 sessionToken);

} // namespace aegis::agent
