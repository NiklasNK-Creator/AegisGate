/**
 * AegisGate Installer — Hardware Compatibility Check
 * Developer: Nik
 */

#include "hardware_check.h"
#include <intrin.h>
#include <string.h>
#include <stdio.h>

namespace aegis::installer {

// ============================================================================
//  CPU Detection
// ============================================================================

CpuVendor DetectCpuVendor(char vendorStr[13]) {
    int regs[4];
    __cpuid(regs, 0);
    memcpy(vendorStr + 0, &regs[1], 4); // EBX
    memcpy(vendorStr + 4, &regs[3], 4); // EDX
    memcpy(vendorStr + 8, &regs[2], 4); // ECX
    vendorStr[12] = '\0';

    if (memcmp(vendorStr, "AuthenticAMD", 12) == 0) return CpuVendor::AMD;
    if (memcmp(vendorStr, "GenuineIntel", 12) == 0) return CpuVendor::Intel;
    return CpuVendor::Unknown;
}

bool CheckSvmSupport(bool* disabledByBios) {
    *disabledByBios = false;
    int regs[4];

    // CPUID Fn8000_0001h ECX bit 2 = SVM
    __cpuid(regs, 0x80000001);
    if (!(regs[2] & (1 << 2))) return false; // No SVM

    // Check if SVM is locked off: MSR 0xC0010114 (VM_CR) bit 4
    // We can't read MSRs from user mode, but we can check CPUID
    // Fn8000_000Ah EDX bit 2 = SVML (SVM Lock)
    __cpuid(regs, 0x8000000A);
    // If SVML is set AND SVM is disabled in BIOS, the VM_CR.SVMDIS bit is set
    // We approximate: if CPUID says SVM exists but we can't use it later,
    // the BIOS has it disabled. We'll verify at runtime.

    return true;
}

bool CheckVtxSupport(bool* disabledByBios) {
    *disabledByBios = false;
    int regs[4];

    // CPUID leaf 1, ECX bit 5 = VMX
    __cpuid(regs, 1);
    if (!(regs[2] & (1 << 5))) return false;

    // Can't check IA32_FEATURE_CONTROL from user mode
    // Will be verified at boot time
    return true;
}

bool CheckAesNi() {
    int regs[4];
    __cpuid(regs, 1);
    return (regs[2] & (1 << 25)) != 0;
}

uint32_t GetPhysAddrBits() {
    int regs[4];
    __cpuid(regs, 0x80000008);
    return regs[0] & 0xFF; // EAX[7:0]
}

// ============================================================================
//  System Checks
// ============================================================================

BootMode DetectBootMode() {
    // GetFirmwareEnvironmentVariable succeeds only on UEFI systems
    DWORD dummy = 0;
    GetFirmwareEnvironmentVariableW(
        L"", L"{00000000-0000-0000-0000-000000000000}",
        &dummy, sizeof(dummy));

    DWORD err = GetLastError();
    // ERROR_INVALID_FUNCTION = Legacy BIOS
    // ERROR_NOACCESS or anything else = UEFI
    if (err == ERROR_INVALID_FUNCTION) return BootMode::LegacyBIOS;
    return BootMode::UEFI;
}

bool IsSecureBootEnabled() {
    DWORD val = 0;
    DWORD size = sizeof(val);

    // Read the SecureBoot UEFI variable
    DWORD result = GetFirmwareEnvironmentVariableW(
        L"SecureBoot",
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        &val, size);

    if (result > 0) return (val & 1) != 0;
    return false; // Can't read = assume not enabled
}

bool IsHyperVEnabled() {
    // Check bcdedit hypervisorlaunchtype
    // Also check if Hyper-V feature is installed
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, L"vmms", SERVICE_QUERY_STATUS);
    bool running = false;
    if (svc) {
        SERVICE_STATUS status;
        if (QueryServiceStatus(svc, &status)) {
            running = (status.dwCurrentState == SERVICE_RUNNING);
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

bool IsVbsEnabled() {
    HKEY key;
    DWORD val = 0, size = sizeof(val);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegQueryValueExW(key, L"EnableVirtualizationBasedSecurity",
            nullptr, nullptr, (LPBYTE)&val, &size);
        RegCloseKey(key);
    }
    return val != 0;
}

bool IsCoreIsolationEnabled() {
    HKEY key;
    DWORD val = 0, size = sizeof(val);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ, &key) == ERROR_SUCCESS) {
        RegQueryValueExW(key, L"Enabled", nullptr, nullptr, (LPBYTE)&val, &size);
        RegCloseKey(key);
    }
    return val != 0;
}

uint64_t GetTotalRamMB() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    return memInfo.ullTotalPhys / (1024 * 1024);
}

// ============================================================================
//  Full Hardware Check
// ============================================================================

void CheckHardware(HardwareReport* r) {
    memset(r, 0, sizeof(*r));

    // CPU
    r->Vendor = DetectCpuVendor(r->VendorString);

    // Brand string (CPUID 0x80000002-4)
    int regs[4];
    for (int i = 0; i < 3; i++) {
        __cpuid(regs, 0x80000002 + i);
        memcpy(r->BrandString + i * 16, regs, 16);
    }
    r->BrandString[48] = '\0';

    bool biosLocked = false;
    r->HasSvm = (r->Vendor == CpuVendor::AMD) && CheckSvmSupport(&biosLocked);
    r->SvmDisabledByBios = biosLocked;

    r->HasVtx = (r->Vendor == CpuVendor::Intel) && CheckVtxSupport(&biosLocked);
    r->VtxDisabledByBios = biosLocked;

    r->HasAesNi = CheckAesNi();
    r->PhysAddrBits = GetPhysAddrBits();

    // System
    r->Boot = DetectBootMode();
    r->SecureBootEnabled = IsSecureBootEnabled();
    r->HyperVEnabled = IsHyperVEnabled();
    r->VbsEnabled = IsVbsEnabled();
    r->CoreIsolationEnabled = IsCoreIsolationEnabled();
    r->TotalRamMB = GetTotalRamMB();

    // Evaluate compatibility
    r->Compatible = true;
    r->ErrorMessage[0] = L'\0';

    if (r->Vendor == CpuVendor::Unknown) {
        r->Compatible = false;
        wcscat_s(r->ErrorMessage, L"Unknown CPU vendor. AMD or Intel required.\n");
    }
    if (!r->HasSvm && !r->HasVtx) {
        r->Compatible = false;
        if (r->Vendor == CpuVendor::AMD)
            wcscat_s(r->ErrorMessage, L"AMD SVM not supported. Enable SVM in BIOS.\n");
        else if (r->Vendor == CpuVendor::Intel)
            wcscat_s(r->ErrorMessage, L"Intel VT-x not supported. Enable VT-x in BIOS.\n");
        else
            wcscat_s(r->ErrorMessage, L"No virtualization support detected.\n");
    }
    if (r->Boot != BootMode::UEFI) {
        r->Compatible = false;
        wcscat_s(r->ErrorMessage, L"Legacy BIOS detected. UEFI boot required.\n");
    }
    if (r->TotalRamMB < 2048) {
        r->Compatible = false;
        wcscat_s(r->ErrorMessage, L"Insufficient RAM. Minimum 2 GB required.\n");
    }
}

} // namespace aegis::installer
