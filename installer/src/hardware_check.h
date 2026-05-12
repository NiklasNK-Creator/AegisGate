/**
 * AegisGate Installer — Hardware Compatibility Check
 * Developer: Nik
 *
 * Checks if the current system can run AegisGate:
 *   - CPU virtualization support (AMD-V / Intel VT-x)
 *   - UEFI boot mode (not Legacy BIOS)
 *   - Secure Boot status
 *   - Hyper-V / VBS status
 *   - Minimum RAM
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>

namespace aegis::installer {

enum class CpuVendor { Unknown, AMD, Intel };
enum class BootMode  { Unknown, UEFI, LegacyBIOS };

struct HardwareReport {
    // CPU
    CpuVendor  Vendor;
    char       VendorString[13];
    char       BrandString[49];
    bool       HasSvm;              // AMD: SVM supported
    bool       HasVtx;              // Intel: VT-x supported
    bool       SvmDisabledByBios;   // AMD: SVM locked off in BIOS
    bool       VtxDisabledByBios;   // Intel: VMXON locked out
    bool       HasAesNi;            // AES-NI for crypto
    uint32_t   PhysAddrBits;        // Physical address width

    // System
    BootMode   Boot;
    bool       SecureBootEnabled;
    bool       HyperVEnabled;
    bool       VbsEnabled;          // Virtualization-Based Security
    bool       CoreIsolationEnabled;
    uint64_t   TotalRamMB;

    // Result
    bool       Compatible;
    wchar_t    ErrorMessage[512];
};

// Run all checks and fill the report
void CheckHardware(HardwareReport* report);

// Individual checks
CpuVendor DetectCpuVendor(char vendorStr[13]);
bool      CheckSvmSupport(bool* disabledByBios);
bool      CheckVtxSupport(bool* disabledByBios);
bool      CheckAesNi();
uint32_t  GetPhysAddrBits();
BootMode  DetectBootMode();
bool      IsSecureBootEnabled();
bool      IsHyperVEnabled();
bool      IsVbsEnabled();
bool      IsCoreIsolationEnabled();
uint64_t  GetTotalRamMB();

} // namespace aegis::installer
