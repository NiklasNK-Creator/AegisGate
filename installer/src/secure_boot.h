/**
 * AegisGate Installer — Secure Boot Certificate Management
 * Developer: Nik
 *
 * Generates a self-signed certificate, signs the EFI binary,
 * and prepares the certificate for UEFI enrollment.
 *
 * Strategy:
 *   1. Generate RSA-2048 self-signed cert via CertCreateSelfSignCertificate
 *   2. Sign aegisgate.efi with signtool (if available) or embedded signing
 *   3. Export .cer to ESP for UEFI firmware enrollment
 *   4. On boards with KeyTool/dbx support: attempt auto-enrollment
 *   5. Fallback: Guide user to enroll via BIOS "Custom Mode"
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace aegis::installer {

struct SecureBootConfig {
    wchar_t CertSubject[128];      // e.g., "AegisGate Local Signing Key"
    wchar_t CertStorePath[MAX_PATH]; // Where to save the .pfx
    wchar_t CerExportPath[MAX_PATH]; // Where to save the .cer (public key)
    wchar_t EfiPath[MAX_PATH];       // Path to the .efi to sign
};

struct SecureBootResult {
    bool CertGenerated;
    bool EfiSigned;
    bool CerExportedToEsp;
    bool NeedsManualEnrollment;  // true if user must enroll in BIOS
    wchar_t ErrorMessage[512];
};

// Generate a self-signed code signing certificate
bool GenerateLocalCert(const SecureBootConfig* config);

// Sign the EFI binary with the generated certificate
bool SignEfiBinary(const SecureBootConfig* config);

// Export the public cert (.cer) to the ESP for firmware enrollment
bool ExportCertToEsp(wchar_t espDrive, const SecureBootConfig* config);

// Full Secure Boot setup pipeline
bool SetupSecureBoot(const SecureBootConfig* config, wchar_t espDrive,
                     SecureBootResult* result);

} // namespace aegis::installer
