/**
 * AegisGate Installer — Secure Boot Certificate Implementation
 * Developer: Nik
 *
 * Uses Windows CryptoAPI to generate a self-signed certificate,
 * then uses PowerShell/signtool to sign the EFI binary.
 */

#include "secure_boot.h"
#include "system_config.h"
#include <wincrypt.h>
#include <shlobj.h>
#include <stdio.h>

#pragma comment(lib, "crypt32.lib")

namespace aegis::installer {

// Local command runner (same logic as system_config.cpp)
static int RunCmd(const wchar_t* cmd) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    wchar_t cmdBuf[2048];
    wcscpy_s(cmdBuf, cmd);
    if (!CreateProcessW(nullptr, cmdBuf, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)exitCode;
}

// ============================================================================
//  Certificate Generation via PowerShell
// ============================================================================

bool GenerateLocalCert(const SecureBootConfig* config) {
    // Use PowerShell to create a self-signed code signing certificate
    // This is more reliable than raw CryptoAPI for UEFI signing
    wchar_t cmd[2048];
    swprintf_s(cmd,
        L"powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        L"$cert = New-SelfSignedCertificate "
        L"-Subject 'CN=%s' "
        L"-Type CodeSigningCert "
        L"-CertStoreLocation Cert:\\LocalMachine\\My "
        L"-KeyLength 2048 "
        L"-KeyAlgorithm RSA "
        L"-HashAlgorithm SHA256 "
        L"-NotAfter (Get-Date).AddYears(10) "
        L"-KeyUsage DigitalSignature "
        L"-FriendlyName 'AegisGate UEFI Signing Key'; "

        // Export .pfx (private key)
        L"$pwd = ConvertTo-SecureString -String 'AegisGateLocal' -Force -AsPlainText; "
        L"Export-PfxCertificate -Cert $cert -FilePath '%s' -Password $pwd; "

        // Export .cer (public key only — for UEFI enrollment)
        L"Export-Certificate -Cert $cert -FilePath '%s' -Type CERT"
        L"\"",
        config->CertSubject,
        config->CertStorePath,
        config->CerExportPath
    );

    return RunCmd(cmd) == 0;
}

// ============================================================================
//  EFI Binary Signing
// ============================================================================

bool SignEfiBinary(const SecureBootConfig* config) {
    // Try signtool first (comes with Windows SDK)
    wchar_t cmd[2048];

    // Method 1: signtool from Windows SDK
    swprintf_s(cmd,
        L"signtool sign /f \"%s\" /p AegisGateLocal "
        L"/fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "
        L"\"%s\"",
        config->CertStorePath,
        config->EfiPath
    );

    if (RunCmd(cmd) == 0) return true;

    // Method 2: PowerShell Set-AuthenticodeSignature
    swprintf_s(cmd,
        L"powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        L"$pwd = ConvertTo-SecureString -String 'AegisGateLocal' -Force -AsPlainText; "
        L"$cert = Get-PfxCertificate -FilePath '%s' -Password $pwd; "
        L"Set-AuthenticodeSignature -FilePath '%s' -Certificate $cert "
        L"-HashAlgorithm SHA256"
        L"\"",
        config->CertStorePath,
        config->EfiPath
    );

    return RunCmd(cmd) == 0;
}

// ============================================================================
//  Export Certificate to ESP
// ============================================================================

bool ExportCertToEsp(wchar_t espDrive, const SecureBootConfig* config) {
    // Copy the .cer file to ESP so user can enroll it from BIOS
    wchar_t destDir[MAX_PATH];
    swprintf_s(destDir, L"%c:\\EFI\\AegisGate\\keys", espDrive);
    SHCreateDirectoryExW(nullptr, destDir, nullptr);

    wchar_t dest[MAX_PATH];
    swprintf_s(dest, L"%c:\\EFI\\AegisGate\\keys\\aegisgate.cer", espDrive);
    return CopyFileW(config->CerExportPath, dest, FALSE) != 0;
}

// ============================================================================
//  Full Secure Boot Pipeline
// ============================================================================

bool SetupSecureBoot(const SecureBootConfig* config, wchar_t espDrive,
                     SecureBootResult* result) {
    memset(result, 0, sizeof(*result));

    // Step 1: Generate certificate
    result->CertGenerated = GenerateLocalCert(config);
    if (!result->CertGenerated) {
        wcscpy_s(result->ErrorMessage,
            L"Failed to generate signing certificate. "
            L"AegisGate will still work if Secure Boot is disabled.");
        // Non-fatal — continue without signing
    }

    // Step 2: Sign the EFI binary
    if (result->CertGenerated) {
        result->EfiSigned = SignEfiBinary(config);
        if (!result->EfiSigned) {
            wcscpy_s(result->ErrorMessage,
                L"EFI binary signing failed. signtool may not be installed. "
                L"Install Windows SDK or disable Secure Boot.");
        }
    }

    // Step 3: Export cert to ESP
    if (result->CertGenerated) {
        result->CerExportedToEsp = ExportCertToEsp(espDrive, config);
    }

    // Step 4: Determine if manual enrollment is needed
    // The certificate needs to be enrolled in UEFI firmware's 'db'
    // This cannot be done programmatically from Windows
    result->NeedsManualEnrollment = result->EfiSigned;

    // If enrollment is needed, the installer will show instructions:
    // "Your EFI is signed. To complete Secure Boot setup:
    //  1. Restart and enter BIOS (DEL/F2)
    //  2. Go to Security → Secure Boot → Key Management
    //  3. Select 'Enroll DB' or 'Append DB'
    //  4. Navigate to EFI\AegisGate\keys\aegisgate.cer
    //  5. Confirm and save"

    return result->CertGenerated && result->EfiSigned;
}

} // namespace aegis::installer
