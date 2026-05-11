# create_usb.ps1 — AegisGate USB Boot Drive Creator
# 
# This script formats a USB drive as FAT32 (UEFI compatible) and copies
# the AegisGate.efi bootloader into the correct EFI boot path.

param(
    [Parameter(Mandatory=$true, HelpMessage="Drive letter of the USB drive (e.g., E:)")]
    [ValidatePattern("^[A-Za-z]:\\?$")]
    [string]$DriveLetter
)

$ErrorActionPreference = "Stop"

# Normalize drive letter format to "E:"
$DriveLetter = $DriveLetter.Substring(0,2).ToUpper()

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AegisGate USB Boot Drive Creator" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Safety Checks ───────────────────────────────────────────────────

# Prevent formatting C:
if ($DriveLetter -eq "C:") {
    Write-Host "ERROR: Cannot format the system drive (C:)." -ForegroundColor Red
    exit 1
}

$efiFile = Join-Path $PSScriptRoot "output\AegisGate.efi"
if (-not (Test-Path $efiFile)) {
    Write-Host "ERROR: AegisGate.efi not found in output directory." -ForegroundColor Red
    Write-Host "Please build the bootloader first: .\build.ps1 -Boot" -ForegroundColor Yellow
    exit 1
}

# Verify drive exists and is removable (to prevent accidental data loss)
try {
    $drive = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $DriveLetter }
    if (-not $drive) {
        Write-Host "ERROR: Drive $DriveLetter not found." -ForegroundColor Red
        exit 1
    }
    if ($drive.DriveType -ne 2) {
        Write-Host "WARNING: Drive $DriveLetter is not a removable USB drive!" -ForegroundColor Yellow
        $confirm = Read-Host "Are you SURE you want to format $DriveLetter? All data will be lost (Y/N)"
        if ($confirm -notmatch "^[Yy]$") {
            Write-Host "Aborted." -ForegroundColor DarkGray
            exit 0
        }
    }
} catch {
    Write-Host "WARNING: Could not verify drive type. Ensure $DriveLetter is correct." -ForegroundColor Yellow
}

Write-Host "WARNING: ALL DATA ON $DriveLetter WILL BE DESTROYED." -ForegroundColor Red
$confirm2 = Read-Host "Type 'YES' to format and install AegisGate"
if ($confirm2 -cne "YES") {
    Write-Host "Aborted." -ForegroundColor DarkGray
    exit 0
}

# ── 2. Format Drive ────────────────────────────────────────────────────
Write-Host "Formatting $DriveLetter as FAT32..." -ForegroundColor Cyan
try {
    Format-Volume -DriveLetter $DriveLetter[0] -FileSystem FAT32 -NewFileSystemLabel "AEGISGATE" -Confirm:$false
} catch {
    Write-Host "ERROR: Formatting failed. Please format the drive manually to FAT32." -ForegroundColor Red
    exit 1
}

# ── 3. Copy Bootloader ─────────────────────────────────────────────────
Write-Host "Copying UEFI boot files..." -ForegroundColor Cyan
$efiBootDir = Join-Path $DriveLetter "\EFI\Boot"
New-Item -ItemType Directory -Path $efiBootDir -Force | Out-Null

$targetEfi = Join-Path $efiBootDir "bootx64.efi"
Copy-Item $efiFile $targetEfi -Force

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Success! USB Drive is ready." -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "To boot AegisGate:" -ForegroundColor White
Write-Host "1. Restart your computer." -ForegroundColor DarkGray
Write-Host "2. Enter BIOS/UEFI settings." -ForegroundColor DarkGray
Write-Host "3. Ensure Secure Boot is Disabled." -ForegroundColor DarkGray
Write-Host "4. Select the USB drive as the first boot device." -ForegroundColor DarkGray
