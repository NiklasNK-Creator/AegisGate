# run_qemu.ps1 — Local QEMU Test for AegisGate UEFI Bootloader
# 
# This script sets up a virtual FAT32 drive and launches QEMU with OVMF
# to test the AegisGate bootloader without needing to flash a USB stick.

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AegisGate QEMU Test Launcher" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Check for QEMU ──────────────────────────────────────────────────
$qemuPath = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if (-not $qemuPath) {
    # Typical install path for QEMU on Windows
    if (Test-Path "C:\Program Files\qemu\qemu-system-x86_64.exe") {
        $qemuPath = "C:\Program Files\qemu\qemu-system-x86_64.exe"
    } else {
        Write-Host "ERROR: QEMU is not installed or not in PATH." -ForegroundColor Red
        Write-Host "Please install QEMU for Windows:" -ForegroundColor Yellow
        Write-Host "  winget install --id SoftwareFreedomConservancy.QEMU" -ForegroundColor White
        exit 1
    }
}
Write-Host "Found QEMU: $qemuPath" -ForegroundColor Green

# ── 2. Check for OVMF (UEFI Firmware) ──────────────────────────────────
$ovmfPath = "OVMF_CODE.fd" # Default local path
if (-not (Test-Path $ovmfPath)) {
    if (Test-Path "C:\Program Files\qemu\share\OVMF.fd") {
        $ovmfPath = "C:\Program Files\qemu\share\OVMF.fd"
    } else {
        Write-Host "ERROR: OVMF firmware (OVMF.fd) not found." -ForegroundColor Red
        Write-Host "Please download an OVMF build and place it in the project root." -ForegroundColor Yellow
        exit 1
    }
}
Write-Host "Found OVMF: $ovmfPath" -ForegroundColor Green

# ── 3. Prepare Virtual FAT Drive ───────────────────────────────────────
$qemuDir = Join-Path $PSScriptRoot "qemu_fat"
$efiBootDir = Join-Path $qemuDir "EFI\Boot"
$efiFile = Join-Path $PSScriptRoot "output\AegisGate.efi"

if (-not (Test-Path $efiFile)) {
    Write-Host "ERROR: AegisGate.efi not found in output directory." -ForegroundColor Red
    Write-Host "Please build the bootloader first:" -ForegroundColor Yellow
    Write-Host "  .\build.ps1 -Boot" -ForegroundColor White
    exit 1
}

if (Test-Path $qemuDir) { Remove-Item $qemuDir -Recurse -Force }
New-Item -ItemType Directory -Path $efiBootDir | Out-Null
Copy-Item $efiFile (Join-Path $efiBootDir "bootx64.efi")

Write-Host "Prepared virtual FAT drive at: $qemuDir" -ForegroundColor Green

# ── 4. Launch QEMU ─────────────────────────────────────────────────────
Write-Host "Launching QEMU... (Press Ctrl+C in this console to stop)" -ForegroundColor Cyan
Write-Host "Note: SVM/VT-x might not be available depending on your host OS and QEMU version." -ForegroundColor Yellow

# qemu args:
# -M q35 : modern chipset
# -cpu host or max : attempt to pass through virtualization features if possible
# -bios : OVMF firmware
# -drive : virtual FAT folder
# -net none : disable networking
# -serial stdio : redirect serial output to this console

& $qemuPath -M q35 -m 2G -cpu max -bios $ovmfPath -drive file=fat:rw:$qemuDir,format=raw -net none -serial stdio

Write-Host "QEMU exited." -ForegroundColor Cyan
