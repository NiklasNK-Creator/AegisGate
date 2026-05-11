# AegisGate Build Script (PowerShell)
# Developer: Nik
# 
# Builds all AegisGate components:
#   1. UEFI Bootloader (via EDK2)
#   2. Windows Agent (via CMake + MSVC)
#   3. Installer (via NSIS)

param(
    [switch]$Agent,
    [switch]$Boot,
    [switch]$Installer,
    [switch]$All,
    [switch]$Clean,
    [ValidateSet("Debug","Release")]
    [string]$Config = "Release"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AegisGate Build System" -ForegroundColor Cyan
Write-Host "  Developer: Nik" -ForegroundColor DarkGray
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
#  Build Agent (CMake + MSVC)
# ============================================================================

function Build-Agent {
    Write-Host "[Agent] Building Windows Agent..." -ForegroundColor Yellow
    
    $agentDir = Join-Path $ProjectRoot "agent"
    $buildDir = Join-Path $agentDir "build"
    
    if (-not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir | Out-Null
    }
    
    Push-Location $buildDir
    try {
        # Configure
        Write-Host "[Agent] Configuring CMake..." -ForegroundColor DarkGray
        cmake .. -G "Visual Studio 17 2022" -A x64
        
        # Build
        Write-Host "[Agent] Compiling..." -ForegroundColor DarkGray
        cmake --build . --config $Config --parallel
        
        $exe = Join-Path $buildDir "bin\$Config\AegisGate.exe"
        if (Test-Path $exe) {
            Write-Host "[Agent] SUCCESS: $exe" -ForegroundColor Green
        } else {
            Write-Host "[Agent] WARNING: Executable not found at expected path" -ForegroundColor Yellow
        }
    } finally {
        Pop-Location
    }
}

# ============================================================================
#  Build UEFI Bootloader (EDK2)
# ============================================================================

function Build-Bootloader {
    Write-Host "[Boot] Building UEFI Bootloader..." -ForegroundColor Yellow
    
    $edk2Path = "D:\tools\edk2"
    
    if (-not (Test-Path $edk2Path)) {
        Write-Host "[Boot] ERROR: EDK2 not found at $edk2Path" -ForegroundColor Red
        Write-Host "[Boot] Please clone EDK2:" -ForegroundColor Red
        Write-Host "  git clone https://github.com/tianocore/edk2.git $edk2Path" -ForegroundColor DarkGray
        Write-Host "  cd $edk2Path && git submodule update --init" -ForegroundColor DarkGray
        return
    }
    
    # Symlink our package into EDK2
    $pkgLink = Join-Path $edk2Path "AegisGatePkg"
    $pkgSource = Join-Path $ProjectRoot "boot\AegisGatePkg"
    
    if (-not (Test-Path $pkgLink)) {
        Write-Host "[Boot] Creating symlink to AegisGatePkg..." -ForegroundColor DarkGray
        New-Item -ItemType Junction -Path $pkgLink -Target $pkgSource | Out-Null
    }
    
    # Build with EDK2
    Push-Location $edk2Path
    try {
        $buildTarget = if ($Config -eq "Debug") { "DEBUG" } else { "RELEASE" }
        
        # Source EDK2 environment
        & "$edk2Path\edksetup.bat"
        
        # Build
        Write-Host "[Boot] Building AegisGatePkg ($buildTarget)..." -ForegroundColor DarkGray
        build -a X64 -t VS2022 -p AegisGatePkg/AegisGatePkg.dsc -b $buildTarget
        
        $efi = Join-Path $edk2Path "Build\AegisGate\${buildTarget}_VS2022\X64\AegisGate.efi"
        if (Test-Path $efi) {
            Write-Host "[Boot] SUCCESS: $efi" -ForegroundColor Green
            # Copy to output
            Copy-Item $efi (Join-Path $ProjectRoot "output\AegisGate.efi") -Force
        }
    } finally {
        Pop-Location
    }
}

# ============================================================================
#  Build Installer (NSIS)
# ============================================================================

function Build-Installer {
    Write-Host "[Installer] Building NSIS Installer..." -ForegroundColor Yellow
    
    $nsiFile = Join-Path $ProjectRoot "installer\aegisgate.nsi"
    
    # Check for NSIS
    $nsis = Get-Command "makensis" -ErrorAction SilentlyContinue
    if (-not $nsis) {
        $nsisPath = "C:\Program Files (x86)\NSIS\makensis.exe"
        if (Test-Path $nsisPath) {
            $nsis = $nsisPath
        } else {
            Write-Host "[Installer] ERROR: NSIS not found. Install from https://nsis.sourceforge.io/" -ForegroundColor Red
            return
        }
    }
    
    # Ensure agent is built first
    $agentExe = Join-Path $ProjectRoot "agent\build\bin\$Config\AegisGate.exe"
    if (-not (Test-Path $agentExe)) {
        Write-Host "[Installer] Agent not built yet. Building..." -ForegroundColor Yellow
        Build-Agent
    }
    
    # Copy agent to installer staging
    $stagingDir = Join-Path $ProjectRoot "installer\bin"
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
    Copy-Item $agentExe $stagingDir -Force
    
    # Build installer
    Push-Location (Join-Path $ProjectRoot "installer")
    try {
        & $nsis $nsiFile
        
        $installer = Join-Path $ProjectRoot "installer\AegisGate-Setup.exe"
        if (Test-Path $installer) {
            Write-Host "[Installer] SUCCESS: $installer" -ForegroundColor Green
            Copy-Item $installer (Join-Path $ProjectRoot "output\AegisGate-Setup.exe") -Force
        }
    } finally {
        Pop-Location
    }
}

# ============================================================================
#  Clean
# ============================================================================

function Clean-All {
    Write-Host "[Clean] Removing build artifacts..." -ForegroundColor Yellow
    
    $dirs = @(
        (Join-Path $ProjectRoot "agent\build"),
        (Join-Path $ProjectRoot "output"),
        (Join-Path $ProjectRoot "installer\bin")
    )
    
    foreach ($dir in $dirs) {
        if (Test-Path $dir) {
            Remove-Item $dir -Recurse -Force
            Write-Host "[Clean] Removed $dir" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "[Clean] Done." -ForegroundColor Green
}

# ============================================================================
#  Main
# ============================================================================

# Create output directory
$outputDir = Join-Path $ProjectRoot "output"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

if ($Clean) { Clean-All; return }

if ($All -or (-not $Agent -and -not $Boot -and -not $Installer)) {
    Build-Agent
    Build-Bootloader
    Build-Installer
} else {
    if ($Agent) { Build-Agent }
    if ($Boot) { Build-Bootloader }
    if ($Installer) { Build-Installer }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
