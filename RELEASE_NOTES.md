# AegisGate v1.0.0-alpha — First Public Release

> *"The Gate Below"* — Ring -1 Hypervisor Security Gate for Windows

**Developer:** Nik

---

## ⚠️ Alpha Release

This is the **first alpha release** of AegisGate. The codebase is feature-complete for the core architecture, but has **not been tested on real hardware yet**.

**Do NOT use this on your main system.** Test in a VM first (QEMU/KVM with nested virtualization).

---

## What's Included

### Core Components
- **UEFI Bootloader** (`AegisGatePkg`) — Boots before Windows, probes CPU features, procedural logo, NVRAM settings, chain-boot
- **AMD SVM Backend** — Full VMCB layout, VMRUN loop, NPT identity mapping with 2MB large pages
- **Intel VT-x Backend** — Stub (VMCS fields defined, implementation coming in v1.1)
- **Hypervisor Core** — Per-CPU VCPU management, multi-core init via UEFI MP Services

### Security Features
- **Stealth Engine** — CPUID masking (hides hypervisor from Vanguard/EAC/BattlEye), MSR filtering, TSC offsetting
- **Kernel Integrity Monitor** — NPT-based code protection for ntoskrnl.exe, hal.dll, CI.dll
- **USB Attack Detection** — Known BadUSB/Rubber Ducky signature database, composite device analysis

### Crypto
- **AES-256-GCM** — Hardware-accelerated via AES-NI intrinsics (PCLMULQDQ GHASH)
- **SHA-256** — Software implementation for hardware fingerprinting
- **HKDF** — Key derivation from hardware fingerprint

### Windows Agent
- **System Tray App** — Status display, heartbeat, hypervisor detection via custom CPUID leaf
- **Direct VMCALL** — No kernel driver needed, Ring 3 → Ring -1 communication
- **SEH Protection** — Graceful fallback when hypervisor isn't active

### Build & Packaging
- **PowerShell Build Script** (`build.ps1`) — Orchestrates EDK2 + CMake + NSIS builds
- **NSIS Installer** — UAC admin elevation, auto-disables Hyper-V, autostart setup, uninstaller

---

## Hardware Requirements

| Component | Requirement |
|---|---|
| CPU | AMD Ryzen 1000+ (Zen 1+) or Intel Core 4th Gen+ |
| Firmware | UEFI (not Legacy BIOS) |
| OS | Windows 10/11 64-bit |
| BIOS Setting | SVM/VT-x must be **Enabled** |
| Windows | Hyper-V must be **Disabled** |

---

## Build Prerequisites

1. **EDK2** — Clone to `D:\tools\edk2`
2. **Visual Studio 2022** — With C++ desktop workload
3. **NASM** — For assembly modules
4. **CMake 3.28+** — For agent build
5. **NSIS** — For installer

```powershell
# Build everything
.\build.ps1 -All

# Build only agent
.\build.ps1 -Agent

# Build only bootloader
.\build.ps1 -Boot
```

---

## Known Limitations (Alpha)

- Intel VT-x backend is a stub (returns `HV_NOT_SUPPORTED`)
- Curve25519 ECDH is not fully implemented (stubs only)
- USB monitoring I/O interception handler is a framework (device parsing TODO)
- Kernel integrity periodic scan hash comparison not yet implemented
- No ISO builder for boot USB (manual flash required)
- Session token validation is placeholder (hardcoded temp token)

---

## Changelog

### v1.0.0-alpha (2025-05-12)
- Initial release
- 44 source files, ~6700 lines of C++/ASM
- Complete AMD SVM hypervisor implementation
- UEFI bootloader with procedural logo and settings UI
- Windows tray agent with direct VMCALL
- AES-256-GCM crypto engine with AES-NI
- Stealth engine (CPUID/MSR/TSC masking)
- USB + Kernel protection modules
- NSIS installer with Hyper-V auto-disable
