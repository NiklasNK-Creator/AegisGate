<p align="center">
  <img src="https://img.shields.io/badge/Ring--1-Hypervisor-blueviolet?style=for-the-badge" alt="Ring -1"/>
  <img src="https://img.shields.io/badge/AMD--V-SVM-ed1c24?style=for-the-badge&logo=amd" alt="AMD-V"/>
  <img src="https://img.shields.io/badge/Intel-VT--x-0071c5?style=for-the-badge&logo=intel" alt="VT-x"/>
  <img src="https://img.shields.io/badge/C++-20-00599C?style=for-the-badge&logo=cplusplus" alt="C++20"/>
  <img src="https://img.shields.io/badge/ASM-x86__64-orange?style=for-the-badge" alt="x86-64"/>
</p>

<h1 align="center">🛡️ AegisGate</h1>

<p align="center">
  <strong>The Gate Below</strong> — A Ring -1 Hypervisor Security Gate for Windows
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#building">Building</a> •
  <a href="#usage">Usage</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/NiklasNK-Creator/AegisGate?include_prereleases&style=flat-square&color=blue" alt="Release"/>
  <img src="https://img.shields.io/github/license/NiklasNK-Creator/AegisGate?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/github/languages/top/NiklasNK-Creator/AegisGate?style=flat-square" alt="Language"/>
  <img src="https://img.shields.io/github/repo-size/NiklasNK-Creator/AegisGate?style=flat-square" alt="Size"/>
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=flat-square&logo=windows" alt="Platform"/>
</p>

---

## 💡 What is AegisGate?

AegisGate is a **bare-metal Type-1 hypervisor** that boots before Windows via UEFI. It leverages hardware virtualization (AMD-V / Intel VT-x) to create an **invisible security layer at Ring -1** — below the OS kernel.

Windows runs as a controlled guest VM, while AegisGate silently monitors and protects the system — with **zero performance impact**.

```
┌──────────────────────────────────────────────────────┐
│                    User Applications                  │
│                      (Ring 3)                         │
├──────────────────────────────────────────────────────┤
│              Windows Kernel (ntoskrnl.exe)            │
│                      (Ring 0)                         │
├══════════════════════════════════════════════════════╡
│           ⬇  AegisGate Security Gate  ⬇              │
│  ┌────────────────────────────────────────────────┐  │
│  │  NPT/EPT Monitor • Stealth Engine • Crypto    │  │
│  │  USB Shield • Kernel Integrity • VMCALL API    │  │
│  └────────────────────────────────────────────────┘  │
│                     (Ring -1)                         │
├──────────────────────────────────────────────────────┤
│                   CPU Hardware                        │
│              AMD-V (SVM) / Intel VT-x                │
└──────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🔒 Security
| Feature | Description |
|---|---|
| **Kernel Integrity** | NPT/EPT write-protection on `ntoskrnl.exe`, `hal.dll`, `CI.dll` — blocks rootkit code patching |
| **USB Shield** | Detects Rubber Ducky, BadUSB, and malicious composite devices via I/O interception |
| **Bootkit Protection** | AegisGate loads before Windows — bootkits cannot install before the gate |
| **Memory Watchpoints** | Hardware-enforced watchpoints on critical kernel structures (SSDT, IDT) |

### 🥷 Stealth
| Feature | Description |
|---|---|
| **CPUID Masking** | Hides hypervisor-present bit (leaf 1, bit 31) from Vanguard, EAC, BattlEye |
| **MSR Filtering** | Masks EFER.SVME, VM_CR, IA32_FEATURE_CONTROL reads |
| **TSC Offsetting** | Compensates VM-Exit latency to defeat timing-based detection |
| **HV Leaf Zeroing** | Returns zeros for all `0x4000000x` hypervisor info leaves |

### ⚡ Performance
| Feature | Description |
|---|---|
| **2MB Large Pages** | NPT identity mapping with large pages — minimal TLB pressure |
| **VMCB Clean Bits** | Skip VMCB field reloading on re-entry for faster VMRUN |
| **No Driver** | Agent communicates via direct `VMCALL` — no kernel driver overhead |
| **Selective Intercepts** | Only intercept what's needed (CPUID, MSR, VMCALL) |

### 🔐 Cryptography
| Feature | Description |
|---|---|
| **AES-256-GCM** | Hardware-accelerated via AES-NI intrinsics (AESENC, PCLMULQDQ) |
| **SHA-256** | Software implementation for hardware fingerprinting |
| **HKDF** | Key derivation bound to hardware identity (anti-cloning) |
| **ECDH** | Curve25519 key exchange stubs (session encryption) |

---

## 🏗️ Architecture

```
d:\projekte\hype\
│
├── boot/AegisGatePkg/          # UEFI Bootloader (EDK2)
│   ├── src/main.cpp            #   Entry point, orchestration
│   ├── src/hardware_probe.cpp  #   CPU feature detection
│   ├── src/logo.cpp            #   Procedural boot logo (GOP)
│   ├── src/settings.cpp        #   NVRAM settings + interactive menu
│   ├── src/chain_boot.cpp      #   Chain-boot to bootmgfw.efi
│   └── asm/cpuid_check.asm     #   7 ASM detection functions
│
├── hypervisor/
│   ├── hal/                    # Hardware Abstraction Layer
│   │   ├── hal_interface.h     #   Abstract backend interface
│   │   ├── amd/svm_hal.cpp     #   AMD SVM implementation (full)
│   │   └── intel/vmx_hal.cpp   #   Intel VMX implementation
│   ├── core/
│   │   ├── src/hypervisor_init.cpp  # Multi-core HV initialization
│   │   ├── src/stealth.cpp     #   Anti-detection engine
│   │   ├── src/vcpu.cpp        #   Per-CPU VCPU management
│   │   └── asm/svm_ops.asm     #   VMRUN loop, MSR ops (286 lines)
│   └── protection/
│       ├── usb_monitor.cpp     #   USB attack detection
│       └── kernel_integrity.cpp #  NPT code protection
│
├── crypto/
│   ├── public/aegis_crypto.h   # Crypto interface
│   └── core/src/
│       ├── aes_gcm.cpp         #   AES-NI accelerated AES-256-GCM
│       └── hardware_fingerprint.cpp  # SHA-256 + HKDF
│
├── agent/                      # Windows Tray Agent
│   ├── src/main.cpp            #   WinMain, system tray, status UI
│   ├── src/vmcall_direct.cpp   #   Direct VMCALL wrappers
│   └── src/vmcall_stub.asm     #   Ring 3 VMCALL instruction
│
├── common/                     # Shared headers
│   ├── include/types.h         #   Fundamental types (freestanding)
│   ├── include/aegis_hypercalls.h  # VMCALL protocol
│   ├── include/aegis_status.h  #   Error codes
│   └── asm/common_macros.asm   #   Shared ASM macros
│
├── installer/aegisgate.nsi     # NSIS installer script
├── build.ps1                   # PowerShell build orchestrator
└── README.md
```

### Communication Flow

```
┌─────────────┐     VMCALL      ┌──────────────────┐
│  AegisGate  │ ──────────────▶ │   Hypervisor     │
│  Agent.exe  │    (Ring 3)     │   VM-Exit Handler│
│  (Tray App) │ ◀────────────── │   (Ring -1)      │
└─────────────┘   RAX/RBX/RCX   └──────────────────┘
                  Return Values
```

No kernel driver. No IOCTL. Just a raw `VMCALL` instruction from user mode.

---

## 📦 Installation

### Prerequisites

| Requirement | Details |
|---|---|
| **CPU** | AMD Ryzen 1000+ (Zen 1+) or Intel Core 4th Gen+ (Haswell+) |
| **Firmware** | UEFI (not Legacy BIOS) |
| **OS** | Windows 10 / 11 — 64-bit only |
| **BIOS** | Virtualization must be **Enabled** (SVM Mode / VT-x) |
| **Windows** | Hyper-V / VBS must be **Disabled** |

### Step 1 — Enable Virtualization in BIOS

1. Restart → Enter BIOS (`DEL` or `F2`)
2. Find the virtualization setting:
   - **AMD:** `SVM Mode` → **Enabled**
   - **Intel:** `Intel Virtualization Technology` → **Enabled**
3. Save & Exit

### Step 2 — Disable Hyper-V

Open **PowerShell as Administrator**:
```powershell
bcdedit /set hypervisorlaunchtype off
```
Restart your PC.

### Step 3 — Run the Installer

Download `AegisGate-Setup.exe` from [Releases](../../releases) and run it.  
The installer will:
- ✅ Request Administrator privileges
- ✅ Disable Hyper-V automatically (if needed)
- ✅ Install the AegisGate tray agent
- ✅ Register for Windows autostart
- ✅ Create an uninstaller

### Step 4 — Flash Boot Image (Advanced)

For full hardware-level protection:
1. Download `AegisGate-Boot.iso` from Releases
2. Flash to USB with [Rufus](https://rufus.ie/) (GPT / UEFI / FAT32)
3. Set USB as first boot device in BIOS

---

## 🔨 Building

### Build Dependencies

| Tool | Purpose | Install |
|---|---|---|
| **Visual Studio 2022+** | MSVC compiler | [Download](https://visualstudio.microsoft.com/) |
| **CMake 3.28+** | Agent build system | `winget install Kitware.CMake` |
| **NASM** | Assembly modules | `winget install NASM.NASM` |
| **EDK2** | UEFI bootloader | [TianoCore](https://github.com/tianocore/edk2) |
| **NSIS** | Windows installer | `winget install NSIS.NSIS` |

### Quick Build

```powershell
# Build the Windows agent (demo mode)
cd agent
mkdir build && cd build
cmake .. -DAEGIS_TEST_MODE=ON
cmake --build . --config Release

# Run the agent
.\bin\Release\AegisGate.exe
```

### Full Build (all components)

```powershell
.\build.ps1 -All          # Everything
.\build.ps1 -Agent        # Agent only
.\build.ps1 -Boot         # UEFI bootloader only
.\build.ps1 -Installer    # NSIS installer only
```

---

## 🖥️ Usage

### Boot-time Settings

On boot, press **F2** within 2 seconds to open the settings menu:

| Setting | Options | Description |
|---|---|---|
| **Protection** | AN / AUS | Enable or disable the hypervisor |
| **Auto-Start** | AUTO / MANUAL | Auto-enable on boot or ask every time |

### System Tray Agent

Once Windows boots, the AegisGate agent runs in the system tray:

- 🟢 **Green shield** — Hypervisor active, system protected
- 🟡 **Yellow shield** — Hypervisor active, reduced protection
- 🔴 **Red shield** — Hypervisor not detected

**Right-click menu:**
- Status — Show protection details
- Settings — Toggle features
- Shutdown HV — Devirtualize (requires confirmation)

---

## 🧪 Testing

### QEMU (Nested Virtualization)

```bash
# Linux host with KVM (nested virt enabled)
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host,+svm \
  -m 4G \
  -bios /usr/share/OVMF/OVMF_CODE.fd \
  -drive file=fat:rw:esp/,format=raw \
  -net none \
  -serial stdio
```

### Hardware Testing

1. Flash `aegisgate.efi` to USB ESP partition: `\EFI\Boot\bootx64.efi`
2. Set USB as first boot device
3. AegisGate logo appears → Windows boots as guest VM
4. Run `AegisGate.exe` → should show "Connected ✅"

---

## 🗺️ Roadmap

- [x] AMD SVM backend (full implementation)
- [x] Intel VT-x backend
- [x] UEFI bootloader with settings UI
- [x] Windows tray agent (driverless VMCALL)
- [x] AES-256-GCM crypto engine
- [x] Stealth engine (CPUID/MSR/TSC)
- [x] USB attack detection
- [x] Kernel integrity protection
- [x] NSIS installer
- [ ] Full Curve25519 ECDH implementation
- [ ] ISO builder for boot USB
- [ ] GitHub Actions CI/CD pipeline
- [ ] Linux agent port
- [ ] ARM64 support (Hyper-V compatible)

---

## 🤝 Contributing

Contributions are welcome! Please read [SECURITY.md](SECURITY.md) for vulnerability reporting.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Developer:</strong> Nik<br>
  <sub>Built with 🔥 — Zero latency, maximum security.</sub>
</p>
