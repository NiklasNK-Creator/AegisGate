# AegisGate

> *"The Gate Below"* — A Ring -1 Hypervisor Security Gate for Windows
> 
> Developer: **Nik**

---

## What is AegisGate?

AegisGate is a bare-metal hypervisor that boots **before Windows** via UEFI. It uses hardware virtualization (AMD-V / Intel VT-x) to create an invisible security layer at Ring -1 — below the operating system kernel.

Windows runs as a controlled guest VM while AegisGate monitors and protects the system from:

-  **Kernel-level malware & rootkits** (NPT/EPT memory protection)
-  **USB hardware attacks** (Rubber Ducky, BadUSB) via I/O interception
-  **Bootkits** (AegisGate loads before any OS code)
-  **Memory manipulation** (watchpoints on critical kernel structures)

**Zero performance impact** — designed for extreme speed with minimal VM-Exit overhead.

---

## How It Works

```
┌─────────────────────────────────────────┐
│  1. PC boots → UEFI loads aegisgate.efi │
│  2. Logo screen (2 sec, press F2 for    │
│     settings)                           │
│  3. Hypervisor initializes (AMD-V/VT-x) │
│  4. Windows boots as VM guest           │
│  5. AegisGate.exe connects to HV        │
└─────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

1. **CPU**: AMD Ryzen 1000+ or Intel Core 4th Gen+ (with AMD-V/VT-x support)
2. **Firmware**: UEFI (not Legacy BIOS)
3. **OS**: Windows 10/11 64-Bit

### Step 1: Enable Virtualization in BIOS

1. Restart your PC and enter BIOS/UEFI (usually `DEL` or `F2` during boot)
2. Find the virtualization setting:
   - **AMD**: Look for `SVM Mode` → set to `Enabled`
   - **Intel**: Look for `Intel Virtualization Technology` / `VT-x` → set to `Enabled`
3. Save and exit BIOS

### Step 2: Disable Hyper-V (if enabled)

Open **PowerShell as Administrator** and run:
```powershell
bcdedit /set hypervisorlaunchtype off
```
Restart your PC.

### Step 3: Disable Secure Boot

1. Enter BIOS/UEFI settings
2. Find `Secure Boot` → set to `Disabled`
3. Save and exit

### Step 4: Flash AegisGate to USB

1. Download `AegisGate-Boot.iso` from [Releases](../../releases)
2. Download [Rufus](https://rufus.ie/)
3. Flash the ISO to a USB stick using Rufus (GPT, UEFI, FAT32)

### Step 5: Set Boot Order

1. Enter BIOS/UEFI settings
2. Set the USB stick (or later: the AegisGate partition) as **first boot device**
3. Save and exit

### Step 6: Install Windows Agent

1. Download `AegisGate-Setup.exe` from [Releases](../../releases)
2. Run the installer
3. AegisGate icon appears in system tray

---

## Settings

On boot, you have **2 seconds** to press `F2` to enter the settings menu:

| Option | Values | Description |
|---|---|---|
| **Protection** | AN / AUS | Enable or disable the hypervisor |
| **Auto-Start** | AUTO / MANUELL | Auto-enable on next boot or ask every time |

---

## Architecture

```
Ring -1 (VMX/SVM Root) ─── AegisGate Hypervisor Core
                           ├── NPT/EPT Memory Protection
                           ├── AES-256-GCM Crypto Engine
                           ├── Stealth Engine
                           └── Protection Modules

Ring 3 (Windows)      ─── AegisGate.exe (Tray Agent)
                           └── Direct VMCALL Communication
```

No kernel driver required — the Agent communicates directly with the Hypervisor via `VMCALL` instructions.

---

## Hardware Compatibility

| CPU | Support |
|---|---|
| AMD Ryzen 1000+ (Zen 1+) | ✅ Full |
| Intel Core 4th Gen+ (Haswell+) | ✅ Full |
| Intel Atom (Goldmont+) | ⚠️ Limited |
| Older CPUs (pre-2013) | ❌ Not supported |

---

## License

Open-source components (boot, HAL, agent, SDK) are under MIT License.  
Core hypervisor and crypto engine are distributed as prebuilt binaries.

---

## Security

Found a vulnerability? Please report it responsibly via [SECURITY.md](SECURITY.md).
