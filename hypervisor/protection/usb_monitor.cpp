/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * usb_monitor.cpp — USB attack detection and blocking via I/O interception.
 */

#include "usb_monitor.h"
#include "../../common/include/aegis_config.h"

namespace aegis::protection {

BOOLEAN UsbMonitor::s_Enabled = FALSE;

// ============================================================================
//  Known attack device signatures
// ============================================================================

struct KnownBadDevice {
    UINT16 VendorId;
    UINT16 ProductId;
    const char* Name;
};

// USB Rubber Ducky and common BadUSB vendor/product IDs
static const KnownBadDevice g_BlockedDevices[] = {
    { 0x05AC, 0x0000, "Spoofed Apple Keyboard" },   // Common BadUSB spoof
    { 0x1B4F, 0x9205, "SparkFun Pro Micro" },        // Often used for BadUSB
    { 0x1B4F, 0x9206, "SparkFun Pro Micro (alt)" },
    { 0x2341, 0x8036, "Arduino Leonardo" },           // HID attack platform
    { 0x2341, 0x8037, "Arduino Micro" },
    { 0x16C0, 0x0486, "Teensy HID" },                // Teensy-based attacks
    { 0x16C0, 0x0487, "Teensy Serial+HID" },
    { 0x0483, 0x5740, "STM32 Virtual COM" },          // STM32 BadUSB
    { 0x239A, 0x000E, "Adafruit Trinket" },           // Trinket HID attack
};

static const UINT32 g_BlockedDeviceCount = sizeof(g_BlockedDevices) / sizeof(g_BlockedDevices[0]);

// ============================================================================
//  Initialization
// ============================================================================

HvStatus UsbMonitor::Initialize() {
    s_Enabled = config::PROTECT_USB_ENABLED_DEFAULT;
    
    // The I/O permission map (IOPM) bits for USB controller ports
    // are set up during SVM initialization. Here we just configure
    // which ports to monitor.
    //
    // For xHCI/EHCI (modern USB 3.0/2.0):
    //   These use MMIO, so we protect their BAR address ranges via NPT.
    //   The NPT pages covering the xHCI MMIO region are set to read-only.
    //   Any write from the guest triggers an NPT fault → we inspect it.
    //
    // For UHCI (legacy USB 1.x):
    //   These use I/O ports. We set the IOPM bits for the UHCI port range.
    //   Any IN/OUT to those ports triggers an I/O VM-Exit.
    
    return HV_SUCCESS;
}

// ============================================================================
//  Device Evaluation
// ============================================================================

bool UsbMonitor::IsRubberDuckySignature(const UsbDeviceInfo* dev) {
    // Rubber Ducky pattern: appears as a keyboard (HID)
    // but has unusual vendor ID or extremely fast keystroke injection
    
    // Check known blocked device list
    for (UINT32 i = 0; i < g_BlockedDeviceCount; i++) {
        if (dev->VendorId == g_BlockedDevices[i].VendorId &&
            dev->ProductId == g_BlockedDevices[i].ProductId) {
            return true;
        }
    }
    
    return false;
}

bool UsbMonitor::IsBadUsbSignature(const UsbDeviceInfo* dev) {
    // BadUSB pattern: mass storage device that ALSO presents as HID
    // (legitimate USB drives don't have keyboard interfaces)
    
    if (dev->HasHidInterface && dev->HasStorageInterface) {
        return true;  // Composite device with HID + Storage = suspicious
    }
    
    // Device claims to be a hub but has HID interface
    if (dev->Class == UsbDeviceClass::Hub && dev->HasHidInterface) {
        return true;
    }
    
    return false;
}

UsbThreatLevel UsbMonitor::EvaluateDevice(const UsbDeviceInfo* device) {
    if (!device || !s_Enabled) return UsbThreatLevel::Normal;
    
    // Check known attack devices
    if (IsRubberDuckySignature(device)) {
        return UsbThreatLevel::Blocked;
    }
    
    // Check BadUSB composite patterns
    if (IsBadUsbSignature(device)) {
        return UsbThreatLevel::Suspicious;
    }
    
    // Multiple interfaces on a "simple" device
    if (device->InterfaceCount > 3) {
        return UsbThreatLevel::Suspicious;
    }
    
    return UsbThreatLevel::Normal;
}

// ============================================================================
//  I/O Interception Handler
// ============================================================================

HvStatus UsbMonitor::HandleUsbIo(UINT16 port, BOOLEAN isWrite, UINT32 value) {
    if (!s_Enabled) return HV_SUCCESS;
    
    (void)port;
    (void)isWrite;
    (void)value;
    
    // TODO: Parse USB controller register writes to extract device descriptors
    // and feed them to EvaluateDevice()
    //
    // For xHCI MMIO:
    //   Watch for PORTSC register writes (port status change)
    //   Extract device descriptor from transfer ring
    //
    // For UHCI I/O:
    //   Watch PORTSC register for connect/disconnect
    //   Intercept setup packets on the schedule
    
    return HV_SUCCESS;
}

// ============================================================================
//  Runtime Control
// ============================================================================

void UsbMonitor::GetMonitoredPorts(UINT16* ports, UINT32* count) {
    if (!ports || !count) return;
    // Ports are detected from PCI config space at init time
    *count = 0;
}

void UsbMonitor::SetEnabled(BOOLEAN enabled) { s_Enabled = enabled; }
BOOLEAN UsbMonitor::IsEnabled() { return s_Enabled; }

} // namespace aegis::protection
