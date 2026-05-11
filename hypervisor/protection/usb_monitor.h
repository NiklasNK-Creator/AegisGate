/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * usb_monitor.h — USB device monitoring via I/O port interception.
 *                 Detects and blocks malicious USB devices (Rubber Ducky, BadUSB).
 */

#pragma once

#include "../../../common/include/types.h"
#include "../../../common/include/aegis_status.h"

namespace aegis::protection {

// ============================================================================
//  USB Device Classification
// ============================================================================

enum class UsbDeviceClass : UINT8 {
    Unknown     = 0x00,
    HID         = 0x03,  // Human Interface Device (keyboard, mouse)
    MassStorage = 0x08,  // USB drives
    Hub         = 0x09,
    Vendor      = 0xFF,  // Vendor-specific (suspicious)
};

enum class UsbThreatLevel : UINT8 {
    Safe        = 0,  // Known-good device
    Normal      = 1,  // Standard device, allow
    Suspicious  = 2,  // Multiple interfaces (e.g., storage + HID) — warn
    Blocked     = 3,  // Known attack pattern — block
};

/// USB device descriptor (minimal, extracted from USB traffic)
struct UsbDeviceInfo {
    UINT16 VendorId;
    UINT16 ProductId;
    UsbDeviceClass Class;
    UsbThreatLevel Threat;
    UINT8  InterfaceCount;
    BOOLEAN HasHidInterface;
    BOOLEAN HasStorageInterface;
};

// ============================================================================
//  USB Monitor Interface
// ============================================================================

class UsbMonitor {
public:
    /// Initialize USB monitoring (setup IOPM bits for USB controller ports)
    static HvStatus Initialize();
    
    /// Handle an intercepted I/O port access to a USB controller
    /// Called from the VM-Exit I/O handler
    static HvStatus HandleUsbIo(UINT16 port, BOOLEAN isWrite, UINT32 value);
    
    /// Evaluate a newly connected USB device
    static UsbThreatLevel EvaluateDevice(const UsbDeviceInfo* device);
    
    /// Get the list of monitored USB I/O port ranges
    static void GetMonitoredPorts(UINT16* ports, UINT32* count);
    
    /// Enable/disable USB monitoring at runtime
    static void SetEnabled(BOOLEAN enabled);
    static BOOLEAN IsEnabled();

private:
    /// Known attack signatures
    static bool IsRubberDuckySignature(const UsbDeviceInfo* dev);
    static bool IsBadUsbSignature(const UsbDeviceInfo* dev);
    
    static BOOLEAN s_Enabled;
};

// ============================================================================
//  USB Controller I/O Ports (xHCI, EHCI, UHCI)
// ============================================================================

namespace usb_ports {
    // UHCI (legacy) uses I/O port ranges, typically 0x??00-0x??1F
    // EHCI and xHCI use MMIO (memory-mapped I/O) — monitored via NPT
    
    // Common UHCI base addresses (PCI-assigned, vary per system)
    // These are detected at runtime from PCI config space
    constexpr UINT16 UHCI_CMD    = 0x00;  // Offset from base
    constexpr UINT16 UHCI_STS    = 0x02;
    constexpr UINT16 UHCI_INTR   = 0x04;
    constexpr UINT16 UHCI_PORTSC = 0x10;  // Port Status/Control
    
    // xHCI/EHCI MMIO BAR ranges — monitored via NPT page faults
    // Set the MMIO pages to read-only in NPT, catch writes
}

} // namespace aegis::protection
