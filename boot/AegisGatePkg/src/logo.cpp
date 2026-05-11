/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * logo.cpp — Boot logo rendering via UEFI Graphics Output Protocol (GOP).
 *            Renders a procedural AegisGate shield logo directly to the framebuffer.
 *            No external image files needed — logo is generated from geometry.
 */

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>
#include <Library/UefiBootServicesTableLib.h>
#include "../../common/include/types.h"

using namespace aegis;

// ============================================================================
//  Color Palette
// ============================================================================

struct Pixel {
    UINT8 Blue;
    UINT8 Green;
    UINT8 Red;
    UINT8 Reserved;
};

static constexpr Pixel COLOR_BG       = {0x0A, 0x0A, 0x0A, 0};   // Near-black
static constexpr Pixel COLOR_SHIELD   = {0xE0, 0x80, 0x20, 0};   // Deep blue (#2080E0)
static constexpr Pixel COLOR_ACCENT   = {0xFF, 0xAA, 0x00, 0};   // Cyan accent (#00AAFF)
static constexpr Pixel COLOR_GLOW     = {0x60, 0x40, 0x10, 0};   // Subtle blue glow
static constexpr Pixel COLOR_TEXT     = {0xFF, 0xFF, 0xFF, 0};   // White

// ============================================================================
//  Procedural Shield Logo Generator
// ============================================================================

// Simple abs for integers
static inline INT32 Abs(INT32 x) { return x < 0 ? -x : x; }

/**
 * Check if point (x, y) is inside the shield shape.
 * Shield is a pointed-bottom rounded shape centered at (cx, cy).
 */
static BOOLEAN IsInsideShield(INT32 x, INT32 y, INT32 cx, INT32 cy, INT32 size) {
    INT32 dx = x - cx;
    INT32 dy = y - cy;
    INT32 adx = Abs(dx);

    // Top half: rounded rectangle
    if (dy < 0 && dy > -(size)) {
        INT32 width = size - ((-dy) * size / (size * 4));
        return adx < width;
    }

    // Bottom half: triangle tapering to a point
    if (dy >= 0 && dy < size) {
        INT32 width = size - (dy * size / size);
        // Tapered: wider at top, pointed at bottom
        INT32 taperWidth = (size * (size - dy)) / size;
        return adx < taperWidth;
    }

    return FALSE;
}

/**
 * Check if point is on the shield border (outline).
 */
static BOOLEAN IsShieldBorder(INT32 x, INT32 y, INT32 cx, INT32 cy, INT32 size, INT32 thickness) {
    BOOLEAN outer = IsInsideShield(x, y, cx, cy, size);
    BOOLEAN inner = IsInsideShield(x, y, cx, cy, size - thickness);
    return outer && !inner;
}

// ============================================================================
//  Text Rendering (bitmap font for "AegisGate")
//  Simple 8x8 pixel character bitmaps for key letters
// ============================================================================

// Minimal bitmap font — only chars needed for "AegisGate"
static const UINT8 FONT_A[8] = {0x3C,0x42,0x42,0x7E,0x42,0x42,0x42,0x00};
static const UINT8 FONT_e[8] = {0x00,0x00,0x3C,0x42,0x7E,0x40,0x3C,0x00};
static const UINT8 FONT_g[8] = {0x00,0x00,0x3E,0x42,0x42,0x3E,0x02,0x3C};
static const UINT8 FONT_i[8] = {0x08,0x00,0x18,0x08,0x08,0x08,0x1C,0x00};
static const UINT8 FONT_s[8] = {0x00,0x00,0x3E,0x40,0x3C,0x02,0x7C,0x00};
static const UINT8 FONT_G[8] = {0x3C,0x42,0x40,0x4E,0x42,0x42,0x3C,0x00};
static const UINT8 FONT_a[8] = {0x00,0x00,0x3C,0x02,0x3E,0x42,0x3E,0x00};
static const UINT8 FONT_t[8] = {0x10,0x10,0x7C,0x10,0x10,0x10,0x0C,0x00};

static void DrawChar(
    EFI_GRAPHICS_OUTPUT_PROTOCOL* gop,
    const UINT8* bitmap,
    UINT32 posX, UINT32 posY,
    UINT32 scale,
    Pixel color
) {
    for (UINT32 row = 0; row < 8; row++) {
        for (UINT32 col = 0; col < 8; col++) {
            if (bitmap[row] & (0x80 >> col)) {
                // Draw a scaled pixel block
                for (UINT32 sy = 0; sy < scale; sy++) {
                    for (UINT32 sx = 0; sx < scale; sx++) {
                        EFI_GRAPHICS_OUTPUT_BLT_PIXEL px = {color.Blue, color.Green, color.Red, 0};
                        gop->Blt(gop, &px, EfiBltVideoFill,
                                0, 0,
                                posX + col * scale + sx,
                                posY + row * scale + sy,
                                1, 1, 0);
                    }
                }
            }
        }
    }
}

static void DrawTitle(EFI_GRAPHICS_OUTPUT_PROTOCOL* gop, UINT32 cx, UINT32 y, UINT32 scale) {
    // "AegisGate" — 9 characters, centered
    const UINT8* chars[] = {FONT_A, FONT_e, FONT_g, FONT_i, FONT_s, FONT_G, FONT_a, FONT_t, FONT_e};
    UINT32 charCount = 9;
    UINT32 charWidth = 8 * scale + scale;  // char width + spacing
    UINT32 totalWidth = charCount * charWidth;
    UINT32 startX = cx - totalWidth / 2;

    for (UINT32 i = 0; i < charCount; i++) {
        Pixel color = (i < 5) ? COLOR_ACCENT : COLOR_TEXT;  // "Aegis" in accent, "Gate" in white
        DrawChar(gop, chars[i], startX + i * charWidth, y, scale, color);
    }
}

// ============================================================================
//  Main Logo Display Function
// ============================================================================

EFI_STATUS DisplayLogo(EFI_SYSTEM_TABLE* ST) {
    EFI_GRAPHICS_OUTPUT_PROTOCOL* gop = NULL;
    EFI_STATUS status = ST->BootServices->LocateProtocol(
        &gEfiGraphicsOutputProtocolGuid,
        NULL,
        (VOID**)&gop
    );

    if (EFI_ERROR(status) || !gop) {
        // No GOP available — fall back to text mode
        ST->ConOut->SetAttribute(ST->ConOut, EFI_LIGHTCYAN | EFI_BACKGROUND_BLACK);
        ST->ConOut->ClearScreen(ST->ConOut);
        ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"\r\n\r\n\r\n");
        ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"              AegisGate\r\n");
        ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"            \"The Gate Below\"\r\n\r\n");
        ST->ConOut->SetAttribute(ST->ConOut, EFI_DARKGRAY | EFI_BACKGROUND_BLACK);
        ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"        Press any key for settings...\r\n");
        return EFI_SUCCESS;
    }

    UINT32 width  = gop->Mode->Info->HorizontalResolution;
    UINT32 height = gop->Mode->Info->VerticalResolution;

    // Fill screen with dark background
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL bgColor = {COLOR_BG.Blue, COLOR_BG.Green, COLOR_BG.Red, 0};
    gop->Blt(gop, &bgColor, EfiBltVideoFill, 0, 0, 0, 0, width, height, 0);

    // Shield parameters
    UINT32 cx = width / 2;
    UINT32 cy = height / 2 - height / 8;
    UINT32 shieldSize = height / 6;
    UINT32 borderThickness = shieldSize / 8;

    // Draw shield with glow effect
    for (INT32 y = (INT32)(cy - shieldSize - 10); y < (INT32)(cy + shieldSize + 10); y++) {
        for (INT32 x = (INT32)(cx - shieldSize - 10); x < (INT32)(cx + shieldSize + 10); x++) {
            if (x < 0 || y < 0 || (UINT32)x >= width || (UINT32)y >= height) continue;

            if (IsShieldBorder(x, y, cx, cy, shieldSize, borderThickness)) {
                EFI_GRAPHICS_OUTPUT_BLT_PIXEL px = {COLOR_SHIELD.Blue, COLOR_SHIELD.Green, COLOR_SHIELD.Red, 0};
                gop->Blt(gop, &px, EfiBltVideoFill, 0, 0, x, y, 1, 1, 0);
            }
            else if (IsInsideShield(x, y, cx, cy, shieldSize - borderThickness)) {
                // Inner shield — subtle gradient
                EFI_GRAPHICS_OUTPUT_BLT_PIXEL px = {COLOR_GLOW.Blue, COLOR_GLOW.Green, COLOR_GLOW.Red, 0};
                gop->Blt(gop, &px, EfiBltVideoFill, 0, 0, x, y, 1, 1, 0);
            }
        }
    }

    // Draw "AegisGate" title below shield
    UINT32 textY = cy + shieldSize + shieldSize / 2;
    UINT32 textScale = (width >= 1920) ? 4 : ((width >= 1280) ? 3 : 2);
    DrawTitle(gop, cx, textY, textScale);

    // Draw "Press F2 for settings" hint
    UINT32 hintY = height - height / 8;
    // Simple text via ConOut fallback (easier than full bitmap font)
    ST->ConOut->SetCursorPosition(ST->ConOut, (width / 16) / 2 - 14, hintY / 16);
    ST->ConOut->SetAttribute(ST->ConOut, EFI_DARKGRAY | EFI_BACKGROUND_BLACK);
    ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"Press any key for settings...");

    return EFI_SUCCESS;
}

/**
 * Display an error message on screen.
 */
void DisplayError(EFI_SYSTEM_TABLE* ST, const CHAR16* message) {
    ST->ConOut->SetAttribute(ST->ConOut, EFI_LIGHTRED | EFI_BACKGROUND_BLACK);
    ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"\r\n  [ERROR] ");
    ST->ConOut->OutputString(ST->ConOut, (CHAR16*)message);
    ST->ConOut->OutputString(ST->ConOut, (CHAR16*)L"\r\n");
    ST->ConOut->SetAttribute(ST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
}
