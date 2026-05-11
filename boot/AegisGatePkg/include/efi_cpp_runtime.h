/**
 * AegisGate — Hypervisor Security Gate System
 * Developer: Nik
 * 
 * efi_cpp_runtime.h — Minimal C++ runtime for freestanding UEFI environment.
 *                     Provides placement new, basic memory ops, and static init support.
 *                     No exceptions, no RTTI, no standard library.
 */

#pragma once

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

// ============================================================================
//  Placement new / delete operators
//  Required for C++ object construction without stdlib
// ============================================================================

inline void* operator new(unsigned long long, void* ptr) noexcept {
    return ptr;
}

inline void* operator new[](unsigned long long, void* ptr) noexcept {
    return ptr;
}

inline void operator delete(void*, void*) noexcept {}
inline void operator delete[](void*, void*) noexcept {}

// Regular new/delete using UEFI AllocatePool
inline void* operator new(unsigned long long size) noexcept {
    return AllocatePool(size);
}

inline void* operator new[](unsigned long long size) noexcept {
    return AllocatePool(size);
}

inline void operator delete(void* ptr) noexcept {
    if (ptr) FreePool(ptr);
}

inline void operator delete[](void* ptr) noexcept {
    if (ptr) FreePool(ptr);
}

inline void operator delete(void* ptr, unsigned long long) noexcept {
    if (ptr) FreePool(ptr);
}

inline void operator delete[](void* ptr, unsigned long long) noexcept {
    if (ptr) FreePool(ptr);
}

// ============================================================================
//  Basic memory operations (wrapping UEFI BaseMemoryLib)
// ============================================================================

namespace aegis {

inline void MemZero(void* dest, UINTN size) {
    ZeroMem(dest, size);
}

inline void MemCopy(void* dest, const void* src, UINTN size) {
    CopyMem(dest, src, size);
}

inline void MemSet(void* dest, UINT8 value, UINTN size) {
    SetMem(dest, size, value);
}

inline INTN MemCompare(const void* a, const void* b, UINTN size) {
    return CompareMem(a, b, size);
}

/// Allocate page-aligned memory (4KB aligned)
inline void* AllocAlignedPages(UINTN numPages) {
    return AllocateAlignedPages(numPages, 4096);
}

/// Free page-aligned memory
inline void FreeAlignedPages(void* ptr, UINTN numPages) {
    if (ptr) FreePages(ptr, numPages);
}

/// Allocate memory aligned to a specific boundary
inline void* AllocAligned(UINTN size, UINTN alignment) {
    UINTN numPages = (size + 4095) / 4096;
    return AllocateAlignedPages(numPages, alignment);
}

} // namespace aegis

// ============================================================================
//  Pure virtual function handler (required by MSVC for abstract classes)
// ============================================================================

extern "C" int _purecall(void) {
    // Should never be called — indicates a bug
    // In a real system this would trigger a debug break
    while (1) {}
    return 0;
}

// ============================================================================
//  Guard variable support (for static local initialization)
//  Required by MSVC when using static locals in C++
// ============================================================================

#ifdef _MSC_VER
extern "C" {
    int __cdecl _guard_check_icall_nop(void) { return 0; }
    void __cdecl _guard_dispatch_icall(void) {}
}
#endif
