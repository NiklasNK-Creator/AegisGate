;; ============================================================================
;; AegisGate — Hypervisor Security Gate System
;; Developer: Nik
;;
;; common_macros.asm — Shared assembly macros for NASM (x86-64)
;;                     Used by boot, hypervisor, and crypto ASM modules.
;; ============================================================================

;; Target: x86-64 only
BITS 64
DEFAULT REL

;; ============================================================================
;;  Calling Convention: Microsoft x64 ABI
;;  RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
;;  Volatile: RAX, RCX, RDX, R8, R9, R10, R11, XMM0-XMM5
;;  Non-volatile: RBX, RBP, RDI, RSI, R12-R15, XMM6-XMM15
;;  Return: RAX (integer), XMM0 (float)
;;  Shadow space: 32 bytes (4 × 8) must be allocated before CALL
;; ============================================================================

;; ── Function Prologue/Epilogue ─────────────────────────────────────────────

;; Save all non-volatile registers (for functions that need them)
%macro SAVE_NONVOLATILE 0
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
%endmacro

%macro RESTORE_NONVOLATILE 0
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
%endmacro

;; ── Guest Register Save/Restore (VM-Exit) ──────────────────────────────────
;; Must match the layout of aegis::GuestRegisters struct exactly!

%macro SAVE_GUEST_REGS 0
    push    rax         ; offset 0x00
    push    rcx         ; offset 0x08
    push    rdx         ; offset 0x10
    push    rbx         ; offset 0x18
    push    rbp         ; offset 0x20
    push    rsi         ; offset 0x28
    push    rdi         ; offset 0x30
    push    r8          ; offset 0x38
    push    r9          ; offset 0x40
    push    r10         ; offset 0x48
    push    r11         ; offset 0x50
    push    r12         ; offset 0x58
    push    r13         ; offset 0x60
    push    r14         ; offset 0x68
    push    r15         ; offset 0x70
%endmacro

%macro RESTORE_GUEST_REGS 0
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
%endmacro

;; ── MSR Access ─────────────────────────────────────────────────────────────

;; Read MSR: ECX = MSR index, returns EDX:EAX (also in RAX combined)
%macro READ_MSR 1
    mov     ecx, %1
    rdmsr
    shl     rdx, 32
    or      rax, rdx
%endmacro

;; Write MSR: ECX = MSR index, EDX:EAX = value
%macro WRITE_MSR 2
    mov     ecx, %1
    mov     eax, %2
    mov     edx, %2
    shr     rdx, 32
    wrmsr
%endmacro

;; ── Control Register Access ────────────────────────────────────────────────

%macro READ_CR0 0
    mov     rax, cr0
%endmacro

%macro READ_CR3 0
    mov     rax, cr3
%endmacro

%macro READ_CR4 0
    mov     rax, cr4
%endmacro

;; ── CPUID Helper ───────────────────────────────────────────────────────────

;; Execute CPUID and return all 4 registers via memory pointers
;; Args: leaf (imm32), out_eax (reg), out_ebx (reg), out_ecx (reg), out_edx (reg)
%macro DO_CPUID 1
    push    rbx
    mov     eax, %1
    xor     ecx, ecx
    cpuid
    pop     rbx
%endmacro

;; ── Memory Barriers ────────────────────────────────────────────────────────

%macro FULL_BARRIER 0
    mfence
%endmacro

%macro STORE_BARRIER 0
    sfence
%endmacro

%macro LOAD_BARRIER 0
    lfence
%endmacro

;; ── Page Constants ─────────────────────────────────────────────────────────

PAGE_SIZE_4K    equ 0x1000
PAGE_SIZE_2M    equ 0x200000
PAGE_SIZE_1G    equ 0x40000000

;; ── AMD SVM Constants ──────────────────────────────────────────────────────

MSR_VM_CR           equ 0xC0010114
MSR_VM_HSAVE_PA     equ 0xC0010117
MSR_EFER            equ 0xC0000080
EFER_SVME_BIT       equ 12              ; SVM Enable bit in EFER

;; SVM VMCB offsets (control area)
VMCB_CR_INTERCEPTS  equ 0x010
VMCB_DR_INTERCEPTS  equ 0x014
VMCB_EXCEPTION_VEC  equ 0x018
VMCB_INTERCEPT_MISC1 equ 0x00C
VMCB_INTERCEPT_MISC2 equ 0x010
VMCB_GUEST_ASID     equ 0x058
VMCB_TLB_CONTROL    equ 0x05C
VMCB_EXITCODE       equ 0x070
VMCB_EXITINFO1      equ 0x078
VMCB_EXITINFO2      equ 0x080
VMCB_GUEST_RIP      equ 0x178
VMCB_GUEST_RSP      equ 0x1D8
VMCB_GUEST_RAX      equ 0x1F8
VMCB_NPT_CR3        equ 0x0B0
VMCB_NPT_ENABLE     equ 0x090

;; SVM #VMEXIT codes
VMEXIT_CR_READ      equ 0x000   ; 0x000 - 0x00F (CR0-CR15)
VMEXIT_CR_WRITE     equ 0x010   ; 0x010 - 0x01F
VMEXIT_CPUID        equ 0x072
VMEXIT_HLT          equ 0x078
VMEXIT_INVD         equ 0x076
VMEXIT_VMRUN        equ 0x080
VMEXIT_VMCALL       equ 0x081
VMEXIT_VMLOAD       equ 0x082
VMEXIT_VMSAVE       equ 0x083
VMEXIT_MSR          equ 0x07C
VMEXIT_NPF          equ 0x400   ; Nested Page Fault
VMEXIT_SHUTDOWN     equ 0x07F

;; ── Intel VMX Constants (for future use) ───────────────────────────────────

MSR_IA32_VMX_BASIC           equ 0x480
MSR_IA32_VMX_CR0_FIXED0      equ 0x486
MSR_IA32_VMX_CR0_FIXED1      equ 0x487
MSR_IA32_VMX_CR4_FIXED0      equ 0x488
MSR_IA32_VMX_CR4_FIXED1      equ 0x489
MSR_IA32_FEATURE_CONTROL     equ 0x03A
