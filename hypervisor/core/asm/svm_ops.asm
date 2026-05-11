;; ============================================================================
;; AegisGate — Hypervisor Security Gate System
;; Developer: Nik
;;
;; svm_ops.asm — AMD SVM low-level operations in x86-64 assembly.
;;               VMRUN loop, host/guest state transitions, MSR access.
;;               Microsoft x64 ABI calling convention.
;; ============================================================================

%include "../../../common/asm/common_macros.asm"

SECTION .text

;; ============================================================================
;; void AsmSvmEnable(void)
;; Sets EFER.SVME (bit 12) to enable SVM on this CPU.
;; ============================================================================
global AsmSvmEnable
AsmSvmEnable:
    mov     ecx, MSR_EFER           ; 0xC0000080
    rdmsr
    bts     eax, EFER_SVME_BIT      ; Set bit 12
    wrmsr
    ret

;; ============================================================================
;; void AsmSvmDisable(void)
;; Clears EFER.SVME (bit 12) to disable SVM on this CPU.
;; ============================================================================
global AsmSvmDisable
AsmSvmDisable:
    mov     ecx, MSR_EFER
    rdmsr
    btr     eax, EFER_SVME_BIT      ; Clear bit 12
    wrmsr
    ret

;; ============================================================================
;; void AsmSvmVmrun(UINT64 vmcbPhysAddr)
;; Executes the VMRUN instruction. RCX = physical address of VMCB.
;; After VMRUN, CPU enters guest mode. On #VMEXIT, execution resumes
;; after the VMRUN instruction.
;; ============================================================================
global AsmSvmVmrun
AsmSvmVmrun:
    mov     rax, rcx                ; VMRUN uses RAX for VMCB PA
    vmrun   rax
    ret

;; ============================================================================
;; void AsmSvmVmload(UINT64 vmcbPhysAddr)
;; Loads additional guest state from VMCB (FS, GS, TR, LDTR, etc.)
;; ============================================================================
global AsmSvmVmload
AsmSvmVmload:
    mov     rax, rcx
    vmload  rax
    ret

;; ============================================================================
;; void AsmSvmVmsave(UINT64 vmcbPhysAddr)
;; Saves additional host state to VMCB.
;; ============================================================================
global AsmSvmVmsave
AsmSvmVmsave:
    mov     rax, rcx
    vmsave  rax
    ret

;; ============================================================================
;; void AsmSvmStgi(void) / void AsmSvmClgi(void)
;; Set/Clear Global Interrupt Flag
;; ============================================================================
global AsmSvmStgi
AsmSvmStgi:
    stgi
    ret

global AsmSvmClgi
AsmSvmClgi:
    clgi
    ret

;; ============================================================================
;; void AsmSetVmHsavePa(UINT64 physAddr)
;; Write the VM_HSAVE_PA MSR (0xC0010117)
;; ============================================================================
global AsmSetVmHsavePa
AsmSetVmHsavePa:
    mov     rax, rcx
    mov     edx, ecx
    shr     rdx, 32
    mov     ecx, MSR_VM_HSAVE_PA   ; 0xC0010117
    wrmsr
    ret

;; ============================================================================
;; UINT64 AsmGetVmHsavePa(void)
;; Read the VM_HSAVE_PA MSR
;; ============================================================================
global AsmGetVmHsavePa
AsmGetVmHsavePa:
    mov     ecx, MSR_VM_HSAVE_PA
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    ret

;; ============================================================================
;; UINT64 AsmReadMsr(UINT32 msrIndex)
;; Generic MSR read. RCX = MSR index. Returns 64-bit value in RAX.
;; ============================================================================
global AsmReadMsr
AsmReadMsr:
    ; RCX already contains MSR index (MS x64 ABI, arg1 = RCX)
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    ret

;; ============================================================================
;; void AsmWriteMsr(UINT32 msrIndex, UINT64 value)
;; Generic MSR write. RCX = index, RDX = value.
;; ============================================================================
global AsmWriteMsr
AsmWriteMsr:
    ; RCX = MSR index, RDX = 64-bit value
    mov     rax, rdx
    shr     rdx, 32
    ; Now: ECX = index, EDX:EAX = value
    wrmsr
    ret

;; ============================================================================
;; UINT64 AsmVirtToPhys(void* virtualAddr)
;; Walk current page tables to translate VA → PA.
;; Simplified: assumes 4-level paging, 4KB pages.
;; RCX = virtual address. Returns physical address in RAX.
;; ============================================================================
global AsmVirtToPhys
AsmVirtToPhys:
    ; For UEFI context, we can use the identity mapping or CR3 walk
    ; In UEFI boot services, VA = PA (identity mapped), so:
    mov     rax, rcx
    ret
    ; NOTE: In a general OS context, this would need a full page table walk.
    ; The hypervisor should maintain its own VA→PA translation tables.

;; ============================================================================
;; void AsmSvmEntryLoop(VcpuData* vcpu)
;;
;; The core SVM guest entry/exit loop.
;; This is the most performance-critical code in the entire hypervisor.
;;
;; RCX = pointer to VcpuData struct.
;;
;; Flow:
;;   1. Save host (non-volatile) registers
;;   2. Load VMCB physical address
;;   3. Load guest GPRs from VMCB
;;   4. CLGI (disable interrupts globally)
;;   5. VMRUN (enter guest mode)
;;   6. On #VMEXIT: save guest GPRs to stack
;;   7. STGI (re-enable interrupts)
;;   8. Call C handler
;;   9. If handler says "continue" → go to step 3
;;  10. If handler says "stop" → restore host regs and return
;;
;; Register allocation:
;;   RBX = pointer to VcpuData (preserved across calls)
;;   R12 = VMCB physical address (preserved across calls)
;; ============================================================================

;; Offset of GuestVmcb within VcpuData (it's the first field, offset 0)
VCPU_VMCB_OFFSET    equ 0
;; Offset of GuestVmcb.State.Rax (VMCB offset 0x5F8)
VMCB_RAX_OFFSET     equ 0x5F8

;; External C handler:
;;   bool HandleVmExitSvm(VcpuData* vcpu, GuestRegisters* regs)
;;   Returns: 1 = continue guest, 0 = stop hypervisor
extern HandleVmExitSvm

global AsmSvmEntryLoop
AsmSvmEntryLoop:
    ;; ── Save host non-volatile registers ──────────────────────────────
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ;; Save VcpuData pointer in RBX (non-volatile)
    mov     rbx, rcx

    ;; Get VMCB physical address
    ;; VcpuData starts with the VMCB struct, so VMCB PA = VirtToPhys(vcpu)
    lea     rcx, [rbx + VCPU_VMCB_OFFSET]
    call    AsmVirtToPhys
    mov     r12, rax            ; R12 = VMCB physical address

.guest_entry:
    ;; ── Load guest GPRs from VMCB state ──────────────────────────────
    ;; Note: SVM automatically loads/saves RAX, RSP, RIP, RFLAGS from VMCB.
    ;; We must manually load/save all other GPRs.
    
    ;; Load guest general-purpose registers
    ;; These are stored in the VcpuData's save area (after VMCB)
    ;; For simplicity, we use a separate save area adjacent to VcpuData
    ;; The VMCB State Area only saves RAX. All other GPRs must be
    ;; manually managed by the hypervisor.
    
    ;; We use the stack-based approach: guest GPRs are saved on the
    ;; host stack during #VMEXIT and restored before VMRUN.
    ;; First run: registers are already in their initial state.
    
    ;; Load guest RAX from VMCB (SVM uses VMCB.State.RAX)
    mov     rax, [rbx + VMCB_RAX_OFFSET]
    
    ;; ── Disable interrupts globally ──────────────────────────────────
    clgi
    
    ;; ── Execute VMRUN ────────────────────────────────────────────────
    ;; RAX = VMCB physical address for VMRUN
    push    rax                 ; Save guest RAX temporarily
    mov     rax, r12            ; RAX = VMCB PA (required by VMRUN)
    vmrun   rax                 ; >>> ENTER GUEST MODE <<<
    
    ;; ──────────────────────────────────────────────────────────────────
    ;; #VMEXIT: We're back in host mode!
    ;; CPU has restored host state from HSAVE area.
    ;; Guest RAX is in VMCB.State.RAX (saved by CPU).
    ;; All other guest GPRs are still in physical registers!
    ;; ──────────────────────────────────────────────────────────────────
    
    pop     rax                 ; Discard the saved guest RAX (it's in VMCB now)
    
    ;; ── Re-enable interrupts ─────────────────────────────────────────
    stgi
    
    ;; ── Save guest GPRs to stack (GuestRegisters struct) ─────────────
    ;; This creates a GuestRegisters struct on the stack that we
    ;; pass to the C handler.
    SAVE_GUEST_REGS             ; push rax..r15 (15 registers = 120 bytes)
    
    ;; ── Call C VM-Exit handler ───────────────────────────────────────
    mov     rcx, rbx            ; Arg1: VcpuData* vcpu
    mov     rdx, rsp            ; Arg2: GuestRegisters* regs (on stack)
    sub     rsp, 32             ; Shadow space (MS x64 ABI)
    call    HandleVmExitSvm
    add     rsp, 32
    
    ;; ── Check handler result ─────────────────────────────────────────
    ;; EAX = 1: continue guest, 0: stop
    test    eax, eax
    jz      .exit_loop
    
    ;; ── Restore guest GPRs from stack ────────────────────────────────
    ;; The C handler may have modified them (e.g., CPUID result in RAX)
    RESTORE_GUEST_REGS
    
    ;; ── Store updated guest RAX back to VMCB ─────────────────────────
    ;; (VMRUN loads RAX from VMCB, not from the physical register)
    mov     [rbx + VMCB_RAX_OFFSET], rax
    
    ;; ── Loop back to guest entry ─────────────────────────────────────
    jmp     .guest_entry

.exit_loop:
    ;; ── Clean up guest GPRs from stack ───────────────────────────────
    RESTORE_GUEST_REGS          ; Pop but discard (we're exiting)
    
    ;; ── Restore host non-volatile registers ──────────────────────────
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret
