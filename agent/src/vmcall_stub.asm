;; ============================================================================
;; AegisGate — Windows Agent VMCALL Stub
;; Developer: Nik
;;
;; vmcall_stub.asm — Execute VMCALL from Ring 3 (user mode).
;;                   Microsoft x64 ABI.
;;
;; void AsmDoVmcall(
;;     RCX = rax_val (hypercall ID),
;;     RDX = rbx_val (param 1),
;;     R8  = rcx_val (param 2),
;;     R9  = rdx_val (session token),
;;     [rsp+40] = out_rax ptr,
;;     [rsp+48] = out_rbx ptr,
;;     [rsp+56] = out_rcx ptr
;; )
;; ============================================================================

SECTION .text

global AsmDoVmcall
AsmDoVmcall:
    ;; Save non-volatile registers
    push    rbx
    push    rsi
    push    rdi

    ;; Load parameters into the registers VMCALL expects
    ;; AegisGate convention:
    ;;   RAX = Hypercall ID
    ;;   RBX = Parameter 1
    ;;   RCX = Parameter 2
    ;;   RDX = Session Token
    
    mov     rax, rcx        ; arg1 → RAX (hypercall ID)
    mov     rbx, rdx        ; arg2 → RBX (param 1)
    ;; R8 contains arg3 (param 2) → needs to go to RCX
    ;; R9 contains arg4 (session token) → needs to go to RDX
    mov     rsi, r8         ; Save param 2 temporarily
    mov     rdi, r9         ; Save session token temporarily
    mov     rcx, rsi        ; RCX = param 2
    mov     rdx, rdi        ; RDX = session token

    ;; Execute VMCALL — triggers VM-Exit to hypervisor
    vmcall

    ;; After VMCALL returns:
    ;; RAX = HvStatus
    ;; RBX = Return value 1
    ;; RCX = Return value 2

    ;; Store results to output pointers
    ;; out_rax = [rsp + 40 + 24] (3 pushes × 8 = 24 bytes offset)
    mov     rsi, [rsp + 40 + 24]    ; out_rax ptr
    mov     [rsi], rax
    
    mov     rsi, [rsp + 48 + 24]    ; out_rbx ptr
    mov     [rsi], rbx
    
    mov     rsi, [rsp + 56 + 24]    ; out_rcx ptr
    mov     [rsi], rcx

    ;; Restore non-volatile registers
    pop     rdi
    pop     rsi
    pop     rbx
    ret
