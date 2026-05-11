;; ============================================================================
;; AegisGate — Hypervisor Security Gate System
;; Developer: Nik
;;
;; cpuid_check.asm — CPUID-based CPU vendor and virtualization feature detection.
;;                   x86-64 NASM, Microsoft x64 ABI.
;; ============================================================================

%include "../../common/asm/common_macros.asm"

SECTION .text

;; ============================================================================
;; UINT32 AsmCheckCpuVendor(void)
;;
;; Returns: 0 = Unknown, 1 = Intel ("GenuineIntel"), 2 = AMD ("AuthenticAMD")
;; ============================================================================
global AsmCheckCpuVendor
AsmCheckCpuVendor:
    push    rbx

    xor     eax, eax            ; CPUID leaf 0: Vendor ID
    cpuid

    ;; Intel: EBX=756E6547h EDX=49656E69h ECX=6C65746Eh ("GenuineIntel")
    cmp     ebx, 0x756E6547
    jne     .try_amd
    cmp     edx, 0x49656E69
    jne     .try_amd
    cmp     ecx, 0x6C65746E
    jne     .try_amd
    mov     eax, 1              ; Intel
    pop     rbx
    ret

.try_amd:
    ;; AMD: EBX=68747541h EDX=69746E65h ECX=444D4163h ("AuthenticAMD")
    cmp     ebx, 0x68747541
    jne     .unknown
    cmp     edx, 0x69746E65
    jne     .unknown
    cmp     ecx, 0x444D4163
    jne     .unknown
    mov     eax, 2              ; AMD
    pop     rbx
    ret

.unknown:
    xor     eax, eax            ; 0 = Unknown
    pop     rbx
    ret


;; ============================================================================
;; BOOLEAN AsmCheckVtxSupport(void)
;;
;; Check Intel VT-x: CPUID.1:ECX bit 5 (VMX)
;; Returns: 1 = supported, 0 = not supported
;; ============================================================================
global AsmCheckVtxSupport
AsmCheckVtxSupport:
    push    rbx
    mov     eax, 1
    cpuid
    bt      ecx, 5             ; VMX feature bit
    setc    al
    movzx   eax, al
    pop     rbx
    ret


;; ============================================================================
;; BOOLEAN AsmCheckSvmSupport(void)
;;
;; Check AMD SVM: CPUID.8000_0001h:ECX bit 2 (SVM)
;; Returns: 1 = supported, 0 = not supported
;; ============================================================================
global AsmCheckSvmSupport
AsmCheckSvmSupport:
    push    rbx
    mov     eax, 0x80000001
    cpuid
    bt      ecx, 2             ; SVM feature bit
    setc    al
    movzx   eax, al
    pop     rbx
    ret


;; ============================================================================
;; BOOLEAN AsmCheckVtxEnabled(void)
;;
;; Read IA32_FEATURE_CONTROL MSR (0x3A) for Intel VT-x.
;; Checks Lock bit (0) and Enable VMX outside SMX (bit 2).
;; Returns: 1 = VT-x enabled and locked, 0 = disabled or unlocked
;; ============================================================================
global AsmCheckVtxEnabled
AsmCheckVtxEnabled:
    mov     ecx, 0x3A          ; IA32_FEATURE_CONTROL
    rdmsr
    and     eax, 0x05          ; Bit 0 (Lock) + Bit 2 (VMX outside SMX)
    cmp     eax, 0x05
    sete    al
    movzx   eax, al
    ret


;; ============================================================================
;; BOOLEAN AsmCheckSvmDisabledByBios(void)
;;
;; Read VM_CR MSR (0xC001_0114) for AMD SVM.
;; Checks SVM_DISABLE bit (bit 4). If set, BIOS has locked SVM off.
;; Returns: 1 = SVM disabled by BIOS, 0 = SVM available
;; ============================================================================
global AsmCheckSvmDisabledByBios
AsmCheckSvmDisabledByBios:
    mov     ecx, 0xC0010114    ; MSR_VM_CR
    rdmsr
    bt      eax, 4             ; SVM_DISABLE bit
    setc    al
    movzx   eax, al
    ret


;; ============================================================================
;; BOOLEAN AsmCheckNptSupport(void)
;;
;; Check AMD NPT (Nested Page Tables): CPUID.8000_000Ah:EDX bit 0
;; Returns: 1 = NPT supported, 0 = not supported
;; ============================================================================
global AsmCheckNptSupport
AsmCheckNptSupport:
    push    rbx
    mov     eax, 0x8000000A    ; SVM Features leaf
    cpuid
    bt      edx, 0             ; NPT bit
    setc    al
    movzx   eax, al
    pop     rbx
    ret


;; ============================================================================
;; BOOLEAN AsmCheckAesNiSupport(void)
;;
;; Check AES-NI: CPUID.1:ECX bit 25
;; Returns: 1 = AES-NI supported, 0 = not supported
;; ============================================================================
global AsmCheckAesNiSupport
AsmCheckAesNiSupport:
    push    rbx
    mov     eax, 1
    cpuid
    bt      ecx, 25            ; AES-NI bit
    setc    al
    movzx   eax, al
    pop     rbx
    ret


;; ============================================================================
;; UINT32 AsmGetMaxPhysAddrBits(void)
;;
;; Get maximum physical address width: CPUID.8000_0008h:EAX[7:0]
;; Returns: Number of physical address bits (e.g., 36, 39, 48)
;; ============================================================================
global AsmGetMaxPhysAddrBits
AsmGetMaxPhysAddrBits:
    push    rbx
    mov     eax, 0x80000008
    cpuid
    and     eax, 0xFF          ; Low 8 bits = phys addr width
    pop     rbx
    ret
