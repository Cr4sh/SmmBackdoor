BITS 64
GLOBAL smm_call

;
; Magic values that backdoor checks for.
;
%define R8_VAL 0x4141414141414141
%define R9_VAL 0x4242424242424242

;
; int smm_call(long code, unsigned long long arg1, unsigned long long arg2)
;
; Sends control request with specified code and argument to
; SMM backdoor.
;
; Returns EFI_STATUS of requested operation.
;
smm_call:

    push   rcx
    push   r8
    push   r9

    ; SMI timer handler checks R8 and R9 for this magic values
    mov    r8, R8_VAL
    mov    r9, R9_VAL

    xor    rax, rax
    dec    rax

    ; jump in infinite loop with RCX as instruction address
    mov    rcx, _loop
    jmp    rcx

    ; landing area for modified RCX value
    nop
    nop
    nop
    nop
    nop
    nop
    jmp    short _end

_loop:
    ;
    ; SMI timer handler will be called when process runs in 
    ; infinite loop with magic registers values. SMM backdoor 
    ; decrements RCX value (--> jmp _end) to exit from the loop.
    ; Code and Arg for SmmCallHandle() are going in RDI and RSI.
    ;
    nop
    jmp    rcx

_end:

    pop    r9
    pop    r8
    pop    rcx

    ; SMM backdoor returns status code in RAX register
    ret

