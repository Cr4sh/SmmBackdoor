.code

public _get_addr

public _clear_wp
public _set_wp

PUSHAD  macro

        push    rbx
        push    rcx
        push    rdx
        push    rsi
        push    rdi
        push    r8
        push    r9
        push    r10
        push    r11
        push    r12
        push    r13
        push    r14
        push    r15

        endm

POPAD   macro

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
        pop     rdx
        pop     rcx
        pop     rbx

        endm


_get_addr:

    call    _lb
    
_lb:

    pop     rax
    ret


_clear_wp:

    push    rax                 
    mov     rax, cr0             
    and     eax, not 000010000h
    mov     cr0, rax
    pop     rax
    ret


_set_wp:

    push    rax
    mov     rax, cr0
    or      eax, 000010000h
    mov     cr0, rax
    pop     rax
    ret


end
