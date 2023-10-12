PUBLIC QuadSleep 
PUBLIC memset

.code

QuadSleep PROC
    sub rsp, 28h               ;28h
    mov r10, _end
    sub r10, 0
    push r10                   ;30h
    push r9                    ;38h

    mov r10, 0FFFFFFFFh
    push r10    ;first arg     ;40h
    push rcx                   ;48h
    mov r10, 1
    push r10    ;second arg    ;50h
    push rdx                   ;58h

    lea r10, [rdx + 1]
    push r10                   ;60h

    sub rsp, 28h               ;88h
    push r8                    ;90h
    push r9                    ;98h
    mov r10, 0FFFFFFFFh
    push r10    ;first arg     ;A0h
    push rcx                   ;A8h
    mov r10, 1
    push r10    ;second arg    ;B0h
    push rdx                   ;B8h

    lea r10, [rdx + 1]
    push r10                   ;C0h

    sub rsp, 28h               ;E8h
    push r8                    ;F0h
    push r9                    ;F8h
    mov r10, 0FFFFFFFFh
    push r10    ;first arg     ;100h
    push rcx                   ;108h
    mov r10, 1
    push r10    ;second arg    ;110h
    push rdx                   ;118h

    lea r10, [rdx + 1]
    push r10                   ;120h
    
    sub rsp, 28h               ;148h
    push r8                    ;150h
    mov rcx, 0FFFFFFFFh     ;first arg
    mov rdx, 1              ;second arg

    jmp r9
    _end:

    add rsp, 28h
    ret
QuadSleep ENDP

memset PROC
    ; RCX = Dest, RDX = Ch, R8 = Count

    ; Check if Count (R8) is zero
    test r8, r8
    jz _memset_end

    ; Prepare to set bytes
    mov al, dl ; Move Ch (RDX) into AL (low 8 bits)
    
_memset_loop:
    ; Set byte at [RCX]
    mov byte ptr [rcx], al

    ; Increment Dest (RCX)
    inc rcx

    ; Decrement Count (R8)
    dec r8

    ; Check if Count is zero yet
    test r8, r8
    jnz _memset_loop

_memset_end:
    ; Return with original Dest (RCX) in RAX
    mov rax, rcx

    ret
memset ENDP

END