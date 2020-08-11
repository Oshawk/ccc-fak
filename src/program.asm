action:
            dd      exit
times 34    dd      0

node:       dd      start

eax_s:      dd      0
ebx_s:      dd      0
ecx_s:      dd      0
edx_s:      dd      0
flags_s:    dd      0

_start:
    ; Avoid the need for multiple sections by makng everything RWX.
    ; mprotect($$ (start of section), 0x2000, 7 (RWX))
    mov     eax, 125
    mov     ebx, $$
    mov     ecx, 0x2000
    mov     edx, 7
    int     0x80
    ; Call the main functions.
    call    sigaction
    call    main


sigaction:
    ; Exit gracefully on segfault.

    ; sigaction(11 (SIGSEGV), action (-> {exit, [], 0}), NULL)
    mov     eax, 67
    mov     ebx, 11
    mov     ecx, action
    mov     edx, 0
    int     0x80

    ret


exit:
    ; Wait for children to die, then exit.

    ; waitpid(-1, NULL, 0)
    mov     eax, 7
    mov     ebx, -1
    mov     ecx, 0
    mov     edx, 0
    int     0x80
    ; if (ret >= 0) loop
    cmp     eax, 0
    jge     exit
    ; exit(0)
    mov     eax, 1
    mov     ebx, 0
    int     0x80


main:
    ; Call the current node and fork.
    ; Parent takes left, child right.

    call    call_node
    ; fork()
    mov     eax, 2
    int     0x80
    ; if (ret == 0) child
    test    eax, eax
    jz      main_child
main_parent:
    mov     eax, dword [node]
    mov     eax, dword [eax]
    mov     dword [node], eax
    jmp     main
main_child:
    mov     eax, dword [node]
    mov     eax, dword [eax+4]
    mov     dword [node], eax
    jmp     main


call_node:
    ; struct node {
    ;     left,
    ;     right,
    ;     instruction,
    ; }

    ; Get the address of the instruction.
    ; Must be done here so as not to mess with flags.
    mov     esi, dword [node]
    add     esi, 8

    ; Restore registers. Flag restoration feels hacky.
    xchg    dword [eax_s], eax
    xchg    dword [ebx_s], ebx
    xchg    dword [ecx_s], ecx
    xchg    dword [edx_s], edx
    pushfd
    pop     edi
    xchg    dword [flags_s], edi
    push    edi
    popfd

    ; Call the instruction.
    call    esi

    ; Restore registers. Flag restoration feels hacky.
    xchg    dword [eax_s], eax
    xchg    dword [ebx_s], ebx
    xchg    dword [ecx_s], ecx
    xchg    dword [edx_s], edx
    pushfd
    pop     edi
    xchg    dword [flags_s], edi
    push    edi
    popfd
    
    ret
