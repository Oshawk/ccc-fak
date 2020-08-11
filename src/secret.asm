; write(1 (STDOUT), prompt, 20)
mov     eax, 4
mov     ebx, 1
mov     ecx, prompt
mov     edx, 20
int     0x80

; read(0 (STDIN), password, 16)
mov     eax, 3
mov     ebx, 0
mov     ecx, password
mov     edx, 16
int     0x80

mov     edx, 0

; The password is: CCC{d0n7_347_m3}

; C
mov     al, byte [password]
cmp     al, 'C'
jne     wrong

; C
mov     al, byte [password+1]
add     al, 0x20  ; 'c' - 'C'
cmp     al, 'c'
jne     wrong

; C
mov     al, byte [password+2]
add     al, 0x13  ; 'V' - 'C'
cmp     al, 'V'
jne     wrong

; {
mov     al, byte [password+3]
xor     al, '{'
cmp     al, al
jnz     wrong

; d
mov     al, byte [password+4]
sub     al, 'd'
cmp     al, al
jnz     wrong

; 0
mov     al, byte [password+5]
xor     al, 0x72  ; '0' ^ 0x42 = 0x72
cmp     al, 0x42
jne     wrong

; n
mov     al, byte [password+6]
xor     al, 0x91  ; 'n' ^ 0xff = 0x91
xor     al, 0xff
cmp     al, al
jnz     wrong

; 7
mov     al, byte [password+7]
mov     bl, 0x76
and     bl, 0x53
xor     al, bl
cmp     al, 0x65  ; (0x53 & 0x76) ^ '7' = 0x65
jne     wrong

; _
mov     al, byte [password+8]
sub     al, byte [password]
cmp     al, 0x1c  ; '_' - 'C' = 0x1c
jne     wrong

; 3
mov     al, byte [password+9]
xor     al, byte [password+4]
cmp     al, 0x57  ; '3' ^ 'd' = 0x57
jne     wrong

; 4
mov     al, byte [password+10]
mov     bl, byte [password+3]
xor     bl, byte [password+6]
xor     al, bl
cmp     al, 0x21  ; '{' ^ 'n' ^ '4' = 0x21
jne     wrong

; 7
mov     al, byte [password+11]
xor     al, byte [password+10]
sub     al, 0x03  ; '7' ^ '4' = 0x03
cmp     al, al
jnz     wrong

; _
mov     al, byte [password+12]
cmp     al, byte [password+8]
jne     wrong

; m
mov     al, byte [password+13]
mov     bl, byte [password+5]
mov     cl, byte [password+10]
xor     bl, cl
add     al, bl
cmp     al, 0x71  ; ('0' ^ '4') + 'm' = 0x71
jne     wrong

; 3
mov     al, byte [password+14]
xor     al, byte [password+13]
xor     al, byte [password+12]
xor     al, byte [password+11]
xor     al, byte [password+10]
xor     al, byte [password+9]
xor     al, byte [password+8]
xor     al, byte [password+7]
xor     al, byte [password+6]
xor     al, byte [password+5]
xor     al, byte [password+4]
xor     al, byte [password+3]
xor     al, byte [password+2]
xor     al, byte [password+1]
xor     al, byte [password]
cmp     al, 0x5b  ; 'C' ^ 'C' ^ 'C' ^ '{' ^ 'd' ^ '0' ^ 'n' ^ '7' ^ '_' ^ '3' ^ '4' ^ '7' ^ '_' ^ 'm' ^ '3' = 0x5b
jne     wrong

; }
mov     al, byte [password+15]
dec     al
dec     al
cmp     al, byte [password+3]
jne     wrong

; write(1 (STDOUT), correct/incorrect, 13)
mov     eax, 4
mov     ebx, 1
mov     ecx, correct
test    edx, edx
jnz     set_wrong
mov     edx, 13
int     0x80

; exit(0)
mov     eax, 1
mov     ebx, 0
int     0x80

prompt:     db      'Enter the password: '
correct:    db      'Correct! :-)', 10
incorrect:  db      'Incorrect :(', 10
password:   db      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

wrong:      inc     edx
set_wrong:  mov     ecx, incorrect