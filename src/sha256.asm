; SHA-256 primitive for Val0x04/ASM.
; ABI: sha256_digest(rdi=input, rsi=input_length, rdx=32-byte output).
; It is syscall-free and uses no external library. The temporary state is static,
; so callers must serialize use; that matches the current single-process design.

BITS 64
DEFAULT REL

global sha256_digest

section .text
sha256_digest:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                    ; current input
    mov r13, rsi                    ; remaining bytes
    mov r14, rdx                    ; output
    mov r15, rsi                    ; total bytes

    mov dword [sha256_h0], 0x6a09e667
    mov dword [sha256_h1], 0xbb67ae85
    mov dword [sha256_h2], 0x3c6ef372
    mov dword [sha256_h3], 0xa54ff53a
    mov dword [sha256_h4], 0x510e527f
    mov dword [sha256_h5], 0x9b05688c
    mov dword [sha256_h6], 0x1f83d9ab
    mov dword [sha256_h7], 0x5be0cd19

.full_blocks:
    cmp r13, 64
    jb .pad
    mov rdi, r12
    call sha256_compress
    add r12, 64
    sub r13, 64
    jmp .full_blocks

.pad:
    lea rdi, [sha256_block]
    mov ecx, 64
    xor eax, eax
.zero:
    mov [rdi], al
    inc rdi
    dec ecx
    jnz .zero

    xor ecx, ecx
.copy_tail:
    cmp rcx, r13
    jae .copy_done
    mov al, [r12 + rcx]
    mov [sha256_block + rcx], al
    inc rcx
    jmp .copy_tail
.copy_done:
    mov byte [sha256_block + rcx], 0x80
    cmp r13, 55
    jbe .length_in_first
    lea rdi, [sha256_block]
    call sha256_compress
    lea rdi, [sha256_block]
    mov ecx, 64
    xor eax, eax
.zero_second:
    mov [rdi], al
    inc rdi
    dec ecx
    jnz .zero_second
.length_in_first:
    mov rax, r15
    shl rax, 3
    bswap rax
    mov [sha256_block + 56], rax
    lea rdi, [sha256_block]
    call sha256_compress

    mov eax, [sha256_h0]
    bswap eax
    mov [r14], eax
    mov eax, [sha256_h1]
    bswap eax
    mov [r14 + 4], eax
    mov eax, [sha256_h2]
    bswap eax
    mov [r14 + 8], eax
    mov eax, [sha256_h3]
    bswap eax
    mov [r14 + 12], eax
    mov eax, [sha256_h4]
    bswap eax
    mov [r14 + 16], eax
    mov eax, [sha256_h5]
    bswap eax
    mov [r14 + 20], eax
    mov eax, [sha256_h6]
    bswap eax
    mov [r14 + 24], eax
    mov eax, [sha256_h7]
    bswap eax
    mov [r14 + 28], eax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; HMAC-SHA256 one-shot primitive.
; rdi=key, rsi=key length, rdx=message, rcx=message length, r8=32-byte output.
; EAX=0 on success, -1 when the bounded working buffer is exceeded.
global hmac_sha256
hmac_sha256:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbp, r8
    cmp r15, 1024
    ja .error

    ; Normalize key into a zero-padded 64-byte block.
    lea rdi, [hmac_key]
    mov ecx, 64
    xor eax, eax
.zero_key:
    mov [rdi], al
    inc rdi
    dec ecx
    jnz .zero_key
    cmp r13, 64
    jbe .copy_key
    mov rdi, r12
    mov rsi, r13
    lea rdx, [hmac_key]
    call sha256_digest
    lea r12, [hmac_key]
    mov r13, 32
.copy_key:
    xor ecx, ecx
.copy_key_loop:
    cmp rcx, r13
    jae .inner_pad
    mov al, [r12 + rcx]
    mov [hmac_key + rcx], al
    inc rcx
    jmp .copy_key_loop

.inner_pad:
    xor ecx, ecx
.inner_pad_loop:
    cmp ecx, 64
    jae .copy_message
    mov al, [hmac_key + rcx]
    xor al, 0x36
    mov [hmac_work + rcx], al
    inc ecx
    jmp .inner_pad_loop
.copy_message:
    xor ecx, ecx
.copy_message_loop:
    cmp rcx, r15
    jae .hash_inner
    mov al, [r14 + rcx]
    mov [hmac_work + 64 + rcx], al
    inc rcx
    jmp .copy_message_loop
.hash_inner:
    lea rdi, [hmac_work]
    mov rsi, r15
    add rsi, 64
    lea rdx, [hmac_inner_digest]
    call sha256_digest

    xor ecx, ecx
.outer_pad_loop:
    cmp ecx, 64
    jae .copy_inner_digest
    mov al, [hmac_key + rcx]
    xor al, 0x5c
    mov [hmac_work + rcx], al
    inc ecx
    jmp .outer_pad_loop
.copy_inner_digest:
    xor ecx, ecx
.copy_inner_loop:
    cmp ecx, 32
    jae .hash_outer
    mov al, [hmac_inner_digest + rcx]
    mov [hmac_work + 64 + rcx], al
    inc ecx
    jmp .copy_inner_loop
.hash_outer:
    lea rdi, [hmac_work]
    mov esi, 96
    mov rdx, rbp
    call sha256_digest
    xor eax, eax
    jmp .out
.error:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; rdi points to one complete 64-byte block. Updates sha256_h0..sha256_h7.
sha256_compress:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    xor ecx, ecx
.load_words:
    mov eax, [rdi + rcx * 4]
    bswap eax
    mov [sha256_words + rcx * 4], eax
    inc ecx
    cmp ecx, 16
    jb .load_words

.expand_words:
    ; s1(W[t-2]) = rotr17 ^ rotr19 ^ shr10
    mov eax, [sha256_words + rcx * 4 - 8]
    mov edx, eax
    ror eax, 17
    ror edx, 19
    xor eax, edx
    mov edx, [sha256_words + rcx * 4 - 8]
    shr edx, 10
    xor eax, edx
    add eax, [sha256_words + rcx * 4 - 28]

    ; s0(W[t-15]) = rotr7 ^ rotr18 ^ shr3
    mov edx, [sha256_words + rcx * 4 - 60]
    mov esi, edx
    ror edx, 7
    ror esi, 18
    xor edx, esi
    mov esi, [sha256_words + rcx * 4 - 60]
    shr esi, 3
    xor edx, esi
    add eax, edx
    add eax, [sha256_words + rcx * 4 - 64]
    mov [sha256_words + rcx * 4], eax
    inc ecx
    cmp ecx, 64
    jb .expand_words

    mov r8d, [sha256_h0]             ; a
    mov r9d, [sha256_h1]             ; b
    mov r10d, [sha256_h2]            ; c
    mov r11d, [sha256_h3]            ; d
    mov ebp, [sha256_h4]             ; e
    mov r12d, [sha256_h5]            ; f
    mov r13d, [sha256_h6]            ; g
    mov r14d, [sha256_h7]            ; h
    xor ecx, ecx
.round:
    ; temp1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
    mov eax, ebp
    mov edx, eax
    ror eax, 6
    ror edx, 11
    xor eax, edx
    mov edx, ebp
    ror edx, 25
    xor eax, edx
    add eax, r14d

    mov edx, ebp
    and edx, r12d
    mov esi, ebp
    not esi
    and esi, r13d
    xor edx, esi
    add eax, edx
    add eax, [sha256_k + rcx * 4]
    add eax, [sha256_words + rcx * 4]
    mov r15d, eax                    ; temp1

    ; temp2 = Σ0(a) + Maj(a,b,c)
    mov eax, r8d
    mov edx, eax
    ror eax, 2
    ror edx, 13
    xor eax, edx
    mov edx, r8d
    ror edx, 22
    xor eax, edx

    mov edx, r8d
    and edx, r9d
    mov esi, r8d
    and esi, r10d
    xor edx, esi
    mov esi, r9d
    and esi, r10d
    xor edx, esi
    add eax, edx                     ; temp2

    mov r14d, r13d
    mov r13d, r12d
    mov r12d, ebp
    add r11d, r15d                   ; e = d + temp1
    mov ebp, r11d
    mov r11d, r10d
    mov r10d, r9d
    mov r9d, r8d
    add r15d, eax
    mov r8d, r15d                    ; a = temp1 + temp2

    inc ecx
    cmp ecx, 64
    jb .round

    add [sha256_h0], r8d
    add [sha256_h1], r9d
    add [sha256_h2], r10d
    add [sha256_h3], r11d
    add [sha256_h4], ebp
    add [sha256_h5], r12d
    add [sha256_h6], r13d
    add [sha256_h7], r14d

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

section .rodata
align 4
sha256_k:
    dd 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
    dd 0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    dd 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
    dd 0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    dd 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
    dd 0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    dd 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
    dd 0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    dd 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
    dd 0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    dd 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
    dd 0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    dd 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
    dd 0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    dd 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
    dd 0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

section .bss
align 16
sha256_block: resb 64
sha256_words: resd 64
sha256_h0:    resd 1
sha256_h1:    resd 1
sha256_h2:    resd 1
sha256_h3:    resd 1
sha256_h4:    resd 1
sha256_h5:    resd 1
sha256_h6:    resd 1
sha256_h7:    resd 1
hmac_key:     resb 64
hmac_work:    resb 1088
hmac_inner_digest: resb 32
