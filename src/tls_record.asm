; TLSPlaintext / TLSCiphertext record envelope parser for Val0x04/ASM.
; ABI: tls_parse_record(rdi=record bytes, rsi=available bytes)
; Returns EAX=0 success, RDX=payload, RCX=payload length, R8D=content type.
; Returns EAX=-1 for invalid/truncated/oversized input. No allocation is done.

BITS 64
DEFAULT REL

global tls_parse_record

section .text
tls_parse_record:
    cmp rsi, 5
    jb .error

    movzx r8d, byte [rdi]
    cmp r8d, 21                       ; alert
    je .type_ok
    cmp r8d, 22                       ; handshake
    je .type_ok
    cmp r8d, 23                       ; application_data
    jne .error
.type_ok:
    movzx eax, byte [rdi + 1]
    shl eax, 8
    movzx edx, byte [rdi + 2]
    or eax, edx
    cmp eax, 0x0303                   ; TLS 1.3 legacy_record_version
    jne .error

    movzx ecx, byte [rdi + 3]
    shl ecx, 8
    movzx eax, byte [rdi + 4]
    or ecx, eax
    cmp ecx, 16640                    ; 2^14 + 256 maximum ciphertext allowance
    ja .error
    lea rax, [rcx + 5]
    cmp rsi, rax
    jb .error

    lea rdx, [rdi + 5]
    xor eax, eax
    ret
.error:
    mov eax, -1
    ret
