; Discord Gateway v10 application protocol helpers.
; Transport, TLS and certificates are delegated to the libcurl adapter only.
; Opcode/sequence parsing and payload construction remain NASM application logic.

BITS 64
DEFAULT REL

global gateway_extract_opcode
global gateway_extract_sequence
global gateway_build_identify
global gateway_build_heartbeat
global gateway_build_resume
global gateway_write_u64

section .text

; rdi=JSON bytes, rsi=length. EAX=opcode or -1 when absent/malformed.
gateway_extract_opcode:
    lea rdx, [op_key]
    mov ecx, op_key_len
    call gateway_find_key
    test rax, rax
    jz .bad
    add rax, op_key_len
    mov rdi, rax
    mov rsi, 6
    jmp gateway_parse_decimal
.bad:
    mov eax, -1
    ret

; rdi=JSON bytes, rsi=length. RAX=sequence, RDX=1 if present; RDX=0 if null/absent.
gateway_extract_sequence:
    lea rdx, [sequence_key]
    mov ecx, sequence_key_len
    call gateway_find_key
    test rax, rax
    jz .none
    add rax, sequence_key_len
    cmp dword [rax], 0x6c6c756e        ; "null" little-endian
    je .none
    mov rdi, rax
    mov rsi, 20
    call gateway_parse_decimal
    cmp eax, -1
    je .none
    ; Writing EAX above already zero-extends RAX on x86-64.
    mov edx, 1
    ret
.none:
    xor eax, eax
    xor edx, edx
    ret

; rdi=output, rsi=capacity, rdx=token, rcx=token length. EAX=output length or -1.
gateway_build_identify:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                    ; output
    mov r13, rsi                    ; capacity
    mov r15, rdx                    ; token pointer
    mov rbx, rcx                    ; token length
    ; Serenity 0.12.5 sends SystemTime::now() in presence.since.
    mov eax, 228                    ; SYS_CLOCK_GETTIME
    xor edi, edi                    ; CLOCK_REALTIME
    lea rsi, [identify_timespec]
    syscall
    test rax, rax
    js .bad
    mov r10, [identify_timespec]
    mov r11, [identify_timespec + 8]
    ; Reserve room for both decimal SystemTime fields before writing.
    mov rax, rbx
    add rax, identify_prefix_len + identify_suffix_len
    add rax, 40
    cmp r13, rax
    jb .bad
    mov rdi, r12
    lea rsi, [identify_prefix]
    mov edx, identify_prefix_len
    call gateway_copy
    lea rdi, [r12 + identify_prefix_len]
    mov rsi, r15
    mov rdx, rbx
    call gateway_copy
    mov r14, identify_prefix_len
    add r14, rbx
    lea rdi, [r12 + r14]
    lea rsi, [identify_suffix]
    mov edx, identify_suffix_len
    call gateway_copy
    add r14, identify_suffix_len
    lea rdi, [r12 + r14]
    mov rax, r10
    call gateway_write_u64
    add r14, rax
    lea rdi, [r12 + r14]
    lea rsi, [identify_since_middle]
    mov edx, identify_since_middle_len
    call gateway_copy
    add r14, identify_since_middle_len
    lea rdi, [r12 + r14]
    mov rax, r11
    call gateway_write_u64
    add r14, rax
    lea rdi, [r12 + r14]
    lea rsi, [identify_suffix_end]
    mov edx, identify_suffix_end_len
    call gateway_copy
    add r14, identify_suffix_end_len
    mov eax, r14d
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rdi=output, rsi=capacity, rdx=sequence, rcx=1 when a sequence exists.
; EAX=output length or -1. A missing sequence emits JSON null.
gateway_build_heartbeat:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx                     ; latest sequence
    mov r15, rcx                     ; sequence-present flag
    cmp r13, 64
    jb .bad
    mov rdi, r12
    lea rsi, [heartbeat_prefix]
    mov edx, heartbeat_prefix_len
    call gateway_copy
    test r15, r15
    jz .null
    lea rdi, [r12 + heartbeat_prefix_len]
    mov rax, r14
    call gateway_write_u64
    mov r9d, eax
    lea rdi, [r12 + heartbeat_prefix_len]
    add rdi, r9
    lea rsi, [heartbeat_suffix]
    mov edx, heartbeat_suffix_len
    call gateway_copy
    mov eax, r9d
    add eax, heartbeat_prefix_len + heartbeat_suffix_len
    jmp .out
.null:
    lea rdi, [r12 + heartbeat_prefix_len]
    lea rsi, [json_null]
    mov edx, json_null_len
    call gateway_copy
    lea rdi, [r12 + heartbeat_prefix_len + json_null_len]
    lea rsi, [heartbeat_suffix]
    mov edx, heartbeat_suffix_len
    call gateway_copy
    mov eax, heartbeat_prefix_len + json_null_len + heartbeat_suffix_len
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; rdi=json, rsi=length, rdx=key, rcx=key length. RAX=key start or zero.
gateway_find_key:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
.loop:
    cmp r13, rcx
    jb .none
    push rdi
    push rsi
    mov rdi, r12
    mov rsi, rdx
    push rcx
    call gateway_equal
    pop rcx
    pop rsi
    pop rdi
    test al, al
    jnz .found
    inc r12
    dec r13
    jmp .loop
.found:
    mov rax, r12
    jmp .out
.none:
    xor eax, eax
.out:
    pop r13
    pop r12
    ret

; rdi=decimal pointer, rsi=max digits. EAX=value or -1.
gateway_parse_decimal:
    xor eax, eax
    xor ecx, ecx
.loop:
    cmp rcx, rsi
    jae .done
    movzx edx, byte [rdi + rcx]
    sub dl, '0'
    cmp dl, 9
    ja .done
    imul eax, eax, 10
    jo .bad
    movzx edx, dl
    add eax, edx
    jo .bad
    inc rcx
    jmp .loop
.done:
    test rcx, rcx
    jz .bad
    ret
.bad:
    mov eax, -1
    ret

; rdi=destination, rsi=source, edx=count. Does not alter RDX.
gateway_copy:
    xor ecx, ecx
.loop:
    cmp ecx, edx
    jae .done
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    inc ecx
    jmp .loop
.done:
    ret

; rdi=output, rsi=capacity, rdx=token, rcx=token length,
; r8=session id, r9=session length, r10=sequence. EAX=output length or -1.
gateway_build_resume:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
    mov r11, r9
    mov rax, r15
    add rax, r11
    add rax, resume_prefix_len + resume_middle_len + resume_suffix_len + 20
    cmp r13, rax
    jb .bad
    mov rdi, r12
    lea rsi, [resume_prefix]
    mov edx, resume_prefix_len
    call gateway_copy
    lea rdi, [r12 + resume_prefix_len]
    mov rsi, rbx
    mov rdx, r11
    call gateway_copy
    lea rdi, [r12 + resume_prefix_len]
    add rdi, r11
    lea rsi, [resume_middle]
    mov edx, resume_middle_len
    call gateway_copy
    lea rdi, [r12 + resume_prefix_len]
    add rdi, r11
    add rdi, resume_middle_len
    mov rsi, r14
    mov rdx, r15
    call gateway_copy
    lea rdi, [r12 + resume_prefix_len]
    add rdi, r11
    add rdi, resume_middle_len
    add rdi, r15
    lea rsi, [resume_seq_prefix]
    mov edx, resume_seq_prefix_len
    call gateway_copy
    lea rdi, [r12 + resume_prefix_len]
    add rdi, r15
    add rdi, resume_middle_len
    add rdi, r11
    add rdi, resume_seq_prefix_len
    mov rax, r10
    call gateway_write_u64
    mov r9d, eax
    lea rdi, [r12 + resume_prefix_len]
    add rdi, r15
    add rdi, resume_middle_len
    add rdi, r11
    add rdi, resume_seq_prefix_len
    add rdi, r9
    lea rsi, [resume_suffix]
    mov edx, resume_suffix_len
    call gateway_copy
    mov eax, resume_prefix_len
    add eax, r11d
    add eax, resume_middle_len
    add eax, r15d
    add eax, resume_seq_prefix_len
    add eax, r9d
    add eax, resume_suffix_len
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; rdi=destination, rax=value. RAX=written decimal count.
gateway_write_u64:
    lea r8, [gateway_digits + 31]
    mov byte [r8], 0
    xor ecx, ecx
.loop:
    xor edx, edx
    mov r9, 10
    div r9
    add dl, '0'
    dec r8
    mov [r8], dl
    inc ecx
    test rax, rax
    jnz .loop
    xor edx, edx
.copy:
    cmp edx, ecx
    jae .done
    mov al, [r8 + rdx]
    mov [rdi + rdx], al
    inc edx
    jmp .copy
.done:
    mov eax, ecx
    ret

gateway_equal:
    test rcx, rcx
    jz .yes
.loop:
    mov al, [rdi]
    cmp al, [rsi]
    jne .no
    inc rdi
    inc rsi
    dec rcx
    jnz .loop
.yes:
    mov al, 1
    ret
.no:
    xor eax, eax
    ret

section .rodata
op_key: db '"op":'
op_key_len equ $ - op_key
sequence_key: db '"s":'
sequence_key_len equ $ - sequence_key
identify_prefix: db '{"op":2,"d":{"compress":true,"token":"'
identify_prefix_len equ $ - identify_prefix
identify_suffix: db '","large_threshold":250,"shard":[0,1],"intents":33283,"properties":{"browser":"serenity","device":"serenity","os":"linux"},"presence":{"afk":false,"status":"online","since":{"secs_since_epoch":'
identify_suffix_len equ $ - identify_suffix
identify_since_middle: db ',"nanos_since_epoch":'
identify_since_middle_len equ $ - identify_since_middle
identify_suffix_end: db '},"activities":[]}}}'
identify_suffix_end_len equ $ - identify_suffix_end
heartbeat_prefix: db '{"op":1,"d":'
heartbeat_prefix_len equ $ - heartbeat_prefix
heartbeat_suffix: db '}'
heartbeat_suffix_len equ $ - heartbeat_suffix
resume_prefix: db '{"op":6,"d":{"session_id":"'
resume_prefix_len equ $ - resume_prefix
resume_middle: db '","token":"'
resume_middle_len equ $ - resume_middle
resume_seq_prefix: db '","seq":'
resume_seq_prefix_len equ $ - resume_seq_prefix
resume_suffix: db '}}'
resume_suffix_len equ $ - resume_suffix
json_null: db 'null'
json_null_len equ $ - json_null

section .bss
gateway_digits: resb 32
identify_timespec: resb 16
