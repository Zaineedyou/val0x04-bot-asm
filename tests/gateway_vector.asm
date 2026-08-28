BITS 64
DEFAULT REL

extern gateway_extract_opcode
extern gateway_extract_sequence
extern gateway_build_identify
extern gateway_build_heartbeat
extern gateway_build_resume
global _start

%define SYS_EXIT 60

section .text
_start:
    lea rdi, [hello]
    mov esi, hello_len
    call gateway_extract_opcode
    cmp eax, 10
    jne .fail

    lea rdi, [dispatch]
    mov esi, dispatch_len
    call gateway_extract_sequence
    cmp rax, 42
    jne .fail
    cmp edx, 1
    jne .fail

    lea rdi, [null_sequence]
    mov esi, null_sequence_len
    call gateway_extract_sequence
    test rax, rax
    jnz .fail
    test edx, edx
    jnz .fail

    lea rdi, [identify_output]
    mov esi, 512
    lea rdx, [token]
    mov ecx, token_len
    call gateway_build_identify
    cmp eax, identify_min_len
    jb .fail
    mov r12d, eax
    lea rdi, [identify_output]
    lea rsi, [identify_expected_head]
    mov edx, identify_expected_head_len
    call compare_bytes
    test eax, eax
    jnz .fail
    lea rdi, [identify_output + identify_expected_head_len]
    lea rsi, [identify_expected_middle]
    mov edx, identify_expected_middle_len
    call compare_bytes
    test eax, eax
    jnz .fail
    lea rdi, [identify_output + r12 - identify_expected_tail_len]
    lea rsi, [identify_expected_tail]
    mov edx, identify_expected_tail_len
    call compare_bytes
    test eax, eax
    jnz .fail

    lea rdi, [heartbeat_output]
    mov esi, 64
    mov edx, 42
    mov ecx, 1
    call gateway_build_heartbeat
    cmp eax, heartbeat_expected_len
    jne .fail
    lea rdi, [heartbeat_output]
    lea rsi, [heartbeat_expected]
    mov edx, heartbeat_expected_len
    call compare_bytes
    test eax, eax
    jnz .fail

    lea rdi, [resume_output]
    mov esi, 256
    lea rdx, [token]
    mov ecx, token_len
    lea r8, [session]
    mov r9d, session_len
    mov r10, 42
    call gateway_build_resume
    cmp eax, resume_expected_len
    jne .fail
    lea rdi, [resume_output]
    lea rsi, [resume_expected]
    mov edx, resume_expected_len
    call compare_bytes
    test eax, eax
    jnz .fail

    mov eax, SYS_EXIT
    xor edi, edi
    syscall
.fail:
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

compare_bytes:
    xor ecx, ecx
.loop:
    cmp ecx, edx
    jae .equal
    mov al, [rdi + rcx]
    cmp al, [rsi + rcx]
    jne .not_equal
    inc ecx
    jmp .loop
.equal:
    xor eax, eax
    ret
.not_equal:
    mov eax, 1
    ret

section .rodata
hello: db '{"op":10,"d":{"heartbeat_interval":45000}}'
hello_len equ $ - hello
dispatch: db '{"op":0,"s":42,"t":"MESSAGE_CREATE"}'
dispatch_len equ $ - dispatch
null_sequence: db '{"op":10,"s":null}'
null_sequence_len equ $ - null_sequence
token: db 'abc.def'
token_len equ $ - token
identify_expected_head: db '{"op":2,"d":{"compress":true,"token":"abc.def'
identify_expected_head_len equ $ - identify_expected_head
identify_expected_middle: db '","large_threshold":250,"shard":[0,1],"intents":33283,"properties":{"browser":"serenity","device":"serenity","os":"linux"},"presence":{"afk":false,"status":"online","since":{"secs_since_epoch":'
identify_expected_middle_len equ $ - identify_expected_middle
identify_expected_tail: db '},"activities":[]}}}'
identify_expected_tail_len equ $ - identify_expected_tail
identify_min_len equ identify_expected_head_len + identify_expected_middle_len + identify_expected_tail_len + 2
heartbeat_expected: db '{"op":1,"d":42}'
heartbeat_expected_len equ $ - heartbeat_expected
session: db 'session-1'
session_len equ $ - session
resume_expected: db '{"op":6,"d":{"session_id":"session-1","token":"abc.def","seq":42}}'
resume_expected_len equ $ - resume_expected

section .bss
identify_output: resb 256
heartbeat_output: resb 64
resume_output: resb 256
