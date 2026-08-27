BITS 64
DEFAULT REL

extern secure_gateway_connect
extern secure_gateway_close
extern secure_gateway_socket
extern secure_gateway_send
extern secure_gateway_recv
extern gateway_extract_opcode
extern gateway_extract_sequence
extern gateway_build_identify
extern gateway_build_heartbeat
extern discord_token_ptr
extern discord_token_len
extern discord_channel_ptr
extern discord_channel_len
extern gateway_pipe_write
extern write_all

global gateway_worker
global gateway_find_key
global gateway_decode_string
global gateway_escape_copy
global gateway_copy

%define SYS_READ            0
%define SYS_WRITE           1
%define SYS_CLOSE           3
%define SYS_POLL            7
%define SYS_EXIT            60
%define SYS_GETRANDOM       318
%define SYS_CLOCK_GETTIME   228
%define SYS_NANOSLEEP       35
%define CLOCK_MONOTONIC     1
%define POLLIN              1
%define CURLWS_TEXT         1
%define CURLWS_PING         16
%define CURLWS_CLOSE        8
%define CURLWS_CONT         4
%define CURLWS_PONG         64

section .text

gateway_worker:
    call gateway_connect_loop
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

; Reconnect forever. The Discord Gateway is deliberately isolated in this
; process so a stalled remote connection cannot stop the local bridge.
gateway_connect_loop:
.reconnect:
    lea rdi, [gateway_url]
    call secure_gateway_connect
    test eax, eax
    js .retry
    call gateway_wait_hello
    test eax, eax
    js .close_retry
    call gateway_identify
    test eax, eax
    js .close_retry
    call gateway_session_loop
    test eax, eax
    jz .close_retry
.close_retry:
    call secure_gateway_close
.retry:
    call gateway_sleep
    jmp .reconnect

; Wait for Hello (opcode 10), then cache the server heartbeat interval.
gateway_wait_hello:
.wait:
    call gateway_poll_readable
    test eax, eax
    js .bad
    jz .wait
    call gateway_receive_packet
    test eax, eax
    js .bad
    mov rdi, [gateway_packet_len]
    test rdi, rdi
    jz .wait
    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    call gateway_extract_opcode
    cmp eax, 10
    jne .wait
    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    lea rdx, [hello_interval_key]
    mov ecx, hello_interval_key_len
    call gateway_find_key
    test rax, rax
    jz .bad
    add rax, hello_interval_key_len
    mov rdi, rax
    mov rsi, 32
    call gateway_parse_u64
    cmp eax, -1
    je .bad
    mov [heartbeat_interval_ms], rax
    cmp rax, 1000
    jb .bad
    call gateway_set_first_heartbeat
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

gateway_identify:
    lea rdi, [gateway_identify_buffer]
    mov esi, 16384
    mov rdx, [discord_token_ptr]
    mov ecx, [discord_token_len]
    call gateway_build_identify
    cmp eax, -1
    je .bad
    mov esi, eax
    lea rdi, [gateway_identify_buffer]
    mov edx, CURLWS_TEXT
    call secure_gateway_send
    test rax, rax
    js .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

gateway_session_loop:
.loop:
    call gateway_check_heartbeat
    test eax, eax
    js .bad
    call gateway_poll_readable
    test eax, eax
    js .bad
    jz .loop
    call gateway_receive_packet
    test eax, eax
    js .bad
    call gateway_dispatch_packet
    test eax, eax
    js .bad
    jmp .loop
.bad:
    mov eax, -1
    ret

; Process a complete text packet. Control frames are handled by the transport
; worker, while all Discord application decisions stay here in NASM.
gateway_dispatch_packet:
    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    call gateway_extract_sequence
    test edx, edx
    jz .sequence_done
    mov [gateway_sequence], rax
.sequence_done:
    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    call gateway_extract_opcode
    cmp eax, 11
    je .ack
    cmp eax, 1
    je .heartbeat_request
    cmp eax, 7
    je .reconnect
    cmp eax, 9
    je .reconnect
    cmp eax, 0
    jne .ok

    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    lea rdx, [message_create_key]
    mov ecx, message_create_key_len
    call gateway_find_key
    test rax, rax
    jz .ok
    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    call gateway_forward_message
.ok:
    xor eax, eax
    ret
.ack:
    mov dword [heartbeat_waiting], 0
    xor eax, eax
    ret
.heartbeat_request:
    call gateway_send_heartbeat
    ret
.reconnect:
    mov eax, -1
    ret

; Send a heartbeat and require its ACK before the next interval.
gateway_send_heartbeat:
    lea rdi, [gateway_heartbeat_buffer]
    mov esi, 256
    mov rdx, [gateway_sequence]
    mov ecx, 1
    call gateway_build_heartbeat
    cmp eax, -1
    je .bad
    mov esi, eax
    lea rdi, [gateway_heartbeat_buffer]
    mov edx, CURLWS_TEXT
    call secure_gateway_send
    test rax, rax
    js .bad
    mov dword [heartbeat_waiting], 1
    call gateway_now_ms
    add rax, [heartbeat_interval_ms]
    mov [heartbeat_due_ms], rax
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

gateway_check_heartbeat:
    call gateway_now_ms
    cmp rax, [heartbeat_due_ms]
    jb .ok
    cmp dword [heartbeat_waiting], 0
    jne .bad
    call gateway_send_heartbeat
    ret
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

gateway_set_first_heartbeat:
    call gateway_now_ms
    mov r13, rax
    mov r12, [heartbeat_interval_ms]
    test r12, r12
    jz .no_jitter
    lea rdi, [jitter_bytes]
    mov esi, 8
    mov eax, SYS_GETRANDOM
    syscall
    test rax, rax
    jle .no_jitter
    mov rax, [jitter_bytes]
    xor edx, edx
    div r12
    mov r12, rdx
.no_jitter:
    add r13, r12
    mov [heartbeat_due_ms], r13
    mov dword [heartbeat_waiting], 0
    ret

; Receive one complete frame. Fragmented Gateway application frames are
; rejected rather than silently truncating a JSON packet.
gateway_receive_packet:
    mov rdi, [gateway_packet]
    mov esi, 16383
    lea rdx, [gateway_packet_len]
    lea rcx, [gateway_frame_flags]
    lea r8, [gateway_bytes_left]
    call secure_gateway_recv
    test rax, rax
    js .bad
    cmp qword [gateway_bytes_left], 0
    jne .bad
    mov eax, [gateway_frame_flags]
    test eax, CURLWS_CLOSE
    jnz .bad
    test eax, CURLWS_PING
    jz .not_ping
    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    mov edx, CURLWS_PONG
    call secure_gateway_send
    test rax, rax
    js .bad
    mov qword [gateway_packet_len], 0
.not_ping:
    mov eax, [gateway_frame_flags]
    test eax, CURLWS_TEXT
    jnz .text
    mov qword [gateway_packet_len], 0
.text:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

gateway_poll_readable:
    call secure_gateway_socket
    test eax, eax
    js .bad
    mov [gateway_poll_fd], eax
    mov word [gateway_poll_entry + 4], POLLIN
    mov word [gateway_poll_entry + 6], 0
    mov eax, SYS_POLL
    lea rdi, [gateway_poll_entry]
    mov esi, 1
    mov edx, 1000
    syscall
    test rax, rax
    js .bad
    jz .timeout
    movzx eax, word [gateway_poll_entry + 6]
    test eax, POLLIN
    jz .timeout
    mov eax, 1
    ret
.timeout:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

gateway_forward_message:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi

    ; Restrict forwarding to the configured channel.
    mov rdi, r12
    mov rsi, r13
    lea rdx, [channel_id_key]
    mov ecx, channel_id_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, channel_id_key_len
    mov rdi, rax
    mov rsi, 32
    lea rdx, [gateway_channel]
    mov ecx, 64
    call gateway_decode_string
    cmp eax, -1
    je .out
    mov r14d, eax
    cmp eax, [discord_channel_len]
    jne .out
    lea rdi, [gateway_channel]
    mov rsi, [discord_channel_ptr]
    mov ecx, [discord_channel_len]
    call gateway_equal
    test al, al
    jz .out

    ; Messages authored by bots are ignored, matching the Rust handler.
    mov rdi, r12
    mov rsi, r13
    lea rdx, [bot_key]
    mov ecx, bot_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, bot_key_len
    cmp dword [rax], 'true'
    jne .not_bot
    jmp .out
.not_bot:
    mov rdi, r12
    mov rsi, r13
    lea rdx, [username_key]
    mov ecx, username_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, username_key_len
    mov rdi, rax
    mov rsi, 512
    lea rdx, [gateway_author]
    mov ecx, 1024
    call gateway_decode_string
    cmp eax, -1
    je .out
    mov [gateway_author_len], eax

    mov rdi, r12
    mov rsi, r13
    lea rdx, [content_key]
    mov ecx, content_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, content_key_len
    mov rdi, rax
    mov rsi, 2048
    lea rdx, [gateway_content]
    mov ecx, 2048
    call gateway_decode_string
    cmp eax, -1
    je .out
    mov [gateway_content_len], eax

    lea rdi, [gateway_outgoing]
    lea rsi, [outgoing_prefix]
    mov edx, outgoing_prefix_len
    call gateway_copy
    lea rdi, [gateway_outgoing + outgoing_prefix_len]
    lea rsi, [gateway_author]
    mov edx, [gateway_author_len]
    mov ecx, 16384 - outgoing_prefix_len
    call gateway_escape_copy
    cmp eax, -1
    je .out
    mov r14d, eax
    lea rdi, [gateway_outgoing + outgoing_prefix_len]
    add rdi, r14
    lea rsi, [outgoing_middle]
    mov edx, outgoing_middle_len
    call gateway_copy
    add r14d, outgoing_middle_len
    lea rdi, [gateway_outgoing + outgoing_prefix_len]
    add rdi, r14
    lea rsi, [gateway_content]
    mov edx, [gateway_content_len]
    mov ecx, 16384 - outgoing_prefix_len - outgoing_middle_len
    call gateway_escape_copy
    cmp eax, -1
    je .out
    add r14d, eax
    lea rdi, [gateway_outgoing + outgoing_prefix_len]
    add rdi, r14
    lea rsi, [outgoing_suffix]
    mov edx, outgoing_suffix_len
    call gateway_copy
    add r14d, outgoing_suffix_len
    mov byte [gateway_outgoing + r14], 10
    inc r14d

    mov edi, [gateway_pipe_write]
    lea rsi, [gateway_outgoing]
    mov edx, r14d
    call write_all
.out:
    pop r14
    pop r13
    pop r12
    ret

; Find a literal key in a bounded JSON buffer.
gateway_find_key:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
.loop:
    cmp r13, r15
    jb .none
    mov rdi, r12
    mov rsi, r14
    mov rcx, r15
    call gateway_equal
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
    pop r15
    pop r14
    pop r13
    pop r12
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

; Parse a bounded unsigned decimal number.
gateway_parse_u64:
    xor eax, eax
    xor ecx, ecx
.loop:
    cmp rcx, rsi
    jae .done
    movzx edx, byte [rdi + rcx]
    cmp dl, '0'
    jb .done
    cmp dl, '9'
    ja .done
    sub dl, '0'
    imul rax, rax, 10
    add rax, rdx
    inc rcx
    jmp .loop
.done:
    test rcx, rcx
    jz .bad
    ret
.bad:
    mov eax, -1
    ret

; Decode a JSON string into a bounded buffer.
gateway_decode_string:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    dec r15
    xor ebx, ebx
    xor ecx, ecx
.loop:
    cmp rcx, r13
    jae .bad
    mov al, [r12 + rcx]
    inc rcx
    cmp al, '"'
    je .done
    cmp al, 0x5c
    jne .plain
    cmp rcx, r13
    jae .bad
    mov al, [r12 + rcx]
    inc rcx
    cmp al, 'n'
    jne .not_n
    mov al, 10
    jmp .store
.not_n:
    cmp al, 'r'
    jne .not_r
    mov al, 13
    jmp .store
.not_r:
    cmp al, 't'
    jne .not_t
    mov al, 9
    jmp .store
.not_t:
    cmp al, 'b'
    jne .not_f
    mov al, 8
    jmp .store
.not_f:
    cmp al, 'f'
    jne .not_quote
    mov al, 12
    jmp .store
.not_quote:
    cmp al, '"'
    jne .not_slash
    mov al, '"'
    jmp .store
.not_slash:
    cmp al, '/'
    jne .not_backslash
    mov al, '/'
    jmp .store
.not_backslash:
    cmp al, 0x5c
    jne .bad
    mov al, 0x5c
    jmp .store
.plain:
.store:
    cmp rbx, r15
    jae .bad
    mov [r14 + rbx], al
    inc rbx
    jmp .loop
.done:
    mov byte [r14 + rbx], 0
    mov rax, rbx
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; Escape a decoded string into JSON output. EAX is bytes written.
gateway_escape_copy:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    mov r15d, ecx
    xor ebx, ebx
    xor ecx, ecx
.loop:
    cmp ecx, r14d
    jae .done
    mov al, [r13 + rcx]
    cmp al, '"'
    je .slash
    cmp al, 0x5c
    je .slash
    cmp al, 10
    je .escaped_n
    cmp al, 13
    je .escaped_r
    cmp al, 9
    je .escaped_t
    cmp al, 32
    jb .unicode
    jmp .one
.slash:
    mov r8d, r15d
    sub r8d, 2
    cmp ebx, r8d
    jae .bad
    mov byte [r12 + rbx], 0x5c
    mov byte [r12 + rbx + 1], al
    add ebx, 2
    inc ecx
    jmp .loop
.escaped_n:
    mov al, 'n'
    jmp .two
.escaped_r:
    mov al, 'r'
    jmp .two
.escaped_t:
    mov al, 't'
.two:
    mov r8d, r15d
    sub r8d, 2
    cmp ebx, r8d
    jae .bad
    mov byte [r12 + rbx], 0x5c
    mov [r12 + rbx + 1], al
    add ebx, 2
    inc ecx
    jmp .loop
.unicode:
    mov r8d, r15d
    sub r8d, 6
    cmp ebx, r8d
    jae .bad
    mov byte [r12 + rbx], 0x5c
    mov byte [r12 + rbx + 1], 'u'
    mov byte [r12 + rbx + 2], '0'
    mov byte [r12 + rbx + 3], '0'
    movzx eax, byte [r13 + rcx]
    mov r9d, eax
    shr eax, 4
    call gateway_hex_digit
    mov [r12 + rbx + 4], al
    mov eax, r9d
    and eax, 0xf
    call gateway_hex_digit
    mov [r12 + rbx + 5], al
    add ebx, 6
    inc ecx
    jmp .loop
.one:
    mov r8d, r15d
    dec r8d
    cmp ebx, r8d
    jae .bad
    mov [r12 + rbx], al
    inc ebx
    inc ecx
    jmp .loop
.done:
    mov eax, ebx
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

gateway_hex_digit:
    cmp al, 9
    jbe .digit
    add al, 'a' - 10
    ret
.digit:
    add al, '0'
    ret

gateway_copy:
    test edx, edx
    jz .done
.loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec edx
    jnz .loop
.done:
    ret

gateway_sleep:
    mov qword [sleep_timespec], 5
    mov qword [sleep_timespec + 8], 0
    mov eax, SYS_NANOSLEEP
    lea rdi, [sleep_timespec]
    xor esi, esi
    syscall
    ret

gateway_now_ms:
    mov eax, SYS_CLOCK_GETTIME
    mov edi, CLOCK_MONOTONIC
    lea rsi, [gateway_timespec]
    syscall
    test rax, rax
    js .failed
    mov r10, [gateway_timespec]
    imul r10, r10, 1000
    mov rax, [gateway_timespec + 8]
    xor edx, edx
    mov r9, 1000000
    div r9
    add rax, r10
    ret
.failed:
    xor eax, eax
    ret

section .rodata
gateway_url: db 'wss://gateway.discord.gg/?v=10&encoding=json',0
hello_interval_key: db '"heartbeat_interval":'
hello_interval_key_len equ $ - hello_interval_key
message_create_key: db '"t":"MESSAGE_CREATE"'
message_create_key_len equ $ - message_create_key
channel_id_key: db '"channel_id":"'
channel_id_key_len equ $ - channel_id_key
bot_key: db '"bot":'
bot_key_len equ $ - bot_key
username_key: db '"username":"'
username_key_len equ $ - username_key
content_key: db '"content":"'
content_key_len equ $ - content_key
outgoing_prefix: db '{"type":"chat","author":"'
outgoing_prefix_len equ $ - outgoing_prefix
outgoing_middle: db '","role":"","message":"'
outgoing_middle_len equ $ - outgoing_middle
outgoing_suffix: db '"}'
outgoing_suffix_len equ $ - outgoing_suffix

section .data
align 8
heartbeat_interval_ms: dq 45000
heartbeat_due_ms: dq 0
gateway_sequence: dq 0
gateway_packet_len: dq 0
gateway_bytes_left: dq 0
gateway_packet: dq gateway_packet_buffer
gateway_poll_fd: dd -1
gateway_frame_flags: dd 0
heartbeat_waiting: dd 0
gateway_author_len: dd 0
gateway_content_len: dd 0

section .bss
align 16
gateway_packet_buffer: resb 16384
gateway_identify_buffer: resb 16384
gateway_heartbeat_buffer: resb 256
gateway_channel: resb 64
gateway_author: resb 1024
gateway_content: resb 8192
gateway_outgoing: resb 16384
jitter_bytes: resb 8
gateway_poll_entry: resb 8
gateway_timespec: resb 16
sleep_timespec: resb 16
