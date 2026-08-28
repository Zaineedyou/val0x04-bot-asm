BITS 64
DEFAULT REL

extern secure_gateway_connect
extern secure_gateway_close
extern secure_gateway_socket
extern secure_gateway_send
extern secure_gateway_recv
extern secure_https_get_json
extern gateway_extract_opcode
extern gateway_extract_sequence
extern gateway_build_identify
extern gateway_build_heartbeat
extern gateway_build_resume
extern discord_token_ptr
extern discord_token_len
extern discord_channel_ptr
extern discord_channel_len
extern gateway_pipe_write
extern write_all
extern log_static
extern log_transport_failure
extern log_gateway_transport_failure
extern log_http_status

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
%define POLLOUT             4
%define EAGAIN              11
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
    mov rdi, [gateway_connect_url]
    call secure_gateway_connect
    test eax, eax
    jns .connected
    call log_gateway_transport_failure
    jmp .retry
.connected:
    lea rdi, [log_gateway_connected]
    mov esi, log_gateway_connected_len
    call log_static
    call gateway_wait_hello
    test eax, eax
    js .close_retry
    lea rdi, [log_gateway_hello_ok]
    mov esi, log_gateway_hello_ok_len
    call log_static
    cmp dword [gateway_session_valid], 0
    je .identify
    call gateway_resume
    test eax, eax
    jz .resumed
    call gateway_clear_session
    jmp .close_retry
.identify:
    mov qword [gateway_sequence], 0
    call gateway_identify
    test eax, eax
    js .close_retry
    lea rdi, [log_gateway_identify_ok]
    mov esi, log_gateway_identify_ok_len
    call log_static
    jmp .session
.resumed:
    lea rdi, [log_gateway_resume_ok]
    mov esi, log_gateway_resume_ok_len
    call log_static
.session:
    call gateway_session_loop
.close_retry:
    call secure_gateway_close
.retry:
    call gateway_sleep
    jmp .reconnect

; Wait for Hello (opcode 10), then cache the server heartbeat interval.
gateway_wait_hello:
    call gateway_now_ms
    add rax, 15000
    mov [gateway_hello_deadline_ms], rax
.wait:
    call gateway_poll_readable
    test eax, eax
    js .bad
    jnz .readable
    call gateway_now_ms
    cmp rax, [gateway_hello_deadline_ms]
    jb .wait
    jmp .bad
.readable:
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
    lea rdi, [log_gateway_hello_failed]
    mov esi, log_gateway_hello_failed_len
    call log_static
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
    call gateway_send_wait_writable
    test rax, rax
    js .bad
    xor eax, eax
    ret
.bad:
    call log_gateway_transport_failure
    lea rdi, [log_gateway_identify_failed]
    mov esi, log_gateway_identify_failed_len
    call log_static
    mov eax, -1
    ret

gateway_resume:
    cmp dword [gateway_session_valid], 0
    je .bad
    lea rdi, [gateway_resume_buffer]
    mov esi, 16384
    mov rdx, [discord_token_ptr]
    mov ecx, [discord_token_len]
    lea r8, [gateway_session_id]
    mov r9d, [gateway_session_id_len]
    mov r10, [gateway_sequence]
    call gateway_build_resume
    cmp eax, -1
    je .bad
    mov esi, eax
    lea rdi, [gateway_resume_buffer]
    mov edx, CURLWS_TEXT
    call gateway_send_wait_writable
    test rax, rax
    js .bad
    xor eax, eax
    ret
.bad:
    call log_gateway_transport_failure
    lea rdi, [log_gateway_resume_failed]
    mov esi, log_gateway_resume_failed_len
    call log_static
    mov eax, -1
    ret

gateway_clear_session:
    mov dword [gateway_session_valid], 0
    lea rax, [gateway_url]
    mov [gateway_connect_url], rax
    ret

gateway_capture_ready:
    push r12
    push r13
    push r14
    push r15
    mov r12, [gateway_packet]
    mov r13, [gateway_packet_len]

    mov rdi, r12
    mov rsi, r13
    lea rdx, [session_id_key]
    mov ecx, session_id_key_len
    call gateway_find_key
    test rax, rax
    jz .bad
    mov r14, rax
    add r14, session_id_key_len
    mov rdi, r14
    mov rsi, r13
    sub rsi, r14
    add rsi, r12
    lea rdx, [gateway_session_id]
    mov ecx, 256
    call gateway_decode_string
    cmp eax, -1
    je .bad
    mov [gateway_session_id_len], eax

    mov rdi, r12
    mov rsi, r13
    lea rdx, [resume_url_key]
    mov ecx, resume_url_key_len
    call gateway_find_key
    test rax, rax
    jz .bad
    add rax, resume_url_key_len
    mov rdi, rax
    mov rsi, r13
    sub rsi, rax
    add rsi, r12
    lea rdx, [gateway_resume_url]
    mov ecx, 256
    call gateway_decode_string
    cmp eax, -1
    je .bad
    test eax, eax
    jz .bad
    lea rax, [gateway_resume_url]
    mov [gateway_connect_url], rax
    mov dword [gateway_session_valid], 1
    xor eax, eax
    jmp .out
.bad:
    mov dword [gateway_session_valid], 0
    lea rax, [gateway_url]
    mov [gateway_connect_url], rax
    lea rdi, [log_gateway_ready_failed]
    mov esi, log_gateway_ready_failed_len
    call log_static
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
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
    lea rdi, [log_gateway_session_failed]
    mov esi, log_gateway_session_failed_len
    call log_static
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
    je .invalid_session
    cmp eax, 0
    jne .ok

    mov rdi, [gateway_packet]
    mov rsi, [gateway_packet_len]
    lea rdx, [ready_key]
    mov ecx, ready_key_len
    call gateway_find_key
    test rax, rax
    jnz .ready
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
    jmp .ok
.ready:
    call gateway_capture_ready
    test eax, eax
    js .ready_failed
    lea rdi, [log_gateway_ready_ok]
    mov esi, log_gateway_ready_ok_len
    call log_static
.ok:
    xor eax, eax
    ret
.ready_failed:
    mov eax, -1
    ret
.ack:
    mov dword [heartbeat_waiting], 0
    xor eax, eax
    ret
.heartbeat_request:
    call gateway_send_heartbeat
    ret
.reconnect:
    lea rdi, [log_gateway_reconnect]
    mov esi, log_gateway_reconnect_len
    call log_static
    mov eax, -1
    ret
.invalid_session:
    lea rdi, [log_gateway_invalid_session]
    mov esi, log_gateway_invalid_session_len
    call log_static
    call gateway_clear_session
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
    call gateway_send_wait_writable
    test rax, rax
    js .bad
    mov dword [heartbeat_waiting], 1
    call gateway_now_ms
    add rax, [heartbeat_interval_ms]
    mov [heartbeat_due_ms], rax
    xor eax, eax
    ret
.bad:
    call log_gateway_transport_failure
    lea rdi, [log_gateway_heartbeat_failed]
    mov esi, log_gateway_heartbeat_failed_len
    call log_static
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
    lea rdi, [log_gateway_heartbeat_failed]
    mov esi, log_gateway_heartbeat_failed_len
    call log_static
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
; Send through libcurl, waiting for socket writability when it reports EAGAIN.
; RDI=payload, ESI=length, EDX=WebSocket flags. EAX=bytes or -1.
gateway_send_wait_writable:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13d, esi
    mov r14d, edx
.retry:
    mov rdi, r12
    mov esi, r13d
    mov edx, r14d
    call secure_gateway_send
    test rax, rax
    jns .out
    cmp eax, -EAGAIN
    jne .bad
    call secure_gateway_socket
    test eax, eax
    js .bad
    mov [gateway_poll_fd], eax
    mov word [gateway_poll_entry + 4], POLLOUT
    mov word [gateway_poll_entry + 6], 0
    mov eax, SYS_POLL
    lea rdi, [gateway_poll_entry]
    mov esi, 1
    mov edx, 1000
    syscall
    test rax, rax
    jle .bad
    test word [gateway_poll_entry + 6], POLLOUT
    jz .bad
    jmp .retry
.bad:
    mov eax, -1
.out:
    pop r14
    pop r13
    pop r12
    ret

gateway_recv_wait_readable:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
.retry:
    mov rdi, r12
    mov esi, r13d
    mov rdx, r14
    mov rcx, r15
    mov r8, rbx
    call secure_gateway_recv
    test rax, rax
    jns .out
    cmp eax, -EAGAIN
    jne .bad
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
    jle .bad
    test word [gateway_poll_entry + 6], POLLIN
    jz .bad
    jmp .retry
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

gateway_receive_packet:
    mov rdi, [gateway_packet]
    mov esi, 16383
    lea rdx, [gateway_packet_len]
    lea rcx, [gateway_frame_flags]
    lea r8, [gateway_bytes_left]
    call gateway_recv_wait_readable
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
    call gateway_send_wait_writable
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
    call log_gateway_transport_failure
    lea rdi, [log_gateway_frame_failed]
    mov esi, log_gateway_frame_failed_len
    call log_static
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
    call log_gateway_transport_failure
    lea rdi, [log_gateway_poll_failed]
    mov esi, log_gateway_poll_failed_len
    call log_static
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
    jz .not_bot
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
    call gateway_fetch_highest_role

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
    lea rsi, [gateway_role_name]
    mov edx, [gateway_role_name_len]
    mov ecx, 16384 - outgoing_prefix_len - outgoing_middle_len
    call gateway_escape_copy
    cmp eax, -1
    je .out
    add r14d, eax
    lea rdi, [gateway_outgoing + outgoing_prefix_len]
    add rdi, r14
    lea rsi, [outgoing_role_middle]
    mov edx, outgoing_role_middle_len
    call gateway_copy
    add r14d, outgoing_role_middle_len
    lea rdi, [gateway_outgoing + outgoing_prefix_len]
    add rdi, r14
    lea rsi, [gateway_content]
    mov edx, [gateway_content_len]
    mov ecx, 16384 - outgoing_prefix_len - outgoing_middle_len - outgoing_role_middle_len
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
    test rax, rax
    jle .pipe_write_failed
    jmp .out
.pipe_write_failed:
    lea rdi, [log_gateway_pipe_write_failed]
    mov esi, log_gateway_pipe_write_failed_len
    call log_static
.out:
    pop r14
    pop r13
    pop r12
    ret

gateway_fetch_highest_role:
    push r12
    push r13
    push r14
    push r15
    mov dword [gateway_role_name_len], 0
    mov r12, [gateway_packet]
    mov r13, [gateway_packet_len]

    ; Get guild_id from MESSAGE_CREATE.
    mov rdi, r12
    mov rsi, r13
    lea rdx, [guild_id_key]
    mov ecx, guild_id_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, guild_id_key_len
    mov rdi, rax
    mov rsi, r13
    sub rsi, rax
    add rsi, r12
    lea rdx, [gateway_role_id]
    mov ecx, 64
    call gateway_decode_string
    cmp eax, -1
    je .out
    mov [gateway_role_id_len], eax

    ; Find the member role id array in the event.
    mov rdi, r12
    mov rsi, r13
    lea rdx, [roles_array_key]
    mov ecx, roles_array_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, roles_array_key_len
    mov [gateway_role_member_start], rax
    mov rdi, rax
    mov rsi, r13
    sub rsi, rax
    add rsi, r12
    mov dl, ']'
    call gateway_find_byte
    test rax, rax
    jz .out
    sub rax, [gateway_role_member_start]
    mov [gateway_role_member_len], rax

    ; Build Authorization and /guilds/<id>/roles.
    lea rdi, [gateway_rest_auth]
    lea rsi, [bot_auth_prefix]
    mov edx, bot_auth_prefix_len
    call gateway_copy
    lea rdi, [gateway_rest_auth + bot_auth_prefix_len]
    mov rsi, [discord_token_ptr]
    mov edx, [discord_token_len]
    call gateway_copy
    mov eax, bot_auth_prefix_len
    add eax, [discord_token_len]
    mov byte [gateway_rest_auth + rax], 0

    lea rdi, [gateway_role_url]
    lea rsi, [roles_url_prefix]
    mov edx, roles_url_prefix_len
    call gateway_copy
    lea rdi, [gateway_role_url + roles_url_prefix_len]
    lea rsi, [gateway_role_id]
    mov edx, [gateway_role_id_len]
    call gateway_copy
    mov eax, roles_url_prefix_len
    add eax, [gateway_role_id_len]
    lea rdi, [gateway_role_url + rax]
    lea rsi, [roles_url_suffix]
    mov edx, roles_url_suffix_len
    call gateway_copy
    mov eax, roles_url_prefix_len
    add eax, [gateway_role_id_len]
    add eax, roles_url_suffix_len
    mov byte [gateway_role_url + rax], 0

    lea rdi, [gateway_role_url]
    lea rsi, [gateway_rest_auth]
    lea rdx, [gateway_role_response]
    mov ecx, 32768
    lea r8, [gateway_role_response_len]
    lea r9, [gateway_role_http_status]
    call secure_https_get_json
    test rax, rax
    js .transport_failed
    mov rax, [gateway_role_http_status]
    cmp rax, 200
    jb .http_failed
    cmp rax, 300
    jae .http_failed

    mov qword [gateway_best_position], -1
    mov r14, gateway_role_response
    mov r15, [gateway_role_response_len]
.scan_role:
    mov rdi, r14
    mov rsi, r15
    lea rdx, [role_id_key]
    mov ecx, role_id_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, role_id_key_len
    mov rdi, rax
    mov rsi, r15
    sub rsi, rax
    add rsi, r14
    lea rdx, [gateway_role_id]
    mov ecx, 64
    call gateway_decode_string
    cmp eax, -1
    je .out
    mov [gateway_role_id_len], eax

    lea rdi, [gateway_role_needle]
    mov byte [rdi], '"'
    inc rdi
    lea rsi, [gateway_role_id]
    mov edx, [gateway_role_id_len]
    call gateway_copy
    mov eax, [gateway_role_id_len]
    lea rdi, [gateway_role_needle + 1]
    add rdi, rax
    mov byte [rdi], '"'
    mov eax, [gateway_role_id_len]
    inc eax
    inc eax
    mov [gateway_role_needle_len], eax

    mov rdi, [gateway_role_member_start]
    mov rsi, [gateway_role_member_len]
    lea rdx, [gateway_role_needle]
    mov ecx, [gateway_role_needle_len]
    call gateway_find_key
    test rax, rax
    jz .next_role

    mov rdi, r14
    mov rsi, r15
    lea rdx, [role_name_key]
    mov ecx, role_name_key_len
    call gateway_find_key
    test rax, rax
    jz .next_role
    add rax, role_name_key_len
    mov rdi, rax
    mov rsi, r15
    sub rsi, rax
    add rsi, r14
    lea rdx, [gateway_role_name]
    mov ecx, 512
    call gateway_decode_string
    cmp eax, -1
    je .next_role
    mov [gateway_role_name_len], eax

    mov rdi, r14
    mov rsi, r15
    lea rdx, [role_position_key]
    mov ecx, role_position_key_len
    call gateway_find_key
    test rax, rax
    jz .next_role
    add rax, role_position_key_len
    mov rdi, rax
    mov rsi, 32
    call gateway_parse_u64
    cmp eax, -1
    je .next_role
    cmp rax, [gateway_best_position]
    jbe .next_role
    mov [gateway_best_position], rax
.next_role:
    mov rdi, r14
    mov rsi, r15
    lea rdx, [role_id_key]
    mov ecx, role_id_key_len
    call gateway_find_key
    test rax, rax
    jz .out
    add rax, role_id_key_len
    mov r14, rax
    mov rax, [gateway_role_response]
    add rax, [gateway_role_response_len]
    sub rax, r14
    mov r15, rax
    test r15, r15
    jnz .scan_role
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.transport_failed:
    call log_transport_failure
    lea rdi, [log_gateway_role_transport]
    mov esi, log_gateway_role_transport_len
    call log_static
    jmp .out
.http_failed:
    lea rdi, [log_gateway_role_http_prefix]
    mov esi, log_gateway_role_http_prefix_len
    mov rdx, [gateway_role_http_status]
    call log_http_status
    lea rdi, [log_gateway_role_http_failed]
    mov esi, log_gateway_role_http_failed_len
    call log_static
    jmp .out

gateway_find_byte:
    test rsi, rsi
    jz .none
.loop:
    cmp byte [rdi], dl
    je .found
    inc rdi
    dec rsi
    jnz .loop
.none:
    xor eax, eax
    ret
.found:
    mov rax, rdi
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
gateway_url: db 'wss://gateway.discord.gg/?v=10',0
hello_interval_key: db '"heartbeat_interval":'
hello_interval_key_len equ $ - hello_interval_key
message_create_key: db '"t":"MESSAGE_CREATE"'
message_create_key_len equ $ - message_create_key
ready_key: db '"t":"READY"'
ready_key_len equ $ - ready_key
session_id_key: db '"session_id":"'
session_id_key_len equ $ - session_id_key
resume_url_key: db '"resume_gateway_url":"'
resume_url_key_len equ $ - resume_url_key
channel_id_key: db '"channel_id":"'
channel_id_key_len equ $ - channel_id_key
guild_id_key: db '"guild_id":"'
guild_id_key_len equ $ - guild_id_key
roles_array_key: db '"roles":['
roles_array_key_len equ $ - roles_array_key
role_id_key: db '"id":"'
role_id_key_len equ $ - role_id_key
role_name_key: db '"name":"'
role_name_key_len equ $ - role_name_key
role_position_key: db '"position":'
role_position_key_len equ $ - role_position_key
roles_url_prefix: db 'https://discord.com/api/v10/guilds/'
roles_url_prefix_len equ $ - roles_url_prefix
roles_url_suffix: db '/roles'
roles_url_suffix_len equ $ - roles_url_suffix
bot_key: db '"bot":'
bot_key_len equ $ - bot_key
username_key: db '"username":"'
username_key_len equ $ - username_key
content_key: db '"content":"'
content_key_len equ $ - content_key
outgoing_prefix: db '{"type":"chat","author":"'
outgoing_prefix_len equ $ - outgoing_prefix
outgoing_middle: db '","role":"'
outgoing_middle_len equ $ - outgoing_middle
outgoing_role_middle: db '","message":"'
outgoing_role_middle_len equ $ - outgoing_role_middle
bot_auth_prefix: db 'Bot '
bot_auth_prefix_len equ $ - bot_auth_prefix
outgoing_suffix: db '"}'
outgoing_suffix_len equ $ - outgoing_suffix
log_gateway_connected: db 'val0x04-asm: WSS Gateway terhubung',10
log_gateway_connected_len equ $ - log_gateway_connected
log_gateway_hello_ok: db 'val0x04-asm: Gateway Hello diterima',10
log_gateway_hello_ok_len equ $ - log_gateway_hello_ok
log_gateway_identify_ok: db 'val0x04-asm: Gateway Identify terkirim',10
log_gateway_identify_ok_len equ $ - log_gateway_identify_ok
log_gateway_resume_ok: db 'val0x04-asm: Gateway Resume terkirim',10
log_gateway_resume_ok_len equ $ - log_gateway_resume_ok
log_gateway_ready_ok: db 'val0x04-asm: Gateway READY diterima',10
log_gateway_ready_ok_len equ $ - log_gateway_ready_ok
log_gateway_hello_failed: db 'val0x04-asm: Gateway Hello gagal',10
log_gateway_hello_failed_len equ $ - log_gateway_hello_failed
log_gateway_identify_failed: db 'val0x04-asm: Gateway Identify gagal',10
log_gateway_identify_failed_len equ $ - log_gateway_identify_failed
log_gateway_resume_failed: db 'val0x04-asm: Gateway Resume gagal',10
log_gateway_resume_failed_len equ $ - log_gateway_resume_failed
log_gateway_ready_failed: db 'val0x04-asm: payload READY tidak lengkap',10
log_gateway_ready_failed_len equ $ - log_gateway_ready_failed
log_gateway_session_failed: db 'val0x04-asm: sesi Gateway berhenti',10
log_gateway_session_failed_len equ $ - log_gateway_session_failed
log_gateway_heartbeat_failed: db 'val0x04-asm: heartbeat Gateway gagal atau ACK timeout',10
log_gateway_heartbeat_failed_len equ $ - log_gateway_heartbeat_failed
log_gateway_frame_failed: db 'val0x04-asm: frame Gateway gagal diproses',10
log_gateway_frame_failed_len equ $ - log_gateway_frame_failed
log_gateway_poll_failed: db 'val0x04-asm: poll Gateway gagal',10
log_gateway_poll_failed_len equ $ - log_gateway_poll_failed
log_gateway_reconnect: db 'val0x04-asm: Discord meminta reconnect',10
log_gateway_reconnect_len equ $ - log_gateway_reconnect
log_gateway_invalid_session: db 'val0x04-asm: sesi Gateway tidak valid; kembali ke Identify',10
log_gateway_invalid_session_len equ $ - log_gateway_invalid_session
log_gateway_role_transport: db 'val0x04-asm: role lookup Discord gagal di transport',10
log_gateway_role_transport_len equ $ - log_gateway_role_transport
log_gateway_role_http_prefix: db 'val0x04-asm: role lookup Discord HTTP status='
log_gateway_role_http_prefix_len equ $ - log_gateway_role_http_prefix
log_gateway_role_http_failed: db 'val0x04-asm: role lookup Discord ditolak oleh API',10
log_gateway_role_http_failed_len equ $ - log_gateway_role_http_failed
log_gateway_pipe_write_failed: db 'val0x04-asm: write pipe Gateway ke bridge gagal',10
log_gateway_pipe_write_failed_len equ $ - log_gateway_pipe_write_failed

section .data
align 8
heartbeat_interval_ms: dq 45000
heartbeat_due_ms: dq 0
gateway_hello_deadline_ms: dq 0
gateway_connect_url: dq gateway_url
gateway_session_valid: dd 0
gateway_session_id_len: dd 0
gateway_sequence: dq 0
gateway_packet_len: dq 0
gateway_bytes_left: dq 0
gateway_packet: dq gateway_packet_buffer
gateway_poll_fd: dd -1
gateway_frame_flags: dd 0
heartbeat_waiting: dd 0
gateway_author_len: dd 0
gateway_content_len: dd 0
gateway_role_name_len: dd 0
gateway_role_id_len: dd 0
gateway_role_needle_len: dd 0
gateway_role_response_len: dq 0
gateway_role_http_status: dq 0
gateway_best_position: dq -1

section .bss
align 16
gateway_packet_buffer: resb 16384
gateway_identify_buffer: resb 16384
gateway_heartbeat_buffer: resb 256
gateway_resume_buffer: resb 16384
gateway_session_id: resb 256
gateway_resume_url: resb 256
gateway_channel: resb 64
gateway_author: resb 1024
gateway_content: resb 8192
gateway_outgoing: resb 16384
gateway_rest_auth: resb 512
gateway_role_url: resb 256
gateway_role_response: resb 32768
gateway_role_id: resb 64
gateway_role_name: resb 512
gateway_role_needle: resb 80
gateway_role_member_start: resq 1
gateway_role_member_len: resq 1
jitter_bytes: resb 8
gateway_poll_entry: resb 8
gateway_timespec: resb 16
sleep_timespec: resb 16
