; Val0x04/ASM — syscall-only x86-64 Linux prototype.
; No Rust runtime or networking/JSON/WebSocket libraries are linked.
; The small C driver only passes envp and exposes a TLS-verified libcurl transport ABI.

BITS 64
DEFAULT REL

extern secure_https_post_json
extern secure_transport_last_error
extern secure_transport_last_response
extern secure_gateway_connect
extern secure_gateway_close
extern secure_gateway_socket
extern secure_gateway_send
extern secure_gateway_recv
extern secure_https_get_json
extern gateway_worker
extern gateway_escape_copy
extern gateway_copy
extern gateway_find_key
extern gateway_decode_string
extern gateway_write_u64

global discord_token_ptr
global discord_token_len
global discord_channel_ptr
global discord_channel_len
global gateway_pipe_write
global write_all
global log_static
global log_transport_failure
global log_http_status

%define SYS_READ            0
%define SYS_WRITE           1
%define SYS_OPEN            2
%define SYS_CLOSE           3
%define SYS_SOCKET          41
%define SYS_ACCEPT          43
%define SYS_BIND            49
%define SYS_LISTEN          50
%define SYS_SETSOCKOPT      54
%define SYS_EXIT            60
%define SYS_GETRANDOM       318
%define SYS_POLL            7
%define SYS_FORK            57
%define SYS_CLOCK_GETTIME   228
%define SYS_PIPE            22
%define SYS_NANOSLEEP       35
%define SYS_PRCTL           157
%define SYS_FLOCK           73
%define LOCK_EX             2
%define LOCK_NB             4
%define LOCK_UN             8
%define PR_SET_PDEATHSIG    1
%define SIGTERM             15
%define CLOCK_MONOTONIC     1
%define POLLIN              1
%define CURLWS_TEXT         1
%define CURLWS_PING         16
%define CURLWS_CLOSE        8
%define CURLWS_PONG         64

%define AF_INET             2
%define SOCK_STREAM         1
%define SOL_SOCKET          1
%define SO_REUSEADDR        2
%define REQUEST_CAPACITY    16384

section .text
global asm_service_start

; rdi = environment-pointer array supplied by the C process driver.
asm_service_start:
    ; Keep envp in r15 for the existing syscall-only configuration parser.
    mov r15, rdi
    call load_environment_from_envp
    lea rdi, [runtime_entropy]
    mov esi, 32
    call secure_random
    cmp eax, 32
    jne fatal_entropy
    call open_listener
    call open_gateway_pipe
    call spawn_gateway_worker

.accept_loop:
    mov eax, [server_fd]
    mov [listener_pollfds], eax
    mov word [listener_pollfds + 4], POLLIN
    mov word [listener_pollfds + 6], 0
    mov eax, SYS_POLL
    lea rdi, [listener_pollfds]
    mov esi, 1
    mov edx, 1000
    syscall
    test rax, rax
    js .poll_error
    jz .accept_loop
    test word [listener_pollfds + 6], POLLIN
    jz .accept_loop

    mov eax, SYS_ACCEPT
    mov edi, dword [server_fd]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .accept_error

    mov rdi, rax
    call spawn_client_process
    test eax, eax
    js .fork_error
    jmp .accept_loop
.poll_error:
    lea rdi, [log_poll_failed]
    mov esi, log_poll_failed_len
    call log_static
    jmp .accept_loop
.accept_error:
    lea rdi, [log_accept_failed]
    mov esi, log_accept_failed_len
    call log_static
    jmp .accept_loop
.fork_error:
    lea rdi, [log_client_fork_failed]
    mov esi, log_client_fork_failed_len
    call log_static
    jmp .accept_loop

; ---------------------------------------------------------------------------
; Gateway worker process and parent-to-bridge message pipe.
; ---------------------------------------------------------------------------
open_bridge_lock:
    mov eax, SYS_OPEN
    lea rdi, [bridge_lock_path]
    mov esi, 66
    mov edx, 0o600
    syscall
    test rax, rax
    js fatal_gateway
    mov [bridge_lock_fd], eax
    ret

spawn_client_process:
    push r12
    mov r12, rdi
    mov eax, SYS_FORK
    syscall
    test rax, rax
    js .fork_failed
    jnz .parent
    mov [client_fd], r12d
    mov eax, SYS_PRCTL
    mov edi, PR_SET_PDEATHSIG
    mov esi, SIGTERM
    syscall
    mov eax, SYS_CLOSE
    mov edi, [server_fd]
    syscall
    mov eax, SYS_CLOSE
    mov edi, [gateway_pipe_write]
    syscall
    mov edi, r12d
    call handle_http_request
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
.fork_failed:
    mov eax, -1
    pop r12
    ret
.parent:
    mov eax, SYS_CLOSE
    mov edi, r12d
    syscall
    xor eax, eax
    pop r12
    ret

open_gateway_pipe:
    mov eax, SYS_PIPE
    lea rdi, [gateway_pipe]
    syscall
    test eax, eax
    js fatal_gateway
    mov eax, [gateway_pipe]
    mov [gateway_pipe_read], eax
    mov eax, [gateway_pipe + 4]
    mov [gateway_pipe_write], eax
    ret

spawn_gateway_worker:
    mov eax, SYS_FORK
    syscall
    test rax, rax
    js fatal_gateway
    jz .child
    mov [gateway_pid], eax
    mov eax, SYS_CLOSE
    mov edi, [gateway_pipe_write]
    syscall
    mov dword [gateway_pipe_write], -1
    ret
.child:
    mov eax, SYS_PRCTL
    mov edi, PR_SET_PDEATHSIG
    mov esi, SIGTERM
    syscall
    mov eax, SYS_CLOSE
    mov edi, [gateway_pipe_read]
    syscall
    mov eax, SYS_CLOSE
    mov edi, [server_fd]
    syscall
    call gateway_worker
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

; Drain complete JSON messages produced by the Gateway worker.
drain_gateway_messages:
    cmp dword [gateway_pipe_read], 0
    jl .done
    mov eax, [gateway_pipe_read]
    mov [gateway_pipe_poll], eax
    mov word [gateway_pipe_poll + 4], POLLIN
    mov word [gateway_pipe_poll + 6], 0
    mov eax, SYS_POLL
    lea rdi, [gateway_pipe_poll]
    mov esi, 1
    xor edx, edx
    syscall
    test rax, rax
    js .pipe_poll_failed
    jz .done
    test word [gateway_pipe_poll + 6], POLLIN
    jz .done

    mov r8d, [gateway_message_length]
    cmp r8d, 65535
    jae .drop
    mov eax, 65535
    sub eax, r8d
    mov edx, eax
    mov edi, [gateway_pipe_read]
    lea rsi, [gateway_message_buffer + r8]
    mov eax, SYS_READ
    syscall
    test rax, rax
    js .pipe_read_failed
    jz .done
    add r8, rax
    mov [gateway_message_length], r8d
    cmp dword [bridge_active], 0
    je .drop

.next_line:
    xor ecx, ecx
.find_line:
    cmp rcx, r8
    jae .done
    cmp byte [gateway_message_buffer + rcx], 10
    je .line_found
    inc rcx
    jmp .find_line
.line_found:
    test ecx, ecx
    jz .remove_line
    lea rdi, [gateway_message_buffer]
    mov esi, ecx
    mov edx, 1
    call websocket_send_frame
    test eax, eax
    js .pipe_send_failed
.remove_line:
    mov r9, r8
    sub r9, rcx
    dec r9
    jz .clear
    lea rdi, [gateway_message_buffer]
    lea rsi, [gateway_message_buffer + rcx + 1]
    mov rdx, r9
    call memory_copy
    mov r8, r9
    mov [gateway_message_length], r8d
    jmp .next_line
.clear:
    mov dword [gateway_message_length], 0
    jmp .done
.drop:
    mov dword [gateway_message_length], 0
.done:
    ret
.pipe_poll_failed:
    lea rdi, [log_pipe_poll_failed]
    mov esi, log_pipe_poll_failed_len
    call log_static
    jmp .done
.pipe_read_failed:
    lea rdi, [log_pipe_read_failed]
    mov esi, log_pipe_read_failed_len
    call log_static
    jmp .done
.pipe_send_failed:
    lea rdi, [log_pipe_send_failed]
    mov esi, log_pipe_send_failed_len
    call log_static
    jmp .done

; ---------------------------------------------------------------------------
; Environment configuration.
; Reads PORT, BRIDGE_WEBSOCKET_AUTH_TOKEN and PANEL_ACCESS_TOKEN directly
; from envp. Secrets remain runtime configuration and are never in the image.
; _start passes envp through r15.
; ---------------------------------------------------------------------------
load_environment_from_envp:
.env_next:
    mov rbx, [r15]
    test rbx, rbx
    jz .done

    mov rdi, rbx
    lea rsi, [env_port]
    mov ecx, env_port_len
    call has_prefix
    test al, al
    jz .bridge
    lea rdi, [rbx + env_port_len]
    call parse_decimal_u16
    test ax, ax
    jz .advance
    xchg al, ah                     ; host u16 -> network byte order
    mov [listen_port_network], ax
    jmp .advance

.bridge:
    mov rdi, rbx
    lea rsi, [env_bridge]
    mov ecx, env_bridge_len
    call has_prefix
    test al, al
    jz .panel
    lea rax, [rbx + env_bridge_len]
    mov [bridge_token_ptr], rax
    mov rdi, rax
    call cstring_length
    mov [bridge_token_len], eax
    jmp .advance

.panel:
    mov rdi, rbx
    lea rsi, [env_panel]
    mov ecx, env_panel_len
    call has_prefix
    test al, al
    jz .discord_token
    lea rax, [rbx + env_panel_len]
    mov [panel_token_ptr], rax
    mov rdi, rax
    call cstring_length
    mov [panel_token_len], eax
    jmp .advance

.discord_token:
    ; Stored for a later pure TLS/Discord transport phase. It is intentionally
    ; not transmitted by the current inbound-only milestone.
    mov rdi, rbx
    lea rsi, [env_discord]
    mov ecx, env_discord_len
    call has_prefix
    test al, al
    jz .discord_channel
    lea rax, [rbx + env_discord_len]
    mov [discord_token_ptr], rax
    mov rdi, rax
    call cstring_length
    mov [discord_token_len], eax
    jmp .advance

.discord_channel:
    mov rdi, rbx
    lea rsi, [env_discord_channel]
    mov ecx, env_discord_channel_len
    call has_prefix
    test al, al
    jz .advance
    lea rax, [rbx + env_discord_channel_len]
    mov [discord_channel_ptr], rax
    mov rdi, rax
    call cstring_length
    mov [discord_channel_len], eax
    mov rdi, [discord_channel_ptr]
    call parse_decimal_u64
    test edx, edx
    jz .advance
    mov dword [config_invalid], 1

.advance:
    add r15, 8
    jmp .env_next
.done:
    cmp dword [config_invalid], 0
    jne fatal_config
    cmp dword [discord_token_len], 0
    je fatal_config
    cmp dword [discord_channel_len], 0
    je fatal_config
    cmp dword [bridge_token_len], 0
    je fatal_config
    cmp dword [panel_token_len], 0
    je fatal_config
    ret

; Parse an unsigned 64-bit decimal value. EDX=0 valid, EDX=1 invalid.
parse_decimal_u64:
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    mov r9, 10
.loop_u64:
    movzx r8d, byte [rdi + rcx]
    test r8b, r8b
    jz .valid_u64
    sub r8b, '0'
    cmp r8b, 9
    ja .invalid_u64
    mul r9
    test rdx, rdx
    jnz .invalid_u64
    add rax, r8
    jc .invalid_u64
    inc rcx
    jmp .loop_u64
.valid_u64:
    xor edx, edx
    ret
.invalid_u64:
    xor eax, eax
    mov edx, 1
    ret

; rdi = candidate, rsi = prefix, rcx = length. AL = 1 when equal.
has_prefix:
    push rdi
    push rsi
    push rcx
    call memory_equal
    pop rcx
    pop rsi
    pop rdi
    ret

; rdi = NUL-terminated decimal string, returns AX (0 on malformed/overflow).
parse_decimal_u16:
    xor eax, eax
    xor ecx, ecx
.loop:
    movzx edx, byte [rdi + rcx]
    test dl, dl
    jz .finish
    sub dl, '0'
    cmp dl, 9
    ja .bad
    movzx edx, dl
    imul eax, eax, 10
    add eax, edx
    cmp eax, 65535
    ja .bad
    inc rcx
    jmp .loop
.finish:
    test ecx, ecx
    jz .bad
    ret
.bad:
    xor eax, eax
    ret

; rdi = C string, EAX = byte count, excluding NUL.
cstring_length:
    xor eax, eax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc eax
    jmp .loop
.done:
    ret

; Tulis satu pesan diagnostik tetap ke stderr.
; RDI = alamat pesan, RSI = panjang pesan.
log_static:
    mov rdx, rsi
    mov rsi, rdi
    mov edi, 2
    call write_all
    ret

; ---------------------------------------------------------------------------
; TCP listener.
; ---------------------------------------------------------------------------
open_listener:
    mov eax, SYS_SOCKET
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    syscall
    test rax, rax
    js fatal_socket
    mov [server_fd], eax

    mov eax, SYS_SETSOCKOPT
    mov edi, dword [server_fd]
    mov esi, SOL_SOCKET
    mov edx, SO_REUSEADDR
    lea r10, [one]
    mov r8d, 4
    syscall
    test rax, rax
    js .setsockopt_failed

    mov eax, SYS_BIND
    mov edi, dword [server_fd]
    lea rsi, [listen_address]
    mov edx, 16
    syscall
    test rax, rax
    js fatal_bind

    mov eax, SYS_LISTEN
    mov edi, dword [server_fd]
    mov esi, 32
    syscall
    test rax, rax
    js fatal_listen
    ret
.setsockopt_failed:
    lea rdi, [log_setsockopt_failed]
    mov esi, log_setsockopt_failed_len
    call log_static
    jmp fatal_socket

; ---------------------------------------------------------------------------
; HTTP/1.1 subset. One complete request per accepted connection.
; Endpoints: GET /health, GET /panel, POST /api/chat. WebSocket root endpoint
; intentionally returns 426 until the WebSocket milestone is installed.
; ---------------------------------------------------------------------------
handle_http_request:
    mov [client_fd], edi
    xor r12d, r12d
.read_more:
    mov eax, SYS_READ
    mov edi, dword [client_fd]
    lea rsi, [request_buffer + r12]
    mov edx, REQUEST_CAPACITY - 1
    sub edx, r12d
    syscall
    test rax, rax
    js .read_failed
    jz .read_failed
    add r12, rax
    mov [request_length], r12
    lea rdi, [request_buffer]
    lea rsi, [header_terminator]
    mov ecx, header_terminator_len
    mov rdx, r12
    call find_bytes
    test rax, rax
    jnz .request_ready
    cmp r12, REQUEST_CAPACITY - 1
    jb .read_more
.read_failed:
    lea rdi, [log_http_read_failed]
    mov esi, log_http_read_failed_len
    call log_static
    jmp .done
.request_ready:
    mov rax, [request_length]
    mov byte [request_buffer + rax], 0

    lea rdi, [request_buffer]
    lea rsi, [method_health]
    mov ecx, method_health_len
    call has_prefix
    test al, al
    jnz .health

    lea rdi, [request_buffer]
    lea rsi, [method_panel]
    mov ecx, method_panel_len
    call has_prefix
    test al, al
    jnz .panel

    lea rdi, [request_buffer]
    lea rsi, [method_chat]
    mov ecx, method_chat_len
    call has_prefix
    test al, al
    jnz .chat

    lea rdi, [request_buffer]
    lea rsi, [method_root]
    mov ecx, method_root_len
    call has_prefix
    test al, al
    jnz .upgrade_required

    lea rdi, [log_route_not_found]
    mov esi, log_route_not_found_len
    call log_static
    lea rsi, [response_not_found]
    mov edx, response_not_found_len
    jmp .send
.health:
    lea rsi, [response_health]
    mov edx, response_health_len
    jmp .send
.panel:
    lea rsi, [response_panel]
    mov edx, response_panel_len
    jmp .send
.chat:
    call panel_authorized
    test al, al
    jz .unauthorized
    call send_panel_message_to_discord
    cmp eax, -2
    je .bad_request
    test eax, eax
    jnz .discord_failure
    lea rsi, [response_discord_sent]
    mov edx, response_discord_sent_len
    jmp .send
.bad_request:
    lea rdi, [log_panel_bad_json]
    mov esi, log_panel_bad_json_len
    call log_static
    lea rsi, [response_bad_request]
    mov edx, response_bad_request_len
    jmp .send
.discord_failure:
    lea rsi, [response_discord_failure]
    mov edx, response_discord_failure_len
    jmp .send
.bridge_unauthorized:
    lea rdi, [log_bridge_unauthorized]
    mov esi, log_bridge_unauthorized_len
    call log_static
    lea rsi, [response_unauthorized]
    mov edx, response_unauthorized_len
    jmp .send
.unauthorized:
    lea rdi, [log_panel_unauthorized]
    mov esi, log_panel_unauthorized_len
    call log_static
    lea rsi, [response_unauthorized]
    mov edx, response_unauthorized_len
    jmp .send
.upgrade_required:
    call bridge_authorized
    test al, al
    jz .bridge_unauthorized
    lea rdi, [request_buffer]
    lea rsi, [upgrade_header]
    mov ecx, upgrade_header_len
    mov rdx, [request_length]
    call find_bytes
    test rax, rax
    jz .send_upgrade_required
    call upgrade_websocket
    jmp .done
.send_upgrade_required:
    lea rsi, [response_upgrade_required]
    mov edx, response_upgrade_required_len
.send:
    mov edi, dword [client_fd]
    call write_all
.done:
    ret

; Serialize the validated panel message as a Discord JSON content value.
; EAX = 0 only when Discord returns an HTTP 2xx status.
send_panel_message_to_discord:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp dword [discord_token_len], 0
    je .bad_panel_send
    cmp dword [discord_channel_len], 0
    je .bad_panel_send
    call prepare_panel_message
    test eax, eax
    js .bad_panel_json
    mov r13d, eax

    lea rdi, [discord_json]
    lea rsi, [discord_json_prefix]
    mov edx, discord_json_prefix_len
    call memory_copy
    lea rdi, [discord_json + discord_json_prefix_len]
    lea rsi, [panel_message]
    mov edx, r13d
    mov ecx, 4096 - discord_json_prefix_len - discord_json_suffix_len
    call gateway_escape_copy
    cmp eax, -1
    je .bad_panel_send
    mov r14d, eax
    lea rdi, [discord_json + discord_json_prefix_len + r14]
    lea rsi, [discord_json_suffix]
    mov edx, discord_json_suffix_len
    call memory_copy
    mov r15d, r14d
    add r15d, discord_json_prefix_len + discord_json_suffix_len
    mov rdi, r15
    call send_discord_json_buffer
    jmp .out_panel_send
.bad_panel_json:
    mov eax, -2
    jmp .out_panel_send
.bad_panel_send:
    mov eax, -1
.out_panel_send:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Parse {"message":"..."}, trim ASCII JSON whitespace, and validate UTF-8.
prepare_panel_message:
    push r12
    push r13
    lea rdi, [request_buffer]
    lea rsi, [header_terminator]
    mov ecx, header_terminator_len
    mov rdx, [request_length]
    call find_bytes
    test rax, rax
    jz .bad_prepare
    add rax, header_terminator_len
    mov r12, rax
    lea rdx, [request_buffer]
    add rdx, [request_length]
    sub rdx, r12
    mov r13, rdx
    test r13, r13
    jz .bad_prepare
    mov rdi, r12
    mov rsi, r13
    lea rdx, [panel_message]
    mov ecx, 4096
    call extract_panel_json_message
    cmp eax, -1
    je .bad_prepare
    mov rdi, panel_message
    mov esi, eax
    call trim_validate_utf8
    cmp eax, -1
    je .bad_prepare
    mov [panel_message_length], eax
    jmp .out_prepare
.bad_prepare:
    mov eax, -1
.out_prepare:
    pop r13
    pop r12
    ret

; Trim Rust-style ASCII whitespace and count UTF-8 code points.
; Extract a required JSON string field named message with optional JSON whitespace.
; RDI=input, RSI=input length, RDX=output, RCX=capacity. EAX=length or -1.
extract_panel_json_message:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    lea rsi, [panel_message_name]
    mov ecx, panel_message_name_len
    mov rdi, r12
    mov rdx, r13
    call find_bytes
    test rax, rax
    jz .bad_panel_json
    add rax, panel_message_name_len
    mov r8, rax
.skip_space:
    cmp r8, r12
    jb .bad_panel_json
    mov r9, r12
    add r9, r13
    cmp r8, r9
    jae .bad_panel_json
    mov al, [r8]
    cmp al, ' '
    je .advance_space
    cmp al, 9
    je .advance_space
    cmp al, 10
    je .advance_space
    cmp al, 13
    je .advance_space
    cmp al, ':'
    jne .bad_panel_json
    inc r8
.after_colon:
    cmp r8, r9
    jae .bad_panel_json
    mov al, [r8]
    cmp al, ' '
    je .advance_after_colon
    cmp al, 9
    je .advance_after_colon
    cmp al, 10
    je .advance_after_colon
    cmp al, 13
    je .advance_after_colon
    cmp al, '"'
    jne .bad_panel_json
    inc r8
    mov rdi, r8
    sub r9, r8
    mov rsi, r9
    mov rdx, r14
    mov rcx, r15
    call gateway_decode_string
    jmp .out_panel_json
.advance_space:
    inc r8
    jmp .skip_space
.advance_after_colon:
    inc r8
    jmp .after_colon
.bad_panel_json:
    mov eax, -1
.out_panel_json:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

trim_validate_utf8:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    xor r14d, r14d
.leading_trim:
    cmp r14, r13
    jae .bad_trim
    mov dil, [r12 + r14]
    call is_ascii_space
    test al, al
    jz .right_trim
    inc r14
    jmp .leading_trim
.right_trim:
    mov r15, r13
.trailing_trim:
    cmp r15, r14
    jbe .trimmed
    mov dil, [r12 + r15 - 1]
    call is_ascii_space
    test al, al
    jz .trimmed
    dec r15
    jmp .trailing_trim
.trimmed:
    mov r13, r15
    sub r13, r14
    test r13, r13
    jz .bad_trim
    test r14, r14
    jz .count_utf8
    mov rdx, r13
    lea rdi, [r12]
    lea rsi, [r12 + r14]
    call memory_copy
.count_utf8:
    xor ecx, ecx
    xor r8d, r8d
.next_utf8:
    cmp rcx, r13
    jae .count_done
    movzx eax, byte [r12 + rcx]
    cmp al, 0x80
    jb .one_utf8
    cmp al, 0xc2
    jb .bad_trim
    cmp al, 0xdf
    jbe .two_utf8
    cmp al, 0xef
    jbe .three_utf8
    cmp al, 0xf4
    ja .bad_trim
    jmp .four_utf8
.one_utf8:
    inc rcx
    inc r8
    jmp .next_utf8
.two_utf8:
    lea r9, [rcx + 1]
    cmp r9, r13
    jae .bad_trim
    mov al, [r12 + r9]
    call is_utf8_continuation
    test al, al
    jz .bad_trim
    add rcx, 2
    inc r8
    jmp .next_utf8
.three_utf8:
    lea r9, [rcx + 2]
    cmp r9, r13
    jae .bad_trim
    mov al, [r12 + rcx + 1]
    call is_utf8_continuation
    test al, al
    jz .bad_trim
    mov al, [r12 + r9]
    call is_utf8_continuation
    test al, al
    jz .bad_trim
    add rcx, 3
    inc r8
    jmp .next_utf8
.four_utf8:
    lea r9, [rcx + 3]
    cmp r9, r13
    jae .bad_trim
    mov al, [r12 + rcx + 1]
    call is_utf8_continuation
    test al, al
    jz .bad_trim
    mov al, [r12 + rcx + 2]
    call is_utf8_continuation
    test al, al
    jz .bad_trim
    mov al, [r12 + r9]
    call is_utf8_continuation
    test al, al
    jz .bad_trim
    add rcx, 4
    inc r8
    jmp .next_utf8
.count_done:
    cmp r8, 2000
    ja .bad_trim
    mov rax, r13
    jmp .out_trim
.bad_trim:
    mov eax, -1
.out_trim:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

is_ascii_space:
    cmp dil, 9
    jb .not_space
    cmp dil, 13
    jbe .space
    cmp dil, 32
    je .space
.not_space:
    xor eax, eax
    ret
.space:
    mov eax, 1
    ret

is_utf8_continuation:
    and eax, 0xc0
    cmp al, 0x80
    sete al
    ret

; Send the already serialized Discord message through verified HTTPS.
; RDI contains the JSON byte length; EAX is zero only for HTTP 2xx.
send_discord_json_buffer:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15, rdi
    cmp r15, 4096
    ja .bad
    cmp dword [discord_token_len], 0
    je .bad
    cmp dword [discord_channel_len], 0
    je .bad

    lea rdi, [discord_authorization]
    lea rsi, [discord_authorization_prefix]
    mov edx, discord_authorization_prefix_len
    call memory_copy
    lea rdi, [discord_authorization + discord_authorization_prefix_len]
    mov rsi, [discord_token_ptr]
    mov edx, [discord_token_len]
    call memory_copy
    mov byte [discord_authorization + discord_authorization_prefix_len + rdx], 0

    lea rdi, [discord_url]
    lea rsi, [discord_url_prefix]
    mov edx, discord_url_prefix_len
    call memory_copy
    lea rdi, [discord_url + discord_url_prefix_len]
    mov rsi, [discord_channel_ptr]
    mov edx, [discord_channel_len]
    call memory_copy
    lea rdi, [discord_url + discord_url_prefix_len + rdx]
    lea rsi, [discord_url_suffix]
    mov edx, discord_url_suffix_len
    call memory_copy
    mov byte [rdi + rdx], 0

    xor r14d, r14d
.rest_retry:
    lea rdi, [discord_url]
    lea rsi, [discord_authorization]
    lea rdx, [discord_json]
    mov rcx, r15
    lea r8, [discord_http_status]
    call secure_https_post_json
    test rax, rax
    jnz .bad
    mov rax, [discord_http_status]
    cmp rax, 429
    jne .status_check
    cmp r14d, 3
    jae .bad
    mov eax, 1
    mov ecx, r14d
    shl eax, cl
    mov [rest_sleep_seconds], rax
    call rest_sleep
    inc r14d
    jmp .rest_retry
.status_check:
    cmp rax, 200
    jb .bad
    cmp rax, 300
    jae .bad
    xor eax, eax
    jmp .out
.bad:
    call log_transport_failure
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Write a status-only HTTP diagnostic. The destination is never a URL/body.
; RDI=prefix, RSI=prefix length, RDX=status.
log_http_status:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    lea rdi, [discord_log_buffer]
    mov rsi, r12
    mov edx, r13d
    call memory_copy
    lea rdi, [discord_log_buffer + r13]
    mov rax, r14
    call gateway_write_u64
    add r13d, eax
    mov byte [discord_log_buffer + r13], 10
    inc r13d
    mov edi, 2
    lea rsi, [discord_log_buffer]
    mov edx, r13d
    call write_all
    pop r14
    pop r13
    pop r12
    ret

; Log status plus a bounded libcurl error string; never log response/request data.
log_transport_failure:
    push r12
    push r13
    push r14
    lea rdi, [transport_status_prefix]
    mov esi, transport_status_prefix_len
    mov rdx, [discord_http_status]
    call log_http_status
    call secure_transport_last_error
    mov r12, rax
    test r12, r12
    jz .done
    mov rdi, r12
    call cstring_length
    test eax, eax
    jz .done
    mov r14d, eax
    cmp r14d, 900
    jbe .copy_error
    mov r14d, 900
.copy_error:
    lea rdi, [discord_log_buffer]
    lea rsi, [transport_detail_prefix]
    mov edx, transport_detail_prefix_len
    call memory_copy
    mov r13d, transport_detail_prefix_len
    lea rdi, [discord_log_buffer + r13]
    mov rsi, r12
    mov edx, r14d
    call memory_copy
    add r13d, r14d
    mov byte [discord_log_buffer + r13], 10
    inc r13d
    mov edi, 2
    lea rsi, [discord_log_buffer]
    mov edx, r13d
    call write_all
.done:
    pop r14
    pop r13
    pop r12
    ret

rest_sleep:
    mov rax, [rest_sleep_seconds]
    mov [rest_sleep_timespec], rax
    mov qword [rest_sleep_timespec + 8], 0
    mov eax, SYS_NANOSLEEP
    lea rdi, [rest_sleep_timespec]
    xor esi, esi
    syscall
    ret

; Validate `Authorization: Bearer <PANEL_ACCESS_TOKEN>` with a CRLF boundary.
; AL = 1 only on an exact configured token match.
panel_authorized:
    cmp dword [panel_token_len], 0
    je .no
    lea rdi, [request_buffer]
    lea rsi, [authorization_prefix]
    mov ecx, authorization_prefix_len
    mov rdx, [request_length]
    call find_bytes
    test rax, rax
    jz .no
    add rax, authorization_prefix_len
    mov rdi, rax
    mov rsi, [panel_token_ptr]
    mov ecx, dword [panel_token_len]
    call memory_equal
    test al, al
    jz .no
    mov rax, [request_length]
    lea rdx, [request_buffer]
    add rdx, rax
    ; memory_equal advances rdi to exactly the byte after the token.
    cmp rdi, rdx
    jae .no
    cmp word [rdi], 0x0a0d           ; CR LF in little-endian word
    jne .no
    mov al, 1
    ret
.no:
    xor eax, eax
    ret

; rdi = haystack, rsi = needle, rcx = needle length, rdx = haystack length.
; RAX = first pointer, or zero.
find_bytes:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rdx
    mov r14, rsi
    mov r15, rcx
    cmp r13, r15
    jb .none
.loop:
    mov rdi, r12
    mov rsi, r14
    mov rcx, r15
    call memory_equal
    test al, al
    jnz .found
    inc r12
    dec r13
    cmp r13, r15
    jae .loop
.none:
    xor eax, eax
    jmp .out
.found:
    mov rax, r12
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; rdi and rsi point to buffers, rcx is their common length. AL = equality.
memory_equal:
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

; rdi = fd, rsi = bytes, rdx = length. Handles partial writes.
write_all:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
.loop:
    test r14, r14
    jz .done
    mov eax, SYS_WRITE
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    syscall
    test rax, rax
    jle .done
    add r13, rax
    sub r14, rax
    jmp .loop
.done:
    pop r14
    pop r13
    pop r12
    ret

; rdi = destination, esi = requested bytes. EAX = bytes read or a negative errno.
; This wrapper retries EINTR and refuses a zero-byte result.
secure_random:
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13d, esi
    mov r14d, esi
    xor edx, edx
.loop:
    test r13d, r13d
    jz .done
    mov eax, SYS_GETRANDOM
    mov rdi, r12
    mov esi, r13d
    xor edx, edx
    syscall
    cmp rax, -4                         ; EINTR
    je .loop
    test rax, rax
    jle .out
    add r12, rax
    sub r13d, eax
    jmp .loop
.done:
    mov eax, r14d
.out:
    pop r14
    pop r13
    pop r12
    ret

fatal_entropy:
    lea rsi, [error_entropy]
    mov edx, error_entropy_len
    jmp fatal
fatal_socket:
    lea rsi, [error_socket]
    mov edx, error_socket_len
    jmp fatal
fatal_bind:
    lea rsi, [error_bind]
    mov edx, error_bind_len
    jmp fatal
fatal_listen:
    lea rsi, [error_listen]
    mov edx, error_listen_len
    jmp fatal
fatal_config:
    lea rsi, [error_config]
    mov edx, error_config_len
    jmp fatal
fatal_gateway:
    lea rsi, [error_gateway]
    mov edx, error_gateway_len
fatal:
    mov edi, 2
    call write_all
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

; ---------------------------------------------------------------------------
; WebSocket bridge. The upgrade implementation is RFC 6455-compatible for one
; Fabric client. It validates the bridge header before it reaches this point.
; ---------------------------------------------------------------------------
bridge_authorized:
    cmp dword [bridge_token_len], 0
    je .no
    lea rdi, [request_buffer]
    lea rsi, [bridge_authorization_prefix]
    mov ecx, bridge_authorization_prefix_len
    mov rdx, [request_length]
    call find_bytes
    test rax, rax
    jz .no
    add rax, bridge_authorization_prefix_len
    mov rdi, rax
    mov rsi, [bridge_token_ptr]
    mov ecx, dword [bridge_token_len]
    call memory_equal
    test al, al
    jz .no
    mov rax, [request_length]
    lea rdx, [request_buffer]
    add rdx, rax
    cmp rdi, rdx
    jae .no
    cmp word [rdi], 0x0a0d
    jne .no
    mov al, 1
    ret
.no:
    xor eax, eax
    ret

upgrade_websocket:
    push r12
    push r13
    push r14
    call bridge_lock_acquire
    test al, al
    jz .conflict
    lea rdi, [request_buffer]
    lea rsi, [websocket_key_prefix]
    mov ecx, websocket_key_prefix_len
    mov rdx, [request_length]
    call find_bytes
    test rax, rax
    jz .missing_key
    add rax, websocket_key_prefix_len
    mov r12, rax
    mov rdi, r12
    call line_length
    cmp eax, 24                         ; RFC 6455 client key: Base64(16 bytes)
    jne .bad_key_length

    ; SHA1(Sec-WebSocket-Key || RFC 6455 magic GUID), then Base64.
    lea rdi, [sha_input]
    mov rsi, r12
    mov edx, 24
    call memory_copy
    lea rdi, [sha_input + 24]
    lea rsi, [websocket_magic]
    mov edx, websocket_magic_len
    call memory_copy
    lea rdi, [sha_input]
    mov esi, 24 + websocket_magic_len
    call sha1_single_block

    lea rdi, [ws_response]
    lea rsi, [websocket_handshake_prefix]
    mov edx, websocket_handshake_prefix_len
    call memory_copy
    lea r13, [ws_response + websocket_handshake_prefix_len]
    lea rdi, [sha_digest]
    mov rsi, r13
    call base64_sha1
    lea rdi, [r13 + 28]
    lea rsi, [websocket_handshake_suffix]
    mov edx, websocket_handshake_suffix_len
    call memory_copy

    mov edi, dword [client_fd]
    lea rsi, [ws_response]
    mov edx, websocket_handshake_prefix_len + 28 + websocket_handshake_suffix_len
    call write_all
    call websocket_loop
    jmp .out
.conflict:
    lea rdi, [log_bridge_conflict]
    mov esi, log_bridge_conflict_len
    call log_static
    mov edi, dword [client_fd]
    lea rsi, [response_conflict]
    mov edx, response_conflict_len
    call write_all
    jmp .out
.missing_key:
    lea rdi, [log_ws_key_missing]
    mov esi, log_ws_key_missing_len
    call log_static
    jmp .bad_request
.bad_key_length:
    lea rdi, [log_ws_key_length]
    mov esi, log_ws_key_length_len
    call log_static
.bad_request:
    lea rdi, [log_ws_bad_handshake]
    mov esi, log_ws_bad_handshake_len
    call log_static
    call bridge_lock_release
    mov dword [bridge_active], 0
    mov edi, dword [client_fd]
    lea rsi, [response_bad_websocket]
    mov edx, response_bad_websocket_len
    call write_all
.out:
    call bridge_lock_release
    pop r14
    pop r13
    pop r12
    ret

; Acquire a cross-process bridge lock. Healthy active connections reject 409.
bridge_lock_acquire:
    mov eax, SYS_OPEN
    lea rdi, [bridge_lock_path]
    mov esi, 66
    mov edx, 0o600
    syscall
    test rax, rax
    js .reject_lock
    mov [bridge_lock_fd], eax
    mov eax, SYS_FLOCK
    mov edi, [bridge_lock_fd]
    mov esi, LOCK_EX | LOCK_NB
    syscall
    test rax, rax
    js .close_reject_lock
    mov dword [bridge_active], 1
    mov eax, 1
    ret
.close_reject_lock:
    mov eax, SYS_CLOSE
    mov edi, [bridge_lock_fd]
    syscall
    mov dword [bridge_lock_fd], -1
.reject_lock:
    xor eax, eax
    ret

bridge_lock_release:
    cmp dword [bridge_lock_fd], 0
    jl .done_lock
    mov eax, SYS_FLOCK
    mov edi, [bridge_lock_fd]
    mov esi, LOCK_UN
    syscall
    mov eax, SYS_CLOSE
    mov edi, [bridge_lock_fd]
    syscall
    mov dword [bridge_lock_fd], -1
    mov dword [bridge_active], 0
.done_lock:
    ret

; Returns EAX: byte length up to CRLF, or zero when malformed/too long.
line_length:
    xor eax, eax
.loop:
    cmp eax, 128
    jae .bad
    cmp word [rdi + rax], 0x0a0d
    je .done
    cmp byte [rdi + rax], 0
    je .bad
    inc eax
    jmp .loop
.done:
    ret
.bad:
    xor eax, eax
    ret

; Claim bridge slot. Healthy active connections reject a new upgrade with 409;
; a connection idle for the configured stale period may be replaced.
prepare_bridge_connection:
    cmp dword [bridge_active], 0
    je .claim
    mov eax, [ws_idle_seconds]
    cmp eax, 75
    jb .reject
.claim:
    mov dword [bridge_active], 1
    xor eax, eax
    inc eax
    ret
.reject:
    xor eax, eax
    ret

; rdi = destination, rsi = source, rdx = byte count.
memory_copy:
    test rdx, rdx
    jz .done
.loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rdx
    jnz .loop
.done:
    ret

; SHA-1 for an input shorter than 56 bytes. rdi=input, esi=input length.
; The WebSocket key material is exactly 60 bytes, so it uses the two-block
; padding path below; no cryptographic library is linked.
sha1_single_block:
    push r12
    push r13
    push r14
    push r15
    ; First 64-byte block for the 60-byte WebSocket handshake string.
    mov r12, rdi
    mov r13d, esi
    mov dword [sha_h0], 0x67452301
    mov dword [sha_h1], 0xefcdab89
    mov dword [sha_h2], 0x98badcfe
    mov dword [sha_h3], 0x10325476
    mov dword [sha_h4], 0xc3d2e1f0

    ; The fixed 60-byte input needs two SHA-1 blocks. Its mandatory 0x80
    ; padding byte occupies byte 60 in block 1; bytes 61..63 are zero.
    lea rdi, [sha_block]
    mov rsi, r12
    mov edx, 60
    call memory_copy
    mov byte [sha_block + 60], 0x80
    mov dword [sha_block + 61], 0
    lea rdi, [sha_block]
    call sha1_compress

    ; Block 2 is all zeroes except the 64-bit big-endian bit length 480.
    lea rdi, [sha_block]
    mov ecx, 64
    xor eax, eax
.zero2:
    mov [rdi], al
    inc rdi
    dec ecx
    jnz .zero2
    mov dword [sha_block + 56], 0x00000000
    mov dword [sha_block + 60], 0xe0010000 ; bytes 00 00 01 e0
    lea rdi, [sha_block]
    call sha1_compress

    mov eax, [sha_h0]
    bswap eax
    mov [sha_digest], eax
    mov eax, [sha_h1]
    bswap eax
    mov [sha_digest + 4], eax
    mov eax, [sha_h2]
    bswap eax
    mov [sha_digest + 8], eax
    mov eax, [sha_h3]
    bswap eax
    mov [sha_digest + 12], eax
    mov eax, [sha_h4]
    bswap eax
    mov [sha_digest + 16], eax
    pop r15
    pop r14
    pop r13
    pop r12
    ret

; rdi points at 64 bytes. Updates SHA-1 state in memory.
sha1_compress:
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
    mov [sha_words + rcx * 4], eax
    inc ecx
    cmp ecx, 16
    jb .load_words
.expand_words:
    mov eax, [sha_words + rcx * 4 - 12]
    xor eax, [sha_words + rcx * 4 - 32]
    xor eax, [sha_words + rcx * 4 - 56]
    xor eax, [sha_words + rcx * 4 - 64]
    rol eax, 1
    mov [sha_words + rcx * 4], eax
    inc ecx
    cmp ecx, 80
    jb .expand_words

    mov r8d, [sha_h0]
    mov r9d, [sha_h1]
    mov r10d, [sha_h2]
    mov r11d, [sha_h3]
    mov ebp, [sha_h4]
    xor ecx, ecx
.round:
    cmp ecx, 20
    jb .round0
    cmp ecx, 40
    jb .round1
    cmp ecx, 60
    jb .round2
    mov eax, r9d
    xor eax, r10d
    xor eax, r11d
    mov edx, 0xca62c1d6
    jmp .compute
.round0:
    mov eax, r9d
    and eax, r10d
    mov esi, r9d
    not esi
    and esi, r11d
    or eax, esi
    mov edx, 0x5a827999
    jmp .compute
.round1:
    mov eax, r9d
    xor eax, r10d
    xor eax, r11d
    mov edx, 0x6ed9eba1
    jmp .compute
.round2:
    mov eax, r9d
    and eax, r10d
    mov esi, r9d
    and esi, r11d
    or eax, esi
    mov esi, r10d
    and esi, r11d
    or eax, esi
    mov edx, 0x8f1bbcdc
.compute:
    mov esi, r8d
    rol esi, 5
    add esi, eax
    add esi, ebp
    add esi, edx
    add esi, [sha_words + rcx * 4]
    mov ebp, r11d
    mov r11d, r10d
    mov eax, r9d
    rol eax, 30
    mov r10d, eax
    mov r9d, r8d
    mov r8d, esi
    inc ecx
    cmp ecx, 80
    jb .round
    add [sha_h0], r8d
    add [sha_h1], r9d
    add [sha_h2], r10d
    add [sha_h3], r11d
    add [sha_h4], ebp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; rdi = 20-byte SHA-1 digest, rsi = 28-byte output. Encodes exactly SHA-1.
base64_sha1:
    push rbx
    mov ecx, 6
.full_group:
    movzx eax, byte [rdi]
    shl eax, 16
    movzx edx, byte [rdi + 1]
    shl edx, 8
    or eax, edx
    movzx edx, byte [rdi + 2]
    or eax, edx
    mov edx, eax
    shr edx, 18
    mov bl, [base64_table + rdx]
    mov [rsi], bl
    mov edx, eax
    shr edx, 12
    and edx, 63
    mov bl, [base64_table + rdx]
    mov [rsi + 1], bl
    mov edx, eax
    shr edx, 6
    and edx, 63
    mov bl, [base64_table + rdx]
    mov [rsi + 2], bl
    and eax, 63
    mov bl, [base64_table + rax]
    mov [rsi + 3], bl
    add rdi, 3
    add rsi, 4
    dec ecx
    jnz .full_group
    ; Final two digest bytes -> three Base64 characters plus padding.
    movzx eax, byte [rdi]
    shl eax, 16
    movzx edx, byte [rdi + 1]
    shl edx, 8
    or eax, edx
    mov edx, eax
    shr edx, 18
    mov bl, [base64_table + rdx]
    mov [rsi], bl
    mov edx, eax
    shr edx, 12
    and edx, 63
    mov bl, [base64_table + rdx]
    mov [rsi + 1], bl
    mov edx, eax
    shr edx, 6
    and edx, 63
    mov bl, [base64_table + rdx]
    mov [rsi + 2], bl
    mov byte [rsi + 3], '='
    pop rbx
    ret

; Poll every five seconds. Ping on every 20 seconds of inactivity and close
; after 75 seconds without a received frame, matching the source bridge policy.
websocket_loop:
    mov dword [bridge_active], 1
    mov dword [ws_idle_seconds], 0
    mov dword [ws_next_ping], 20
.loop:
    call drain_gateway_messages
    mov eax, dword [client_fd]
    mov [poll_descriptor], eax
    mov word [poll_descriptor + 4], 1
    mov word [poll_descriptor + 6], 0
    mov eax, 7                             ; poll(2)
    lea rdi, [poll_descriptor]
    mov esi, 1
    mov edx, 1000
    syscall
    test rax, rax
    js .poll_failed
    jz .timeout
    call websocket_receive_frame
    test eax, eax
    js .frame_failed
    mov dword [ws_idle_seconds], 0
    mov dword [ws_next_ping], 20
    jmp .loop
.timeout:
    add dword [ws_idle_seconds], 1
    mov eax, [ws_idle_seconds]
    cmp eax, 75
    jae .idle_timeout
    cmp eax, [ws_next_ping]
    jb .loop
    add dword [ws_next_ping], 20
    lea rdi, [empty_payload]
    xor esi, esi
    mov edx, 9                             ; Ping
    call websocket_send_frame
    test eax, eax
    js .send_failed
    jmp .loop
.poll_failed:
    lea rdi, [log_ws_poll_failed]
    mov esi, log_ws_poll_failed_len
    call log_static
    jmp .done
.frame_failed:
    lea rdi, [log_ws_protocol_error]
    mov esi, log_ws_protocol_error_len
    call log_static
    jmp .done
.send_failed:
    lea rdi, [log_ws_send_failed]
    mov esi, log_ws_send_failed_len
    call log_static
    jmp .done
.idle_timeout:
    lea rdi, [log_ws_idle_timeout]
    mov esi, log_ws_idle_timeout_len
    call log_static
.done:
    mov dword [bridge_active], 0
    ret

; EAX=0 on success; negative on close/protocol/read error.
websocket_receive_frame:
    lea rdi, [ws_frame_header]
    mov esi, 2
    call read_exact
    test rax, rax
    js .bad
    movzx ebx, byte [ws_frame_header]
    movzx eax, byte [ws_frame_header + 1]
    test al, 0x80
    jz .bad                               ; Fabric clients must mask frames.
    and eax, 0x7f
    cmp eax, 125
    jbe .length_ready
    cmp eax, 126
    jne .bad
    lea rdi, [ws_extended_length]
    mov esi, 2
    call read_exact
    test rax, rax
    js .bad
    movzx eax, byte [ws_extended_length]
    shl eax, 8
    movzx edx, byte [ws_extended_length + 1]
    or eax, edx
    cmp eax, 4096
    ja .bad
.length_ready:
    mov [ws_payload_length], eax
    lea rdi, [ws_mask]
    mov esi, 4
    call read_exact
    test rax, rax
    js .bad
    lea rdi, [ws_payload]
    mov esi, [ws_payload_length]
    call read_exact
    test rax, rax
    js .bad
    xor ecx, ecx
.unmask:
    cmp ecx, [ws_payload_length]
    jae .dispatch
    mov eax, ecx
    and eax, 3
    mov dl, [ws_payload + rcx]
    xor dl, [ws_mask + rax]
    mov [ws_payload + rcx], dl
    inc ecx
    jmp .unmask
.dispatch:
    and ebx, 0x0f
    cmp ebx, 8
    je .bad
    cmp ebx, 9
    jne .text
    lea rdi, [ws_payload]
    mov esi, [ws_payload_length]
    mov edx, 10
    call websocket_send_frame
    xor eax, eax
    ret
.text:
    cmp ebx, 1
    jne .ok
    call forward_fabric_chat_to_discord
    inc qword [bridge_events_received]
.ok:
    xor eax, eax
    ret
.bad:
    lea rdi, [log_ws_protocol_error]
    mov esi, log_ws_protocol_error_len
    call log_static
    mov eax, -1
    ret

; Parse and format the Fabric event contract in NASM. The C adapter never
; decides event types or message content.
forward_fabric_chat_to_discord:
    push r12
    push r13
    mov r12, ws_payload
    mov r13, [ws_payload_length]
    mov rdi, r12
    mov rsi, r13
    call build_fabric_event
.out:
    pop r13
    pop r12
    ret

build_fabric_event:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi

    mov rdi, r12
    mov rsi, r13
    mov rdx, event_type_key
    mov ecx, event_type_key_len
    lea r8, [event_type]
    mov r9d, 32
    call extract_json_string
    cmp eax, -1
    je .out
    mov [event_type_len], eax
    mov rdi, r12
    mov rsi, r13
    mov rdx, emoji_key
    mov ecx, emoji_key_len
    lea r8, [event_emoji]
    mov r9d, 256
    call extract_json_string
    cmp eax, -1
    jne .emoji_ready
    xor eax, eax
.emoji_ready:
    mov [event_emoji_len], eax

    ; Chat is plain text, matching the Rust formatter.
    lea rdi, [event_type]
    lea rsi, [event_chat]
    mov ecx, event_chat_len
    call memory_equal
    test al, al
    jz .not_chat
    call build_chat_payload
    jmp .send
.not_chat:
    lea rdi, [event_type]
    lea rsi, [event_join]
    mov ecx, event_join_len
    call memory_equal
    test al, al
    jnz .join
    lea rdi, [event_type]
    lea rsi, [event_leave]
    mov ecx, event_leave_len
    call memory_equal
    test al, al
    jnz .leave
    lea rdi, [event_type]
    lea rsi, [event_death]
    mov ecx, event_death_len
    call memory_equal
    test al, al
    jnz .death
    lea rdi, [event_type]
    lea rsi, [event_advancement]
    mov ecx, event_advancement_len
    call memory_equal
    test al, al
    jnz .advancement
    lea rdi, [event_type]
    lea rsi, [event_bridge_status]
    mov ecx, event_bridge_status_len
    call memory_equal
    test al, al
    jnz .bridge_status
    lea rdi, [event_type]
    lea rsi, [event_server_start]
    mov ecx, event_server_start_len
    call memory_equal
    test al, al
    jnz .server_start
    lea rdi, [event_type]
    lea rsi, [event_server_stop]
    mov ecx, event_server_stop_len
    call memory_equal
    test al, al
    jz .out
    lea rsi, [title_server_status]
    mov edx, title_server_status_len
    lea rcx, [description_server_stop]
    mov r8d, description_server_stop_len
    call build_embed_payload
    jmp .send
.join:
    call extract_player
    call build_bold_player_field
    lea rsi, [title_player_joined]
    mov edx, title_player_joined_len
    lea rcx, [event_field]
    mov r8d, [event_field_len]
    call build_embed_with_field
    jmp .send
.leave:
    call extract_player
    call build_bold_player_field
    lea rsi, [title_player_left]
    mov edx, title_player_left_len
    lea rcx, [event_field]
    mov r8d, [event_field_len]
    call build_embed_with_field
    jmp .send
.death:
    call extract_message
    lea rsi, [title_death]
    mov edx, title_death_len
    cmp dword [event_message_len], 0
    jne .death_message_ready
    lea rdi, [event_message]
    lea rsi, [default_death]
    mov edx, default_death_len
    call gateway_copy
    mov dword [event_message_len], default_death_len
.death_message_ready:
    lea rcx, [event_message]
    mov r8d, [event_message_len]
    call build_embed_with_field
    jmp .send
.advancement:
    call extract_message
    lea rsi, [title_advancement]
    mov edx, title_advancement_len
    cmp dword [event_message_len], 0
    jne .advancement_message_ready
    lea rdi, [event_message]
    lea rsi, [default_advancement]
    mov edx, default_advancement_len
    call gateway_copy
    mov dword [event_message_len], default_advancement_len
.advancement_message_ready:
    lea rcx, [event_message]
    mov r8d, [event_message_len]
    call build_embed_with_field
    jmp .send
.bridge_status:
    lea rsi, [title_bridge_status]
    mov edx, title_bridge_status_len
    call extract_status
    lea rdi, [event_field]
    lea rsi, [status_connect]
    mov ecx, status_connect_len
    call memory_equal
    test al, al
    jnz .status_connect
    lea rdi, [event_field]
    lea rsi, [status_disconnect]
    mov ecx, status_disconnect_len
    call memory_equal
    test al, al
    jnz .status_disconnect
    lea rsi, [title_bridge_status]
    mov edx, title_bridge_status_len
    lea rcx, [description_bridge_status]
    mov r8d, description_bridge_status_len
    call build_embed_payload
    jmp .send
.status_connect:
    lea rsi, [title_bridge_status]
    mov edx, title_bridge_status_len
    lea rcx, [description_bridge_connect]
    mov r8d, description_bridge_connect_len
    call build_embed_payload
    jmp .send
.status_disconnect:
    lea rsi, [title_bridge_status]
    mov edx, title_bridge_status_len
    lea rcx, [description_bridge_disconnect]
    mov r8d, description_bridge_disconnect_len
    call build_embed_payload
    jmp .send
.server_start:
    lea rsi, [title_server_status]
    mov edx, title_server_status_len
    lea rcx, [description_server_start]
    mov r8d, description_server_start_len
    call build_embed_payload
.send:
    lea rdi, [discord_json]
    mov rsi, [fabric_json_length]
    call send_discord_json_buffer
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

extract_json_string:
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov r10, r8
    mov r11d, r9d
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    call gateway_find_key
    test rax, rax
    jz .bad
    add rax, r15
    mov rdi, rax
    mov rsi, r13
    sub rsi, rax
    add rsi, r12
    mov rdx, r10
    mov rcx, r11
    call gateway_decode_string
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret

build_chat_payload:
    lea rdi, [event_player]
    mov rdx, 512
    call extract_player
    lea rdi, [event_message]
    mov rdx, 2048
    call extract_message
    lea rdi, [discord_json]
    lea rsi, [chat_prefix]
    mov edx, chat_prefix_len
    call gateway_copy
    mov r14d, chat_prefix_len
    lea rdi, [discord_json + r14]
    lea rsi, [event_player]
    mov edx, [event_player_len]
    mov ecx, 4096 - chat_prefix_len
    call gateway_escape_copy
    add r14d, eax
    lea rdi, [discord_json + r14]
    lea rsi, [chat_middle]
    mov edx, chat_middle_len
    call gateway_copy
    add r14d, chat_middle_len
    lea rdi, [discord_json + r14]
    lea rsi, [event_message]
    mov edx, [event_message_len]
    mov ecx, 4096 - chat_prefix_len - chat_middle_len
    call gateway_escape_copy
    add r14d, eax
    lea rdi, [discord_json + r14]
    lea rsi, [json_close]
    mov edx, json_close_len
    call gateway_copy
    add r14d, json_close_len
    mov [fabric_json_length], r14
    ret

build_bold_player_field:
    lea rdi, [event_field]
    lea rsi, [bold_prefix]
    mov edx, bold_prefix_len
    call gateway_copy
    mov r10d, bold_prefix_len
    lea rdi, [event_field + r10]
    lea rsi, [event_player]
    mov edx, [event_player_len]
    call gateway_copy
    add r10d, [event_player_len]
    lea rdi, [event_field + r10]
    lea rsi, [bold_suffix]
    mov edx, bold_suffix_len
    call gateway_copy
    add r10d, bold_suffix_len
    mov [event_field_len], r10d
    ret

build_embed_with_field:
    push r12
    push r13
    push r14
    push r15
    mov r12, rsi
    mov r13d, edx
    mov r14, rcx
    mov r15d, r8d
    lea rdi, [event_field]
    mov rsi, r14
    mov edx, r15d
    call gateway_copy
    mov [event_field_len], r15d
    lea rdi, [discord_json]
    lea rsi, [embed_prefix]
    mov edx, embed_prefix_len
    call gateway_copy
    mov r14d, embed_prefix_len
    cmp dword [event_emoji_len], 0
    je .no_emoji_field
    lea rdi, [discord_json + r14]
    lea rsi, [event_emoji]
    mov edx, [event_emoji_len]
    mov ecx, 4096 - embed_prefix_len
    call gateway_escape_copy
    add r14d, eax
    mov byte [discord_json + r14], ' '
    inc r14d
.no_emoji_field:
    lea rdi, [discord_json + r14]
    mov rsi, r12
    mov edx, r13d
    call gateway_copy
    add r14d, r13d
    lea rdi, [discord_json + r14]
    lea rsi, [embed_description_prefix]
    mov edx, embed_description_prefix_len
    call gateway_copy
    add r14d, embed_description_prefix_len
    lea rdi, [discord_json + r14]
    lea rsi, [event_field]
    mov edx, [event_field_len]
    mov ecx, 4096 - 256
    call gateway_escape_copy
    add r14d, eax
    lea rdi, [discord_json + r14]
    lea rsi, [json_embed_close]
    mov edx, json_embed_close_len
    call gateway_copy
    add r14d, json_embed_close_len
    mov [fabric_json_length], r14
    pop r15
    pop r14
    pop r13
    pop r12
    ret

build_embed_payload:
    push r12
    push r13
    mov r12, rsi
    mov r13d, edx
    mov r10, rcx
    mov r11d, r8d
    lea rdi, [discord_json]
    lea rsi, [embed_prefix]
    mov edx, embed_prefix_len
    call gateway_copy
    mov r14d, embed_prefix_len
    cmp dword [event_emoji_len], 0
    je .no_emoji_payload
    lea rdi, [discord_json + r14]
    lea rsi, [event_emoji]
    mov edx, [event_emoji_len]
    mov ecx, 4096 - embed_prefix_len
    call gateway_escape_copy
    add r14d, eax
    mov byte [discord_json + r14], ' '
    inc r14d
.no_emoji_payload:
    lea rdi, [discord_json + r14]
    mov rsi, r12
    mov edx, r13d
    call gateway_copy
    add r14d, r13d
    lea rdi, [discord_json + r14]
    lea rsi, [embed_description_prefix]
    mov edx, embed_description_prefix_len
    call gateway_copy
    add r14d, embed_description_prefix_len
    lea rdi, [discord_json + r14]
    mov rsi, r10
    mov edx, r11d
    mov ecx, 4096 - 256
    call gateway_escape_copy
    add r14d, eax
    lea rdi, [discord_json + r14]
    lea rsi, [json_embed_close]
    mov edx, json_embed_close_len
    call gateway_copy
    add r14d, json_embed_close_len
    mov [fabric_json_length], r14
    pop r13
    pop r12
    ret

extract_player:
    push rdi
    mov rdi, r12
    mov rsi, r13
    mov rdx, player_key
    mov ecx, player_key_len
    lea r8, [event_player]
    mov r9d, 512
    call extract_json_string
    cmp eax, -1
    jne .player_done
    lea rdi, [event_player]
    lea rsi, [default_unknown]
    mov edx, default_unknown_len
    call gateway_copy
    mov eax, default_unknown_len
.player_done:
    mov [event_player_len], eax
    pop rdi
    ret
extract_status:
    push rdi
    mov rdi, r12
    mov rsi, r13
    mov rdx, status_key
    mov ecx, status_key_len
    lea r8, [event_field]
    mov r9d, 2048
    call extract_json_string
    cmp eax, -1
    jne .status_done
    xor eax, eax
.status_done:
    mov [event_field_len], eax
    pop rdi
    ret
extract_message:
    push rdi
    mov rdi, r12
    mov rsi, r13
    mov rdx, message_key
    mov ecx, message_key_len
    lea r8, [event_message]
    mov r9d, 2048
    call extract_json_string
    cmp eax, -1
    jne .message_done
    xor eax, eax
.message_done:
    mov [event_message_len], eax
    pop rdi
    ret
extract_event_field:
    ; RCX points to destination and RDX is its capacity.
    mov rdi, r12
    mov rsi, r13
    mov rdx, message_key
    mov ecx, message_key_len
    lea r8, [event_field]
    mov r9d, 2048
    call extract_json_string
    mov [event_field_len], eax
    ret

; rdi=buffer, esi=count; reads all bytes from the active bridge socket.
read_exact:
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
.loop:
    test r13d, r13d
    jz .ok
    mov eax, SYS_READ
    mov edi, dword [client_fd]
    mov rsi, r12
    mov edx, r13d
    syscall
    test rax, rax
    jle .bad
    add r12, rax
    sub r13d, eax
    jmp .loop
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r13
    pop r12
    ret

; rdi=payload, esi=payload length <=125, edx=opcode. Server frames are unmasked.
websocket_send_frame:
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
    cmp r13d, 125
    ja .out
    mov eax, edx
    or al, 0x80
    mov [ws_out_header], al
    mov [ws_out_header + 1], r13b
    mov edi, dword [client_fd]
    lea rsi, [ws_out_header]
    mov edx, 2
    call write_all
    test r13d, r13d
    jz .out
    mov edi, dword [client_fd]
    mov rsi, r12
    mov edx, r13d
    call write_all
.out:
    pop r13
    pop r12
    ret

section .rodata
bridge_authorization_prefix: db 'X-Auth-Token: '
bridge_authorization_prefix_len equ $ - bridge_authorization_prefix
upgrade_header:        db 'Upgrade: websocket'
upgrade_header_len     equ $ - upgrade_header
websocket_key_prefix:  db 'Sec-WebSocket-Key: '
websocket_key_prefix_len equ $ - websocket_key_prefix
websocket_magic:       db '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
websocket_magic_len    equ $ - websocket_magic
websocket_handshake_prefix:
    db 'HTTP/1.1 101 Switching Protocols',13,10
    db 'Upgrade: websocket',13,10
    db 'Connection: Upgrade',13,10
    db 'Sec-WebSocket-Accept: '
websocket_handshake_prefix_len equ $ - websocket_handshake_prefix
websocket_handshake_suffix: db 13,10,13,10
websocket_handshake_suffix_len equ $ - websocket_handshake_suffix
base64_table:          db 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
empty_payload:         db 0

response_bad_websocket:
    db 'HTTP/1.1 400 Bad Request',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"invalid websocket handshake"}',10
response_bad_websocket_len equ $ - response_bad_websocket
response_conflict:
    db 'HTTP/1.1 409 Conflict',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"bridge connection already active"}',10
response_conflict_len equ $ - response_conflict

bridge_lock_path:       db '/tmp/val0x04-bridge.lock',0
env_port:              db 'PORT='
env_port_len           equ $ - env_port
env_bridge:            db 'BRIDGE_WEBSOCKET_AUTH_TOKEN='
env_bridge_len         equ $ - env_bridge
env_panel:             db 'PANEL_ACCESS_TOKEN='
env_panel_len          equ $ - env_panel
env_discord:           db 'DISCORD_TOKEN='
env_discord_len        equ $ - env_discord
env_discord_channel:   db 'DISCORD_CHANNEL_ID='
env_discord_channel_len equ $ - env_discord_channel

method_health:         db 'GET /health '
method_health_len      equ $ - method_health
method_panel:          db 'GET /panel '
method_panel_len       equ $ - method_panel
method_chat:           db 'POST /api/chat '
method_chat_len        equ $ - method_chat
method_root:           db 'GET / '
method_root_len        equ $ - method_root
fabric_message_prefix: db '"message":"'
fabric_message_prefix_len equ $ - fabric_message_prefix
event_type_key:        db '"type":"'
event_type_key_len equ $ - event_type_key
emoji_key:              db '"emoji":"'
emoji_key_len equ $ - emoji_key
player_key:            db '"player":"'
player_key_len equ $ - player_key
message_key:           db '"message":"'
message_key_len equ $ - message_key
panel_message_key:      db '"message":"'
panel_message_key_len equ $ - panel_message_key
panel_message_name:     db '"message"'
panel_message_name_len equ $ - panel_message_name
chat_prefix:           db '{"content":"**'
chat_prefix_len equ $ - chat_prefix
chat_middle:           db '**: '
chat_middle_len equ $ - chat_middle
bold_prefix:            db '**'
bold_prefix_len equ $ - bold_prefix
bold_suffix:            db '**'
bold_suffix_len equ $ - bold_suffix
json_close:            db '"}'
json_close_len equ $ - json_close
embed_prefix:          db '{"embeds":[{"title":"'
embed_prefix_len equ $ - embed_prefix
embed_description_prefix: db '","description":"'
embed_description_prefix_len equ $ - embed_description_prefix
json_embed_close:      db '"}]}'
json_embed_close_len equ $ - json_embed_close
event_chat:            db 'chat'
event_chat_len equ $ - event_chat
event_join:            db 'join'
event_join_len equ $ - event_join
event_leave:           db 'leave'
event_leave_len equ $ - event_leave
event_death:           db 'death'
event_death_len equ $ - event_death
event_advancement:     db 'advancement'
event_advancement_len equ $ - event_advancement
event_bridge_status:   db 'bridge_status'
event_bridge_status_len equ $ - event_bridge_status
event_server_start:    db 'server_start'
event_server_start_len equ $ - event_server_start
event_server_stop:     db 'server_stop'
event_server_stop_len equ $ - event_server_stop
title_player_joined:   db 'Player Joined'
title_player_joined_len equ $ - title_player_joined
title_player_left:     db 'Player Left'
title_player_left_len equ $ - title_player_left
title_death:           db 'Death'
title_death_len equ $ - title_death
title_advancement:     db 'Advancement'
title_advancement_len equ $ - title_advancement
title_bridge_status:   db 'Bridge Status'
title_bridge_status_len equ $ - title_bridge_status
title_server_status:   db 'Server Status'
title_server_status_len equ $ - title_server_status
description_server_start: db 'Server telah menyala.'
description_server_start_len equ $ - description_server_start
description_server_stop: db 'Server sedang dimatikan.'
description_server_stop_len equ $ - description_server_stop
description_bridge_status: db 'Status bridge berubah.'
description_bridge_status_len equ $ - description_bridge_status
description_bridge_connect: db 'Bridge tersambung ke server Minecraft.'
description_bridge_connect_len equ $ - description_bridge_connect
description_bridge_disconnect: db 'Bridge terputus dari server Minecraft.'
description_bridge_disconnect_len equ $ - description_bridge_disconnect
status_key: db '"status":"'
status_key_len equ $ - status_key
status_connect: db 'connect'
status_connect_len equ $ - status_connect
status_disconnect: db 'disconnect'
status_disconnect_len equ $ - status_disconnect
default_unknown:         db 'Unknown'
default_unknown_len equ $ - default_unknown
default_death:           db 'Seorang pemain telah meninggal.'
default_death_len equ $ - default_death
default_advancement:     db 'Sebuah advancement telah dicapai.'
default_advancement_len equ $ - default_advancement
authorization_prefix:  db 'Authorization: Bearer '
authorization_prefix_len equ $ - authorization_prefix
header_terminator:      db 13,10,13,10
header_terminator_len   equ $ - header_terminator
discord_url_prefix:     db 'https://discord.com/api/v10/channels/'
discord_url_prefix_len  equ $ - discord_url_prefix
discord_url_suffix:     db '/messages'
discord_url_suffix_len  equ $ - discord_url_suffix
discord_authorization_prefix: db 'Authorization: Bot '
discord_authorization_prefix_len equ $ - discord_authorization_prefix
discord_json_prefix:    db '{"content":"'
discord_json_prefix_len equ $ - discord_json_prefix
discord_json_suffix:    db '"}'
discord_json_suffix_len equ $ - discord_json_suffix
transport_status_prefix: db 'val0x04-asm: transport Discord gagal, HTTP status='
transport_status_prefix_len equ $ - transport_status_prefix
transport_detail_prefix: db 'val0x04-asm: detail transport: '
transport_detail_prefix_len equ $ - transport_detail_prefix

response_health:
    db 'HTTP/1.1 200 OK',13,10
    db 'Content-Type: application/json; charset=utf-8',13,10
    db 'Cache-Control: no-store',13,10
    db 'Connection: close',13,10,13,10
    db '{"status":"ok","runtime":"assembly-dominant"}',10
response_health_len equ $ - response_health

response_panel:
    db 'HTTP/1.1 200 OK',13,10
    db 'Content-Type: text/html; charset=utf-8',13,10
    db 'Cache-Control: no-store',13,10
    db 'Connection: close',13,10,13,10
    db `<!doctype html><meta charset="utf-8"><title>Val0x04/ASM</title><style>body{max-width:44rem;margin:8vh auto;background:#10131a;color:#e9eef5;font:16px system-ui;padding:2rem}input,textarea,button{width:100%;box-sizing:border-box;margin:.5rem 0;padding:.7rem;background:#181d27;color:inherit;border:1px solid #40506d}textarea{height:9rem}button{cursor:pointer;background:#4c75ff;border:0}</style><h1>Val0x04/ASM</h1><p>Panel eksperimen syscall-only.</p><input id="t" type="password" placeholder="PANEL_ACCESS_TOKEN"><textarea id="m" maxlength="2000" placeholder="Pesan untuk Discord"></textarea><button onclick="go()">Kirim</button><pre id="o"></pre><script>async function go(){let message=m.value.trim();if(!message){o.textContent='Pesan tidak boleh kosong.';return}let r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+t.value},body:JSON.stringify({message})});o.textContent=await r.text()}</script>`
response_panel_len equ $ - response_panel

response_bad_request:
    db 'HTTP/1.1 400 Bad Request',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"invalid request"}',10
response_bad_request_len equ $ - response_bad_request

response_unauthorized:
    db 'HTTP/1.1 401 Unauthorized',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"unauthorized"}',10
response_unauthorized_len equ $ - response_unauthorized

response_discord_sent:
    db 'HTTP/1.1 200 OK',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"status":"sent"}',10
response_discord_sent_len equ $ - response_discord_sent

response_discord_failure:
    db 'HTTP/1.1 502 Bad Gateway',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"Discord transport rejected the request"}',10
response_discord_failure_len equ $ - response_discord_failure

response_upgrade_required:
    db 'HTTP/1.1 426 Upgrade Required',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"WebSocket bridge pending next milestone"}',10
response_upgrade_required_len equ $ - response_upgrade_required

response_not_found:
    db 'HTTP/1.1 404 Not Found',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"not found"}',10
response_not_found_len equ $ - response_not_found

error_entropy:         db 'val0x04-asm: getrandom() failed',10
error_entropy_len      equ $ - error_entropy
error_socket:          db 'val0x04-asm: socket() failed',10
error_socket_len       equ $ - error_socket
error_bind:            db 'val0x04-asm: bind() failed (check PORT)',10
error_bind_len         equ $ - error_bind
error_listen:          db 'val0x04-asm: listen() failed',10
error_listen_len equ $ - error_listen
error_gateway:         db 'val0x04-asm: Gateway worker setup failed',10
error_gateway_len equ $ - error_gateway
error_config:          db 'val0x04-asm: required environment is missing or invalid',10
error_config_len equ $ - error_config
log_accept_failed:       db 'val0x04-asm: accept() gagal',10
log_accept_failed_len equ $ - log_accept_failed
log_poll_failed:         db 'val0x04-asm: poll() listener gagal',10
log_poll_failed_len equ $ - log_poll_failed
log_client_fork_failed:  db 'val0x04-asm: fork() koneksi gagal',10
log_client_fork_failed_len equ $ - log_client_fork_failed
log_http_read_failed:    db 'val0x04-asm: request HTTP kosong atau gagal dibaca',10
log_http_read_failed_len equ $ - log_http_read_failed
log_route_not_found:     db 'val0x04-asm: route HTTP tidak dikenal',10
log_route_not_found_len equ $ - log_route_not_found
log_panel_unauthorized:  db 'val0x04-asm: autentikasi panel ditolak',10
log_panel_unauthorized_len equ $ - log_panel_unauthorized
log_bridge_unauthorized: db 'val0x04-asm: autentikasi bridge ditolak',10
log_bridge_unauthorized_len equ $ - log_bridge_unauthorized
log_setsockopt_failed:   db 'val0x04-asm: setsockopt() gagal',10
log_setsockopt_failed_len equ $ - log_setsockopt_failed
log_panel_bad_json:      db 'val0x04-asm: JSON panel tidak valid atau pesan ditolak',10
log_panel_bad_json_len equ $ - log_panel_bad_json
log_bridge_conflict:     db 'val0x04-asm: koneksi bridge kedua ditolak (409)',10
log_bridge_conflict_len equ $ - log_bridge_conflict
log_ws_bad_handshake:    db 'val0x04-asm: Fabric bridge menolak handshake WebSocket',10
log_ws_bad_handshake_len equ $ - log_ws_bad_handshake
log_ws_key_missing:       db 'val0x04-asm: header Sec-WebSocket-Key tidak ditemukan',10
log_ws_key_missing_len equ $ - log_ws_key_missing
log_ws_key_length:        db 'val0x04-asm: panjang Sec-WebSocket-Key tidak valid',10
log_ws_key_length_len equ $ - log_ws_key_length
log_ws_protocol_error:   db 'val0x04-asm: frame WebSocket tidak valid atau tidak termask',10
log_ws_protocol_error_len equ $ - log_ws_protocol_error
log_ws_poll_failed:      db 'val0x04-asm: poll() WebSocket gagal',10
log_ws_poll_failed_len equ $ - log_ws_poll_failed
log_pipe_read_failed:    db 'val0x04-asm: pembacaan pipe Gateway gagal',10
log_pipe_read_failed_len equ $ - log_pipe_read_failed
log_pipe_poll_failed:    db 'val0x04-asm: poll() pipe Gateway gagal',10
log_pipe_poll_failed_len equ $ - log_pipe_poll_failed
log_pipe_send_failed:    db 'val0x04-asm: forwarding pipe ke Fabric gagal',10
log_pipe_send_failed_len equ $ - log_pipe_send_failed
log_ws_send_failed:      db 'val0x04-asm: pengiriman frame WebSocket gagal',10
log_ws_send_failed_len equ $ - log_ws_send_failed
log_ws_idle_timeout:     db 'val0x04-asm: koneksi bridge timeout setelah 75 detik',10
log_ws_idle_timeout_len equ $ - log_ws_idle_timeout

section .data
align 8
server_fd:              dd -1
client_fd:              dd -1
request_length:         dq 0
bridge_token_ptr:       dq 0
bridge_token_len:       dd 0
panel_token_ptr:        dq 0
panel_token_len:        dd 0
discord_token_ptr:      dq 0
discord_token_len:      dd 0
discord_channel_ptr:    dq 0
discord_channel_len:    dd 0
discord_http_status:    dq 0
bridge_events_received: dq 0
gateway_pipe_read:      dd -1
gateway_pipe_write:     dd -1
gateway_pid:            dd -1
bridge_active:          dd 0
bridge_lock_fd:         dd -1
config_invalid:         dd 0
gateway_message_length:  dd 0
rest_sleep_seconds:      dq 0
event_type_len:         dd 0
event_emoji_len:        dd 0
event_player_len:       dd 0
event_message_len:      dd 0
event_field_len:        dd 0
event_field_capacity:   dd 0
fabric_json_length:     dq 0
ws_payload_length:      dd 0
ws_idle_seconds:        dd 0
ws_next_ping:           dd 20
poll_descriptor:        dq 0
listener_pollfds:       dq 0, 0
gateway_pipe_poll:       dq 0
gateway_pipe:            dd 0, 0
sha_h0:                 dd 0
sha_h1:                 dd 0
sha_h2:                 dd 0
sha_h3:                 dd 0
sha_h4:                 dd 0
one:                    dd 1
listen_address:
    dw AF_INET
listen_port_network:    dw 0x901f              ; default 8080, network order
    dd 0
    dq 0

section .bss
align 16
request_buffer:         resb REQUEST_CAPACITY
runtime_entropy:        resb 32
sha_input:              resb 60
sha_block:              resb 64
sha_words:              resd 80
sha_digest:             resb 20
ws_response:            resb 256
ws_frame_header:        resb 2
ws_extended_length:     resb 2
ws_mask:                resb 4
ws_payload:             resb 4096
ws_out_header:          resb 2
gateway_message_buffer:  resb 65536
rest_sleep_timespec:     resb 16
discord_url:            resb 256
discord_authorization:  resb 512
discord_log_buffer:     resb 1200
discord_json:           resb 4096
panel_message:          resb 4096
panel_message_length:    resq 1
event_type:             resb 32
event_emoji:            resb 256
event_player:           resb 512
event_message:          resb 2048
event_field:            resb 2048
