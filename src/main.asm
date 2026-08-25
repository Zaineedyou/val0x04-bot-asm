; Val0x04/ASM — syscall-only x86-64 Linux prototype.
; No libc, no Rust runtime, and no networking/JSON/WebSocket libraries are linked.
; Build: nasm -f elf64 src/main.asm -o build/main.o && ld -static -o build/val0x04-asm build/main.o

BITS 64
DEFAULT REL

%define SYS_READ            0
%define SYS_WRITE           1
%define SYS_CLOSE           3
%define SYS_SOCKET          41
%define SYS_ACCEPT          43
%define SYS_BIND            49
%define SYS_LISTEN          50
%define SYS_SETSOCKOPT      54
%define SYS_EXIT            60
%define SYS_GETRANDOM       318

%define AF_INET             2
%define SOCK_STREAM         1
%define SOL_SOCKET          1
%define SO_REUSEADDR        2
%define REQUEST_CAPACITY    16384

section .text
global _start

_start:
    ; Process entry stack: argc, argv[], NULL, envp[].
    ; Locate envp without libc and retain it in r15 for the parser.
    mov r15, rsp
    mov rax, [r15]
    lea r15, [r15 + rax * 8 + 16]
    call load_environment_from_envp
    lea rdi, [runtime_entropy]
    mov esi, 32
    call secure_random
    cmp eax, 32
    jne fatal_entropy
    call open_listener

.accept_loop:
    mov eax, SYS_ACCEPT
    mov edi, dword [server_fd]
    xor esi, esi
    xor edx, edx
    syscall
    test rax, rax
    js .accept_loop

    mov rdi, rax
    call handle_http_request

    mov eax, SYS_CLOSE
    mov edi, dword [client_fd]
    syscall
    jmp .accept_loop

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
    jz .advance
    lea rax, [rbx + env_discord_len]
    mov [discord_token_ptr], rax

.advance:
    add r15, 8
    jmp .env_next
.done:
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

; ---------------------------------------------------------------------------
; HTTP/1.1 subset. One complete request per accepted connection.
; Endpoints: GET /health, GET /panel, POST /api/chat. WebSocket root endpoint
; intentionally returns 426 until the WebSocket milestone is installed.
; ---------------------------------------------------------------------------
handle_http_request:
    mov [client_fd], edi
    mov eax, SYS_READ
    mov edi, dword [client_fd]
    lea rsi, [request_buffer]
    mov edx, REQUEST_CAPACITY - 1
    syscall
    test rax, rax
    jle .done
    mov [request_length], rax
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
    lea rsi, [response_discord_pending]
    mov edx, response_discord_pending_len
    jmp .send
.unauthorized:
    lea rsi, [response_unauthorized]
    mov edx, response_unauthorized_len
    jmp .send
.upgrade_required:
    call bridge_authorized
    test al, al
    jz .unauthorized
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
    lea rdi, [request_buffer]
    lea rsi, [websocket_key_prefix]
    mov ecx, websocket_key_prefix_len
    mov rdx, [request_length]
    call find_bytes
    test rax, rax
    jz .bad_request
    add rax, websocket_key_prefix_len
    mov r12, rax
    mov rdi, r12
    call line_length
    cmp eax, 24                         ; RFC 6455 client key: Base64(16 bytes)
    jne .bad_request

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
.bad_request:
    mov edi, dword [client_fd]
    lea rsi, [response_bad_websocket]
    mov edx, response_bad_websocket_len
    call write_all
.out:
    pop r14
    pop r13
    pop r12
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
    mov dword [ws_idle_seconds], 0
    mov dword [ws_next_ping], 20
.loop:
    mov eax, dword [client_fd]
    mov [poll_descriptor], eax
    mov word [poll_descriptor + 4], 1
    mov word [poll_descriptor + 6], 0
    mov eax, 7                             ; poll(2)
    lea rdi, [poll_descriptor]
    mov esi, 1
    mov edx, 5000
    syscall
    test rax, rax
    js .done
    jz .timeout
    call websocket_receive_frame
    test eax, eax
    js .done
    mov dword [ws_idle_seconds], 0
    mov dword [ws_next_ping], 20
    jmp .loop
.timeout:
    add dword [ws_idle_seconds], 5
    mov eax, [ws_idle_seconds]
    cmp eax, 75
    jae .done
    cmp eax, [ws_next_ping]
    jb .loop
    add dword [ws_next_ping], 20
    lea rdi, [empty_payload]
    xor esi, esi
    mov edx, 9                             ; Ping
    call websocket_send_frame
    jmp .loop
.done:
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
    inc qword [bridge_events_received]    ; Discord transport is the next phase.
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
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

env_port:              db 'PORT='
env_port_len           equ $ - env_port
env_bridge:            db 'BRIDGE_WEBSOCKET_AUTH_TOKEN='
env_bridge_len         equ $ - env_bridge
env_panel:             db 'PANEL_ACCESS_TOKEN='
env_panel_len          equ $ - env_panel
env_discord:           db 'DISCORD_TOKEN='
env_discord_len        equ $ - env_discord

method_health:         db 'GET /health '
method_health_len      equ $ - method_health
method_panel:          db 'GET /panel '
method_panel_len       equ $ - method_panel
method_chat:           db 'POST /api/chat '
method_chat_len        equ $ - method_chat
method_root:           db 'GET / '
method_root_len        equ $ - method_root
authorization_prefix:  db 'Authorization: Bearer '
authorization_prefix_len equ $ - authorization_prefix

response_health:
    db 'HTTP/1.1 200 OK',13,10
    db 'Content-Type: application/json; charset=utf-8',13,10
    db 'Cache-Control: no-store',13,10
    db 'Connection: close',13,10,13,10
    db '{"status":"ok","runtime":"pure-assembly"}',10
response_health_len equ $ - response_health

response_panel:
    db 'HTTP/1.1 200 OK',13,10
    db 'Content-Type: text/html; charset=utf-8',13,10
    db 'Cache-Control: no-store',13,10
    db 'Connection: close',13,10,13,10
    db `<!doctype html><meta charset="utf-8"><title>Val0x04/ASM</title><style>body{max-width:44rem;margin:8vh auto;background:#10131a;color:#e9eef5;font:16px system-ui;padding:2rem}input,textarea,button{width:100%;box-sizing:border-box;margin:.5rem 0;padding:.7rem;background:#181d27;color:inherit;border:1px solid #40506d}textarea{height:9rem}button{cursor:pointer;background:#4c75ff;border:0}</style><h1>Val0x04/ASM</h1><p>Panel eksperimen syscall-only.</p><input id="t" type="password" placeholder="PANEL_ACCESS_TOKEN"><textarea id="m" maxlength="2000" placeholder="Pesan untuk Discord"></textarea><button onclick="go()">Kirim</button><pre id="o"></pre><script>async function go(){let r=await fetch('/api/chat',{method:'POST',headers:{Authorization:'Bearer '+t.value},body:m.value});o.textContent=await r.text()}</script>`
response_panel_len equ $ - response_panel

response_unauthorized:
    db 'HTTP/1.1 401 Unauthorized',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"unauthorized"}',10
response_unauthorized_len equ $ - response_unauthorized

response_discord_pending:
    db 'HTTP/1.1 501 Not Implemented',13,10
    db 'Content-Type: application/json',13,10
    db 'Connection: close',13,10,13,10
    db '{"error":"pure Discord TLS/Gateway transport is not installed"}',10
response_discord_pending_len equ $ - response_discord_pending

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
error_listen_len       equ $ - error_listen

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
bridge_events_received: dq 0
ws_payload_length:      dd 0
ws_idle_seconds:        dd 0
ws_next_ping:           dd 20
poll_descriptor:        dq 0
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
