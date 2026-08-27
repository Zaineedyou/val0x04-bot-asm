#!/usr/bin/env python3
"""Black-box smoke test for the syscall-only WebSocket listener."""
import os
import socket

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "18080"))
TOKEN = os.environ.get("BRIDGE_TOKEN", "bridge-test")
KEY = "dGhlIHNhbXBsZSBub25jZQ=="
EXPECTED_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("server closed socket before complete HTTP response")
        data += chunk
    return data


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("server closed socket before complete WebSocket frame")
        data += chunk
    return data


def masked_frame(opcode: int, payload: bytes = b"") -> bytes:
    if len(payload) > 125:
        raise ValueError("test helper only supports short frames")
    mask = b"\x11\x22\x33\x44"
    body = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + body


def main() -> None:
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {KEY}\r\n"
        f"X-Auth-Token: {TOKEN}\r\n\r\n"
    ).encode()
    with socket.create_connection((HOST, PORT), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(request)
        response = recv_until(sock, b"\r\n\r\n")
        response_text = response.decode("ascii")
        assert response_text.startswith("HTTP/1.1 101"), response_text
        assert f"Sec-WebSocket-Accept: {EXPECTED_ACCEPT}" in response_text, response_text

        # A client Ping must be answered with an unmasked server Pong.
        sock.sendall(masked_frame(0x9, b"ok"))
        pong = recv_exact(sock, 4)
        assert pong == b"\x8a\x02ok", pong.hex()

        # Every Rust event variant must be accepted without disconnecting.
        events = [
            b'{"type":"chat","player":"Alex","message":"smoke"}',
            b'{"type":"join","player":"Alex","emoji":"+"}',
            b'{"type":"leave","player":"Alex","emoji":"-"}',
            b'{"type":"death","message":"fell","emoji":"!"}',
            b'{"type":"advancement","message":"Stone Age"}',
            b'{"type":"bridge_status","status":"connect","emoji":"~"}',
            b'{"type":"bridge_status","status":"disconnect"}',
            b'{"type":"server_start"}',
            b'{"type":"server_stop"}',
            b'{"type":"unknown"}',
        ]
        for event in events:
            sock.sendall(masked_frame(0x1, event))
        sock.sendall(masked_frame(0x8))
    print("WebSocket handshake, Pong, and all event variants passed")


if __name__ == "__main__":
    main()
