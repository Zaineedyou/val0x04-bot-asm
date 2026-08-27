#!/usr/bin/env python3
import os
import socket
import time

PORT = int(os.environ.get('PORT', '19051'))
TOKEN = os.environ.get('BRIDGE_TOKEN', 'bridge-test')
KEY = 'dGhlIHNhbXBsZSBub25jZQ=='

REQUEST = (
    'GET / HTTP/1.1\r\n'
    'Host: localhost\r\n'
    'Connection: Upgrade\r\n'
    'Upgrade: websocket\r\n'
    'Sec-WebSocket-Version: 13\r\n'
    f'Sec-WebSocket-Key: {KEY}\r\n'
    f'X-Auth-Token: {TOKEN}\r\n\r\n'
).encode()

def read_headers(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

with socket.create_connection(('127.0.0.1', PORT), timeout=3) as first:
    first.sendall(REQUEST)
    first_response = read_headers(first)
    assert first_response.startswith(b'HTTP/1.1 101'), first_response
    with socket.create_connection(('127.0.0.1', PORT), timeout=3) as second:
        second.sendall(REQUEST)
        second_response = read_headers(second)
        assert second_response.startswith(b'HTTP/1.1 409 Conflict'), second_response
print('Concurrent bridge conflict test passed')
