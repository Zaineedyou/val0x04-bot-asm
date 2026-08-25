# Val0x04 pure-assembly port — implementation basis

## Product requirements from the source repository

The port must run as a Linux x86-64 process on Railway and listen on the `PORT` environment variable. Railway terminates public TLS, so the inbound listener receives plain HTTP and WebSocket traffic. It must serve `/panel`, accept `POST /api/chat` with bearer authentication, and upgrade `/` to a single authenticated Fabric bridge WebSocket. The accepted bridge client supplies `X-Auth-Token`; a second healthy client is rejected. The server sends WebSocket Pings every 20 seconds, marks an inactive bridge stale after 75 seconds, and accepts a replacement.

Fabric emits JSON events `chat`, `join`, `leave`, `death`, `advancement`, `bridge_status`, `server_start`, and `server_stop`. The bot forwards these to Discord as normal text or embeds. It also accepts messages from the configured Discord channel, annotates them with the author's highest guild role where available, serializes `{ "type":"chat", "author":"…", "role":"…", "message":"…" }`, and forwards it to the active Fabric bridge.

Required environment variables are `DISCORD_TOKEN`, `DISCORD_CHANNEL_ID`, `BRIDGE_WEBSOCKET_AUTH_TOKEN`, `PANEL_ACCESS_TOKEN`, and Railway-provided `PORT`.

## Pure assembly definition

The implementation uses NASM x86-64 assembly, Linux system calls, and an ELF linker. It must not link Rust, C, libc, OpenSSL, libcurl, a JSON library, or a WebSocket library. The inbound process, HTTP parser, WebSocket framing, SHA-1/Base64 handshake support, timing/event loop, JSON serialization/parsing, and state machine are therefore implemented in assembly.

## Discord compatibility requirements

Discord REST and Gateway use TLS. A complete pure implementation must include DNS resolution, TCP, TLS 1.2+ record/handshake handling, a cryptographically secure random source, X.509 certificate-chain parsing and validation, public-key signature verification, AEAD cipher support, HTTP client code, a WebSocket client, JSON parser/serializer, and Discord-specific state handling.

For Gateway v10, the client connects with `wss://gateway.discord.gg/?v=10&encoding=json`, processes `Hello` (`op:10`), sends periodic heartbeats (`op:1`) containing the latest sequence, sends Identify (`op:2`) using intents, handles Heartbeat ACK (`op:11`), accepts `READY`, and should reconnect/resume with `session_id`, `resume_gateway_url`, and latest sequence when appropriate. The message bridge consumes `MESSAGE_CREATE` events and filters by configured channel and bot author. REST sends messages to the configured channel with Bot authorization and JSON payload.

## Compatibility boundaries

The repository will be arranged as an incremental research implementation. The first executable milestone is a syscall-only inbound HTTP/WebSocket Fabric bridge. Discord transport can only be considered production-safe after certificate validation, modern TLS, and reconnect/resume behavior are implemented and tested with a real bot. No release should send `DISCORD_TOKEN` through an unauthenticated TLS connection.

## Sources

- Source repository README and current source tree: `Zaineedyou/val0x04-bot`, commit `0895985`.
- Discord Gateway documentation: https://docs.discord.com/developers/events/gateway
- Discord Gateway Events documentation: https://docs.discord.com/developers/events/gateway-events
- Discord API Reference: https://docs.discord.com/developers/reference
- Discord Message Resource: https://docs.discord.com/developers/resources/message

## Design decision

Target: x86-64 Linux, NASM syntax, statically linked ELF, direct syscalls. Deployment: a minimal Docker multi-stage build that installs NASM only at build time and copies the static binary to the runtime image. No secret is baked into the image; all configuration remains Railway environment variables.
