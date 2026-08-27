# Val0x04 Assembly-Dominant Bridge

Eksperimen bridge **Minecraft Fabric ↔ Discord** untuk Linux x86-64 dan Railway. Runtime aplikasi ditulis dalam **NASM**; adapter C kecil hanya menghubungkan NASM ke libcurl untuk TLS, CA chain, hostname verification, HTTPS, dan WSS. Tidak ada Rust runtime dalam image deploy.

| Source runtime | Peran | Target komposisi |
|---|---|---:|
| `src/*.asm` | HTTP, panel, autentikasi, WebSocket Fabric, liveness, JSON, Gateway Discord, dan keputusan aplikasi | **75–90%** |
| `adapter/*.c` | Bootstrap dan ABI libcurl: TLS tervalidasi, HTTPS REST, DNS, dan WSS frame I/O | **10–25%** |
| libcurl + TLS backend | Hanya transport aman dan verifikasi sertifikat | Bukan logika aplikasi |

`make source-ratio` memverifikasi komposisi source saat build. Checkpoint saat ini menghasilkan sekitar **92,8% NASM** dan **7,2% C adapter**.

## Batas library

> Library digunakan hanya ketika menulis ulang dari nol akan berisiko secara keamanan: TLS, certificate chain, hostname verification, DNS/HTTPS/WSS transport. Semua kebijakan dan logika bot yang bisa dibuat sendiri tetap berada di assembly.

| Fungsi | Lokasi |
|---|---|
| Listener HTTP, `/health`, `/panel`, `/api/chat` | NASM + syscall Linux |
| Validasi token panel/bridge | NASM |
| WebSocket Fabric, handshake SHA-1/Base64, Ping/Pong, timeout, dan forwarding pesan | NASM |
| Entropi, SHA-256, HMAC, HKDF, parser record TLS | NASM |
| JSON payload panel/Gateway dan keputusan status HTTP | NASM |
| TLS, CA, hostname verification, HTTPS/WSS byte transport | C adapter + libcurl |

Adapter selalu mengaktifkan certificate dan hostname verification; tidak ada opsi deploy yang mematikannya. Rincian ABI ada di [`docs/secure-transport-abi.md`](docs/secure-transport-abi.md).

## Status checkpoint

| Jalur | Status |
|---|---|
| HTTP/panel/WebSocket Fabric | Berjalan dan diuji lokal |
| Panel → Discord REST HTTPS | Dibangun oleh NASM dan dikirim melalui adapter TLS libcurl |
| Fabric chat → Discord REST | Berjalan melalui formatter JSON NASM |
| Discord Gateway → Fabric | Worker Gateway NASM terpisah; Identify, heartbeat, ACK, reconnect, filter channel/bot, dan forwarding chat aktif |
| Resume Gateway | Belum digunakan; reconnect melakukan Identify ulang pada sesi baru |
| Container Railway | Membangun NASM + C/libcurl langsung, tanpa Rust |

## Build dan test lokal

```bash
sudo apt-get install -y nasm build-essential pkg-config libcurl4-openssl-dev
make all
make test-crypto
make source-ratio
./tests/run-local.sh
```

Rangkaian test memverifikasi binary berjalan, adapter libcurl terhubung, proporsi NASM minimal 75%, endpoint HTTP, autentikasi, WebSocket Ping/Pong, SHA-256, HMAC-SHA256, HKDF, parser record TLS, serta payload Identify dan heartbeat Gateway.

## Railway

`Dockerfile` root membangun binary NASM dan adapter C; Rust tidak termasuk image. Untuk menjalankan service, set variabel berikut pada Railway:

| Variabel | Kegunaan |
|---|---|
| `DISCORD_TOKEN` | Token bot; hanya dipakai untuk authorization dari NASM ke adapter TLS |
| `DISCORD_CHANNEL_ID` | Snowflake channel tujuan REST Discord |
| `BRIDGE_WEBSOCKET_AUTH_TOKEN` | Token yang sama dengan konfigurasi mod Fabric |
| `PANEL_ACCESS_TOKEN` | Token panel operator yang berbeda dari token bridge |
| `PORT` | Dikelola Railway |

Untuk koneksi Fabric, gunakan `wss://<domain-railway>` dan `BRIDGE_WEBSOCKET_AUTH_TOKEN` yang sama. Jangan pernah commit token atau menonaktifkan certificate verification.
