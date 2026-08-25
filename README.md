# Val0x04 Assembly-Dominant Bridge

Eksperimen bridge **Minecraft Fabric ↔ Discord** untuk Linux x86-64 dan Railway. Runtime aplikasi ditulis dalam **NASM**; adapter C kecil hanya menghubungkan NASM ke libcurl untuk TLS, CA chain, hostname verification, HTTPS, dan WSS. Tidak ada Rust runtime dalam image deploy.

| Source runtime | Peran | Target komposisi |
|---|---|---:|
| `src/*.asm` | HTTP, panel, autentikasi, WebSocket Fabric, liveness, JSON sempit, Discord state/payload | **75–90%** |
| `adapter/*.c` | ABI libcurl: TLS tervalidasi, HTTPS REST, WSS frame I/O | **10–25%** |
| libcurl + TLS backend | Hanya transport aman dan verifikasi sertifikat | Bukan logika aplikasi |

`make source-ratio` memverifikasi komposisi source saat build. Checkpoint saat ini menghasilkan sekitar **89% NASM** dan **11% C adapter**.

## Batas library

> Library digunakan hanya ketika menulis ulang dari nol akan berisiko secara keamanan: TLS, certificate chain, hostname verification, DNS/HTTPS/WSS transport. Semua kebijakan dan logika bot yang bisa dibuat sendiri tetap berada di assembly.

| Fungsi | Lokasi |
|---|---|
| Listener HTTP, `/health`, `/panel`, `/api/chat` | NASM + syscall Linux |
| Validasi token panel/bridge | NASM |
| WebSocket Fabric, handshake SHA-1/Base64, Ping/Pong, timeout | NASM |
| Entropi, SHA-256, HMAC, HKDF, parser record TLS | NASM |
| JSON payload panel dan keputusan status HTTP | NASM |
| TLS, CA, hostname verification, HTTPS/WSS byte transport | C adapter + libcurl |

Adapter selalu mengaktifkan certificate dan hostname verification; tidak ada opsi deploy yang mematikannya. Rincian ABI ada di [`docs/secure-transport-abi.md`](docs/secure-transport-abi.md).

## Status checkpoint

| Jalur | Status |
|---|---|
| HTTP/panel/WebSocket Fabric | Berjalan dan diuji lokal |
| Panel → Discord REST HTTPS | Dibangun oleh NASM, dikirim melalui adapter TLS libcurl; tanpa token nyata endpoint mengembalikan kegagalan aman `502` |
| Fabric event → Discord REST | Sedang dipindahkan ke formatter NASM |
| Discord Gateway → Fabric | Sedang dipindahkan ke state machine NASM di atas transport WSS adapter |
| Container Railway | Membangun NASM + C/libcurl langsung, tanpa Rust |

## Build dan test lokal

```bash
sudo apt-get install -y nasm build-essential pkg-config libcurl4-openssl-dev
make all
make test-crypto
make source-ratio
./tests/run-local.sh
```

Rangkaian test memverifikasi binary berjalan, adapter libcurl terhubung, proporsi NASM minimal 75%, endpoint HTTP, autentikasi, WebSocket Ping/Pong, SHA-256, HMAC-SHA256, HKDF, serta parser record TLS.

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
