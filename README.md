# Val0x04/ASM

> **Eksperimen Linux x86-64 syscall-only** untuk fondasi bridge Minecraft–Discord. Binary produksi tidak menautkan Rust, libc, OpenSSL, libcurl, runtime async, parser JSON, atau library WebSocket.

## Status rilis

Ini adalah **milestone inbound bridge yang dapat dibangun dan dijalankan**. Ia bukan pengganti drop-in yang lengkap untuk bot Rust sumber. HTTP, autentikasi, dan server WebSocket Fabric sudah diimplementasikan dalam NASM. Transport Discord keluar belum diaktifkan, karena versi pure assembly yang aman harus memverifikasi TLS dan sertifikat sebelum token bot diizinkan keluar dari proses.

| Kemampuan | Status | Catatan |
|---|---|---|
| ELF Linux x86-64 statis | Siap | Direct syscall, tanpa dynamic section. |
| Runtime `PORT` Railway | Siap | Membaca environment langsung dari process stack. |
| `GET /health` | Siap | Endpoint probe sederhana. |
| `GET /panel` | Siap | UI operator eksperimental. |
| Token panel | Siap | Header `Authorization: Bearer <PANEL_ACCESS_TOKEN>` dibandingkan secara tepat. |
| `POST /api/chat` | Aman tetapi belum aktif | Mengembalikan `501`; tidak pernah mengirim token Discord. |
| WebSocket `/` | Siap untuk fondasi | Memerlukan `X-Auth-Token`; handshake SHA-1/Base64, Ping/Pong, batas satu klien aktif, dan timeout liveness tersedia. |
| Entropi TLS | Siap sebagai fondasi | Wrapper `getrandom(2)` syscall membaca 32 byte sebelum server mulai. |
| SHA-256, HMAC-SHA256, HKDF | Siap sebagai fondasi | Semua assembly dan diuji dengan vektor SHA/HMAC/RFC 5869. |
| Fabric event → Discord | Belum aktif | Menunggu TLS/REST aman. |
| Discord Gateway → Fabric | Belum aktif | Menunggu TLS/WSS, Gateway heartbeat/recovery, serta parser JSON lengkap. |

## Desain

Railway mengakhiri TLS publik dan meneruskan HTTP/WebSocket ke aplikasi melalui nilai `$PORT`. Dengan demikian, binary ini mendengarkan TCP HTTP biasa di dalam container; mod Fabric tetap terhubung dari luar menggunakan `wss://<domain-railway>`.

Endpoint root hanya meng-upgrade request WebSocket yang memiliki `X-Auth-Token` tepat. Client menggunakan masking seperti diwajibkan WebSocket. Server dapat menerima frame teks pendek (maksimal 4096 byte), membalas `Ping` client dengan `Pong`, mengirim `Ping` saat idle setiap 20 detik, dan menutup koneksi yang tidak mengirim frame selama 75 detik.

## Build lokal

Prasyaratnya hanya `nasm`, GNU `ld`, `make`, Python 3, dan `curl` untuk test.

```bash
make all
make test-crypto
make inspect
./tests/run-local.sh
```

Binary hasilnya berada di `build/val0x04-asm`. Untuk menjalankan secara lokal:

```bash
PORT=8080 \
BRIDGE_WEBSOCKET_AUTH_TOKEN='ganti-dengan-token-acak-panjang' \
PANEL_ACCESS_TOKEN='ganti-dengan-token-panel-berbeda' \
./build/val0x04-asm
```

Uji sederhana:

```bash
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/panel
```

## Deploy Railway

`Dockerfile` multi-stage menginstal NASM hanya pada tahap build, lalu memindahkan binary statis ke image `scratch`. Tidak ada compiler, shell, package manager, token, atau file `.env` dalam runtime image.

Buat project Railway dari repositori ini, lalu set environment berikut:

| Variabel | Diperlukan | Kegunaan saat ini |
|---|---:|---|
| `PORT` | Railway yang mengatur | Port listener. Jangan set manual bila Railway menyediakannya. |
| `BRIDGE_WEBSOCKET_AUTH_TOKEN` | Ya | Token header `X-Auth-Token` untuk mod Fabric. |
| `PANEL_ACCESS_TOKEN` | Ya | Token Bearer untuk endpoint operator. Harus berbeda dari token bridge. |
| `DISCORD_TOKEN` | Tidak untuk milestone ini | Dipertahankan untuk kontrak kompatibilitas; **tidak ditransmisikan**. |
| `DISCORD_CHANNEL_ID` | Tidak untuk milestone ini | Akan digunakan oleh adapter Discord mendatang. |

Setelah Railway memberi domain publik, konfigurasi mod Fabric dapat diarahkan ke:

```properties
websocket-url=wss://nama-aplikasi-kamu.railway.app
websocket-auth-token=nilai-yang-sama-dengan-BRIDGE_WEBSOCKET_AUTH_TOKEN
```

## Kontrak keamanan Discord

Mengirim token bot ke Discord memerlukan TLS dan identitas server yang benar. Implementasi pure assembly yang lengkap harus mencakup CSPRNG, TLS 1.2 atau lebih baru, validasi hostname, rantai sertifikat X.509, signature verification, HTTP, rate-limit REST, serta koneksi Gateway berkelanjutan. Discord mengharuskan aplikasi Gateway menerima `Hello`, mengirim heartbeat, melakukan `Identify`, dan menangani reconnect/resume menggunakan state `READY`.[1]

> Sampai syarat tersebut dipenuhi, `POST /api/chat` sengaja tetap `501 Not Implemented`. Ini adalah perlindungan agar `DISCORD_TOKEN` tidak bocor lewat koneksi yang bisa disusupi.

Rincian checkpoint dan kriteria aktivasi ada di [`docs/discord-transport-contract.md`](docs/discord-transport-contract.md).

## Pengujian yang sudah lulus

Skrip `tests/run-local.sh` secara otomatis memverifikasi bahwa binary dapat dibangun, statis, tidak memiliki dynamic dependency, bahwa vektor SHA-256/HMAC-SHA256/HKDF lulus, merespons health check, menolak token panel yang tidak sah, dan menjawab WebSocket Ping dengan Pong. Smoke test handshake juga memeriksa nilai `Sec-WebSocket-Accept` terhadap vektor contoh RFC 6455.

## Struktur

```text
src/main.asm                     Server syscall-only, HTTP, WebSocket, SHA-1/Base64
Makefile                         Build ELF statis
Dockerfile                       Image Railway multi-stage → scratch
tests/run-local.sh               Rangkaian verifikasi lokal
tests/ws_smoke.py                Smoke test WebSocket black-box
docs/protocol-research.md        Spesifikasi dan temuan port
docs/discord-transport-contract.md Kontrak keamanan sebelum Discord aktif
```

## Referensi

[1] [Discord Developer Documentation — Gateway](https://docs.discord.com/developers/events/gateway)

[2] [Discord Developer Documentation — API Reference](https://docs.discord.com/developers/reference)
