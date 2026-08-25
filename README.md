# Val0x04 Hybrid Bridge

Bridge **Minecraft Fabric ↔ Discord** yang siap dibangun untuk Railway. Runtime deploy berada di `runtime/` dan memakai Rust, `serenity`, serta backend `rustls` yang memverifikasi TLS Discord. Direktori `src/` mempertahankan eksperimen NASM x86-64 syscall-only beserta test kriptografinya; ia tidak menangani token bot produksi.

## Status

| Fungsi | Runtime Railway | Implementasi |
|---|---:|---|
| Koneksi Discord Gateway aman | Siap | `serenity` + `rustls_backend` |
| Discord REST: chat dan embed | Siap | API client Serenity |
| Discord → Minecraft | Siap | Filter channel, abaikan bot, role tertinggi dari cache guild |
| Minecraft → Discord | Siap | Chat biasa dan event embed |
| WebSocket Fabric | Siap | Root endpoint dengan header `X-Auth-Token` |
| Panel operator `/panel` | Siap | Token panel terpisah; `POST /api/chat` |
| Koneksi tunggal + liveness | Siap | Ping 20 detik, stale timeout 75 detik |
| Eksperimen NASM | Siap untuk riset | HTTP/WS, entropi, SHA-256, HMAC, HKDF, parser TLS |

## Arsitektur

Mod Fabric melakukan koneksi keluar ke domain Railway. Railway menangani TLS publik dan meneruskan HTTP/WebSocket ke aplikasi pada `$PORT`. Runtime lalu membuat koneksi keluar terverifikasi ke Discord melalui Gateway dan REST API.

> `DISCORD_TOKEN` tidak dipakai oleh kode TLS buatan sendiri. Token hanya diserahkan ke runtime Serenity/Rustls yang menyediakan transport terenkripsi dan validasi sertifikat terpelihara.

## Deploy Railway

1. Buat project Railway dari repository ini. `Dockerfile` di root otomatis membangun `runtime/` menggunakan Rust 1.88 dan menjalankan binary rilis.
2. Pada **Settings → Networking**, generate public domain.
3. Tambahkan environment variables berikut di **Variables**.
4. Deploy, lalu arahkan konfigurasi mod Fabric ke domain Railway tersebut.

| Variabel | Wajib | Nilai |
|---|---:|---|
| `DISCORD_TOKEN` | Ya | Token bot dari Discord Developer Portal. Jangan commit atau kirim lewat chat. |
| `DISCORD_CHANNEL_ID` | Ya | Snowflake channel Discord target bridge. |
| `BRIDGE_WEBSOCKET_AUTH_TOKEN` | Ya | Token acak panjang yang sama dengan konfigurasi mod Fabric. |
| `PANEL_ACCESS_TOKEN` | Ya | Token acak berbeda untuk membuka panel operator. |
| `PORT` | Railway yang mengatur | Tidak perlu diset manual. |

Di Discord Developer Portal, aktifkan **Server Members Intent** dan **Message Content Intent**. Bot memerlukan izin untuk membaca/mengirim pesan pada channel tujuan.

Konfigurasi Fabric:

```properties
websocket-url=wss://nama-aplikasi-kamu.railway.app
websocket-auth-token=nilai-yang-sama-dengan-BRIDGE_WEBSOCKET_AUTH_TOKEN
```

Setelah deploy, panel tersedia pada:

```text
https://nama-aplikasi-kamu.railway.app/panel
```

Gunakan [`docs/railway-deployment-checklist.md`](docs/railway-deployment-checklist.md) untuk urutan konfigurasi rahasia dan verifikasi bridge dua arah setelah service aktif.

## Build dan test lokal

Runtime hybrid memerlukan Rust 1.88.

```bash
cd runtime
cargo fmt --check
cargo test --locked
cargo build --release --locked
```

Tes NASM dijalankan terpisah dari root repository:

```bash
./tests/run-local.sh
```

Test NASM memverifikasi binary ELF statis, health endpoint, token panel, handshake WebSocket, Ping/Pong, SHA-256, HMAC-SHA256, HKDF, dan parsing envelope TLS.

## Struktur

```text
runtime/                         Runtime Railway deployable
runtime/src/                     Discord Gateway, REST, panel, bridge Fabric
src/                             Eksperimen NASM x86-64 syscall-only
tests/                           Test NASM dan smoke test WebSocket
Dockerfile                       Container runtime hybrid untuk Railway
docs/hybrid-runtime-contract.md  Batas keamanan dan pembagian tanggung jawab
docs/                            Catatan eksperimen TLS/NASM
```

## Catatan keamanan

Gunakan token acak yang panjang dan berbeda untuk bridge serta panel. Jangan gunakan token bot di URL, source code, commit, atau screenshot. Bila salah satu token pernah terpapar, rotasi segera dari Discord Developer Portal atau Railway Variables.

## Referensi

- [Discord Gateway Documentation](https://docs.discord.com/developers/events/gateway)
- [Discord API Reference](https://docs.discord.com/developers/reference)
