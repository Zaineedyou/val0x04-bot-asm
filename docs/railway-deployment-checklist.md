# Checklist deploy Railway — NASM dominan

## Sebelum deploy

| Pemeriksaan | Nilai yang diharapkan |
|---|---|
| Repository | `Zaineedyou/val0x04-bot-asm`, branch `main` |
| Runtime | NASM x86-64 + adapter C/libcurl kecil; tidak ada Rust runtime |
| Dockerfile | Build stage memasang `nasm`, `build-essential`, dan `libcurl4-openssl-dev` |
| Discord application | Bot sudah diundang ke server dan memiliki izin membaca/mengirim pada channel target |
| Rahasia | Token Discord, bridge, dan panel berbeda serta tidak pernah dicommit |

## Railway Variables

| Nama | Aturan |
|---|---|
| `DISCORD_TOKEN` | Token bot Discord saat ini. Hanya dirangkai menjadi header authorization oleh NASM dan dikirim melalui TLS libcurl. |
| `DISCORD_CHANNEL_ID` | Snowflake channel Discord target, angka saja. |
| `BRIDGE_WEBSOCKET_AUTH_TOKEN` | Token acak panjang; salin sama persis ke mod Fabric. |
| `PANEL_ACCESS_TOKEN` | Token acak panjang yang berbeda dari token bridge. |
| `PORT` | Dikelola Railway; jangan set manual. |

## Verifikasi pascadeploy

1. Pastikan build log memuat `make all` dan tidak ada kesalahan dependency libcurl.
2. Generate domain Railway, buka `/health`, dan pastikan respons menunjukkan `"runtime":"assembly-dominant"`.
3. Buka `/panel`, gunakan `PANEL_ACCESS_TOKEN`, lalu kirim pesan biasa tanpa quote, backslash, atau karakter kontrol. Endpoint menolak karakter tersebut sampai JSON escaping NASM lengkap diaktifkan.
4. Set mod Fabric ke `wss://<domain>` dan `BRIDGE_WEBSOCKET_AUTH_TOKEN`; tes handshake dan Ping/Pong.
5. Set `DISCORD_TOKEN` serta `DISCORD_CHANNEL_ID`, lalu tes pesan panel ke Discord. Bila transport menolak sertifikat/host atau token, endpoint menampilkan `502` tanpa membocorkan rahasia.

## Keamanan

Jangan menonaktifkan certificate verification. Adapter transport memaksa validasi CA dan hostname di libcurl. Jika token bocor, rotasi pada Discord Developer Portal atau Railway Variables lalu redeploy.

## Batas checkpoint

Rilis ini sudah menjalankan HTTP, panel, WebSocket Fabric, liveness, dan jalur REST yang dibangun NASM. Gateway Discord dua arah sedang dipindahkan ke assembly di atas API WSS adapter; transport WSS sendiri sudah tersedia di adapter tanpa menambah runtime Rust.
