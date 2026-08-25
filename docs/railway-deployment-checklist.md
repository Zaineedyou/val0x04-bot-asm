# Checklist deploy Railway

## Sebelum deploy

| Pemeriksaan | Nilai yang diharapkan |
|---|---|
| Repository | `Zaineedyou/val0x04-bot-asm`, branch `main` |
| Build source | `Dockerfile` root membangun `runtime/` dengan Rust 1.88 |
| Discord application | Bot sudah diundang ke server dan memiliki izin Read/Send Messages pada channel tujuan |
| Discord intents | **Server Members Intent** dan **Message Content Intent** sudah aktif |
| Token | `DISCORD_TOKEN`, `BRIDGE_WEBSOCKET_AUTH_TOKEN`, dan `PANEL_ACCESS_TOKEN` adalah nilai rahasia yang berbeda |

## Railway Variables

Tambahkan semua nilai berikut pada service Railway. Jangan set `PORT`; Railway menyediakannya sendiri.

| Nama | Format / aturan |
|---|---|
| `DISCORD_TOKEN` | Token bot Discord saat ini |
| `DISCORD_CHANNEL_ID` | Snowflake channel Discord target, hanya angka |
| `BRIDGE_WEBSOCKET_AUTH_TOKEN` | Token acak panjang; salin nilai yang sama ke mod Fabric |
| `PANEL_ACCESS_TOKEN` | Token acak panjang yang **berbeda** dari token bridge |

## Verifikasi setelah deploy

1. Pastikan log service tidak menunjukkan kegagalan konfigurasi, koneksi Discord, atau binding port.
2. Generate domain di Railway dan buka `https://<domain>/panel`. Masukkan `PANEL_ACCESS_TOKEN`, lalu kirim pesan uji; pesan harus muncul sebagai bot pada `DISCORD_CHANNEL_ID`.
3. Pada mod Fabric, set `websocket-url=wss://<domain>` dan gunakan token bridge yang sama.
4. Mulai atau restart server Minecraft. Log Railway harus mengindikasikan bridge Fabric tersambung.
5. Kirim chat Minecraft dan pastikan masuk ke Discord. Kirim chat pada channel Discord yang dikonfigurasi dan pastikan muncul di Minecraft.
6. Putuskan mod Fabric sementara, lalu sambungkan kembali. Service harus tetap hidup dan menerima koneksi baru tanpa restart.

## Respons insiden

Jika log memuat token atau token pernah masuk commit/screenshot, rotasi segera nilai itu. Untuk token Discord, lakukan rotasi di Discord Developer Portal lalu update Railway Variables dan redeploy. Untuk bridge atau panel token, buat nilai acak baru, update Railway, dan update konfigurasi mod Fabric bila token bridge berubah.

## Batas verifikasi lokal

Source, test unit runtime, build release, dan rangkaian NASM telah diuji lokal. Koneksi Gateway Discord dan deploy container tidak dapat diuji tanpa token bot serta project Railway milik pengguna; checklist ini adalah langkah verifikasi terakhir yang harus dilakukan setelah secrets diset di Railway.
