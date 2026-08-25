# Kontrak runtime hybrid

## Keputusan

Runtime produksi menggunakan implementasi Discord yang telah teruji di ekosistem Rust: `serenity` dengan backend `rustls`. NASM tetap menjadi artefak eksperimen dan fondasi protokol pada direktori `src/`; runtime produksi tidak mengirim `DISCORD_TOKEN` melalui implementasi TLS buatan sendiri.

| Area | Implementasi produksi | Alasan |
|---|---|---|
| Discord Gateway dan REST | Rust `serenity` + `rustls_backend` | TLS, certificate validation, Gateway heartbeat/reconnect, rate-limit, dan API Discord ditangani library yang dipelihara. |
| HTTP/WebSocket bridge Fabric | Runtime Rust `axum` + `tokio` | Menangani banyak koneksi/event secara bersamaan dengan state machine yang sudah dimiliki repo sumber. |
| Artefak NASM | `src/main.asm`, `src/sha256.asm`, `src/tls_record.asm` | Tetap dapat dibangun dan diuji sebagai jalur riset low-level, namun tidak mengendalikan token bot produksi. |
| Container Railway | Image runtime Rust minimal | Memastikan service yang dideploy benar-benar menjalankan bridge dua arah, bukan proof-of-concept parsial. |

## Batas keamanan

Semua rahasia tetap diterima sebagai environment variable Railway. Tidak ada token, domain, atau certificate bundle yang dicommit. `DISCORD_TOKEN` hanya masuk ke client Discord library setelah runtime berhasil dibangun dan dijalankan.

## Dampak terhadap kompatibilitas

Kontrak perilaku mengikuti bot Rust sumber: autentikasi `X-Auth-Token` untuk mod Fabric, satu koneksi bridge aktif dengan heartbeat/liveness, panel operator `/panel`, event Minecraft ke Discord, dan relay chat Discord ke Minecraft dengan role tertinggi bila tersedia.

Ini adalah penyelesaian yang deployable. Port NASM tetap tersedia untuk eksperimen dan dapat dikembangkan secara terpisah tanpa mempertaruhkan runtime bot atau token Discord.
