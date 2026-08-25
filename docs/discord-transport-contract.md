# Kontrak transport Discord

## Status implementasi

Binary saat ini adalah **milestone inbound bridge**. Ia menjalankan HTTP/WebSocket Fabric dengan assembly x86-64 dan syscall Linux langsung. Koneksi keluar ke Discord secara sengaja belum diaktifkan. `DISCORD_TOKEN` boleh tetap didefinisikan untuk kompatibilitas konfigurasi, tetapi binary tidak mengirimkan nilainya ke jaringan.

> Tidak ada mode fallback yang mengirim token bot melalui koneksi TLS tanpa validasi sertifikat. `POST /api/chat` dengan token panel yang benar akan mengembalikan `501 Not Implemented` sampai transport ini memenuhi kontrak berikut.

## Persyaratan sebelum Discord diaktifkan

| Komponen | Persyaratan minimum | Status |
|---|---|---|
| Resolusi nama | Resolver DNS yang membatasi jawaban dan menangani timeout | Belum diimplementasikan |
| Entropi | CSPRNG dari `getrandom(2)`; tidak memakai timestamp atau PRNG sederhana | Belum diimplementasikan |
| TLS | TLS 1.2 atau lebih baru, negosiasi cipher yang aman, pemeriksaan batas record | Belum diimplementasikan |
| Identitas server | Verifikasi hostname, masa berlaku sertifikat, rantai X.509, dan tanda tangan sampai trust anchor | Belum diimplementasikan |
| HTTP Discord | Header `Authorization: Bot …`, `User-Agent` sah, JSON tervalidasi, timeout, dan pembacaan respons berbatas | Belum diimplementasikan |
| Rate limit REST | Menghormati status `429`, `retry_after`, serta limit rute | Belum diimplementasikan |
| Gateway v10 | WSS, `Hello`, jitter heartbeat, `Identify`, ACK, `READY`, reconnect dan resume | Belum diimplementasikan |
| Pesan Discord | Filter channel, abaikan pesan bot, parsing JSON dengan escape Unicode yang benar, role tertinggi | Belum diimplementasikan |

## Protokol target

Untuk Discord Gateway, transport target mengambil URL Gateway, membuka `wss://…?v=10&encoding=json`, menerima `Hello` (`op:10`), memulai heartbeat dengan interval dari server, lalu mengirim `Identify` (`op:2`) memakai intents yang dibutuhkan. Sequence terakhir harus digunakan pada heartbeat dan resume. `READY` memasok `session_id` serta `resume_gateway_url` yang wajib dipertahankan untuk recovery koneksi.[1]

Gateway hanya dapat dianggap sehat apabila setiap heartbeat memperoleh ACK. Koneksi yang tidak menerima ACK sebelum heartbeat berikutnya wajib dianggap putus dan harus direkoneksi. Untuk mengirim event Minecraft dan pesan dari panel, REST menggunakan endpoint Discord yang autentikasi Bot-nya dilakukan melalui header `Authorization`, JSON body, dan respons rate-limit.[2]

## Kriteria aktivasi

Fitur Discord hanya boleh dipindahkan dari `501` ke aktif setelah semua berikut lulus:

1. Tes vektor kriptografi dan parser certificate untuk input valid maupun malformed.
2. Tes integrasi terhadap endpoint TLS yang menyajikan sertifikat sah dan sertifikat/hostname yang sengaja salah.
3. Tes Gateway menggunakan bot khusus pengujian tanpa token yang disimpan di repository.
4. Tes recovery setelah close, heartbeat ACK hilang, dan HTTP `429`.
5. Audit batas panjang untuk record TLS, frame WebSocket, HTTP header/body, dan payload JSON.

## Referensi

[1] Discord Developer Documentation, [Gateway](https://docs.discord.com/developers/events/gateway).

[2] Discord Developer Documentation, [API Reference](https://docs.discord.com/developers/reference).
