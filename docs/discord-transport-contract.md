# Kontrak transport Discord

## Status implementasi

Binary saat ini menjalankan bridge HTTP/WebSocket Fabric dan worker Discord Gateway dua arah. Logika aplikasi tetap berada di NASM; koneksi TLS, DNS, HTTPS, dan WSS ditangani oleh adapter libcurl dengan verifikasi sertifikat dan hostname yang selalu aktif.

> Token bot hanya dikirim melalui koneksi TLS yang memvalidasi sertifikat dan hostname. `POST /api/chat` meneruskan pesan melalui REST HTTPS, sedangkan worker Gateway mempertahankan koneksi WSS untuk menerima pesan Discord.

## Persyaratan sebelum Discord diaktifkan

| Komponen | Persyaratan minimum | Status |
|---|---|---|
| Resolusi nama | DNS dan timeout melalui libcurl | Ditangani library |
| Entropi | CSPRNG dari `getrandom(2)`; tidak memakai timestamp atau PRNG sederhana | Aktif untuk runtime lokal |
| TLS | Negosiasi TLS dan pemeriksaan record melalui libcurl/TLS backend | Ditangani library |
| Identitas server | Verifikasi hostname dan rantai sertifikat melalui libcurl/TLS backend | Ditangani library |
| HTTP Discord | Header bot, JSON terbatas, timeout, dan status HTTP | Aktif |
| Rate limit REST | Penanganan retry berbasis `429` dengan backoff terbatas | Aktif |
| Gateway v10 | WSS, `Hello`, jitter heartbeat, `Identify`, ACK, `READY`, reconnect, dan Resume | Aktif |
| Pesan Discord | Filter channel, abaikan pesan bot, parsing string JSON, forwarding chat, dan role tertinggi | Aktif melalui REST HTTPS tervalidasi |

## Protokol target

Untuk Discord Gateway, transport target mengambil URL Gateway, membuka `wss://…?v=10&encoding=json`, menerima `Hello` (`op:10`), memulai heartbeat dengan interval dari server, lalu mengirim `Identify` (`op:2`) memakai intents yang dibutuhkan. Sequence terakhir digunakan pada heartbeat dan Resume. `READY` memasok `session_id` serta `resume_gateway_url`, dan worker menyimpannya untuk recovery koneksi.[1]

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
