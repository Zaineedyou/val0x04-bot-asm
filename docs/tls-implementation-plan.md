# Rencana implementasi TLS murni

## Keputusan keamanan

Transport Discord hanya akan ditulis untuk **TLS 1.3** dengan suite `TLS_AES_128_GCM_SHA256` atau `TLS_CHACHA20_POLY1305_SHA256`, X25519 ephemeral key exchange, Server Name Indication, dan verifikasi sertifikat. TLS 1.3 memperlakukan semua handshake setelah `ServerHello` sebagai terenkripsi dan menggunakan HKDF untuk jadwal kunci.[1] Mode TLS 1.2 tidak dijadikan target utama karena memperluas kombinasi cipher serta state machine yang harus diaudit.

TLS tidak cukup hanya membuat socket TCP terenkripsi. Protokol menuntut autentikasi server, kerahasiaan, dan integritas saat penyerang mengendalikan jaringan.[1] Oleh sebab itu, proses tidak boleh menggunakan `DISCORD_TOKEN` sampai certificate chain dan hostname berhasil tervalidasi.

## Batas implementasi pertama

| Lapisan | Modul assembly | Sifat implementasi | Kriteria test |
|---|---|---|---|
| Entropi | `getrandom(2)` syscall wrapper | Membaca tepat jumlah byte atau gagal | Kegagalan parsial dan `EINTR` |
| Primitif hash | SHA-256, HMAC-SHA256, HKDF-Extract/Expand-Label | Constant-time untuk rahasia | Vektor SHA/HMAC/HKDF RFC |
| Kurva | X25519 scalar multiplication | Ladder constant-time | Vektor RFC 7748 |
| AEAD | AES-128 + GCM atau ChaCha20-Poly1305 | Nonce unik per record | Vektor NIST/RFC dan tag gagal |
| Record parser | TLSPlaintext/TLSCiphertext | Batas ukuran sebelum alokasi/copy | Record pendek, oversized, dan malformed |
| Handshake | ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished | State transition eksplisit | Transkrip positif dan perubahan satu bit |
| Sertifikat | DER/ASN.1 terbatas, SAN DNS, chain constraint, expiry | Menolak field/length tak dikenal yang kritis | Chain valid, CA salah, hostname salah, waktu salah |
| Aplikasi | HTTPS dan WSS Discord | Authorization tidak dibentuk sebelum TLS sukses | Endpoint test dengan certificate valid/salah |

## State machine yang akan digunakan

```text
TCP connected
  -> ClientHello sent
  -> ServerHello validated
  -> Handshake keys installed
  -> EncryptedExtensions validated
  -> Certificate chain + hostname verified
  -> CertificateVerify checked
  -> Server Finished checked
  -> Application keys installed
  -> TLS ready
  -> HTTP REST or WebSocket Gateway
```

Setiap transisi menyimpan batas transcript dan menghentikan koneksi pada type/length/message yang tidak sesuai. Tidak ada jalur yang mengubah kesalahan verifikasi sertifikat menjadi warning atau fallback tanpa autentikasi.

## Sertifikat dan trust

Certificate chain harus diproses sebagai DER dengan parser panjang yang tahan overflow. Validasi wajib mencakup trust anchor yang dibundel atau dikelola sebagai artefak build, `basicConstraints`, `keyUsage`, masa berlaku, signature chain, dan Subject Alternative Name DNS untuk host yang dihubungi. RFC 5280 mendefinisikan pemrosesan certification path dan menyatakan implementasi yang sesuai harus memperoleh hasil yang setara dengan prosedur validasi path-nya.[2]

Trust bundle bukan environment variable yang menerima konten bebas; bundle diperlakukan sebagai data rilis yang diberi versi dan diuji. Rotasi CA akan memerlukan update release, bukan fallback ke koneksi tidak tervalidasi.

## Interoperabilitas Discord setelah TLS siap

Sesudah `TLS ready`, REST membuat request `POST /api/v10/channels/{channel.id}/messages` dengan header Bot authorization, JSON tervalidasi, user agent, serta pemrosesan rate limit. Gateway menghubungkan `wss://gateway.discord.gg/?v=10&encoding=json`, lalu mengikuti urutan `Hello`, heartbeat, `Identify`, `READY`, reconnect, dan resume. Gateway Discord menjelaskan bahwa sequence terakhir perlu di-cache untuk heartbeat dan resume.[3]

## Referensi

[1] E. Rescorla, [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446).

[2] D. Cooper et al., [RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280).

[3] Discord, [Gateway Documentation](https://docs.discord.com/developers/events/gateway).
