# Val0x04 assembly-dominant port — basis implementasi

## Requirement produk

Bridge berjalan di Linux x86-64 dan mendengarkan `PORT` Railway. Inbound HTTP/WebSocket dari Railway dapat ditangani NASM karena TLS publik diterminasi oleh Railway. Service melayani `/panel`, menerima `POST /api/chat` dengan bearer authentication, serta menerima satu WebSocket Fabric berautentikasi melalui `X-Auth-Token`. Assembly mengatur handshake, Ping setiap 20 detik, dan timeout 75 detik.

Fabric mengirim event JSON seperti `chat`, `join`, `leave`, `death`, `advancement`, `bridge_status`, `server_start`, dan `server_stop`. Discord REST menerima payload yang dibentuk assembly; Discord Gateway kemudian akan mengirim pesan channel kembali ke WebSocket Fabric melalui state machine assembly.

## Batas library yang disetujui

| Komponen | Implementasi |
|---|---|
| Inbound socket, HTTP, panel, auth, WebSocket, SHA-1/Base64, liveness | NASM dan syscall Linux |
| JSON sempit, format payload Discord, event policy, Gateway opcode/state | NASM |
| CSPRNG, SHA-256, HMAC, HKDF, parser TLS record eksperimen | NASM |
| TLS, certificate chain, hostname verification, DNS/HTTPS/WSS transport | C adapter kecil + libcurl |

Tidak ada Rust runtime, framework web, JSON library, atau WebSocket library aplikasi. Adapter C tidak membuat keputusan Discord; ia hanya menyediakan byte transport TLS tervalidasi bagi NASM.

## Discord compatibility

Gateway v10 menggunakan `wss://gateway.discord.gg/?v=10&encoding=json`. NASM harus memproses `Hello` (`op:10`), mengirim `Identify` (`op:2`), menjadwalkan heartbeat (`op:1`), memproses ACK (`op:11`), menyimpan sequence, dan mengelola reconnect/resume. Adapter libcurl memberikan koneksi WSS dan operasi frame; semua keputusan itu tetap assembly.

REST membangun URL channel, header `Authorization: Bot <token>`, dan JSON payload di NASM. Adapter hanya mengirimkannya sebagai HTTPS dengan certificate dan hostname verification aktif. `DISCORD_TOKEN` tidak masuk ke source atau image.

## Status dan keamanan

Checkpoint sekarang berisi listener NASM, panel, WebSocket Fabric, pengirim panel REST NASM, dan relay chat Fabric → Discord REST. Koneksi Gateway dua arah sedang dipindahkan di atas ABI WSS. Tidak ada jalur yang menonaktifkan verifikasi sertifikat; bila TLS, token, atau endpoint ditolak, request gagal aman.

## Sumber

- Discord [Gateway documentation](https://docs.discord.com/developers/events/gateway)
- Discord [Gateway Events](https://docs.discord.com/developers/events/gateway-events)
- Discord [API Reference](https://docs.discord.com/developers/reference)
- libcurl [WebSocket send API](https://curl.se/libcurl/c/curl_ws_send.html)
- libcurl [certificate verification](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)
