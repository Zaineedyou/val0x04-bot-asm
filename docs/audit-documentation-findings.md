# Temuan acuan dokumentasi — audit 2026-08-28

## Repository

Kontrak repository menetapkan URL Gateway `wss://gateway.discord.gg/?v=10&encoding=json`, urutan koneksi `Hello (op 10) -> Identify (op 2)`, heartbeat berdasarkan interval server, ACK wajib, READY/session_id/resume_gateway_url, reconnect/resume, serta transport WSS dan HTTPS melalui libcurl dengan verifikasi sertifikat dan hostname aktif. ABI menyatakan `CURLOPT_CONNECT_ONLY=2L` untuk model `curl_ws_send`/`curl_ws_recv`, dan handle harus dipertahankan selama koneksi aktif.

## Dokumentasi resmi libcurl

1. `libcurl-ws`: WebSocket diawali GET HTTP/1 upgrade; model CONNECT_ONLY memakai `CURLOPT_CONNECT_ONLY=2L`; setelah `curl_easy_perform` mengembalikan kontrol, aplikasi memakai `curl_ws_send` dan `curl_ws_recv`.
2. `CURLOPT_CONNECT_ONLY`: nilai `2` khusus WebSocket, menjalankan request dan membaca seluruh response headers sebelum menyerahkan kontrol ke aplikasi.
3. `curl_ws_send`: `sent` dapat lebih kecil dari payload, sehingga pemanggil harus mengulang dengan pointer dan panjang tersisa. `CURLE_AGAIN` harus ditangani dengan menunggu socket; dokumentasi menyarankan menunggu socket siap.
4. `curl_ws_recv`: `meta->bytesleft` wajib diperiksa; frame/message terfragmentasi harus dirakit oleh aplikasi. `CURLWS_CONT` menandai fragment lanjutan. `CURLE_AGAIN` berarti menunggu socket; koneksi tutup dilaporkan sebagai `CURLE_GOT_NOTHING`.

## Referensi

- https://docs.discord.com/developers/events/gateway
- https://curl.se/libcurl/c/libcurl-ws.html
- https://curl.se/libcurl/c/CURLOPT_CONNECT_ONLY.html
- https://curl.se/libcurl/c/curl_ws_send.html
- https://curl.se/libcurl/c/curl_ws_recv.html
