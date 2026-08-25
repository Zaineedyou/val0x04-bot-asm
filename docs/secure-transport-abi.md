# Kontrak adapter transport aman

## Prinsip desain

Runtime utama memakai NASM dan syscall Linux untuk konfigurasi, listener HTTP, panel, autentikasi, WebSocket Fabric, event loop, JSON sempit untuk event bot, state liveness, Discord Gateway state machine, heartbeat, reconnect, resume, dan format request Discord. Adapter C hanya menjembatani ABI assembly ke **libcurl** untuk koneksi TLS/HTTPS/WSS yang memerlukan validasi sertifikat.

| Tanggung jawab | Lokasi | Library diizinkan |
|---|---|---|
| HTTP/panel/WebSocket Fabric, state, JSON, Discord payload | NASM | Tidak ada |
| DNS, TCP, TLS, CA chain, hostname verification | libcurl melalui C adapter | libcurl dan TLS backend-nya |
| HTTPS REST Discord | NASM membentuk HTTP/JSON; adapter mengirim melalui HTTPS | libcurl |
| WSS Discord Gateway | NASM menjalankan opcode/heartbeat/resume; adapter mengirim/menerima frame WSS | libcurl |

## ABI C ke NASM

Semua fungsi berikut memakai System V AMD64 ABI dan mengembalikan `0` bila sukses atau kode negatif milik adapter ketika terjadi kegagalan. Adapter tidak menyimpan token atau state protokol Discord selain handle koneksi transport.

```c
int secure_transport_init(void);
int secure_gateway_connect(const char *wss_url);
int secure_gateway_socket(void);
long secure_gateway_send_text(const char *data, size_t len);
long secure_gateway_recv_text(char *out, size_t cap, size_t *out_len);
void secure_gateway_close(void);
long secure_https_post_json(const char *url,
                            const char *authorization,
                            const char *json, size_t json_len,
                            long *http_status);
const char *secure_transport_last_error(void);
```

`secure_gateway_recv_text` mengembalikan `-EAGAIN` ketika tidak ada frame siap dibaca. NASM yang menjalankan `poll`/timer menentukan kapan menerima ulang, sehingga penjadwalan dan recovery tetap berada di assembly.

## Keamanan wajib

Adapter selalu mengaktifkan `CURLOPT_SSL_VERIFYPEER=1` dan `CURLOPT_SSL_VERIFYHOST=2`; tidak ada environment flag atau fallback yang dapat mematikan validasi. libcurl mendokumentasikan bahwa mematikan certificate verification membuka peluang man-in-the-middle dan membuat koneksi tidak aman.[1] Endpoint Gateway memakai `wss://gateway.discord.gg/?v=10&encoding=json`, sedangkan REST memakai base URL API Discord dari konstanta NASM. libcurl menyediakan API WebSocket `curl_ws_send` dan `curl_ws_recv`, termasuk hasil `CURLE_AGAIN` untuk integrasi dengan event loop aplikasi.[2] [3]

## Aturan ukuran source

Target rilis adalah paling banyak sekitar 10–25% C adapter dan 75–90% NASM dari source runtime. C tidak boleh berisi parsing Discord opcode, JSON event, panel, autentikasi, logika role, atau keputusan state machine.

## Referensi

[1] [libcurl — CURLOPT_SSL_VERIFYPEER](https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)

[2] [libcurl — curl_ws_send](https://curl.se/libcurl/c/curl_ws_send.html)

[3] [libcurl — curl_ws_recv](https://curl.se/libcurl/c/curl_ws_recv.html)
