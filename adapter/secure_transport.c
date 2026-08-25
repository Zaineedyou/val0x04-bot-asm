#define _POSIX_C_SOURCE 200809L

#include <curl/curl.h>
#include <curl/websockets.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * This is deliberately a transport-only boundary. It does not parse Discord
 * JSON, select opcodes, schedule heartbeats, make role decisions, or retain
 * bot tokens. Those responsibilities stay in NASM.
 */

static CURL *gateway;
static char last_error[CURL_ERROR_SIZE];

static void clear_error(void) {
    memset(last_error, 0, sizeof(last_error));
}

static int configure_secure_handle(CURL *handle) {
    CURLcode code;

    clear_error();
    code = curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, last_error);
    if (code != CURLE_OK) return -(int)code;
    code = curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    if (code != CURLE_OK) return -(int)code;
    code = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
    if (code != CURLE_OK) return -(int)code;
    code = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
    if (code != CURLE_OK) return -(int)code;
    code = curl_easy_setopt(handle, CURLOPT_USERAGENT, "val0x04-asm/0.2");
    if (code != CURLE_OK) return -(int)code;
    return 0;
}

int secure_transport_init(void) {
    CURLcode code = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (code != CURLE_OK) {
        clear_error();
        return -(int)code;
    }
    return 0;
}

const char *secure_transport_last_error(void) {
    return last_error[0] ? last_error : curl_easy_strerror(CURLE_OK);
}

void secure_gateway_close(void) {
    if (gateway) {
        curl_easy_cleanup(gateway);
        gateway = NULL;
    }
}

int secure_gateway_connect(const char *wss_url) {
    CURLcode code;
    int configured;

    if (!wss_url) return -EINVAL;
    secure_gateway_close();
    gateway = curl_easy_init();
    if (!gateway) return -ENOMEM;

    configured = configure_secure_handle(gateway);
    if (configured != 0) {
        secure_gateway_close();
        return configured;
    }

    code = curl_easy_setopt(gateway, CURLOPT_URL, wss_url);
    if (code == CURLE_OK)
        code = curl_easy_setopt(gateway, CURLOPT_CONNECT_ONLY, 2L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(gateway, CURLOPT_TIMEOUT_MS, 15000L);
    if (code == CURLE_OK)
        code = curl_easy_perform(gateway);
    if (code != CURLE_OK) {
        if (!last_error[0])
            strncpy(last_error, curl_easy_strerror(code), sizeof(last_error) - 1);
        secure_gateway_close();
        return -(int)code;
    }
    return 0;
}

long secure_gateway_send_text(const char *data, size_t len) {
    size_t offset = 0;

    if (!gateway || (!data && len)) return -EINVAL;
    while (offset < len) {
        size_t sent = 0;
        CURLcode code = curl_ws_send(gateway, data + offset, len - offset,
                                     &sent, 0, CURLWS_TEXT);
        if (code == CURLE_AGAIN) return -EAGAIN;
        if (code != CURLE_OK) {
            if (!last_error[0])
                strncpy(last_error, curl_easy_strerror(code), sizeof(last_error) - 1);
            return -(long)code;
        }
        if (sent == 0) return -EIO;
        offset += sent;
    }
    return (long)offset;
}

long secure_gateway_recv_text(char *out, size_t cap, size_t *out_len) {
    size_t received = 0;
    const struct curl_ws_frame *meta = NULL;
    CURLcode code;

    if (!gateway || !out || !out_len || cap == 0) return -EINVAL;
    *out_len = 0;
    code = curl_ws_recv(gateway, out, cap, &received, &meta);
    if (code == CURLE_AGAIN) return -EAGAIN;
    if (code != CURLE_OK) {
        if (!last_error[0])
            strncpy(last_error, curl_easy_strerror(code), sizeof(last_error) - 1);
        return -(long)code;
    }
    if (!meta || meta->bytesleft != 0 || received == cap) return -EMSGSIZE;
    if (!(meta->flags & CURLWS_TEXT)) return -EPROTO;
    *out_len = received;
    return (long)received;
}

static size_t discard_response(char *ptr, size_t size, size_t nmemb, void *userdata) {
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

long secure_https_post_json(const char *url,
                            const char *authorization,
                            const char *json,
                            size_t json_len,
                            long *http_status) {
    CURL *handle;
    struct curl_slist *headers = NULL;
    CURLcode code;
    int configured;
    long status = 0;

    if (!url || !authorization || (!json && json_len) || !http_status) return -EINVAL;
    *http_status = 0;
    handle = curl_easy_init();
    if (!handle) return -ENOMEM;

    configured = configure_secure_handle(handle);
    if (configured != 0) {
        curl_easy_cleanup(handle);
        return configured;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authorization);
    if (!headers) {
        curl_easy_cleanup(handle);
        return -ENOMEM;
    }

    code = curl_easy_setopt(handle, CURLOPT_URL, url);
    if (code == CURLE_OK)
        code = curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    if (code == CURLE_OK)
        code = curl_easy_setopt(handle, CURLOPT_POST, 1L);
    if (code == CURLE_OK)
        code = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, json);
    if (code == CURLE_OK)
        code = curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)json_len);
    if (code == CURLE_OK)
        code = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, discard_response);
    if (code == CURLE_OK)
        code = curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, 15000L);
    if (code == CURLE_OK)
        code = curl_easy_perform(handle);
    if (code == CURLE_OK)
        code = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(handle);
    if (code != CURLE_OK) {
        if (!last_error[0])
            strncpy(last_error, curl_easy_strerror(code), sizeof(last_error) - 1);
        return -(long)code;
    }
    *http_status = status;
    return 0;
}
