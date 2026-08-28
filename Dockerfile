FROM debian:bookworm-slim AS build
ARG CURL_VERSION=8.14.1
ARG CURL_SHA256=f4619a1e2474c4bbfedc88a7c2191209c8334b48fa1f4e53fd584cc12e9120dd
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential nasm pkg-config libssl-dev ca-certificates wget xz-utils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
RUN wget -q https://curl.se/download/curl-${CURL_VERSION}.tar.xz \
    && echo "${CURL_SHA256}  curl-${CURL_VERSION}.tar.xz" | sha256sum -c - \
    && tar -xf curl-${CURL_VERSION}.tar.xz \
    && cd curl-${CURL_VERSION} \
    && ./configure \
       --prefix=/opt/curl \
       --with-openssl \
       --enable-websockets \
       --disable-static \
       --without-zlib \
       --without-brotli \
       --without-zstd \
       --without-nghttp2 \
       --without-libpsl \
       --without-libidn2 \
       --disable-ldap \
       --disable-rtsp \
       --disable-dict \
       --disable-gopher \
       --disable-imap \
       --disable-mqtt \
       --disable-pop3 \
       --disable-smb \
       --disable-smtp \
       --disable-telnet \
       --disable-tftp \
       --disable-manual \
    && make -j"$(nproc)" \
    && make install \
    && /opt/curl/bin/curl --version | grep -E 'Protocols:.*ws.*wss'
WORKDIR /app
ENV PKG_CONFIG_PATH=/opt/curl/lib/pkgconfig
COPY Makefile ./
COPY src ./src
COPY adapter ./adapter
RUN make all

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home app
COPY --from=build /opt/curl/lib/libcurl.so.4* /usr/local/lib/
RUN ldconfig
WORKDIR /app
COPY --from=build /app/build/val0x04-asm /usr/local/bin/val0x04-asm
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/val0x04-asm"]
