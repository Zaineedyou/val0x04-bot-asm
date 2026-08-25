FROM debian:bookworm-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential nasm pkg-config libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Makefile ./
COPY src ./src
COPY adapter ./adapter
RUN make all

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libcurl4 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home app
WORKDIR /app
COPY --from=build /app/build/val0x04-asm /usr/local/bin/val0x04-asm
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/val0x04-asm"]
