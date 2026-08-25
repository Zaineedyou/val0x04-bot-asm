FROM rust:1.88-slim-bookworm AS runtime-build
WORKDIR /app
COPY runtime/Cargo.toml runtime/Cargo.lock ./
COPY runtime/src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home app
WORKDIR /app
COPY --from=runtime-build /app/target/release/val0x04 /usr/local/bin/val0x04
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/val0x04"]
