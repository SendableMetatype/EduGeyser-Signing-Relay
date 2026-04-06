FROM rust:1.82-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/edugeyser-signing-relay /usr/local/bin/

EXPOSE 8080

ENV BIND_ADDR=0.0.0.0:8080
ENV RUST_LOG=edugeyser_signing_relay=info

# Mount accounts.json via volume: -v ./accounts.json:/data/accounts.json
ENV ACCOUNTS_FILE=/data/accounts.json
WORKDIR /data

ENTRYPOINT ["edugeyser-signing-relay"]
CMD ["serve"]
