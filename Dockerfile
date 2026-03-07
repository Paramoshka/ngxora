FROM rust:1.85-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cargo build --release --bin ngxora
RUN ./target/release/ngxora --check /app/examples/ngxora.conf

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /etc/ngxora

COPY --from=builder /app/target/release/ngxora /usr/local/bin/ngxora
COPY examples/ngxora.conf /etc/ngxora/ngxora.conf

EXPOSE 8080

CMD ["/usr/local/bin/ngxora", "/etc/ngxora/ngxora.conf"]
