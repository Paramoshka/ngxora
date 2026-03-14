FROM rust:1.85-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ARG CARGO_BUILD_FLAGS=""

COPY . .

RUN cargo build --release --bin ngxora ${CARGO_BUILD_FLAGS}
RUN ./target/release/ngxora --check /app/examples/ngxora.conf

# Keep the runtime layer free of apt/dpkg userland packages so image scans only
# cover the libraries we actually need to run the proxy.
FROM gcr.io/distroless/cc-debian12

WORKDIR /etc/ngxora

COPY --from=builder /app/target/release/ngxora /usr/local/bin/ngxora
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY examples/ngxora.conf /etc/ngxora/ngxora.conf

EXPOSE 8080

CMD ["/usr/local/bin/ngxora", "/etc/ngxora/ngxora.conf"]
