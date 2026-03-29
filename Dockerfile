FROM rust:1.85-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake pkg-config libssl-dev ca-certificates musl-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ARG CARGO_BUILD_FLAGS=""

COPY . .

RUN ARCH="$(uname -m)" \
    && case "${ARCH}" in \
        x86_64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
        aarch64|arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported builder architecture: ${ARCH}" >&2; exit 1 ;; \
    esac \
    && rustup target add "${RUST_TARGET}" \
    && cargo build --release --bin ngxora --target "${RUST_TARGET}" ${CARGO_BUILD_FLAGS} \
    && cp "target/${RUST_TARGET}/release/ngxora" /usr/local/bin/ngxora
RUN /usr/local/bin/ngxora --check /app/examples/ngxora.conf

FROM golang:1.26.1-bookworm AS control-plane-builder

WORKDIR /app

COPY control-plane ./control-plane
COPY sdk/go ./sdk/go

ENV CGO_ENABLED=0

RUN cd /app/control-plane \
    && go mod download \
    && go build -trimpath -ldflags="-s -w" -o /usr/local/bin/ngxora-control-plane ./cmd/ngxora-control-plane

FROM scratch AS control-plane

WORKDIR /etc/ngxora

COPY --from=control-plane-builder /usr/local/bin/ngxora-control-plane /usr/local/bin/ngxora-control-plane
COPY --from=control-plane-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

CMD ["/usr/local/bin/ngxora-control-plane"]

FROM scratch

WORKDIR /etc/ngxora

COPY --from=builder /usr/local/bin/ngxora /usr/local/bin/ngxora
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY examples/ngxora.conf /etc/ngxora/ngxora.conf

EXPOSE 8080

CMD ["/usr/local/bin/ngxora", "/etc/ngxora/ngxora.conf"]
