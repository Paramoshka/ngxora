FROM rust:1.98-bookworm AS builder

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
    && cargo build --locked --release --bin ngxora --target "${RUST_TARGET}" ${CARGO_BUILD_FLAGS} \
    && cp "target/${RUST_TARGET}/release/ngxora" /usr/local/bin/ngxora
RUN /usr/local/bin/ngxora --check /app/examples/basic/ngxora.conf
RUN /usr/local/bin/ngxora --check /app/examples/sbi-ready/ngxora.conf
RUN /usr/local/bin/ngxora --check /app/examples/scp/ngxora.conf
RUN cat LICENSE THIRD-PARTY-NOTICES > /tmp/expected-licenses \
    && /usr/local/bin/ngxora --licenses > /tmp/actual-licenses \
    && cmp /tmp/expected-licenses /tmp/actual-licenses

FROM scratch

WORKDIR /etc/ngxora

COPY --from=builder /usr/local/bin/ngxora /usr/local/bin/ngxora
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY examples/basic/ngxora.conf /etc/ngxora/ngxora.conf
COPY LICENSE THIRD-PARTY-NOTICES /usr/share/licenses/ngxora/

EXPOSE 8080

CMD ["/usr/local/bin/ngxora", "/etc/ngxora/ngxora.conf"]
