# Stage 1: Builder
# Use a standard Rust image as the build environment.
FROM rust:1.85-bookworm AS builder

# Install the musl toolchain for static linking
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# Copy the source code and build the release binary
COPY . .

# Build the application with static linking flags
RUN RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Runner
FROM gcr.io/distroless/static

# Copy the statically linked binary from the builder stage
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/ngxora /ngxora

# Set the entry point to run the application
CMD ["/ngxora"]
