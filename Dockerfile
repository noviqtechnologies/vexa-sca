# Stage 1: Build native Rust binaries
FROM rust:1-slim-bookworm AS builder
WORKDIR /app

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Cache cargo dependencies with stub sources
RUN mkdir -p src/bin && \
    echo "pub fn lib() {}" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/vexa_sca.rs && \
    echo "fn main() {}" > src/bin/sca.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source code
COPY src ./src

# Touch source files to force cargo to recompile real binary targets
RUN touch src/lib.rs src/main.rs src/bin/vexa_sca.rs src/bin/sca.rs && \
    cargo build --release

# Stage 2: Minimal hardened runtime image
FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="Vexa SCA" \
      org.opencontainers.image.description="Vexa SCA - Software Composition Analysis & Security Engine" \
      org.opencontainers.image.source="https://github.com/noviqtechnologies/vexa-sca" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binaries from builder stage
COPY --from=builder /app/target/release/vexa-sca /usr/local/bin/vexa-sca
COPY --from=builder /app/target/release/vexa /usr/local/bin/vexa
COPY --from=builder /app/target/release/sca /usr/local/bin/sca

WORKDIR /workspace
ENTRYPOINT ["vexa-sca"]
CMD ["--help"]
