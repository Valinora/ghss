# ---- Build stage ----
FROM rust:1.93-alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl

WORKDIR /app

# Copy workspace manifests and lockfile first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY ghss/Cargo.toml ghss/Cargo.toml
COPY ghss-cli/Cargo.toml ghss-cli/Cargo.toml
COPY ghss-scanner/Cargo.toml ghss-scanner/Cargo.toml
COPY ghss-scanner/migrations ghss-scanner/migrations

# Create stub lib/main files so cargo can resolve the workspace and build deps
RUN mkdir -p ghss/src ghss-cli/src ghss-scanner/src && \
    echo "pub fn _stub() {}" > ghss/src/lib.rs && \
    echo "fn main() {}" > ghss-cli/src/main.rs && \
    echo "fn main() {}" > ghss-scanner/src/main.rs

# Build dependencies only — this layer is cached until Cargo.toml/Cargo.lock change
RUN cargo build --release --package ghss-scanner

# Copy real source and rebuild
COPY ghss/src ghss/src
COPY ghss-cli/src ghss-cli/src
COPY ghss-scanner/src ghss-scanner/src

# Touch files so cargo knows they changed vs the stubs
RUN touch ghss/src/lib.rs ghss-cli/src/main.rs ghss-scanner/src/main.rs

RUN cargo build --release --package ghss-scanner

# ---- Runtime stage ----
FROM gcr.io/distroless/static

COPY --from=builder /app/target/release/ghss-scanner /ghss-scanner

ENTRYPOINT ["/ghss-scanner"]
