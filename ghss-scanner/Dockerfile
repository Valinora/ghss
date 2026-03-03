# ---- Build stage ----
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl

WORKDIR /app
COPY . .

RUN cargo build --release --package ghss-scanner

# ---- Runtime stage ----
FROM gcr.io/distroless/static

COPY --from=builder /app/target/release/ghss-scanner /ghss-scanner

ENTRYPOINT ["/ghss-scanner"]
