# ═══════════════════════════════════════════════════════════
#  NetVanguard v1.0.1 - Multi-Stage Dockerfile
#  (Academic Submission Build)
# ═══════════════════════════════════════════════════════════

# Stage 1: Build Environment
FROM rust:1.75-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the application in release mode
RUN cargo build --release

# Stage 2: Runtime Environment
FROM debian:bookworm-slim

# Install runtime dependencies (nmap, pcap, ssl)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libssl-dev \
    nmap \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/netvanguard /app/netvanguard

# Copy static assets (UI)
COPY static /app/static

# Expose API/Web port
EXPOSE 8080

# Run the application
CMD ["./netvanguard"]
