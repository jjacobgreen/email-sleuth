############################################################
# Email Sleuth container image
# - Builds the Rust project from source in a builder stage
# - Copies the optimized binary plus sample config into a
#   minimal runtime image where you can invoke `email-sleuth`
#   or the `es` alias.
############################################################

# ---------- Builder stage ----------
FROM rust:1.84-bullseye AS builder

ARG APP_DIR=/app
WORKDIR ${APP_DIR}

# System dependencies needed for cargo build (vendored OpenSSL still needs pkg-config)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        clang \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation by copying manifests first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch
RUN rm -rf src

# Copy full source tree
COPY . .

# Build optimized binary
RUN cargo build --release

# ---------- Runtime stage ----------
FROM debian:bullseye-slim

ARG APP_HOME=/opt/email-sleuth
WORKDIR ${APP_HOME}

ENV EMAIL_SLEUTH_CONFIG=/etc/email-sleuth/config.toml

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Copy binary (+symlink) and example assets
COPY --from=builder /app/target/release/email-sleuth /usr/local/bin/email-sleuth
RUN ln -s /usr/local/bin/email-sleuth /usr/local/bin/es

COPY --from=builder /app/email-sleuth.toml /etc/email-sleuth/config.toml
COPY --from=builder /app/examples ./examples

# Provide a writable workspace for results/input mounting
RUN mkdir -p /data
WORKDIR /data

# Default to bash shell so `docker run -it` drops you into an interactive prompt.
ENTRYPOINT ["/bin/bash"]
