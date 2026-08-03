FROM rust:1.88-bookworm AS rust

WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN cargo build --locked --release -p wiremesh-agent-linux

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        conntrack \
        iproute2 \
        nftables \
        procps \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/wiremesh

COPY --from=rust /source/target/release/wiremesh-agent-linux /usr/local/sbin/wiremesh-agent-linux
COPY --chmod=0755 deploy/agent-entrypoint.sh /usr/local/bin/wiremesh-agent-entrypoint

VOLUME ["/var/lib/wiremesh"]
ENTRYPOINT ["wiremesh-agent-entrypoint"]
CMD ["wiremesh-agent-linux"]
