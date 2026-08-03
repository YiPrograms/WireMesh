FROM rust:1.88-bookworm AS rust
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN cargo build --locked --release -p wiremesh-agent-mikrotik

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin wiremesh \
    && install -d -o wiremesh -g wiremesh /var/lib/wiremesh
COPY --from=rust /source/target/release/wiremesh-agent-mikrotik /usr/local/bin/wiremesh-agent-mikrotik
COPY --chmod=0755 deploy/agent-entrypoint.sh /usr/local/bin/wiremesh-agent-entrypoint
ENV WIREMESH_RUN_AS_USER=wiremesh
VOLUME ["/var/lib/wiremesh"]
ENTRYPOINT ["wiremesh-agent-entrypoint"]
CMD ["wiremesh-agent-mikrotik"]
