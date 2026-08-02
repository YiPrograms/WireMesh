FROM node:22-bookworm-slim AS web
WORKDIR /source/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:1.88-bookworm AS rust
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN cargo build --locked --release -p wiremesh-controller

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin wiremesh \
    && install -d -o wiremesh -g wiremesh /app/web /var/lib/wiremesh
COPY --from=rust /source/target/release/wiremesh-controller /usr/local/bin/wiremesh-controller
COPY --from=web /source/web/dist/ /app/web/
USER wiremesh
VOLUME ["/var/lib/wiremesh"]
EXPOSE 8080 8443
ENV WIREMESH_DATABASE_URL=sqlite:///var/lib/wiremesh/wiremesh.db \
    WIREMESH_WEB_DIRECTORY=/app/web \
    WIREMESH_LISTEN=0.0.0.0:8080 \
    WIREMESH_AGENT_LISTEN=0.0.0.0:8443
ENTRYPOINT ["wiremesh-controller"]
CMD ["serve"]

