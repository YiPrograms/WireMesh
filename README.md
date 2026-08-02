# WireMesh

WireMesh is a single-controller, on-premises WireGuard access system for user
devices and multiple protected sites. It combines an SQLite-backed Rust
controller, outbound gateway agents for Linux and RouterOS, and a React
administration/self-service console.

## What is implemented

- UUID-based users with unique normalized email linking across local, LDAP, and
  verified-email OIDC identities.
- Explicit Local/LDAP/OIDC login realms, Argon2id passwords, hashed one-time
  enrollment/reset tokens, secure sessions, administrator lockout protection,
  and source-aware groups.
- Paged periodic LDAP full sync, bounded nested-group expansion, safe partial
  failure behavior, and multi-directory disable/reactivation semantics.
- Transactional IPv4 `/32` allocation, quarantine/acknowledgement retirement,
  containing-supernet expansion, and prepared/armed scheduled hard migrations.
- Sites, group grants, overlap validation, typed WireGuard options, ordered
  first-match ACLs, configuration revisions, semantic diffs, and manual or
  download acknowledgement.
- Browser-only X25519 key generation and validation. Client private keys never
  enter an API request or controller storage; incomplete profiles use
  `<CLIENT_PRIVATE_KEY>`.
- An outbound TLS gRPC agent protocol with hashed 256-bit bearer secrets,
  overlapping secret rotation, full desired-state snapshots, persistent caches,
  scheduled cutovers, live-state fingerprints, and drift repair.
- Linux WireGuard, explicit `/32` routes, nftables forwarding policy, and
  conntrack revocation; RouterOS 7.15+ HTTPS REST reconciliation with dedicated
  managed chains and optional compatibility addressing.
- Encrypted provider, SMTP, and RouterOS credentials under an external master
  key, durable SMTP retries, database-enforced append-only audit records,
  Prometheus metrics, health/readiness, and consistent online SQLite snapshots.
- Production container definitions, a Linux systemd unit, and a containerized
  multi-router RouterOS connector.

WireMesh deliberately configures no SNAT. Each protected LAN must route the
client pool back through its gateway unless that gateway is already the LAN's
default router.

## Repository layout

- `crates/controller` — HTTP console API, gRPC control plane, SQLite migrations,
  identity integrations, schedulers, and workers.
- `crates/domain` — identity precedence, IPAM, route validation, ACL evaluation,
  desired state, and client-profile behavior.
- `crates/proto` — versioned bidirectional controller/agent protobuf contract.
- `crates/agent-core` — reconciliation, cache, migration, TLS connection, and
  driver interfaces.
- `crates/agent-linux` — Linux WireGuard/nftables/route/conntrack backend.
- `crates/agent-mikrotik` — RouterOS HTTPS REST backend.
- `crates/key-wasm` — small browser-targetable key primitive crate.
- `web` — React/TypeScript administration and user console.
- `deploy` — production Dockerfiles, Compose example, and systemd assets.

## Development

The host does not need Rust or Node when Docker is available:

```sh
docker compose -f compose.dev.yml run --rm rust cargo test --workspace
docker compose -f compose.dev.yml run --rm rust cargo clippy --workspace --all-targets -- -D warnings
docker compose -f compose.dev.yml run --rm web npm test
docker compose -f compose.dev.yml run --rm web npm run build
```

Run the web development server against a controller on port 8080:

```sh
docker compose -f compose.dev.yml run --rm --service-ports web npm run dev
```

## Controller deployment

Build the image and create deployment material:

```sh
docker build -f deploy/controller.Dockerfile -t wiremesh-controller .
mkdir -p deploy/secrets deploy/tls
docker run --rm wiremesh-controller generate-master-key > deploy/secrets/master.key
chmod 0400 deploy/secrets/master.key deploy/tls/controller.key
chmod 0444 deploy/tls/controller.crt
sudo chown 10001:10001 deploy/secrets/master.key deploy/tls/controller.key
```

The container runs as UID 10001. Ensure that UID can read the master key and
agent TLS files, then start [`deploy/compose.yml`](deploy/compose.yml). Put the
browser endpoint behind an HTTPS reverse proxy; the agent endpoint on port 8443
already requires its configured server certificate.

Bootstrap the first administrator and use the returned seven-day token on the
login screen:

```sh
docker compose -f deploy/compose.yml exec controller \
  wiremesh-controller bootstrap-admin --email admin@example.org --name Administrator
```

Create a gateway agent from the web console or CLI. The 256-bit secret is shown
once:

```sh
docker compose -f deploy/compose.yml exec controller \
  wiremesh-controller create-agent --name edge-1 --kind linux
```

Install the Linux binary, copy
[`wiremesh-agent-linux.service`](deploy/wiremesh-agent-linux.service) and
[`agent.env.example`](deploy/agent.env.example), then enable the service. The
service owns only its selected WireGuard interfaces and a dedicated nftables
table; existing gateway-local input policy remains administrator-managed.
The host must provide `wireguard-tools`, `iproute2`, `nftables`, `conntrack`,
and `sysctl`. Reconciliation enables IPv4 forwarding and fails visibly if the
host policy prevents it.

For RouterOS, build `deploy/mikrotik-agent.Dockerfile`, create a MikroTik agent,
and set the same controller URL, server name, CA, agent ID, secret, and state
directory variables shown in the Linux example. Configure each router under
Sites in the console. Its HTTPS origin, username, password, and CA bundle are
encrypted by the controller and delivered in memory over the authenticated TLS
agent stream; they are not written to the desired-state cache. One connector
can receive targets for multiple assigned gateways.

## Operations

Prometheus metrics are available at `/metrics`; liveness and readiness are
`/healthz` and `/readyz`. The administration dashboard shows client-pool usage,
gateway freshness, and convergence.

Create a consistent snapshot while the controller is running:

```sh
wiremesh-controller --database-url sqlite:///var/lib/wiremesh/wiremesh.db \
  backup --output /var/lib/wiremesh/backups/wiremesh-$(date +%F).db
```

Back up the SQLite snapshot and master-key file separately. A database restore
must use the matching master key or encrypted identity/SMTP settings cannot be
opened. SQLite WAL must remain on a local filesystem; NFS and other network
filesystems are unsupported.

Subnet changes to a different network use Settings → Subnet migrations. A plan
does not alter live state. Every affected gateway must validate and cache its
future snapshot before **Arm** becomes available. Configuration mutations are
paused while a plan is preparing or armed, and the scheduler changes leases,
profiles, controller state, and preloaded agent state at the chosen UTC instant.

## Security boundaries

- Client and gateway private keys are never stored by the controller.
- Arbitrary WireGuard directives and hooks are rejected; only typed options are
  rendered.
- Gateway agent TLS is server-authenticated; the random bearer secret identifies
  the outbound agent. Current and next secrets may overlap during rotation.
- Identity-provider, SMTP, and RouterOS secrets use versioned
  XChaCha20-Poly1305 envelopes.
- Disabling or soft-deleting a user revokes reachable peers. Purge remains
  blocked until every gateway acknowledges the removal, so offline gateways are
  visible availability-over-revocation debt rather than silently ignored.
- Key and address retirement consults retained gateway state history from the
  last acknowledged revision forward. A formerly authorized offline gateway
  therefore cannot be missed after its group grant has already been removed.
- Audit records contain control-plane actions, not packets, flows, client
  private keys, passwords, or raw bearer/token values.
