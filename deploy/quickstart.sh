#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./quickstart.sh <controller-dns-name> [admin-email] [admin-name]

Examples:
  ./quickstart.sh vpn.example.org admin@example.org "VPN Administrator"
  ./quickstart.sh wiremesh.internal

The DNS name must resolve to this host for gateway agents. The generated TLS
certificate is self-signed; install tls/controller-ca.pem on every agent.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

wiremesh_host=${1:-}
admin_email=${2:-}
admin_name=${3:-Administrator}
if [[ -z "$wiremesh_host" ]]; then
  usage >&2
  exit 2
fi
if [[ ! "$wiremesh_host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  echo "controller DNS name is invalid: $wiremesh_host" >&2
  exit 2
fi
if [[ -n "$admin_email" && "$admin_email" != *@* ]]; then
  echo "administrator email is invalid: $admin_email" >&2
  exit 2
fi

for command in docker openssl curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is missing: $command" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required" >&2
  exit 1
fi

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$script_directory"
umask 077
mkdir -p secrets tls
# Docker bind-mounts the TLS directory, so UID 10001 must be able to traverse
# it. The private files themselves remain mode 0400.
chmod 0755 secrets tls

wiremesh_image=${WIREMESH_IMAGE:-ghcr.io/yiprograms/wiremesh:latest}
if [[ ! -s secrets/master.key ]]; then
  temporary_master_key=$(mktemp secrets/master.key.XXXXXX)
  docker run --rm "$wiremesh_image" generate-master-key > "$temporary_master_key"
  mv "$temporary_master_key" secrets/master.key
  echo "Generated secrets/master.key"
else
  echo "Keeping existing secrets/master.key"
fi

if [[ ! -s tls/controller.crt || ! -s tls/controller.key ]]; then
  temporary_key=$(mktemp tls/controller.key.XXXXXX)
  temporary_certificate=$(mktemp tls/controller.crt.XXXXXX)
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -keyout "$temporary_key" \
    -out "$temporary_certificate" \
    -subj "/CN=$wiremesh_host" \
    -addext "subjectAltName=DNS:$wiremesh_host" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
    -addext "extendedKeyUsage=serverAuth"
  mv "$temporary_key" tls/controller.key
  mv "$temporary_certificate" tls/controller.crt
  cp tls/controller.crt tls/controller-ca.pem
  echo "Generated a self-signed agent TLS certificate for $wiremesh_host"
else
  if ! openssl x509 -in tls/controller.crt -noout -checkhost "$wiremesh_host" >/dev/null; then
    echo "existing TLS certificate is not valid for $wiremesh_host" >&2
    echo "replace tls/controller.crt and tls/controller.key, or use the original hostname" >&2
    exit 1
  fi
  echo "Keeping existing tls/controller.crt and tls/controller.key"
  if [[ ! -s tls/controller-ca.pem ]]; then
    cp tls/controller.crt tls/controller-ca.pem
  fi
fi

existing_agent_id=
existing_agent_secret=
existing_http_bind=
if [[ -f .env ]]; then
  while IFS='=' read -r key value; do
    case "$key" in
      WIREMESH_AGENT_ID) existing_agent_id=$value ;;
      WIREMESH_AGENT_SECRET) existing_agent_secret=$value ;;
      WIREMESH_HTTP_BIND) existing_http_bind=$value ;;
    esac
  done < .env
fi
cat > .env <<EOF
WIREMESH_HOST=$wiremesh_host
WIREMESH_IMAGE=$wiremesh_image
WIREMESH_MIKROTIK_IMAGE=${WIREMESH_MIKROTIK_IMAGE:-ghcr.io/yiprograms/wiremesh-mikrotik-agent:latest}
WIREMESH_HTTP_BIND=${WIREMESH_HTTP_BIND:-${existing_http_bind:-127.0.0.1}}
WIREMESH_HTTP_PORT=${WIREMESH_HTTP_PORT:-8080}
WIREMESH_AGENT_PORT=${WIREMESH_AGENT_PORT:-8443}
WIREMESH_AGENT_ID=$existing_agent_id
WIREMESH_AGENT_SECRET=$existing_agent_secret
EOF
chmod 0600 .env

docker run --rm --user 0:0 --entrypoint chmod \
  --volume "$script_directory/secrets:/secrets" \
  --volume "$script_directory/tls:/tls" \
  "$wiremesh_image" 0400 /secrets/master.key /tls/controller.key
docker run --rm --user 0:0 --entrypoint chmod \
  --volume "$script_directory/tls:/tls" \
  "$wiremesh_image" 0444 /tls/controller.crt /tls/controller-ca.pem
docker run --rm --user 0:0 --entrypoint chown \
  --volume "$script_directory/secrets:/secrets" \
  --volume "$script_directory/tls:/tls" \
  "$wiremesh_image" 10001:10001 /secrets/master.key /tls/controller.key

docker compose -f compose.quickstart.yml pull controller
docker compose -f compose.quickstart.yml up -d controller

echo "Waiting for WireMesh readiness..."
ready=false
for _ in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:${WIREMESH_HTTP_PORT:-8080}/readyz" >/dev/null; then
    ready=true
    break
  fi
  sleep 2
done
if [[ "$ready" != true ]]; then
  docker compose -f compose.quickstart.yml logs --tail=100 controller >&2
  echo "WireMesh did not become ready within 120 seconds" >&2
  exit 1
fi

echo
echo "WireMesh is ready: http://127.0.0.1:${WIREMESH_HTTP_PORT:-8080}"
echo "Agent endpoint: https://${wiremesh_host}:${WIREMESH_AGENT_PORT:-8443}"
echo "Agent CA certificate: $script_directory/tls/controller-ca.pem"

if [[ -n "$admin_email" ]]; then
  echo
  echo "Administrator enrollment response (save the one-time token):"
  docker compose -f compose.quickstart.yml exec -T controller \
    wiremesh-controller bootstrap-admin --email "$admin_email" --name "$admin_name"
else
  echo
  echo "Bootstrap an administrator with:"
  echo "docker compose -f compose.quickstart.yml exec controller wiremesh-controller bootstrap-admin --email admin@example.org --name Administrator"
fi

echo
echo "For production, put the HTTP console behind an HTTPS reverse proxy."
echo "Do not delete secrets/master.key; back it up separately from the database."
