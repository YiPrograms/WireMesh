#!/bin/sh
set -eu

data_directory=${WIREMESH_DATA_DIRECTORY:-/var/lib/wiremesh}

# Docker creates a missing bind-mount source as a root-owned directory. Prepare
# it before dropping privileges so a completely empty host directory works on
# first startup as well as subsequent upgrades.
if [ "$(id -u)" -eq 0 ]; then
  umask 077
  mkdir -p "$data_directory"
  chown -R wiremesh:wiremesh "$data_directory"
  exec gosu wiremesh "$0" "$@"
fi

# Administrative subcommands must retain their normal one-shot behavior. Only
# the long-running server performs persistent first-start initialization.
if [ "${1:-serve}" != "serve" ]; then
  exec wiremesh-controller "$@"
fi

if [ -n "${WIREMESH_MASTER_KEY_FILE:-}" ]; then
  master_key_file=$WIREMESH_MASTER_KEY_FILE
elif [ -s /run/secrets/wiremesh_master_key ]; then
  # Compatibility with deployments created before automatic initialization.
  master_key_file=/run/secrets/wiremesh_master_key
else
  master_key_file=$data_directory/master.key
fi
tls_certificate=${WIREMESH_AGENT_TLS_CERT:-$data_directory/tls/controller.crt}
tls_key=${WIREMESH_AGENT_TLS_KEY:-$data_directory/tls/controller.key}
controller_hostname=${WIREMESH_HOSTNAME:-localhost}
admin_email=${WIREMESH_BOOTSTRAP_ADMIN_EMAIL:-admin@example.com}
admin_name=${WIREMESH_BOOTSTRAP_ADMIN_NAME:-Administrator}

export WIREMESH_MASTER_KEY_FILE="$master_key_file"
export WIREMESH_AGENT_TLS_CERT="$tls_certificate"
export WIREMESH_AGENT_TLS_KEY="$tls_key"

umask 077
mkdir -p "$data_directory" "$(dirname "$master_key_file")" \
  "$(dirname "$tls_certificate")" "$(dirname "$tls_key")"

if [ ! -s "$master_key_file" ]; then
  temporary_master_key=$(mktemp "$(dirname "$master_key_file")/.master-key.XXXXXX")
  wiremesh-controller generate-master-key > "$temporary_master_key"
  chmod 0400 "$temporary_master_key"
  mv "$temporary_master_key" "$master_key_file"
  echo "WireMesh generated its master key in the persistent data volume."
fi

if [ ! -s "$tls_certificate" ] || [ ! -s "$tls_key" ]; then
  case "$controller_hostname" in
    *[!0-9.]* ) subject_alt_name="DNS:$controller_hostname" ;;
    * ) subject_alt_name="IP:$controller_hostname" ;;
  esac
  temporary_tls_key=$(mktemp "$(dirname "$tls_key")/.controller-key.XXXXXX")
  temporary_tls_certificate=$(mktemp "$(dirname "$tls_certificate")/.controller-certificate.XXXXXX")
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -keyout "$temporary_tls_key" \
    -out "$temporary_tls_certificate" \
    -subj "/CN=$controller_hostname" \
    -addext "subjectAltName=$subject_alt_name" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
    -addext "extendedKeyUsage=serverAuth"
  chmod 0400 "$temporary_tls_key"
  chmod 0444 "$temporary_tls_certificate"
  mv "$temporary_tls_key" "$tls_key"
  mv "$temporary_tls_certificate" "$tls_certificate"
  cp "$tls_certificate" "$(dirname "$tls_certificate")/controller-ca.pem"
  chmod 0444 "$(dirname "$tls_certificate")/controller-ca.pem"
  echo "WireMesh generated agent TLS for $controller_hostname."
else
  case "$controller_hostname" in
    *[!0-9.]* ) hostname_check="-checkhost" ;;
    * ) hostname_check="-checkip" ;;
  esac
  if ! openssl x509 -in "$tls_certificate" -noout \
    "$hostname_check" "$controller_hostname" >/dev/null; then
    echo "The stored agent TLS certificate is not valid for $controller_hostname." >&2
    echo "Restore the original WIREMESH_HOSTNAME or rotate the agent certificate and CA." >&2
    exit 1
  fi
fi

wiremesh-controller migrate
bootstrap_result=$(wiremesh-controller bootstrap-admin-if-needed \
  --email "$admin_email" --name "$admin_name")
if [ -n "$bootstrap_result" ]; then
  echo
  echo "========== INITIAL WIREMESH ADMINISTRATOR =========="
  echo "$bootstrap_result"
  echo "Save the enrollment token above; it expires in seven days."
  echo "====================================================="
  echo
fi

exec wiremesh-controller "$@"
