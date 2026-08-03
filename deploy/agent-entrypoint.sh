#!/bin/sh
set -eu

state_directory=${WIREMESH_STATE_DIRECTORY:-/var/lib/wiremesh}
ca_certificate=${WIREMESH_CONTROLLER_CA:-}

if [ -z "$ca_certificate" ] || [ ! -f "$ca_certificate" ] || [ ! -s "$ca_certificate" ]; then
  echo "WireMesh controller CA is missing or empty: ${ca_certificate:-WIREMESH_CONTROLLER_CA is unset}" >&2
  echo "Copy controller-ca.pem into the configured read-only bind mount before starting the agent." >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  umask 077
  mkdir -p "$state_directory"
  chmod 0700 "$state_directory"

  if [ -n "${WIREMESH_RUN_AS_USER:-}" ]; then
    chown -R "$WIREMESH_RUN_AS_USER:$WIREMESH_RUN_AS_USER" "$state_directory"
    exec gosu "$WIREMESH_RUN_AS_USER" "$0" "$@"
  fi
fi

exec "$@"
