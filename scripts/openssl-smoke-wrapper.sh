#!/usr/bin/env bash
# Feed premium-e2e-gate's already generated throwaway seed to the detached
# server smoke. Every other OpenSSL operation is delegated byte-for-byte.
set -euo pipefail

if [ "$#" -eq 3 ] && [ "$1" = "rand" ] && [ "$2" = "-hex" ] && [ "$3" = "32" ]; then
  [ -n "${PATANYX_SMOKE_SEED_HEX:-}" ] || {
    echo "openssl smoke wrapper: PATANYX_SMOKE_SEED_HEX is missing" >&2
    exit 2
  }
  printf '%s\n' "$PATANYX_SMOKE_SEED_HEX"
  exit 0
fi

exec "${PATANYX_REAL_OPENSSL:?PATANYX_REAL_OPENSSL is missing}" "$@"
