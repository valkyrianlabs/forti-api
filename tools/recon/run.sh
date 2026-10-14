#!/usr/bin/env bash
# Runs the read-only GUI recorder in a pinned Playwright container (podman, dev box).
#   set -a; . ./.env; set +a; tools/recon/run.sh
# Credentials pass through the environment only (never argv). The repository is mounted read-only
# except the catalog directory the recorder writes to.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${FORTIGATE_HOST:?}" "${FORTI_API_RECON_ADMIN_PASS:?}"
IMAGE="localhost/forti-api-recon:$(sha256sum tools/recon/Containerfile | cut -c1-16)"
podman image exists "$IMAGE" || podman build --quiet --tag "$IMAGE" --file tools/recon/Containerfile tools/recon >/dev/null
version=$(python3 -c 'import tomllib; print(tomllib.load(open("codegen/api.toml","rb"))["fortios_version"])')
add_host=()
[ -n "${FORTIGATE_RESOLVE_IP:-}" ] && add_host=(--add-host "$FORTIGATE_HOST:$FORTIGATE_RESOLVE_IP")
export FORTI_API_RECON_ADMIN_USER=${FORTI_API_RECON_ADMIN_USER:-forti-api-recon}
podman run --rm --init "${add_host[@]}" \
  -v "$PWD:/work:ro,Z" -v "$PWD/codegen/catalog/$version:/work/codegen/catalog/$version:Z" -w /work \
  --env FORTIGATE_HOST --env FORTIGATE_ADMIN_HTTPS_PORT --env FORTI_API_RECON_ADMIN_USER \
  --env FORTI_API_RECON_ADMIN_PASS --env RECON_MAX_PAGES --env RECON_SETTLE_MS --env RECON_VERBOSE --env RECON_DEBUG_LINKS \
  "$IMAGE" python3 -I tools/recon/recorder.py
