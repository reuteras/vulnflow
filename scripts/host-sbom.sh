#!/usr/bin/env bash
# Generate a CycloneDX SBOM of a Linux host (installed packages) and upload it to
# Dependency-Track under the sysadmin team tag. Run on the host, or via your config
# management. Needs syft (https://github.com/anchore/syft) on the host.
#
#   ./scripts/host-sbom.sh <team> [hostname]
#
# Tip: trivy works too:  trivy rootfs --format cyclonedx --output sbom.json /
set -euo pipefail

TEAM="${1:?usage: host-sbom.sh <team> [hostname]}"
HOST="${2:-$(hostname -f 2>/dev/null || hostname)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp --suffix=.cdx.json)"
trap 'rm -f "$OUT"' EXIT

command -v syft >/dev/null || { echo "syft not installed" >&2; exit 1; }

# Dir-scan excludes must be relative (./...). Installed software only, no /home etc.
syft scan dir:/ \
  --exclude './proc/**' --exclude './sys/**' --exclude './dev/**' --exclude './run/**' \
  --exclude './home/**' --exclude './tmp/**' --exclude './var/lib/docker/**' \
  -o cyclonedx-json="$OUT" -q

# OS release as "version" makes major upgrades visible as new DT project versions
# shellcheck disable=SC1091
VERSION="$(. /etc/os-release && echo "${ID}-${VERSION_ID}")"

cd "$ROOT"
python3 -m vulnflow upload-sbom --team "$TEAM" --name "host:$HOST" \
  --version "$VERSION" --file "$OUT" --tag "kind-host"
