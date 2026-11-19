#!/usr/bin/env bash
# CI step: build a CycloneDX SBOM for the repo/image and push it to Dependency-Track.
# Works in GitLab CI / GitHub Actions / Jenkins. Needs: syft, curl, base64, jq.
#
# Env: DT_URL, DT_API_KEY (BOM_UPLOAD + PROJECT_CREATION_UPLOAD),
#      PROJECT_NAME, PROJECT_VERSION, TEAM_TAG (e.g. team-dev), [TARGET] (default: dir:.)
set -euo pipefail
: "${DT_URL:?}" "${DT_API_KEY:?}" "${PROJECT_NAME:?}" "${PROJECT_VERSION:?}" "${TEAM_TAG:?}"
TARGET="${TARGET:-dir:.}"

syft scan "$TARGET" -o cyclonedx-json=sbom.cdx.json -q

jq -n --arg name "$PROJECT_NAME" --arg ver "$PROJECT_VERSION" --arg tag "$TEAM_TAG" \
      --rawfile bom sbom.cdx.json \
  '{projectName:$name, projectVersion:$ver, autoCreate:true,
    projectTags:[{name:$tag},{name:"kind-app"}], bom:($bom|@base64)}' > payload.json

curl -fsS -X PUT "$DT_URL/api/v1/bom" \
  -H "X-Api-Key: $DT_API_KEY" -H "Content-Type: application/json" \
  --data @payload.json
echo
rm -f payload.json
