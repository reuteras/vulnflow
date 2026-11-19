#!/usr/bin/env bash
# vulnflow PoC orchestrator: OpenCVE + Dependency-Track + DefectDojo + vulnflow glue.
#
# Each upstream project is installed with ITS OWN supported method (OpenCVE install.sh,
# DefectDojo's compose file, Dependency-Track's quickstart compose) instead of a
# hand-merged mega-compose, so upgrades follow upstream docs.
#
# Usage: ./poc.sh <command>
#   init             create .env with random secrets
#   check            verify docker/compose/git and free ports
#   opencve-prepare  clone OpenCVE and generate its config (then edit passwords)
#   opencve-start    build + start OpenCVE (upstream says ~30-60 min first time)
#   dtrack-up        start Dependency-Track 5.x
#   dojo-up          clone + start DefectDojo, print admin password
#   glue-up          build + start vulnflow receiver and dt2dojo loop
#   all              dtrack-up, dojo-up, glue-up (OpenCVE is separate: it's slow)
#   status           show containers and health endpoints
#   down             stop DT, DefectDojo and glue (OpenCVE: use its install.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UP="$ROOT/upstream"
cd "$ROOT"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }

load_env() {
  [[ -f .env ]] || die ".env missing - run ./poc.sh init"
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
}

cmd_init() {
  if [[ -f .env ]]; then warn ".env exists, leaving it alone"; return; fi
  cp .env.example .env
  local r1 r2
  r1="$(openssl rand -hex 24)"; r2="$(openssl rand -hex 32)"
  sed -i "s/^DT_DB_PASSWORD=.*/DT_DB_PASSWORD=$r1/" .env
  sed -i "s/^VULNFLOW_WEBHOOK_TOKEN=.*/VULNFLOW_WEBHOOK_TOKEN=$r2/" .env
  chmod 600 .env
  log ".env created with random DB password and webhook token (mode 600)"
}

port_free() { ! (ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}' | grep -qE "[:.]$1\$"; }

cmd_check() {
  command -v docker >/dev/null || die "docker not found"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not found"
  command -v git >/dev/null || die "git not found"
  log "docker: $(docker --version)"
  log "compose: $(docker compose version --short)"
  load_env
  local p
  for p in 80 8080 "${DT_API_PORT:-8180}" "${DT_UI_PORT:-8181}" "${DD_PORT:-8280}" 8443 \
           "${VULNFLOW_PORT:-8380}"; do
    if port_free "$p"; then echo "  port $p free"; else warn "port $p already in use"; fi
  done
  local mem
  mem="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  (( mem >= 12 )) || warn "~${mem} GB RAM; all three stacks together want ~12 GB+"
}

clone_or_update() { # url dir ref
  local url="$1" dir="$2" ref="${3:-}"
  if [[ ! -d "$dir/.git" ]]; then
    git clone --quiet "$url" "$dir"
  fi
  if [[ -n "$ref" ]]; then
    git -C "$dir" fetch --quiet --tags origin
    git -C "$dir" checkout --quiet "$ref"
  fi
  log "$(basename "$dir") at $(git -C "$dir" describe --tags --always 2>/dev/null)"
}

opencve_args() { if [[ -n "${OPENCVE_REF:-}" ]]; then echo "-r $OPENCVE_REF"; fi; }

cmd_opencve_prepare() {
  load_env
  mkdir -p "$UP"
  clone_or_update https://github.com/opencve/opencve.git "$UP/opencve"
  # shellcheck disable=SC2046
  (cd "$UP/opencve/docker" && ./install.sh $(opencve_args) prepare)
  cat <<EOF

Next:
  1. Edit passwords in  $UP/opencve/docker/.env  and  $UP/opencve/web/opencve/conf/.env
  2. Run ./poc.sh opencve-start   (first build takes a long time)
  3. In OpenCVE: create organization '${OPENCVE_ORG}', projects matching inventory.toml
     (opencve_project), and a read-write org API token -> OPENCVE_TOKEN in .env
EOF
}

cmd_opencve_start() {
  load_env
  [[ -d "$UP/opencve/docker" ]] || die "run ./poc.sh opencve-prepare first"
  # shellcheck disable=SC2046
  (cd "$UP/opencve/docker" && ./install.sh $(opencve_args) start)
  log "OpenCVE web: http://localhost  Airflow: http://localhost:8080"
}

cmd_dtrack_up() {
  load_env
  docker compose --env-file .env -f stacks/dependency-track/docker-compose.yml up -d
  log "Dependency-Track UI: http://localhost:${DT_UI_PORT:-8181} (admin/admin, forced change)"
  log "Create a team + API key (BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO,"
  log "VIEW_VULNERABILITY) and put it in .env as DT_API_KEY"
}

cmd_dojo_up() {
  load_env
  mkdir -p "$UP"
  clone_or_update https://github.com/DefectDojo/django-DefectDojo.git "$UP/defectdojo" \
    "${DD_REF:-master}"
  (cd "$UP/defectdojo" && DD_PORT="${DD_PORT:-8280}" docker compose up -d)
  log "Waiting for the DefectDojo initializer (can take a few minutes)..."
  local pw=""
  for _ in $(seq 1 60); do
    pw="$(cd "$UP/defectdojo" && docker compose logs initializer 2>/dev/null \
          | grep -m1 'Admin password:' || true)"
    [[ -n "$pw" ]] && break
    sleep 10
  done
  if [[ -n "$pw" ]]; then
    log "DefectDojo: http://localhost:${DD_PORT:-8280}  user admin  ${pw#*Admin }"
    warn "Store that password now - it is only printed on first initialization"
  else
    warn "No admin password yet; check: (cd upstream/defectdojo && docker compose logs initializer)"
  fi
  warn "DefectDojo's compose publishes on all interfaces (mode: host). Firewall it or put"
  warn "it behind your reverse proxy."
}

cmd_glue_up() {
  load_env
  [[ -n "${VULNFLOW_WEBHOOK_TOKEN:-}" ]] || die "VULNFLOW_WEBHOOK_TOKEN empty"
  docker compose --env-file .env -f deploy/docker-compose.glue.yml up -d --build
  log "Receiver: http://<this-host>:${VULNFLOW_PORT:-8380}/opencve"
  log "In OpenCVE add a Webhook notification per project with header"
  log "  X-Vulnflow-Token: <VULNFLOW_WEBHOOK_TOKEN from .env>"
}

cmd_status() {
  load_env
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
    | grep -Ei 'NAMES|opencve|airflow|dtrack|defectdojo|django|nginx|vulnflow|postgres|redis' || true
  local u
  for u in "http://localhost:${DT_API_PORT:-8180}/health" \
           "http://localhost:${DD_PORT:-8280}/login" \
           "http://localhost:${VULNFLOW_PORT:-8380}/healthz" \
           "http://localhost/"; do
    printf '  %-45s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$u" || echo down)"
  done
}

cmd_down() {
  load_env
  docker compose --env-file .env -f deploy/docker-compose.glue.yml down || true
  docker compose --env-file .env -f stacks/dependency-track/docker-compose.yml down || true
  [[ -d "$UP/defectdojo" ]] && (cd "$UP/defectdojo" && docker compose down) || true
  log "Stopped (volumes kept). OpenCVE: cd upstream/opencve/docker && docker compose down"
}

case "${1:-}" in
  init) cmd_init ;;
  check) cmd_check ;;
  opencve-prepare) cmd_opencve_prepare ;;
  opencve-start) cmd_opencve_start ;;
  dtrack-up) cmd_dtrack_up ;;
  dojo-up) cmd_dojo_up ;;
  glue-up) cmd_glue_up ;;
  all) cmd_dtrack_up; cmd_dojo_up; cmd_glue_up ;;
  status) cmd_status ;;
  down) cmd_down ;;
  *) sed -n '2,22p' "$0"; exit 1 ;;
esac
