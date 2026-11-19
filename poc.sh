#!/usr/bin/env bash
# vulnflow PoC orchestrator: OpenCVE + Dependency-Track + DefectDojo + vulnflow glue.
#
# Each upstream project is installed with ITS OWN supported method (OpenCVE install.sh,
# DefectDojo's compose file, Dependency-Track's quickstart compose) instead of a
# hand-merged mega-compose, so upgrades follow upstream docs.
#
# Usage: ./poc.sh <command>
#   setup             everything below in order, unattended (rerunnable; resumes after a failure)
#   init              create .env / fill in any missing random secrets (rerunnable)
#   check             verify docker/compose/git and free ports
#   opencve-prepare   clone OpenCVE, generate its config, replace upstream default passwords
#   opencve-start     build + start OpenCVE, no prompts (upstream: ~30-60 min first time)
#   opencve-bootstrap admin + org + service user + API token, projects, webhooks (rerunnable)
#   dtrack-up         start Dependency-Track 5.x and bootstrap it (admin pw, team, API key)
#   dt-bootstrap      only the Dependency-Track bootstrap step (rerunnable)
#   dojo-up           clone + start DefectDojo and bootstrap it (admin pw, API key)
#   dd-bootstrap      only the DefectDojo bootstrap step (rerunnable)
#   glue-up           build + start vulnflow receiver and dt2dojo loop
#   all               dtrack-up, dojo-up, glue-up (no OpenCVE; use setup for everything)
#   status            show containers and health endpoints
#   down              stop DT, DefectDojo and glue (OpenCVE: use its install.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UP="$ROOT/upstream"
OPENCVE_NET=opencve_default # upstream compose project "opencve", default network
cd "$ROOT"

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2
  exit 1
}

load_env() {
  [[ -f .env ]] || die ".env missing - run ./poc.sh init"
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
}

vulnflow() { python3 -m vulnflow --env-file .env "$@"; }

# Secrets poc.sh generates when empty: NAME:random-bytes
SECRETS=(DT_DB_PASSWORD:24 DT_ADMIN_PASSWORD:24 DD_ADMIN_PASSWORD:24 DD_SECRET_KEY:32
  DD_CREDENTIAL_AES_256_KEY:16 OPENCVE_ADMIN_PASSWORD:24 VULNFLOW_WEBHOOK_TOKEN:32)

cmd_init() {
  if [[ -f .env ]]; then
    log ".env exists; only filling in empty secrets"
  else
    cp .env.example .env
  fi
  chmod 600 .env
  load_env
  local s name n out=""
  for s in "${SECRETS[@]}"; do
    name="${s%%:*}" n="${s##*:}"
    if [[ -z "${!name:-}" ]]; then
      out+="$name=$(openssl rand -hex "$n")"$'\n'
      echo "  gen   $name"
    fi
  done
  # via stdin so the values never show up in a process list
  [[ -z "$out" ]] || printf '%s' "$out" | vulnflow env-set
  log ".env ready (mode 600)"
}

# GNU stat (Linux) vs BSD stat (macOS)
if stat -c %u / >/dev/null 2>&1; then
  file_uid() { stat -c %u "$1"; }
  file_mode() { stat -c %a "$1"; }
  fs_type() { stat -f -c %T "$1"; }
else
  file_uid() { stat -f %u "$1"; }
  file_mode() { stat -f %Lp "$1"; }
  fs_type() { mount | awk -v m="$(df "$1" | awk 'NR==2 {print $NF}')" \
    '$3 == m {gsub(/[(,]/, "", $4); print $4}'; }
fi

# A checkout on a VM shared folder (virtiofs/9p/vboxsf/NFS) can map ownership and modes in
# ways that break the stacks: git refuses foreign-owned clones, chmod 600 may not stick, and
# containers bind-mount config files from upstream/ (OpenCVE's web .env, airflow.cfg).
check_filesystem() {
  local fs probe mode uid
  fs="$(fs_type "$ROOT" 2>/dev/null || true)"
  uid="$(file_uid "$ROOT")"
  probe="$(mktemp "$ROOT/.vulnflow-fscheck.XXXXXX")" || die "cannot create files in $ROOT"
  chmod 600 "$probe" 2>/dev/null || true
  mode="$(file_mode "$probe")"
  rm -f "$probe"
  local shared=0
  case "$fs" in
    virtiofs | v9fs | 9p | fuse* | vboxsf | nfs* | smb* | cifs | prl_fs) shared=1 ;;
  esac
  [[ "$uid" == "$(id -u)" ]] || shared=1
  if [[ "$mode" != "600" ]]; then
    warn "chmod 600 doesn't stick on $ROOT (filesystem: ${fs:-?}, got mode $mode):"
    warn "  .env and OpenCVE's config files would be readable by others. Use a local disk."
  fi
  if ((shared)); then
    warn "$ROOT looks like a shared/mounted folder (filesystem: ${fs:-?}, owner uid $uid," \
      "you are $(id -u)). git is handled, but containers bind-mount files from upstream/;"
    warn "  if a container can't read them (permission denied in its logs), run from a clone" \
      "on the VM's local disk instead."
  else
    echo "  filesystem ${fs:-?}: local, owned by you"
  fi
}

port_free() { ! (ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}' | grep -qE "[:.]$1\$"; }

cmd_check() {
  command -v docker >/dev/null || die "docker not found"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin not found"
  command -v git >/dev/null || die "git not found"
  local t
  for t in openssl curl python3; do command -v "$t" >/dev/null || die "$t not found"; done
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
    || die "python3 >= 3.11 needed on the host (vulnflow uses tomllib)"
  log "docker: $(docker --version)"
  log "compose: $(docker compose version --short)"
  check_filesystem
  load_env
  local p
  for p in 80 8080 "${DT_API_PORT:-8180}" "${DT_UI_PORT:-8181}" "${DD_PORT:-8280}" 8443 \
    "${VULNFLOW_PORT:-8380}"; do
    if port_free "$p"; then echo "  port $p free"; else warn "port $p already in use"; fi
  done
  local mem
  mem="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  ((mem >= 12)) || warn "~${mem} GB RAM; all three stacks together want ~12 GB+"
}

clone_or_update() { # url dir ref
  local url="$1" dir="$2" ref="${3:-}"
  # safe.directory for just these calls: on a shared/mounted folder the clone can be owned
  # by another uid, and git refuses it ("dubious ownership"). No global git config change.
  local g=(git -c "safe.directory=$dir" -C "$dir")
  if [[ ! -d "$dir/.git" ]]; then
    git clone --quiet "$url" "$dir"
  fi
  if [[ -n "$ref" ]]; then
    "${g[@]}" fetch --quiet --tags origin
    "${g[@]}" checkout --quiet "$ref"
  fi
  log "$(basename "$dir") at $("${g[@]}" describe --tags --always 2>/dev/null)"
}

# Set KEY=value in a dotenv-style file (replace or append). Values must be sed-safe
# (we only pass hex secrets and CIDR lists).
set_kv() { # file key value
  local f="$1" k="$2" v="$3"
  if grep -qE "^#? *$k=" "$f"; then
    sed -i.bak -E "s|^#? *$k=.*|$k=$v|" "$f" && rm -f "$f.bak"
  else
    printf '%s=%s\n' "$k" "$v" >>"$f"
  fi
}

opencve_args() { if [[ -n "${OPENCVE_REF:-}" ]]; then echo "-r $OPENCVE_REF"; fi; }
opencve_compose() { (cd "$UP/opencve/docker" && docker compose "$@"); }

# OpenCVE v3.1.0 pins apache-airflow-providers-celery but not celery, so a fresh build gets
# celery 5.7.0 (2026-11-05), which removed celery.backends.database.retry; the Airflow worker
# and scheduler then crash on import (opencve/opencve#810). Pin the versions from Airflow
# 2.10.4's constraints, as upstream PR #817 does. The scheduler image takes requirements.txt
# from a git clone made during the build, so patch the local Dockerfile's pip install line.
# Skipped once upstream's requirements.txt pins celery itself.
OPENCVE_CELERY_PINS="celery==5.4.0 kombu==5.4.2"
opencve_pin_celery() {
  local df="$UP/opencve/scheduler/Dockerfile" req="$UP/opencve/scheduler/requirements.txt"
  if grep -qiE '^celery==' "$req"; then
    log "OpenCVE: upstream pins celery; no build patch needed (drop opencve_pin_celery)"
    return
  fi
  grep -qF "/requirements.txt $OPENCVE_CELERY_PINS" "$df" && return
  grep -q 'pip install --no-cache-dir -r /requirements.txt$' "$df" \
    || die "OpenCVE scheduler/Dockerfile changed; update opencve_pin_celery in poc.sh"
  sed -i.bak "s#pip install --no-cache-dir -r /requirements.txt\$#& $OPENCVE_CELERY_PINS#" "$df"
  rm -f "$df.bak"
  log "OpenCVE: pinned $OPENCVE_CELERY_PINS in the scheduler image (opencve/opencve#810)"
}

cmd_opencve_prepare() {
  load_env
  mkdir -p "$UP"
  # Undo our build patch first so a ref change doesn't trip over a modified file
  [[ -d "$UP/opencve/.git" ]] \
    && git -c "safe.directory=$UP/opencve" -C "$UP/opencve" checkout --quiet -- scheduler/Dockerfile
  clone_or_update https://github.com/opencve/opencve.git "$UP/opencve" "${OPENCVE_REF:-}"
  opencve_pin_celery
  # shellcheck disable=SC2046
  (cd "$UP/opencve/docker" && ./install.sh $(opencve_args) prepare)

  # Upstream ships postgres opencve/opencve and Airflow airflow/airflow. Postgres only
  # reads its password when the volume is first created, so never rotate after that.
  local denv="$UP/opencve/docker/.env" wenv="$UP/opencve/web/opencve/conf/.env" pg
  pg="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$denv")"
  if [[ "$pg" == "opencve" ]]; then
    if [[ -n "$(opencve_compose ps -a -q postgres 2>/dev/null)" ]]; then
      warn "OpenCVE postgres already initialized with the default password; not rotating"
    else
      pg="$(openssl rand -hex 24)"
      set_kv "$denv" POSTGRES_PASSWORD "$pg"
      log "OpenCVE: random postgres password"
    fi
  fi
  # Keep Django's DB URLs in sync with POSTGRES_PASSWORD
  sed -i.bak -E "s#^(OPENCVE_(DATABASE_URL|V1_DATABASE)=postgresql://[^:]+:)[^@]*@#\1$pg@#" "$wenv"
  rm -f "$wenv.bak"
  if grep -q '^_AIRFLOW_WWW_USER_PASSWORD=airflow$' "$denv"; then
    set_kv "$denv" _AIRFLOW_WWW_USER_PASSWORD "$(openssl rand -hex 16)"
    log "OpenCVE: random Airflow UI password (in $denv)"
  fi
  chmod 600 "$denv" "$wenv"
  cat <<EOF

Next:
  1. ./poc.sh opencve-start      (first build + CVE import take a long time)
  2. ./poc.sh opencve-bootstrap  (admin, org '${OPENCVE_ORG}', API token, projects, webhooks)
EOF
}

cmd_opencve_start() {
  load_env
  [[ -d "$UP/opencve/docker" ]] || die "run ./poc.sh opencve-prepare first"
  # Upstream's "install.sh start" is these steps followed by an interactive
  # create-superuser prompt. Run the steps (each is an install.sh subcommand) and let
  # opencve-bootstrap create the admin from .env instead, so nothing waits for a human.
  local step
  for step in init-docker-stack clone-repositories import-opencve-kb start-opencve-dag; do
    # shellcheck disable=SC2046
    (cd "$UP/opencve/docker" && ./install.sh $(opencve_args) "$step") \
      || die "OpenCVE install.sh $step failed"
  done
  # Same check as upstream's verify-container-versions (only built into "start")
  local want web sched
  want="$(sed -n 's/^OPENCVE_VERSION=//p' "$UP/opencve/docker/.env")"
  web="$(opencve_compose exec -T webserver printenv OPENCVE_VERSION 2>/dev/null || true)"
  sched="$(opencve_compose exec -T airflow-scheduler printenv OPENCVE_VERSION 2>/dev/null || true)"
  [[ "$web" == "$want" && "$sched" == "$want" ]] \
    || die "OpenCVE container versions (web '$web', scheduler '$sched') != OPENCVE_VERSION '$want'"
  log "OpenCVE $want web: http://localhost  Airflow: http://localhost:8080"
  log "Next: ./poc.sh opencve-bootstrap"
}

wait_http() { # url seconds
  local i
  for ((i = 0; i < $2; i += 5)); do
    case "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$1" || true)" in
      2* | 3*) return 0 ;;
    esac
    sleep 5
  done
  die "$1 did not come up within $2 s"
}

cmd_opencve_bootstrap() {
  load_env
  [[ -d "$UP/opencve/docker" ]] || die "run ./poc.sh opencve-prepare + opencve-start first"
  [[ -n "$(opencve_compose ps -q webserver 2>/dev/null)" ]] \
    || die "OpenCVE webserver not running - ./poc.sh opencve-start"

  # 1. Let OpenCVE's SSRF guard accept webhooks to its own docker network, where the
  #    receiver is attached as "vulnflow-receiver".
  local subnet wenv="$UP/opencve/web/opencve/conf/.env"
  subnet="$(docker network inspect "$OPENCVE_NET" \
    -f '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' | grep -m1 -v ':')" \
    || die "cannot read the subnet of docker network $OPENCVE_NET"
  if ! grep -qx "OPENCVE_NOTIFICATION_ALLOWED_INTERNAL_NETWORKS=$subnet" "$wenv"; then
    set_kv "$wenv" OPENCVE_NOTIFICATION_ALLOWED_INTERNAL_NETWORKS "$subnet"
    log "OpenCVE: webhooks allowed to $subnet; restarting webserver"
    opencve_compose restart webserver >/dev/null
  fi
  wait_http "${OPENCVE_URL:-http://localhost}/" 300

  # 2. Admin, org, service user, read-write org token (no API for these: Django shell).
  #    Inputs go in on stdin as a JSON header, never on a command line.
  [[ -n "${OPENCVE_ADMIN_PASSWORD:-}" ]] || die "OPENCVE_ADMIN_PASSWORD empty - run ./poc.sh init"
  local out tok
  out="$({
    python3 -I -c 'import json, os
e = os.environ
print("VF = " + json.dumps({
    "org": e["OPENCVE_ORG"], "user": "vulnflow", "token": e.get("OPENCVE_TOKEN", ""),
    "admin": {"username": e.get("OPENCVE_ADMIN_USER") or "admin",
              "email": e.get("OPENCVE_ADMIN_EMAIL") or "admin@localhost.invalid",
              "password": e["OPENCVE_ADMIN_PASSWORD"]}}))'
    cat "$ROOT/stacks/opencve/bootstrap_org.py"
  } | opencve_compose exec -T webserver python manage.py shell)" \
    || die "OpenCVE admin/org/token bootstrap failed"
  if grep -q '^ADMIN_CREATED=1' <<<"$out"; then
    log "OpenCVE: admin '${OPENCVE_ADMIN_USER:-admin}' created (password: OPENCVE_ADMIN_PASSWORD in .env)"
  fi
  tok="$(sed -n 's/^OPENCVE_TOKEN=//p' <<<"$out" | head -n1)"
  if [[ -n "$tok" ]]; then
    printf 'OPENCVE_TOKEN=%s\n' "$tok" | vulnflow env-set
    log "OpenCVE: new org token written to .env as OPENCVE_TOKEN"
    load_env
  elif grep -q '^OPENCVE_TOKEN_OK=1' <<<"$out"; then
    log "OpenCVE: existing OPENCVE_TOKEN still valid"
  else
    die "unexpected output from OpenCVE bootstrap: $out"
  fi

  # 3. Receiver on OpenCVE's network (the webhook URL must resolve when it is saved)
  cmd_glue_up
  # 4. Projects + subscriptions from inventory.toml, webhook notifications
  vulnflow opencve-bootstrap
}

cmd_dtrack_up() {
  load_env
  docker compose --env-file .env -f stacks/dependency-track/docker-compose.yml up -d
  log "Bootstrapping Dependency-Track (waits for the API server; first start takes a while)"
  vulnflow dt-bootstrap || die "bootstrap failed; rerun ./poc.sh dt-bootstrap once DT is healthy"
  log "Dependency-Track UI: http://localhost:${DT_UI_PORT:-8181}  user admin, password"
  log "  DT_ADMIN_PASSWORD in .env; team 'vulnflow' key is in .env as DT_API_KEY"
}

dojo_compose() {
  # Upstream's compose reads these from the environment; without them it falls back to
  # hard-coded keys and ":latest" images.
  [[ -n "${DD_SECRET_KEY:-}" && -n "${DD_CREDENTIAL_AES_256_KEY:-}" ]] \
    || die "DD_SECRET_KEY/DD_CREDENTIAL_AES_256_KEY empty - run ./poc.sh init"
  local ver="${DD_REF:-master}"
  [[ "$ver" == "master" ]] && ver=latest && warn "DD_REF=master: using :latest images"
  (cd "$UP/defectdojo" && DD_PORT="${DD_PORT:-8280}" DJANGO_VERSION="$ver" NGINX_VERSION="$ver" \
    docker compose -f docker-compose.yml -f "$ROOT/stacks/defectdojo/override.yml" "$@")
}

cmd_dojo_up() {
  load_env
  mkdir -p "$UP"
  clone_or_update https://github.com/DefectDojo/django-DefectDojo.git "$UP/defectdojo" \
    "${DD_REF:-master}"
  dojo_compose up -d
  log "Bootstrapping DefectDojo (waits for the initializer; can take several minutes)"
  vulnflow dd-bootstrap || die "bootstrap failed; rerun ./poc.sh dd-bootstrap"
  log "DefectDojo: http://localhost:${DD_PORT:-8280}  user ${DD_ADMIN_USER:-admin}, password"
  log "  DD_ADMIN_PASSWORD in .env; API key in .env as DD_API_KEY"
  warn "DefectDojo's compose publishes on all interfaces (mode: host). Firewall it or put"
  warn "it behind your reverse proxy."
}

glue_compose() {
  local files=(-f deploy/docker-compose.glue.yml)
  if docker network inspect "$OPENCVE_NET" >/dev/null 2>&1; then
    files+=(-f deploy/docker-compose.glue-opencve.yml)
  fi
  docker compose --env-file .env "${files[@]}" "$@"
}

cmd_glue_up() {
  load_env
  [[ -n "${VULNFLOW_WEBHOOK_TOKEN:-}" ]] || die "VULNFLOW_WEBHOOK_TOKEN empty"
  glue_compose up -d --build
  log "Receiver: http://127.0.0.1:${VULNFLOW_PORT:-8380}/opencve"
  if docker network inspect "$OPENCVE_NET" >/dev/null 2>&1; then
    log "  and http://vulnflow-receiver:${VULNFLOW_PORT:-8380}/opencve on $OPENCVE_NET"
  fi
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
  glue_compose down || true
  docker compose --env-file .env -f stacks/dependency-track/docker-compose.yml down || true
  if [[ -d "$UP/defectdojo" ]]; then dojo_compose down || true; fi
  log "Stopped (volumes kept). OpenCVE: cd upstream/opencve/docker && docker compose down"
}

cmd_setup() {
  local t0=$SECONDS
  cmd_init
  cmd_check
  log "[1/4] Dependency-Track"
  cmd_dtrack_up
  log "[2/4] DefectDojo"
  cmd_dojo_up
  log "[3/4] OpenCVE (first run: build ~30-60 min + CVE import 10-30 min)"
  cmd_opencve_prepare
  cmd_opencve_start
  cmd_opencve_bootstrap # also starts the glue (receiver + dt2dojo)
  log "[4/4] Inventory sync (DefectDojo product types, DT coverage report)"
  load_env
  vulnflow sync --create-projects || die "inventory sync failed; rerun ./poc.sh setup"
  cmd_status
  log "Setup done in $(((SECONDS - t0) / 60)) min. Logins (passwords in .env):"
  log "  Dependency-Track http://localhost:${DT_UI_PORT:-8181}  admin / DT_ADMIN_PASSWORD"
  log "  DefectDojo       http://localhost:${DD_PORT:-8280}  ${DD_ADMIN_USER:-admin} / DD_ADMIN_PASSWORD"
  log "  OpenCVE          ${OPENCVE_URL:-http://localhost}  ${OPENCVE_ADMIN_USER:-admin} / OPENCVE_ADMIN_PASSWORD"
  log "Still yours: feed SBOMs (README 'Feed SBOMs'), optional VULNFLOW_CHAT_WEBHOOK,"
  log "TLS/reverse proxy, and firewalling DefectDojo's 8280/8443."
}

case "${1:-}" in
  setup) cmd_setup ;;
  init) cmd_init ;;
  check) cmd_check ;;
  opencve-prepare) cmd_opencve_prepare ;;
  opencve-start) cmd_opencve_start ;;
  opencve-bootstrap) cmd_opencve_bootstrap ;;
  dtrack-up) cmd_dtrack_up ;;
  dt-bootstrap) load_env && vulnflow dt-bootstrap ;;
  dojo-up) cmd_dojo_up ;;
  dd-bootstrap) load_env && vulnflow dd-bootstrap ;;
  glue-up) cmd_glue_up ;;
  all)
    cmd_dtrack_up
    cmd_dojo_up
    cmd_glue_up
    ;;
  status) cmd_status ;;
  down) cmd_down ;;
  *)
    sed -n '2,22p' "$0"
    exit 1
    ;;
esac
