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
#   tailscale         apply VULNFLOW_TS_HOST: tailnet URLs in .env + tailscale serve (or undo)
#   all               dtrack-up, dojo-up, glue-up (no OpenCVE; use setup for everything)
#   up                start everything again after down or a reboot (no rebuild/bootstrap)
#   down              stop everything; volumes (data) are kept
#   destroy [--yes]   delete all containers, data volumes, upstream/ and .env (asks first)
#   status            show containers and health endpoints
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

# Listening TCP sockets that are reachable from outside loopback and the tailnet
# (Tailscale: 100.64.0.0/10 and fd7a:115c:a1e0::/48). Docker-published ports bypass an
# input-chain firewall such as ufw, so a stack that starts publishing on 0.0.0.0 would be
# public even with a "deny incoming" policy. Linux only (ss).
check_exposure() {
  if ! command -v ss >/dev/null; then
    echo "  exposure check skipped (no ss; Linux only)"
    return 0
  fi
  local open
  open="$(ss -ltnH | awk '{a = $4; gsub(/%[^]:]+/, "", a); print a}' | grep -vE \
    '^(127\.[0-9.]+|\[::1\]|\[::ffff:127\.[0-9.]+\]|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9.]+|\[fd7a:115c:a1e0:[0-9a-f:]*\]):[0-9]+$' \
    | sort -u || true)"
  if [[ -z "$open" ]]; then
    echo "  exposure: only loopback and tailnet listeners"
    return 0
  fi
  warn "listening beyond loopback/tailnet (the host firewall must block these;"
  warn "  Docker-published ports bypass ufw):"
  local a
  while read -r a; do warn "    $a"; done <<<"$open"
}

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
  check_exposure
  if [[ -n "${VULNFLOW_TS_HOST:-}" ]]; then
    command -v tailscale >/dev/null || die "VULNFLOW_TS_HOST is set but tailscale is not installed"
    ts_resolve || die "VULNFLOW_TS_HOST=${VULNFLOW_TS_HOST}: cannot resolve the tailnet name"
    echo "  tailnet name $TS_HOST"
  fi
  local mem
  mem="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  ((mem >= 12)) || warn "~${mem} GB RAM; all three stacks together want ~12 GB+"
  local swap
  swap="$(awk '/SwapTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  if ((mem < 16 && swap < 4)); then
    warn "~${mem} GB RAM and ${swap} GB swap: add 4-8 GB swap so the first imports don't get" \
      "OOM-killed (README 'Own machines on a small VM')"
  fi
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

# Upstream defaults that are the same in every OpenCVE install. Values in docker/.env win
# over airflow.cfg (AIRFLOW__SECTION__KEY). On an existing install a new Fernet key makes
# the stored Airflow connections undecryptable; opencve_reset_airflow_connections (run by
# opencve-start) deletes them so install.sh recreates them. A new webserver key only ends
# UI sessions.
OPENCVE_DEFAULT_FERNET="ywvTuNQw6bW-UlEyS0ykTqiz9on1cyMlHT7e1Ddo060="
opencve_harden_airflow() { # docker/.env
  local denv="$1" v
  v="$(sed -n "s/^AIRFLOW__CORE__FERNET_KEY=//p" "$denv" | tr -d "'\"")"
  if [[ -z "$v" || "$v" == "$OPENCVE_DEFAULT_FERNET" ]]; then
    # Fernet key: 32 random bytes, url-safe base64
    set_kv "$denv" AIRFLOW__CORE__FERNET_KEY "$(openssl rand -base64 32 | tr '+/' '-_')"
    log "OpenCVE: random Airflow Fernet key"
  fi
  if ! grep -qE '^AIRFLOW__WEBSERVER__SECRET_KEY=.+' "$denv"; then
    set_kv "$denv" AIRFLOW__WEBSERVER__SECRET_KEY "$(openssl rand -hex 32)"
    log "OpenCVE: random Airflow webserver secret_key (airflow.cfg ships a fixed one)"
  fi
  # Upstream publishes nginx (80) and the Airflow UI (8080) on all interfaces. The values
  # only feed compose's "${PORT}:80" (and a log line in install.sh), so an IP prefix works.
  local k
  for k in OPENCVE_PORT AIRFLOW_WEBSERVER_PORT; do
    v="$(sed -n "s/^$k=//p" "$denv")"
    if [[ -n "$v" && "$v" != *:* ]]; then
      set_kv "$denv" "$k" "127.0.0.1:$v"
      log "OpenCVE: $k bound to 127.0.0.1:$v"
    fi
  done
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
  opencve_harden_airflow "$denv"
  chmod 600 "$denv" "$wenv"
  if [[ -n "${VULNFLOW_TS_HOST:-}" ]]; then
    ts_resolve || die "cannot resolve VULNFLOW_TS_HOST=$VULNFLOW_TS_HOST (is tailscale up?)"
  fi
  opencve_set_origins "$TS_HOST"
  cat <<EOF

Next:
  1. ./poc.sh opencve-start      (first build + CVE import take a long time)
  2. ./poc.sh opencve-bootstrap  (admin, org '${OPENCVE_ORG}', API token, projects, webhooks)
EOF
}

# install.sh init-docker-stack recreates the Airflow connections opencve_postgres and
# opencve_redis on every run, but deletes them with "airflow connections delete", which
# has to decrypt them first and fails (silently) after a Fernet key change; the following
# "connections add" then crashes with InvalidToken. Delete the rows in SQL instead, which
# needs no key. OpenCVE v3.1.0 stores nothing else Fernet-encrypted (no Airflow Variables).
opencve_reset_airflow_connections() {
  [[ -n "$(opencve_compose ps -q --status running postgres 2>/dev/null)" ]] || return 0
  local user
  user="$(sed -n 's/^POSTGRES_USER=//p' "$UP/opencve/docker/.env")"
  opencve_compose exec -T postgres psql -q -U "${user:-opencve}" -d opencve -v ON_ERROR_STOP=1 \
    -c "DO \$\$ BEGIN IF to_regclass('public.connection') IS NOT NULL THEN
          DELETE FROM connection WHERE conn_id IN ('opencve_postgres', 'opencve_redis');
        END IF; END \$\$;" >/dev/null \
    || die "could not reset OpenCVE's Airflow connections"
}

cmd_opencve_start() {
  load_env
  [[ -d "$UP/opencve/docker" ]] || die "run ./poc.sh opencve-prepare first"
  # Upstream's "install.sh start" is these steps followed by an interactive
  # create-superuser prompt. Run the steps (each is an install.sh subcommand) and let
  # opencve-bootstrap create the admin from .env instead, so nothing waits for a human.
  opencve_reset_airflow_connections
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

  wait_http "$(opencve_local_url)/" 300

  # 1. Admin, org, service user, read-write org token (no API for these: Django shell).
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

  # 2. Receiver, attached to OpenCVE's network as "vulnflow-receiver" so Airflow can reach it
  cmd_glue_up
  # 3. Projects + subscriptions from inventory.toml (API)
  vulnflow opencve-bootstrap || die "OpenCVE project sync failed"
  # 4. Per project a webhook notification + an alert automation that sends it. Django
  #    shell, not the API: v3.1.0's API refuses every private webhook URL (no allow-list).
  #    The input line carries the webhook token, so it only goes through the pipe.
  out="$({
    vulnflow opencve-webhook-input
    cat "$ROOT/stacks/opencve/bootstrap_webhooks.py"
  } | opencve_compose exec -T webserver python manage.py shell)" \
    || die "OpenCVE webhook bootstrap failed"
  grep -q '^WEBHOOK ' <<<"$out" || die "unexpected output from OpenCVE webhook bootstrap: $out"
  sed -n 's/^WEBHOOK \(.*\)/  ok    OpenCVE webhook + automation: \1/p' <<<"$out"
  if grep -q '^MISSING ' <<<"$out"; then
    die "OpenCVE projects missing: $(sed -n 's/^MISSING //p' <<<"$out" | tr '\n' ' ')"
  fi
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

# ---- Tailscale -------------------------------------------------------------------
# With VULNFLOW_TS_HOST set, every service stays bound to 127.0.0.1 and `tailscale serve`
# proxies the browser-facing ones on the tailnet only, over HTTPS (MagicDNS certificate):
#   https://<host>             OpenCVE           -> 127.0.0.1:80
#   https://<host>:DT_UI_PORT  Dependency-Track  -> 127.0.0.1:DT_UI_PORT
#   https://<host>:DT_API_PORT DT API (the DT UI calls it from the browser; also SBOM uploads)
#   https://<host>:DD_PORT     DefectDojo        -> 127.0.0.1:DD_PORT
# Not served: Airflow (8080) and the webhook receiver (OpenCVE reaches it on its docker
# network). tailscale serve listens on the Tailscale addresses only and keeps its config
# across reboots. Needs root or `tailscale set --operator=<user>`, and HTTPS certificates
# enabled for the tailnet.
TS_HOST=""            # resolved tailnet name, set by ts_resolve
OPENCVE_LOCAL_PORT=80 # opencve_harden_airflow binds OpenCVE's nginx to 127.0.0.1:80

# VULNFLOW_TS_HOST: a name ("vulnflow.tail1234.ts.net"), or "auto" for this node's MagicDNS name
ts_resolve() {
  local h="${VULNFLOW_TS_HOST:-}"
  [[ -n "$h" ]] || return 1
  if [[ "$h" == auto ]]; then
    command -v tailscale >/dev/null || return 1
    h="$(tailscale status --json 2>/dev/null | python3 -I -c \
      'import json, sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null)" \
      || return 1
  fi
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
  TS_HOST="$h"
}

ts_ports() { # tailnet-port:local-port
  printf '%s\n' "443:$OPENCVE_LOCAL_PORT" "${DT_UI_PORT:-8181}:${DT_UI_PORT:-8181}" \
    "${DT_API_PORT:-8180}:${DT_API_PORT:-8180}" "${DD_PORT:-8280}:${DD_PORT:-8280}"
}

ts_serve() { # on|off
  local pub loc
  while IFS=: read -r pub loc; do
    if [[ "$1" == on ]]; then
      tailscale serve --bg --https="$pub" "http://127.0.0.1:$loc" >/dev/null \
        || die "tailscale serve failed: run as root or 'sudo tailscale set --operator=$USER'," \
          "and enable HTTPS certificates for the tailnet (admin console, DNS)"
    else
      tailscale serve --https="$pub" off >/dev/null 2>&1 || true
    fi
  done < <(ts_ports)
}

# Browser-facing URLs in .env: for the tailnet name in $1, or back to localhost when empty.
# DT_PUBLIC_API_URL is baked into the DT frontend container; DD_SITE_URL and
# DD_CSRF_TRUSTED_ORIGINS go to DefectDojo's uwsgi (stacks/defectdojo/override.yml);
# OPENCVE_URL is used in chat links, so commands on this host use OPENCVE_API_URL.
ts_env_values() {
  local dd="http://localhost:${DD_PORT:-8280}"
  if [[ -n "$1" ]]; then
    printf '%s\n' "DT_PUBLIC_API_URL=https://$1:${DT_API_PORT:-8180}" \
      "DD_SITE_URL=https://$1:${DD_PORT:-8280}" \
      "DD_CSRF_TRUSTED_ORIGINS=https://$1:${DD_PORT:-8280},$dd" \
      "OPENCVE_URL=https://$1" "OPENCVE_API_URL=${OPENCVE_API_URL:-http://localhost}"
  else
    printf '%s\n' "DT_PUBLIC_API_URL=http://localhost:${DT_API_PORT:-8180}" "DD_SITE_URL=$dd" \
      "DD_CSRF_TRUSTED_ORIGINS=$dd" "OPENCVE_URL=http://localhost"
  fi
}

# OpenCVE's Django compares the browser's Origin (https://<host>) with the plain-HTTP
# request nginx forwards, so the tailnet origin must be trusted. Its local settings.py
# (from install.sh prepare, bind-mounted into the webserver) gets a marked block. Written
# in place, not with sed -i: a file bind mount keeps pointing at the old inode.
OPENCVE_SETTINGS_CHANGED=0
opencve_set_origins() { # tailnet name, or empty to remove the block
  local f="$UP/opencve/web/opencve/conf/settings.py" before new
  [[ -f "$f" ]] || return 0
  before="$(cat "$f")"
  new="$(sed '/^# BEGIN vulnflow/,/^# END vulnflow/d' "$f")"
  if [[ -n "$1" ]]; then
    new+=$'\n'"# BEGIN vulnflow (poc.sh): trust the tailscale serve HTTPS origin"
    new+=$'\n'"CSRF_TRUSTED_ORIGINS = [\"https://$1\"]"
    new+=$'\n'"# END vulnflow"
  fi
  [[ "$new" == "$before" ]] && return 0
  printf '%s\n' "$new" >"$f"
  OPENCVE_SETTINGS_CHANGED=1
  if [[ -n "$1" ]]; then
    log "OpenCVE: settings.py trusts origin https://$1"
  else
    log "OpenCVE: tailnet origin removed from settings.py"
  fi
}

# Resolve the tailnet name and write the URLs that depend on it (no-op when unset).
# Returns 1 when VULNFLOW_TS_HOST is set but can't be resolved.
ts_prepare() {
  [[ -n "${VULNFLOW_TS_HOST:-}" ]] || return 0
  ts_resolve || return 1
  ts_env_values "$TS_HOST" | vulnflow env-set
  load_env
  opencve_set_origins "$TS_HOST"
}

installed() { [[ -d "$UP/defectdojo" && -f "$UP/opencve/docker/.env" && -n "${DT_API_KEY:-}" ]]; }

opencve_local_url() { echo "${OPENCVE_API_URL:-${OPENCVE_URL:-http://localhost}}"; }

print_logins() {
  local dt="http://localhost:${DT_UI_PORT:-8181}" dd="http://localhost:${DD_PORT:-8280}"
  local oc="http://localhost"
  if [[ -n "$TS_HOST" ]]; then
    dt="https://$TS_HOST:${DT_UI_PORT:-8181}" dd="https://$TS_HOST:${DD_PORT:-8280}"
    oc="https://$TS_HOST"
  fi
  log "Logins (passwords in .env):"
  log "  Dependency-Track $dt  admin / DT_ADMIN_PASSWORD"
  log "  DefectDojo       $dd  ${DD_ADMIN_USER:-admin} / DD_ADMIN_PASSWORD"
  log "  OpenCVE          $oc  ${OPENCVE_ADMIN_USER:-admin} / OPENCVE_ADMIN_PASSWORD"
}

cmd_tailscale() {
  load_env
  if [[ -n "${VULNFLOW_TS_HOST:-}" ]]; then
    command -v tailscale >/dev/null || die "tailscale not installed"
    ts_prepare || die "cannot resolve VULNFLOW_TS_HOST=$VULNFLOW_TS_HOST" \
      "(is tailscale up, with MagicDNS on?)"
    log "Tailnet name $TS_HOST; URLs in .env updated"
  else
    log "VULNFLOW_TS_HOST empty: removing tailscale serve entries, URLs back to localhost"
    if command -v tailscale >/dev/null; then ts_serve off; fi
    ts_env_values "" | vulnflow env-set
    load_env
    opencve_set_origins ""
  fi
  if installed; then
    cmd_up # recreates the containers whose settings changed, then serves when enabled
  else
    log "Stacks not installed yet; ./poc.sh setup uses these URLs"
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
    "$(opencve_local_url)/"; do
    printf '  %-45s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$u" || echo down)"
  done
  check_exposure
  if [[ -n "${VULNFLOW_TS_HOST:-}" ]] && command -v tailscale >/dev/null; then
    log "tailscale serve:"
    tailscale serve status || true
  fi
}

cmd_down() {
  load_env
  # Glue first: the receiver is attached to OpenCVE's network, which can't be removed
  # while a container still uses it.
  glue_compose down || true
  if [[ -f "$UP/opencve/docker/.env" ]]; then opencve_compose down || true; fi
  docker compose --env-file .env -f stacks/dependency-track/docker-compose.yml down || true
  if [[ -d "$UP/defectdojo" ]]; then dojo_compose down || true; fi
  log "Stopped (volumes kept; ./poc.sh up starts everything again)"
}

# Start an installed stack again (after down or a reboot): existing images, volumes and
# .env, no clone/build/bootstrap. Use setup for a first install or after changing versions.
cmd_up() {
  load_env
  installed || die "not installed yet - run ./poc.sh setup"
  if ! ts_prepare; then
    warn "cannot resolve VULNFLOW_TS_HOST=$VULNFLOW_TS_HOST (is tailscale up?);"
    warn "  starting with the URLs already in .env and without tailscale serve"
  fi
  log "Dependency-Track"
  docker compose --env-file .env -f stacks/dependency-track/docker-compose.yml up -d
  log "DefectDojo"
  dojo_compose up -d
  log "OpenCVE"
  opencve_compose up -d
  # settings.py is a bind mount: a running webserver only sees a change after a restart
  if ((OPENCVE_SETTINGS_CHANGED)); then opencve_compose restart webserver; fi
  log "vulnflow glue"
  cmd_glue_up
  log "Waiting for the services to answer"
  wait_http "http://localhost:${DT_API_PORT:-8180}/health" 600
  wait_http "http://localhost:${DD_PORT:-8280}/login" 600
  wait_http "$(opencve_local_url)/" 300
  wait_http "http://localhost:${VULNFLOW_PORT:-8380}/healthz" 120
  if [[ -n "$TS_HOST" ]]; then
    log "tailscale serve on $TS_HOST"
    ts_serve on
  fi
  cmd_status
  print_logins
}

# Compose projects of the four stacks (DefectDojo's compose has no name:, so it's the
# directory name of the clone). Glue first: it is attached to OpenCVE's network.
COMPOSE_PROJECTS=(vulnflow-glue opencve vulnflow-dtrack defectdojo)

# Remove everything setup created, for a clean reinstall. Works from Docker labels, so it
# also cleans up when .env or the clones are already gone. Keeps the Docker images.
cmd_destroy() {
  cat <<EOF
This permanently deletes:
  - all containers, networks and Docker volumes (= all data: findings, CVE database,
    projects, users) of compose projects: ${COMPOSE_PROJECTS[*]}
  - $UP (OpenCVE and DefectDojo clones, including their generated config/secrets)
  - $ROOT/data
  - $ROOT/.env (all passwords and API keys)
Kept: Docker images (so the next setup is faster) and this repository.
EOF
  if [[ "${1:-}" != "--yes" ]]; then
    [[ -t 0 ]] || die "no terminal to confirm on; run ./poc.sh destroy --yes"
    local answer
    read -r -p "Type 'destroy' to continue: " answer || answer=""
    [[ "$answer" == "destroy" ]] || die "aborted, nothing deleted"
  fi
  local p ids
  for p in "${COMPOSE_PROJECTS[@]}"; do
    ids="$(docker ps -aq --filter "label=com.docker.compose.project=$p")"
    # shellcheck disable=SC2086
    [[ -z "$ids" ]] || docker rm -f $ids >/dev/null
  done
  for p in "${COMPOSE_PROJECTS[@]}"; do
    ids="$(docker network ls -q --filter "label=com.docker.compose.project=$p")"
    # shellcheck disable=SC2086
    [[ -z "$ids" ]] || docker network rm $ids >/dev/null
    ids="$(docker volume ls -q --filter "label=com.docker.compose.project=$p")"
    # shellcheck disable=SC2086
    [[ -z "$ids" ]] || docker volume rm $ids >/dev/null
    log "removed compose project $p"
  done
  rm -rf -- "$UP" "$ROOT/data" "$ROOT/.env"
  log "Done. ./poc.sh setup installs from scratch."
}

cmd_setup() {
  local t0=$SECONDS
  cmd_init
  cmd_check
  # Before any container starts: DT's frontend and DefectDojo's uwsgi read the URLs at creation
  ts_prepare || die "cannot resolve VULNFLOW_TS_HOST=$VULNFLOW_TS_HOST (is tailscale up?)"
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
  if [[ -n "$TS_HOST" ]]; then
    log "tailscale serve on $TS_HOST"
    ts_serve on
  fi
  cmd_status
  log "Setup done in $(((SECONDS - t0) / 60)) min."
  print_logins
  log "Still yours: feed SBOMs (README 'Feed SBOMs') and optional VULNFLOW_CHAT_WEBHOOK."
  if [[ -z "$TS_HOST" ]]; then
    log "All ports are bound to 127.0.0.1: reach them over ssh -L or set VULNFLOW_TS_HOST."
  fi
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
  tailscale) cmd_tailscale ;;
  all)
    cmd_dtrack_up
    cmd_dojo_up
    cmd_glue_up
    ;;
  status) cmd_status ;;
  up) cmd_up ;;
  down) cmd_down ;;
  destroy) cmd_destroy "${2:-}" ;;
  *)
    sed -n '2,25p' "$0"
    exit 1
    ;;
esac
