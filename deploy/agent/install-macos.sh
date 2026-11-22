#!/usr/bin/env bash
# Install (or remove) the vulnflow push agent on a MacBook, as the logged-in user.
#
#   deploy/agent/install-macos.sh SOURCE [HOST]   install or update, then load the launchd job
#   deploy/agent/install-macos.sh --uninstall     unload the job and remove the agent
#
# SOURCE is the vulnflow server's clone as an ssh path, e.g. vulnflow:containers/vulnflow.
# Everything is fetched from there in one ssh connection: the agent script, the launchd
# plist and this Mac's bundle (config.json + its own upload-only Dependency-Track key,
# written by `python3 -m vulnflow agent-bundle` from machines.toml). HOST is the name in
# machines.toml; default: this Mac's short host name.
#
# Installs (all private to the user):
#   ~/.local/share/vulnflow-agent/vulnflow-agent.py
#   ~/.config/vulnflow-agent/config.json + key            (dir 700, files 600)
#   ~/Library/LaunchAgents/local.vulnflow.agent.plist     daily 11:15, log ~/Library/Logs/vulnflow-agent.log
# Runs with macOS's own /usr/bin/python3 (needs the Command Line Tools). syft is only needed
# for language_paths and [code.*] directories: brew install syft.
set -euo pipefail
umask 077

LABEL=local.vulnflow.agent
AGENT_DIR="$HOME/.local/share/vulnflow-agent"
CONF_DIR="$HOME/.config/vulnflow-agent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DOMAIN="gui/$(id -u)"

die() {
  echo "error: $*" >&2
  exit 1
}

[[ "$(uname -s)" == Darwin ]] || die "this installer is for macOS (Linux servers use the Ansible role)"
[[ $EUID -ne 0 ]] || die "run as the user whose Mac this is, not with sudo"

if [[ "${1:-}" == --uninstall ]]; then
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  rm -rf "$AGENT_DIR" "$CONF_DIR"
  echo "removed the vulnflow agent (revoke its key on the server: python3 -m vulnflow agent-revoke <host>)"
  exit 0
fi

[[ $# -ge 1 && $# -le 2 && "$1" != -* ]] || die "usage: $0 SOURCE [HOST]   or   $0 --uninstall"
src="$1"
host="${2:-$(hostname -s)}"
remote="${src%%:*}"
path="${src#*:}"
[[ "$src" == *:* && -n "$remote" && -n "$path" ]] || die "SOURCE must look like server:path/to/vulnflow"
# both end up in a remote shell command: allow only plain names and paths
[[ "$path" =~ ^[A-Za-z0-9._/~-]+$ ]] || die "unexpected characters in path $path"
[[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "unexpected characters in host $host"

xcode-select -p >/dev/null 2>&1 || die "/usr/bin/python3 needs the Command Line Tools: xcode-select --install"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "fetching the agent and the bundle for $host from $src"
files="scripts/vulnflow-agent.py deploy/agent/$LABEL.plist data/agents/$host/config.json data/agents/$host/key"
# shellcheck disable=SC2029 # expanded locally on purpose; both values are validated above
ssh "$remote" "cd $path && tar -cf - $files" | tar -xf - -C "$tmp" ||
  die "fetch failed: is there a bundle for $host? (python3 -m vulnflow agent-bundle $host on the server)"

/usr/bin/python3 -I - "$tmp/data/agents/$host/config.json" "$host" <<'EOF' || die "the bundle is not for $host"
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
sys.exit(0 if cfg.get("host") == sys.argv[2] else 1)
EOF

mkdir -p "$AGENT_DIR" "$CONF_DIR" "$(dirname "$PLIST")" "$HOME/Library/Logs"
chmod 700 "$CONF_DIR"
install -m 644 "$tmp/scripts/vulnflow-agent.py" "$AGENT_DIR/vulnflow-agent.py"
install -m 600 "$tmp/data/agents/$host/config.json" "$tmp/data/agents/$host/key" "$CONF_DIR/"
sed "s|__HOME__|$HOME|g" "$tmp/deploy/agent/$LABEL.plist" >"$tmp/agent.plist"
plutil -lint -s "$tmp/agent.plist"
install -m 644 "$tmp/agent.plist" "$PLIST"

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"

command -v syft >/dev/null || echo "note: syft not found (only needed for language_paths/code): brew install syft"
/usr/bin/python3 -I "$AGENT_DIR/vulnflow-agent.py" --config "$CONF_DIR/config.json" --dry-run
echo "installed; runs daily at 11:15. Now: launchctl kickstart $DOMAIN/$LABEL; log: ~/Library/Logs/vulnflow-agent.log"
