#!/usr/bin/env python3
"""vulnflow agent: build this machine's SBOMs and push them to Dependency-Track.

    vulnflow-agent.py [--config PATH] [--dry-run | --out DIR]

Runs on every server and laptop from a timer (deploy/agent/: systemd on Linux, launchd on
macOS); nothing connects *to* the machine. The config is written per host on the vulnflow
server by `python3 -m vulnflow agent-bundle` (from machines.toml) and copied here
with the host's own Dependency-Track API key, in a file next to it called `key` (mode 600).

Default config path: /etc/vulnflow-agent/config.json on Linux,
~/.config/vulnflow-agent/config.json on macOS, or $VULNFLOW_AGENT_CONFIG.

Self-contained on purpose: standard library only, one file, and it must keep running on the
Python 3 that ships with macOS (3.9). syft (https://github.com/anchore/syft) does the
package cataloguing; Homebrew and macOS apps are read directly.

Dependency-Track projects, each tagged with its owner (team-<team>) and kind-<kind>:
  host:<host>        the host scans (system, brew, languages, apps) merged into one SBOM
  container:<image>  one per running container image of docker, root's podman (needs its
                     API socket: podman.socket) and users' rootless podman (exported as an
                     OCI archive on stdout to a file under /var/tmp); Forgejo runner job
                     containers are skipped
  code:<name>        a directory with application code and its installed dependencies

An upload replaces a project's components, so a project is only uploaded when every scan
that makes it up worked; otherwise the previous SBOM stays. A failing container or code
project does not hold back the others. Exit code 1 if anything failed.

Homebrew and app components are matched by CPE only (no package-URL type, no OSV data).
NVD vendor names can't be derived from Homebrew metadata: the default guess is vendor =
product, CPE_VENDORS has a few known exceptions, and `[cpe_map]` in machines.toml (copied
into the config) overrides both.

Upstream behaviour relied on: `syft scan ... -o cyclonedx-json -q` writes the SBOM to stdout,
SYFT_FILE_METADATA_SELECTION=none stops the `file` components (syft 1.57.2), and the
`podman:` source talks to the podman API socket;
`brew info --json=v2 --installed` (formulae[].installed[].version, casks[].installed) was
checked against Homebrew on macOS on 2026-11-21; Dependency-Track 5.2.2 PUT /api/v1/bom
(BOM_UPLOAD, plus PROJECT_CREATION_UPLOAD for autoCreate; projectTags are applied when the
project is created).
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import plistlib
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote

CONFIG_FORMAT = 1
NOTHING_TO_SCAN = 3  # exit code of a scan with nothing to look at (no brew, not macOS)
EXTRA_PATH = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/home/linuxbrew/.linuxbrew/bin",
    "/usr/bin",
    "/bin",
)
SYSTEM_EXCLUDES = (
    "./proc/**",
    "./sys/**",
    "./dev/**",
    "./run/**",
    "./home/**",
    "./tmp/**",
    "./root/.cache/**",  # uv/pip download caches, not installed software
    "./var/cache/**",  # downloaded .deb files
    "./var/lib/docker/**",  # images belong to the containers scan
    "./var/lib/containerd/**",
    "./var/lib/containers/**",  # podman/buildah storage
    # one component per kernel module (1,100+); the kernel itself is found from /boot and
    # dpkg. The systemd unit's ProtectKernelModules hides these anyway, so a run by hand
    # and a timer run give the same SBOM.
    "./usr/lib/modules/**",
    "./lib/modules/**",
)
# syft lists every file a package owns as a `file` component (40k+ on a Debian server);
# Dependency-Track can't match files, so they are neither catalogued nor uploaded.
SYFT_ENV = {"SYFT_FILE_METADATA_SELECTION": "none"}
PODMAN_SOCKET_HINT = "is the podman socket on? (systemctl enable --now podman.socket)"
# Forgejo/act runner job containers (`<prefix>_WORKFLOW-<sha256>_JOB-<name>`) only live while
# a workflow runs; they are not part of the host
RUNNER_JOB_RE = re.compile(r"(^|_)WORKFLOW-[0-9a-f]{64}(_|$)")
# rootless podman images are exported here for syft; on disk, /tmp is often a tmpfs
ARCHIVE_DIR = "/var/tmp"  # noqa: S108 - only as mkdtemp() parent (private 700 dir)
# relative to $HOME; plus `npm root -g` when npm exists
DEFAULT_LANGUAGE_PATHS = (
    ".local/share/uv/tools",
    ".local/pipx/venvs",
    ".local/share/pipx/venvs",
    ".cargo/bin",
)
APP_DIRS = ("/Applications", "~/Applications")
# formula/cask/bundle name -> "vendor:product" as NVD spells it, where they differ
CPE_VENDORS = {
    "bash": "gnu:bash",
    "coreutils": "gnu:coreutils",
    "curl": "haxx:curl",
    "git": "git-scm:git",
    "gnupg": "gnupg:gnupg",
    "node": "nodejs:node.js",
    "openssl": "openssl:openssl",
    "python": "python:python",
    "sqlite": "sqlite:sqlite",
    "vim": "vim:vim",
    "wget": "gnu:wget",
}

Doc = dict[str, Any]  # runtime alias: PEP 585 generics work on 3.9


class ScanError(RuntimeError):
    pass


class NothingToScan(Exception):
    pass


# ------------------------------------------------------------------------ running tools
def search_path() -> str:
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    home_bin = str(Path.home() / ".local" / "bin")
    for p in (home_bin, *EXTRA_PATH):
        if p not in parts:
            parts.append(p)
    return os.pathsep.join(parts)


def which(tool: str) -> str | None:
    return shutil.which(tool, path=search_path())


def run(
    argv: list[str], timeout: float = 1800, stdout_file: Any = None, **kw: Any
) -> tuple[int, str, str]:
    """Run argv (never through a shell); returns (code, stdout, stderr). With stdout_file
    (an open binary file) stdout goes there instead and "" is returned for it."""
    env = kw.pop("env", None) or {**os.environ, "PATH": search_path()}
    out: dict[str, Any] = (
        {"stdout": stdout_file, "stderr": subprocess.PIPE} if stdout_file else {"capture_output": True}
    )
    try:
        r = subprocess.run(  # noqa: S603 - argv list from fixed tools and config paths
            argv, timeout=timeout, check=False, env=env, **out, **kw
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError(f"{argv[0]} timed out after {timeout:.0f}s") from e
    except OSError as e:
        raise ScanError(f"cannot run {argv[0]}: {e}") from e
    stdout = "" if stdout_file else r.stdout.decode("utf-8", "replace")
    return r.returncode, stdout, r.stderr.decode("utf-8", "replace")


def syft(target: str, extra: tuple[str, ...] = ()) -> list[Doc]:
    exe = which("syft")
    if not exe:
        raise ScanError("syft not installed")
    env = {**os.environ, "PATH": search_path(), **SYFT_ENV}
    code, out, err = run([exe, "scan", target, *extra, "-o", "cyclonedx-json", "-q"], env=env)
    if code != 0:
        raise ScanError(f"syft {target} failed ({code}): {err.strip()[:300]}")
    return parse_docs(out)


# ----------------------------------------------------------------------- CycloneDX bits
def parse_docs(raw: str) -> list[Doc]:
    """Zero or more concatenated JSON documents."""
    dec = json.JSONDecoder()
    docs: list[Doc] = []
    i, n = 0, len(raw)
    while True:
        while i < n and raw[i].isspace():
            i += 1
        if i >= n:
            return docs
        try:
            obj, i = dec.raw_decode(raw, i)
        except ValueError as e:
            raise ScanError(f"invalid JSON: {e}") from e
        if not isinstance(obj, dict):
            raise ScanError("invalid JSON: expected an object")
        docs.append(obj)


def _spec_key(doc: Doc) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", str(doc.get("specVersion", "1.5"))))


def merge_boms(docs: list[Doc]) -> Doc:
    """The union of all components, duplicates and `file` entries dropped, in one CycloneDX
    document.

    Metadata and the dependency graph are dropped (not needed for matching); specVersion is
    the highest of the inputs so newer syft fields stay valid."""
    spec = max((_spec_key(d) for d in docs), default=(1, 5))
    seen = set()
    comps: list[Doc] = []
    for n, d in enumerate(docs):
        for c in d.get("components") or []:
            if c.get("type") == "file":
                continue
            key = (c.get("purl", ""), c.get("name", ""), c.get("version", ""), c.get("type", ""))
            if key in seen:
                continue
            seen.add(key)
            comps.append({**c, "bom-ref": f"s{n}:{c.get('bom-ref') or len(comps)}"})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": ".".join(str(x) for x in spec),
        "version": 1,
        "components": comps,
    }


def _cpe_part(s: str) -> str:
    return re.sub(r"[^a-z0-9._]", "_", s.lower())


def make_cpe(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{_cpe_part(vendor)}:{_cpe_part(product)}:{_cpe_part(version)}:*:*:*:*:*:*:*"


def resolve_cpe(keys: list[str], guess: tuple[str, str], cpe_map: dict[str, str]) -> tuple[str, str]:
    """vendor, product: the operator's map first, then the built-in table, then the guess."""
    for table in (cpe_map, CPE_VENDORS):
        for k in keys:
            if k in table:
                vendor, _, product = table[k].partition(":")
                return vendor, product
    return guess


def component(name: str, version: str, source: str, vp: tuple[str, str], ident: str = "") -> Doc:
    return {
        "type": "application",
        "bom-ref": f"{source}:{ident or name}@{version}",
        "name": name,
        "version": version,
        # No package-URL type exists for Homebrew or app bundles; `generic` is the honest one.
        "purl": f"pkg:generic/{quote(ident or name, safe='')}@{quote(version, safe='')}",
        "cpe": make_cpe(vp[0], vp[1], version),
        "properties": [{"name": "vulnflow:source", "value": source}],
    }


def bom(components: list[Doc]) -> Doc:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def clean_brew_version(v: Any) -> str:
    """Homebrew appends the bottle revision as `_N` (3.12.7_1); NVD versions don't have it."""
    return re.sub(r"_\d+$", "", str(v or "").strip())


def brew_bom(info: Doc, cpe_map: dict[str, str]) -> Doc:
    """SBOM from `brew info --json=v2 --installed`."""
    comps: list[Doc] = []
    for f in info.get("formulae") or []:
        name = str(f["name"])
        product = name.split("@")[0]  # python@3.12 -> python
        for inst in f.get("installed") or []:
            ver = clean_brew_version(inst.get("version"))
            if ver:
                vp = resolve_cpe([name, product], (product, product), cpe_map)
                comps.append(component(name, ver, "homebrew", vp))
    for c in info.get("casks") or []:
        token = str(c["token"])
        inst = c.get("installed")
        ver = clean_brew_version(inst if isinstance(inst, str) else c.get("version"))
        if ver:
            comps.append(
                component(token, ver, "homebrew-cask", resolve_cpe([token], (token, token), cpe_map))
            )
    return bom(comps)


def app_entry(plist: Doc, cpe_map: dict[str, str]) -> Doc | None:
    bundle_id = str(plist.get("CFBundleIdentifier") or "")
    name = str(plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or "")
    ver = str(plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion") or "").strip()
    if not (bundle_id and name and ver):
        return None
    # com.google.Chrome -> google:chrome; org.mozilla.firefox -> mozilla:firefox
    parts = bundle_id.lower().split(".")
    guess = (parts[1], parts[-1]) if len(parts) >= 3 else (parts[-1], parts[-1])
    vp = resolve_cpe([bundle_id, name], guess, cpe_map)
    return component(name, ver, "macos-app", vp, ident=bundle_id)


def apps_bom(plists: list[Doc], cpe_map: dict[str, str]) -> Doc:
    entries = (app_entry(p, cpe_map) for p in plists)
    return bom([c for c in entries if c is not None])


# ---------------------------------------------------------------------------- the scans
def scan_system(cfg: Doc) -> list[Doc]:
    if sys.platform == "darwin":
        raise ScanError("the system scan is for Linux; use brew/apps on macOS")
    excludes: tuple[str, ...] = ()
    for x in SYSTEM_EXCLUDES:
        excludes += ("--exclude", x)
    return syft("dir:/", excludes)


def scan_languages(cfg: Doc) -> list[Doc]:
    rel = cfg.get("language_paths") or list(DEFAULT_LANGUAGE_PATHS)
    dirs = [Path.home() / p for p in rel]
    npm = which("npm")
    if npm:
        code, out, _ = run([npm, "root", "-g"], timeout=60)
        if code == 0 and out.strip():
            dirs.append(Path(out.strip()))
    docs: list[Doc] = []
    for d in dirs:
        if d.is_dir():
            docs.extend(syft(f"dir:{d}"))
    return docs


def _brew_owner(brew: str) -> dict[str, Any]:
    """Homebrew refuses to run as root: when we are root, run it as the owner of brew."""
    if os.geteuid() != 0:
        return {}
    st = os.stat(brew)
    if st.st_uid == 0:
        raise ScanError(f"{brew} is owned by root; Homebrew can't run as root")
    pw = pwd.getpwuid(st.st_uid)
    env = {**os.environ, "PATH": search_path(), "HOME": pw.pw_dir, "USER": pw.pw_name}
    return {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": [], "env": env}


def scan_brew(cfg: Doc) -> list[Doc]:
    brew = which("brew")
    if not brew:
        raise NothingToScan("Homebrew not found")
    kw = _brew_owner(brew)
    env = kw.pop("env", None) or {**os.environ, "PATH": search_path()}
    env.update(HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1", HOMEBREW_NO_ENV_HINTS="1")
    code, out, err = run([brew, "info", "--json=v2", "--installed"], timeout=600, env=env, **kw)
    if code != 0:
        raise ScanError(f"brew info failed ({code}): {err.strip()[:300]}")
    docs = parse_docs(out)
    if not docs:
        raise ScanError("brew info printed nothing")
    return [brew_bom(docs[0], cfg.get("cpe_map") or {})]


def read_app_plists() -> list[Doc]:
    out: list[Doc] = []
    for d in APP_DIRS:
        root = Path(d).expanduser()
        if not root.is_dir():
            continue
        for app in sorted(root.glob("*.app")):
            try:
                with (app / "Contents" / "Info.plist").open("rb") as fh:
                    out.append(plistlib.load(fh))
            except (OSError, plistlib.InvalidFileException, ValueError) as e:
                print(f"  note  skip {app}: {e}", file=sys.stderr)
    return out


def scan_apps(cfg: Doc) -> list[Doc]:
    if sys.platform != "darwin":
        raise NothingToScan("not macOS")
    return [apps_bom(read_app_plists(), cfg.get("cpe_map") or {})]


HOST_SCANS = {"system": scan_system, "brew": scan_brew, "languages": scan_languages, "apps": scan_apps}


def clean_version(raw: str) -> str:
    first = raw.strip().splitlines()[0] if raw.strip() else ""
    return re.sub(r"[^A-Za-z0-9._-]", "", first) or "unknown"


def os_version() -> str:
    osr = Path("/etc/os-release")
    if osr.is_file():
        vals = {}
        for line in osr.read_text(encoding="utf-8", errors="replace").splitlines():
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip().strip('"')
        if vals.get("ID"):
            return clean_version(f"{vals['ID']}-{vals.get('VERSION_ID', '')}".rstrip("-"))
    sw = which("sw_vers")
    if sw:
        code, out, _ = run([sw, "-productVersion"], timeout=30)
        if code == 0:
            return clean_version(f"macos-{out.strip()}")
    return clean_version(f"{os.uname().sysname}-{os.uname().release}")


def split_image(ref: str) -> tuple[str, str]:
    """`ghcr.io/o/app:1.2` -> (`ghcr.io/o/app`, `1.2`); digest-only or untagged gets a stand-in."""
    base, _, digest = ref.partition("@")
    if ":" in base.rsplit("/", 1)[-1]:
        name, tag = base.rsplit(":", 1)
    else:
        name, tag = base, ""
    return name, clean_version(tag or digest[:19] or "latest")


def is_podman_shim(docker: str) -> bool:
    """podman-docker installs a `docker` that runs podman; its images are podman's."""
    code, out, _ = run([docker, "--version"], timeout=30)
    return code == 0 and "podman" in out.lower()


def rootless_podman_users() -> list[pwd.struct_passwd]:
    """Users with running rootless podman containers: the non-root owners of conmon
    processes. Only root can act for them, and only on Linux."""
    if sys.platform != "linux" or os.geteuid() != 0:
        return []
    uids = set()
    for proc in Path("/proc").iterdir():
        try:
            if not proc.name.isdigit() or (proc / "comm").read_text().strip() != "conmon":
                continue
            for line in (proc / "status").read_text().splitlines():
                if line.startswith("Uid:"):
                    uids.add(int(line.split()[1]))
        except (OSError, ValueError, IndexError):
            continue  # the process ended, or isn't ours to read
    users = []
    for uid in sorted(uids - {0}):
        try:
            users.append(pwd.getpwuid(uid))
        except KeyError:
            continue
    return users


def as_user(pw: pwd.struct_passwd) -> dict[str, Any]:
    """run() keywords for running a tool as pw (rootless podman needs its runtime dir)."""
    env = {
        **os.environ,
        "PATH": search_path(),
        "HOME": pw.pw_dir,
        "USER": pw.pw_name,
        "XDG_RUNTIME_DIR": f"/run/user/{pw.pw_uid}",
    }
    return {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": [], "env": env, "cwd": "/"}


def running_images() -> tuple[list[tuple[str, str]], list[str]]:
    """(source, image) for every running container of docker, root's podman and each user's
    rootless podman, each image once (first source wins), runner job containers left out;
    plus the errors of a source that could not be listed. source is "docker", "podman" or
    "podman@<user>"."""
    sources: list[tuple[str, str, dict[str, Any]]] = []
    docker, podman = which("docker"), which("podman")
    if docker and not (podman and is_podman_shim(docker)):
        sources.append(("docker", docker, {}))
    if podman:
        sources.append(("podman", podman, {}))
        sources += [(f"podman@{pw.pw_name}", podman, as_user(pw)) for pw in rootless_podman_users()]
    if not sources:
        raise ScanError("neither docker nor podman is installed")
    images: dict[str, str] = {}
    errors: list[str] = []
    for source, exe, kw in sources:
        fmt = "{{.Names}}\t{{.Image}}"
        code, out, err = run([exe, "ps", "--format", fmt], timeout=120, **kw)
        if code != 0:
            errors.append(f"{source} ps failed ({code}): {err.strip()[:300]}")
            continue
        for line in out.splitlines():
            names, _, ref = line.strip().rpartition("\t")
            if ref and not RUNNER_JOB_RE.search(names):
                images.setdefault(ref, source)
    return sorted((src, ref) for ref, src in images.items()), errors


def scan_image(source: str, ref: str) -> list[Doc]:
    """syft reads docker's and root's podman's images through their sockets; a user's
    rootless image is exported by that user as an OCI archive on stdout into a file of
    root's, which root then scans. The archive is never a path podman has to open: rootless
    podman runs in the user's own mount namespace, which doesn't see the systemd unit's
    private /tmp and /var/tmp."""
    runtime, _, user = source.partition("@")
    if not user:
        try:
            return syft(f"{runtime}:{ref}")
        except ScanError as e:
            raise ScanError(f"{e}; {PODMAN_SOCKET_HINT}" if runtime == "podman" else str(e)) from e
    podman = which("podman")
    if not podman:
        raise ScanError("podman not installed")
    pw = pwd.getpwnam(user)
    d = Path(tempfile.mkdtemp(prefix="vulnflow-agent-", dir=ARCHIVE_DIR))
    try:
        archive = d / "image.tar"
        argv = [podman, "image", "save", "--format", "oci-archive", ref]
        with archive.open("wb") as fh:
            code, _, err = run(argv, timeout=1800, stdout_file=fh, **as_user(pw))
        if code != 0:
            raise ScanError(f"podman image save as {user} failed ({code}): {err.strip()[:300]}")
        return syft(f"oci-archive:{archive}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def git_version(path: str) -> str:
    git = which("git")
    if not git:
        return "unknown"
    # safe.directory: as root, git refuses a repository owned by another user
    code, out, _ = run(
        [git, "-c", f"safe.directory={path}", "-C", path, "describe", "--tags", "--always"]
    )
    return clean_version(out) if code == 0 else "unknown"


# ------------------------------------------------------------------------------ upload
class Result:
    def __init__(self, project: str, version: str, sbom: Doc, tags: list[str], scans: list[str]):
        self.project = project
        self.version = version
        self.sbom = sbom
        self.tags = tags
        self.scans = scans
        self.notes: list[str] = []


def upload(dt_url: str, key: str, r: Result, timeout: float = 120) -> str:
    body = {
        "projectName": r.project,
        "projectVersion": r.version,
        "autoCreate": True,
        "bom": base64.b64encode(json.dumps(r.sbom).encode()).decode(),
        "projectTags": [{"name": t} for t in r.tags],
    }
    req = urllib.request.Request(  # noqa: S310 - dt_url scheme checked in load_config
        dt_url.rstrip("/") + "/api/v1/bom",
        data=json.dumps(body).encode(),
        method="PUT",
        headers={"X-Api-Key": key, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return str((json.loads(resp.read() or b"{}") or {}).get("token", ""))
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode("utf-8", "replace")
        raise ScanError(f"Dependency-Track answered HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, OSError) as e:
        raise ScanError(f"cannot reach Dependency-Track at {dt_url}: {e}") from e


# ------------------------------------------------------------------------------ driver
def collect_host(cfg: Doc) -> Result | None:
    hp = cfg.get("host_project")
    if not hp:
        return None
    docs: list[Doc] = []
    done: list[str] = []
    skipped: list[str] = []
    for scan in hp["scans"]:
        try:
            docs.extend(HOST_SCANS[scan](cfg))
            done.append(scan)
        except NothingToScan as e:
            skipped.append(f"{scan} ({e})")
    if not done:
        raise ScanError("no scan produced anything: " + "; ".join(skipped))
    r = Result(hp["name"], hp.get("version") or os_version(), merge_boms(docs), hp["tags"], done)
    r.notes = [f"skipped {s}" for s in skipped]
    return r


def collect_containers(cfg: Doc) -> tuple[list[Result], list[str]]:
    spec = cfg.get("containers")
    if not spec:
        return [], []
    results: list[Result] = []
    images, problems = running_images()
    errors = [f"containers on {cfg.get('host')}: {p}" for p in problems]
    for source, ref in images:
        name, version = split_image(ref)
        try:
            docs = scan_image(source, ref)
        except ScanError as e:
            errors.append(f"container:{name}: {e}")
            continue
        results.append(
            Result(f"container:{name}", version, merge_boms(docs), spec["tags"], ["containers"])
        )
    return results, errors


def collect_code(c: Doc) -> Result:
    docs = syft(f"dir:{c['path']}")
    return Result(
        c["name"], c.get("version") or git_version(c["path"]), merge_boms(docs), c["tags"], ["code"]
    )


def default_config_path() -> Path:
    env = os.environ.get("VULNFLOW_AGENT_CONFIG")
    if env:
        return Path(env)
    if sys.platform == "darwin":
        return Path.home() / ".config" / "vulnflow-agent" / "config.json"
    return Path("/etc/vulnflow-agent/config.json")


def load_config(path: Path) -> Doc:
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"cannot read config {path}: {e}") from e
    if not isinstance(cfg, dict) or cfg.get("vulnflow_agent_config") != CONFIG_FORMAT:
        raise SystemExit(f"{path}: not a vulnflow agent config (format {CONFIG_FORMAT})")
    if not str(cfg.get("dt_url", "")).startswith(("https://", "http://")):
        raise SystemExit(f"{path}: dt_url must be an http(s) URL")
    for scan in (cfg.get("host_project") or {}).get("scans", []):
        if scan not in HOST_SCANS:
            raise SystemExit(f"{path}: unknown scan {scan!r}")
    return cfg


def read_key(path: Path) -> str:
    try:
        key = path.read_text(encoding="utf-8").strip()
    except OSError as e:
        raise SystemExit(f"cannot read API key {path}: {e}") from e
    if not key:
        raise SystemExit(f"{path} is empty")
    if os.stat(path).st_mode & 0o077:
        print(f"  warn  {path} is readable by others; chmod 600 it", file=sys.stderr)
    return key


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vulnflow-agent", description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--config", type=Path, default=None, help="default: see the module docstring")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="scan and report, upload nothing")
    mode.add_argument("--out", type=Path, help="write the SBOMs to this directory instead of uploading")
    a = ap.parse_args(argv)

    cfg_path = a.config or default_config_path()
    cfg = load_config(cfg_path)
    key = "" if (a.dry_run or a.out) else read_key(cfg_path.parent / "key")
    failed = 0

    def deliver(r: Result) -> None:
        n = len(r.sbom["components"])
        extra = f"; {', '.join(r.notes)}" if r.notes else ""
        if a.dry_run:
            what = f"{n} components from {', '.join(r.scans)}{extra}"
            print(f"  plan  {r.project}@{r.version} {r.tags}: {what}")
            return
        if a.out:
            a.out.mkdir(parents=True, exist_ok=True)
            f = a.out / (re.sub(r"[^A-Za-z0-9._-]", "_", f"{r.project}@{r.version}") + ".json")
            f.write_text(json.dumps(r.sbom), encoding="utf-8")
            print(f"  wrote {f}: {n} components{extra}")
            return
        token = upload(cfg["dt_url"], key, r)
        what = f"{n} components from {', '.join(r.scans)}{extra}"
        print(f"  ok    {r.project}@{r.version}: {what} (token {token or '-'})")

    jobs: list[tuple[str, Any]] = [("host", lambda: collect_host(cfg))]
    jobs += [(c["name"], (lambda c=c: collect_code(c))) for c in cfg.get("code") or []]
    for label, job in jobs:
        try:
            r = job()
            if r is not None:
                deliver(r)
        except ScanError as e:
            failed += 1
            name = (cfg.get("host_project") or {}).get("name", label) if label == "host" else label
            print(f"  FAIL  {name}: {e}")
    try:
        images, errors = collect_containers(cfg)
    except ScanError as e:
        images, errors = [], [f"containers on {cfg.get('host')}: {e}"]
    for img in images:
        try:
            deliver(img)
        except ScanError as e:
            errors.append(f"{img.project}: {e}")
    for problem in errors:
        failed += 1
        print(f"  FAIL  {problem}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
