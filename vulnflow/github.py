"""SBOMs from GitHub releases into Dependency-Track (`vulnflow github-sboms`).

For projects that build on GitHub while vulnflow is reachable only over the tailnet, the
server pulls instead of CI pushing: no Dependency-Track key or tailnet access is stored
in GitHub. Per [github.<name>] in machines.toml it asks the REST API for the newest
release (drafts and prereleases skipped), downloads the first asset matching `asset`
(default `*.cdx.json`) and uploads it as project <name>, version = the release tag,
tags team-<team>, kind-app and source-github.

- An SBOM that is not CycloneDX JSON or lists no package (no component with a purl) is
  refused: an empty SBOM would close every finding of the project.
- The newest release is uploaded again once a day, also when nothing changed: `prune`
  deactivates the newest version of a `kind-*` project after 7 days without an upload,
  and releases are rarer than that.
- With `verify = { identity = ..., issuer = ... }` the asset's `<asset>.sig.bundle` is
  downloaded too and checked with `cosign verify-blob` (the cosign binary of the glue
  image; the Sigstore bundle can't be verified with the standard library). A missing
  bundle or a failed check means no upload and an error, and the previous upload stays.
- Only https://github.com/<repo>/releases/download/... is downloaded, whatever the API
  answers. Public repositories need no token; VULNFLOW_GITHUB_TOKEN (read-only) only
  raises the API rate limit (60 requests an hour without one) and is not sent with the
  download.

Checked against the GitHub REST API docs (releases list: newest first, `draft`,
`prerelease`, `tag_name`, `assets[].name`, `assets[].browser_download_url`).
"""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .clients import DependencyTrack
from .config import Inventory, Machines
from .net import Http, Transport

API = "https://api.github.com"
STATE_FILE = "github-sboms.json"
REFRESH_SECONDS = 20 * 3600  # re-upload the newest release about once a day


class GitHub:
    def __init__(self, token: str = "", transport: Transport | None = None):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.http = Http(API, headers=headers, transport=transport)
        self.transport = transport

    def latest_release(self, repo: str) -> dict[str, Any] | None:
        """The newest release that is neither a draft nor a prerelease."""
        releases = self.http.get(f"repos/{repo}/releases?per_page=20").json() or []
        return next((r for r in releases if not r.get("draft") and not r.get("prerelease")), None)

    def download(self, repo: str, url: str) -> bytes:
        if not url.startswith(f"https://github.com/{repo}/releases/download/"):
            raise ValueError(f"refusing download URL outside {repo}'s releases: {url!r}")
        # no API headers (and no token): the release download redirects to a signed URL
        return Http(url, transport=self.transport, timeout=60).get("").body


def identity_regexp(glob: str) -> str:
    """Anchored regexp for a certificate identity glob: only `*` is a wildcard."""
    return "^" + ".*".join(re.escape(part) for part in glob.split("*")) + "$"


# (blob, bundle, identity regexp, issuer) -> raises VerifyError when the signature is bad
Verifier = Callable[[bytes, bytes, str, str], None]


class VerifyError(Exception):
    pass


def cosign_verify(blob: bytes, bundle: bytes, identity_re: str, issuer: str) -> None:
    """`cosign verify-blob` on a temporary copy; needs the cosign binary (glue image)."""
    cosign = shutil.which("cosign")
    if cosign is None:
        raise VerifyError("cosign is not installed (it is part of the glue image)")
    with tempfile.TemporaryDirectory() as tmp:
        blob_path, bundle_path = Path(tmp, "asset"), Path(tmp, "asset.sig.bundle")
        blob_path.write_bytes(blob)
        bundle_path.write_bytes(bundle)
        cmd = [
            cosign,
            "verify-blob",
            "--bundle",
            str(bundle_path),
            "--certificate-identity-regexp",
            identity_re,
            "--certificate-oidc-issuer",
            issuer,
            str(blob_path),
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603
        except subprocess.TimeoutExpired as e:
            raise VerifyError("cosign timed out") from e
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip().splitlines()
        raise VerifyError(detail[-1] if detail else f"cosign exited {r.returncode}")


def count_packages(bom: bytes) -> int:
    """Components with a purl in a CycloneDX JSON SBOM; ValueError if it isn't one."""
    try:
        data = json.loads(bom)
    except ValueError as e:
        raise ValueError(f"not JSON: {e}") from e
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise ValueError("not a CycloneDX JSON SBOM")
    return sum(1 for c in data.get("components") or [] if isinstance(c, dict) and c.get("purl"))


@dataclass
class PullResult:
    uploaded: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _load_state(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def pull(
    machines: Machines,
    inv: Inventory,
    gh: GitHub,
    dt: DependencyTrack,
    state_path: Path,
    *,
    now: float | None = None,
    dry_run: bool = False,
    force: bool = False,
    verifier: Verifier = cosign_verify,
) -> PullResult:
    res = PullResult()
    now = time.time() if now is None else now
    state = _load_state(state_path)
    for name, src in sorted(machines.github.items()):
        try:
            rel = gh.latest_release(src.repo)
            if rel is None:
                res.errors.append(f"{name}: {src.repo} has no published release")
                continue
            tag = str(rel.get("tag_name", ""))
            last = state.get(name) or {}
            due = (
                force
                or last.get("tag") != tag
                or now - float(last.get("uploaded", 0)) >= REFRESH_SECONDS
            )
            if not due:
                res.unchanged.append(f"{name}@{tag}")
                continue
            asset = next(
                (
                    a
                    for a in rel.get("assets") or []
                    if fnmatch.fnmatch(str(a.get("name", "")), src.asset)
                ),
                None,
            )
            if asset is None:
                res.errors.append(f"{name}: release {tag} has no asset matching {src.asset!r}")
                continue
            bom = gh.download(src.repo, str(asset.get("browser_download_url", "")))
            signed = ""
            if src.verify is not None:
                bundle_name = f"{asset.get('name')}.sig.bundle"
                bundle_asset = next(
                    (a for a in rel.get("assets") or [] if a.get("name") == bundle_name), None
                )
                if bundle_asset is None:
                    res.errors.append(
                        f"{name}: release {tag} has no {bundle_name} to verify; not uploaded"
                    )
                    continue
                bundle = gh.download(src.repo, str(bundle_asset.get("browser_download_url", "")))
                try:
                    verifier(bom, bundle, identity_regexp(src.verify.identity), src.verify.issuer)
                except VerifyError as e:
                    res.errors.append(
                        f"{name}: signature of {asset.get('name')} in {tag} not verified, "
                        f"not uploaded: {e}"
                    )
                    continue
                signed = ", signature verified"
            n = count_packages(bom)
            if n == 0:
                res.errors.append(
                    f"{name}: {asset.get('name')} in {tag} lists no packages; not uploaded "
                    "(an empty SBOM would close every finding of the project)"
                )
                continue
            label = f"{name}@{tag} ({n} packages, {asset.get('name')}{signed})"
            if dry_run:
                res.uploaded.append(f"{label} [dry run]")
                continue
            team = inv.teams[src.team]
            dt.upload_bom(name, tag, bom, [team.dtrack_tag, "kind-app", "source-github"])
            state[name] = {"tag": tag, "uploaded": now}
            res.uploaded.append(label)
        except Exception as e:
            res.errors.append(f"{name}: {e}")
    if not dry_run and res.uploaded:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(state_path)
    return res
