# AGENTS.md

Guidance for AI coding agents working in this repository. Human-facing docs are in
[README.md](README.md).

## Project shape

- `vulnflow/` is the glue (stdlib-only Python ≥ 3.11): CLI in `__main__.py`, API clients in
  `clients.py`, first-run automation in `bootstrap.py`, webhook receiver in `receiver.py`.
- `poc.sh` orchestrates the three upstream stacks with each project's *own* install method
  (OpenCVE `install.sh`, DefectDojo's compose file, Dependency-Track's quickstart compose)
  plus small overlays in `stacks/` and `deploy/`. Don't merge them into one compose file.
- `upstream/` (clones), `data/` and `.env` are gitignored and only exist at runtime.
- `stacks/opencve/bootstrap_org.py` runs *inside* OpenCVE's webserver container via
  `manage.py shell`; it is not importable from `vulnflow` and is excluded from mypy.

## Checks: pre-commit locally, everything else in CI

Locally, only the pre-commit hooks run (`.pre-commit-config.yaml`, the same set as the
owner's other Python repos):

```sh
uvx pre-commit@4.7.0 install          # once per clone
uvx pre-commit@4.7.0 run --all-files  # what the hook runs on commit
```

That covers file hygiene, `ruff-check` + `ruff-format`, editorconfig, betterleaks (secrets)
and markdownlint. **Do not** run mypy, pytest, super-linter or OSV-Scanner locally as a
commit gate; they run in CI and you read the results there (`gh pr checks`,
`gh run watch`). This repo-level rule overrides any global "run the full suite before
committing" instruction.

| Workflow | What it checks |
| --- | --- |
| `.github/workflows/linter.yml` | super-linter (slim) + a separate `uv run mypy` job |
| `.github/workflows/tests.yml` | `ruff check` + `pytest` on Python 3.11–3.15 |
| `.github/workflows/osv-scanner-scheduled.yml` | OSV-Scanner on push to main and nightly |

Things that keep CI and the hooks in agreement. Don't undo them without a reason:

- `linter.yml` sets `LINTER_RULES_PATH: .`, `PYTHON_RUFF_CONFIG_FILE: pyproject.toml` and
  `MARKDOWN_CONFIG_FILE: .markdownlint.json`. Without that, super-linter runs ruff with its
  bare template, which in ruff 0.17 enables a broader default rule set (BLE001, TRY004,
  PIE810…) and ignores the `S` rules, so the `noqa: S…` comments become RUF100 errors.
- `VALIDATE_SHELL_SHFMT: false` (as in the owner's other repos) and there is no
  `.editorconfig`: adding one would make editorconfig-checker enforce indent multiples on
  the hand-aligned continuation lines.
- `ruff==` in `pyproject.toml` `[dependency-groups] dev` and the ruff-pre-commit `rev` must
  be the same version; bump them together.
- Secret scanning: tests generate dummy credentials at runtime (`secrets.token_hex`)
  instead of `password="..."` literals; betterleaks flags those even in tests.
- pre-commit needs a git repository. Before the first `git init`, run the hooks on a
  `git init`-ed copy in a scratch directory.

## Versions and dependencies

- Runtime dependencies: none. Keep `vulnflow` stdlib-only; dev tools are exact pins in
  `pyproject.toml`, and `uv.lock` is committed and must stay in sync (`uv lock --check`).
- **Cooldown:** pick the newest release that is at least 7 days old (packages, pre-commit
  revs, action SHAs, container images, upstream git tags). Then read the notes of every
  newer release. If one contains a security fix (CVE/GHSA, auth/permission, XSS/injection,
  session handling, patched dependency or base image), stop and ask the owner which version
  to use. Dependabot uses the same 7-day cooldown.
- Dependabot covers uv, GitHub Actions, pre-commit, `deploy/Dockerfile` and the
  Dependency-Track images (tags are written out in
  `stacks/dependency-track/docker-compose.yml` on purpose; `${VAR}` tags are invisible to
  Dependabot). `DD_REF` and `OPENCVE_REF` in `.env.example` are bumped by hand.
- Actions are pinned by commit SHA with a `# vX.Y.Z` comment. For annotated tags, resolve
  the tag object to its commit (`gh api repos/<o>/<r>/git/tags/<sha>`).

## Bootstrap invariants

- `./poc.sh setup` must stay unattended end to end: no prompts, no UI steps. It chains
  `init`, `check`, `dtrack-up`, `dojo-up`, `opencve-prepare`, `opencve-start`,
  `opencve-bootstrap`, `vulnflow sync --create-projects` and `status`, and relies on each step
  being safe to rerun so a rerun resumes after a failure.
- `opencve-start` runs upstream `install.sh` subcommands (`init-docker-stack`,
  `clone-repositories`, `import-opencve-kb`, `start-opencve-dag`) instead of `start`, whose
  last step is an interactive `createsuperuser`; it re-implements upstream's
  `verify-container-versions`. When bumping `OPENCVE_REF`, diff the `start)` case in
  upstream `docker/install.sh` and mirror any new steps.
- Every bootstrap (`dt-bootstrap`, `dd-bootstrap`, `opencve-bootstrap`) is idempotent and
  only replaces a key/token when the one in `.env` no longer works.
- Secrets never go on a command line: values go to `.env` through
  `python -m vulnflow env-set` (KEY=VALUE on stdin) or `bootstrap.set_env_values`, which
  keep the file at mode 600. The OpenCVE shell script gets its inputs as a JSON line
  prepended on stdin.
- Upstream endpoints/behaviour the bootstraps rely on are listed, with the version they
  were checked against, in the docstrings of `vulnflow/bootstrap.py` and
  `vulnflow/clients.py` and in README "Verified vs assumed". When bumping DT, `DD_REF` or
  `OPENCVE_REF`, re-check those against the new upstream source and update the docstrings.
- Networking: `dt2dojo` uses the host network; the receiver is on a bridge network,
  published on 127.0.0.1, and attached to `opencve_default` as `vulnflow-receiver` by
  `deploy/docker-compose.glue-opencve.yml`. OpenCVE's SSRF guard only accepts it because
  `opencve-bootstrap` writes that network's subnet to
  `OPENCVE_NOTIFICATION_ALLOWED_INTERNAL_NETWORKS`.

## Tests

`tests/test_vulnflow.py` is fully offline: all HTTP goes through `FakeTransport` or a
stateful fake (`FakeDT`) that injects into the clients' `transport=` parameter. New API calls
get a test with such a fake that asserts the exact path and body. Don't add network-dependent
tests or test plugins without asking.

## Gotchas

- The Docker daemon may not be reachable where agents run. `docker compose config`
  validates compose files without it; say explicitly when something could not be run
  against the real services.
- `poc.sh` must work with both GNU and BSD (macOS) tools: use `sed -i.bak … && rm`, not
  `sed -i`.
