FROM python:3.15.2-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY vulnflow/ /app/vulnflow/
# cosign: `github-sboms` verifies release signatures with it (`verify` in [github.*]). Pinned
# release binary, checked against the sha256 of the cosign_checksums.txt of that release;
# bump COSIGN_VERSION and both sums together (`vulnflow check-updates` is not aware of it).
ARG TARGETARCH
ARG COSIGN_VERSION=3.1.4
ARG COSIGN_SHA256_AMD64=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
ARG COSIGN_SHA256_ARM64=ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2
RUN python - <<'EOF'
import hashlib, os, urllib.request
arch = os.environ.get("TARGETARCH") or "amd64"
want = os.environ["COSIGN_SHA256_" + arch.upper()]
url = f"https://github.com/sigstore/cosign/releases/download/v{os.environ['COSIGN_VERSION']}/cosign-linux-{arch}"
data = urllib.request.urlopen(url, timeout=120).read()
got = hashlib.sha256(data).hexdigest()
if got != want:
    raise SystemExit(f"cosign {arch}: sha256 {got} != {want}")
with open("/usr/local/bin/cosign", "wb") as f:
    f.write(data)
os.chmod("/usr/local/bin/cosign", 0o755)
EOF
# apt-get upgrade: Debian security updates the official image does not have yet.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /app vulnflow \
 && mkdir -p /app/data && chown vulnflow /app/data
USER vulnflow
# cosign's cache of the Sigstore trust root (TUF); /app is read-only for this user
ENV TUF_ROOT=/app/data/.sigstore
# For `serve` (the webhook receiver); the dt2dojo service turns it off in compose.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('VULNFLOW_PORT','8380')+'/healthz')"]
# .env is provided via env_file in compose; there is no .env file inside the image
ENTRYPOINT ["python", "-m", "vulnflow", "--env-file", "/nonexistent"]
