"""Install the pinned cosign release into the glue image (run by deploy/Dockerfile).

Reads COSIGN_VERSION, TARGETARCH and COSIGN_SHA256_<ARCH> from the build arguments and
refuses a binary whose sha256 differs from the one in the Dockerfile.
"""

import hashlib
import os
import urllib.request

arch = os.environ.get("TARGETARCH") or "amd64"
want = os.environ["COSIGN_SHA256_" + arch.upper()]
url = (
    "https://github.com/sigstore/cosign/releases/download/"
    f"v{os.environ['COSIGN_VERSION']}/cosign-linux-{arch}"
)
data = urllib.request.urlopen(url, timeout=120).read()  # noqa: S310  # fixed https URL
got = hashlib.sha256(data).hexdigest()
if got != want:
    raise SystemExit(f"cosign {arch}: sha256 {got} != {want}")
with open("/usr/local/bin/cosign", "wb") as f:
    f.write(data)
os.chmod("/usr/local/bin/cosign", 0o755)  # noqa: S103  # the binary must be executable
