"""Minimal HTTP layer on urllib with an injectable transport (for tests)."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]

    def json(self) -> Any:
        return json.loads(self.body or b"null")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


Transport = Callable[[str, str, Mapping[str, str], bytes | None, float], Response]


def urllib_transport(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
) -> Response:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"refusing non-HTTP URL {url!r}")
    # S310: scheme checked above; URLs come from .env / inventory, not from requests
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return Response(r.status, r.read(), dict(r.headers))
    except urllib.error.HTTPError as e:
        return Response(e.code, e.read(), dict(e.headers or {}))


class HttpError(RuntimeError):
    def __init__(self, method: str, url: str, resp: Response):
        snippet = resp.body[:500].decode("utf-8", "replace")
        super().__init__(f"{method} {url} -> HTTP {resp.status}: {snippet}")
        self.response = resp


class Http:
    def __init__(
        self,
        base_url: str,
        headers: Mapping[str, str] | None = None,
        transport: Transport | None = None,
        timeout: float = 30.0,
        retries: int = 2,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = {"User-Agent": "vulnflow/0.1", **(headers or {})}
        self.transport = transport or urllib_transport
        self.timeout = timeout
        self.retries = retries

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path:
            return self.base_url
        if path.startswith("?"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/{path.lstrip('/')}"

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        expect_ok: bool = True,
    ) -> Response:
        hdrs = {**self.headers, **(headers or {})}
        if json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        url = self.url(path)
        attempt = 0
        while True:
            try:
                resp = self.transport(method, url, hdrs, body, self.timeout)
            except OSError as e:  # network errors
                if attempt >= self.retries:
                    raise
                attempt += 1
                log.warning("network error on %s %s (%s), retry %d", method, url, e, attempt)
                time.sleep(2**attempt)
                continue
            if resp.status in (429, 502, 503, 504) and attempt < self.retries:
                attempt += 1
                time.sleep(2**attempt)
                continue
            if expect_ok and not resp.ok:
                raise HttpError(method, url, resp)
            return resp

    def get(self, path: str, **kw: Any) -> Response:
        return self.request("GET", path, **kw)

    def put(self, path: str, **kw: Any) -> Response:
        return self.request("PUT", path, **kw)

    def post(self, path: str, **kw: Any) -> Response:
        return self.request("POST", path, **kw)


def multipart(
    fields: Mapping[str, str | list[str]], files: Mapping[str, tuple[str, bytes, str]]
) -> tuple[bytes, str]:
    """Build a multipart/form-data body.

    fields: name -> value, or name -> list of values (sent as repeated fields).
    files:  name -> (filename, content, content_type).
    """
    boundary = f"----vulnflow{uuid.uuid4().hex}"
    out = bytearray()
    for name, value in fields.items():
        for v in value if isinstance(value, list) else [value]:
            out += f"--{boundary}\r\n".encode()
            out += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            out += str(v).encode() + b"\r\n"
    for name, (filename, content, ctype) in files.items():
        out += f"--{boundary}\r\n".encode()
        out += (f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n').encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += content + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={boundary}"
