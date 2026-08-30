"""Test helpers for the range. Makes `vigil_range` importable uninstalled and offers a free-port picker."""

from __future__ import annotations

import os
import socket
import sys

# Allow `import vigil_range` when running the suite from a checkout without an editable install.
_RANGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RANGE_ROOT not in sys.path:
    sys.path.insert(0, _RANGE_ROOT)

REPO_ROOT = os.path.dirname(_RANGE_ROOT)


def free_port() -> int:
    """An ephemeral loopback port, released immediately (races are acceptable in a single-host test)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


import time  # noqa: E402
import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402


class RangeClient:
    """A tiny HTTP client bound to a running MERIDIAN target, with a live mode switch."""

    def __init__(self, base_url: str, base_dir: str) -> None:
        self.base = base_url
        self.base_dir = base_dir
        self._noredir = urllib.request.build_opener(
            type("_NoRedir", (urllib.request.HTTPRedirectHandler,),
                 {"redirect_request": lambda *a, **k: None})())

    def set_mode(self, mode: str) -> None:
        from vigil_range.meridian import config as cfg
        cfg.write_mode(self.base_dir, mode)
        time.sleep(0.03)

    def get(self, path: str, ua: str = "pytest/1.0") -> tuple[int, str]:
        req = urllib.request.Request(self.base + path, headers={"User-Agent": ua})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def location_of(self, path: str) -> tuple[int, str | None]:
        """Return (status, Location header) without following the redirect."""
        req = urllib.request.Request(self.base + path, headers={"User-Agent": "pytest/1.0"})
        try:
            with self._noredir.open(req, timeout=5) as r:
                return r.status, r.headers.get("Location")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location")

    def post(self, path: str, data: dict) -> tuple[int, str]:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(self.base + path, data=body, headers={"User-Agent": "pytest/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def post_form(self, path: str, data: dict, headers: dict | None = None) -> tuple[int, str, dict]:
        body = urllib.parse.urlencode(data).encode()
        h = {"User-Agent": "pytest/1.0"}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=body, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def get_h(self, path: str, headers: dict | None = None) -> tuple[int, str, dict]:
        h = {"User-Agent": "pytest/1.0"}
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def login(self, username: str, password: str) -> str | None:
        """Log in and return the session cookie token (or None)."""
        import http.cookiejar
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        body = urllib.parse.urlencode({"username": username, "password": password, "next": "/"}).encode()
        req = urllib.request.Request(self.base + "/login", data=body, headers={"User-Agent": "pytest/1.0"})
        try:
            opener.open(req, timeout=5)
        except urllib.error.HTTPError:
            pass
        for ck in cj:
            if ck.name == "session":
                return ck.value
        return None

    def cookie(self, token: str) -> dict:
        return {"Cookie": f"session={token}"}

    @staticmethod
    def q(s: str) -> str:
        return urllib.parse.quote(s)


import pytest  # noqa: E402


@pytest.fixture()
def range_client(tmp_path):
    """A running MERIDIAN target on an ephemeral loopback port, yielding a RangeClient."""
    from vigil_range.meridian import Config, serve
    from vigil_range.meridian.app import stop_servers

    cfg = Config(base_dir=str(tmp_path), target_port=free_port(), control_port=free_port())
    target, control = serve(cfg, hardened=False, block=False)
    time.sleep(0.3)
    try:
        yield RangeClient(f"http://127.0.0.1:{cfg.target_port}", str(tmp_path))
    finally:
        stop_servers(target, control)
