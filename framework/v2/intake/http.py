"""
intake.http — HTTP fetcher used by UTI for passive fingerprinting.

Constraints (per FORGE PROTOCOL § 3.1):

  - hard cap of 50 requests per intake (configurable, never larger by default)
  - single-IP, identifiable User-Agent
  - polite: 0.3s default delay between requests, no concurrency
  - never logs in, submits forms, fuzzes, or scans
  - records every request to the engagement log

Two execution modes:

  - LIVE      — actually issues HTTPS requests via httpx
  - REPLAY    — reads a captured fixture from disk; never touches network.
                Used by tests so fingerprinting is deterministic offline.

Capture mode is also supported: when CRUCIBLE_INTAKE_CAPTURE_TO is
set, every live request is also saved to that directory so tests
can replay.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import httpx

from ..common import logging as v2log
from ..common.errors import IntakeBudgetExceeded
from .models import HTTPExchange


_log = v2log.get_logger(__name__)

DEFAULT_BUDGET = 50
DEFAULT_TIMEOUT = 8.0
DEFAULT_DELAY_S = 0.3
DEFAULT_USER_AGENT = "OBSIDIAN/2.0 (authorized owner-test; UTI passive)"
DEFAULT_BODY_LIMIT = 16 * 1024
DEFAULT_PATHS_TO_PROBE = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/login",
    "/api/",
    "/wp-login.php",
    "/admin",
)


# ---------------------------------------------------------------------------
# Fixture I/O (offline tests)
# ---------------------------------------------------------------------------


def _fixture_key(method: str, url: str) -> str:
    h = hashlib.sha256(f"{method.upper()} {url}".encode("utf-8")).hexdigest()[:16]
    return h


def _save_fixture(dir_: Path, exchange: HTTPExchange) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    key = _fixture_key(exchange.method, exchange.url)
    (dir_ / f"{key}.json").write_text(
        exchange.model_dump_json(indent=2), encoding="utf-8",
    )


def _load_fixture(dir_: Path, method: str, url: str) -> HTTPExchange | None:
    key = _fixture_key(method, url)
    fp = dir_ / f"{key}.json"
    if not fp.is_file():
        return None
    return HTTPExchange.model_validate_json(fp.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------


@dataclass
class Fetcher:
    base_url: str
    budget: int = DEFAULT_BUDGET
    timeout: float = DEFAULT_TIMEOUT
    delay_s: float = DEFAULT_DELAY_S
    user_agent: str = DEFAULT_USER_AGENT
    capture_dir: Path | None = None
    fixture_dir: Path | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    _used: int = 0
    _exchanges: list[HTTPExchange] = field(default_factory=list)

    @property
    def used(self) -> int:
        return self._used

    @property
    def exchanges(self) -> list[HTTPExchange]:
        return list(self._exchanges)

    def _ensure_full_url(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return self.base_url.rstrip("/") + "/" + path_or_url.lstrip("/")

    def get(self, path_or_url: str, *, allow_redirects: bool = False) -> HTTPExchange:
        return self._request("GET", path_or_url, allow_redirects=allow_redirects)

    def head(self, path_or_url: str) -> HTTPExchange:
        return self._request("HEAD", path_or_url, allow_redirects=False)

    def _request(
        self, method: str, path_or_url: str, *, allow_redirects: bool = False,
    ) -> HTTPExchange:
        if self._used >= self.budget:
            raise IntakeBudgetExceeded(
                f"intake request budget {self.budget} exceeded "
                f"(would request {method} {path_or_url})"
            )
        url = self._ensure_full_url(path_or_url)

        # Replay path
        if self.fixture_dir is not None:
            cached = _load_fixture(self.fixture_dir, method, url)
            if cached is not None:
                self._used += 1
                self._exchanges.append(cached)
                _log.info(
                    "intake.http.replay",
                    method=method, url=url, status=cached.status,
                )
                return cached
            # fall through to live fetch only if explicitly allowed
            if os.environ.get("CRUCIBLE_INTAKE_FIXTURE_FALLBACK") != "1":
                # synthesise an empty exchange marked as missing fixture
                ex = HTTPExchange(
                    method=method, url=url, status=0,
                    headers={}, body_excerpt="",
                    note="fixture missing; offline mode",
                )
                self._used += 1
                self._exchanges.append(ex)
                return ex

        headers = {"User-Agent": self.user_agent, **self.extra_headers}

        t0 = time.perf_counter()
        try:
            r = httpx.request(
                method, url, headers=headers,
                timeout=self.timeout,
                follow_redirects=allow_redirects,
                verify=True,
            )
            elapsed = (time.perf_counter() - t0) * 1000.0
            body = r.text[:DEFAULT_BODY_LIMIT]
            ex = HTTPExchange(
                method=method, url=url, status=r.status_code,
                headers={k: v for k, v in r.headers.items()},
                body_excerpt=body,
                cookies={c.name: c.value for c in r.cookies.jar},
                elapsed_ms=elapsed,
            )
        except httpx.HTTPError as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            ex = HTTPExchange(
                method=method, url=url, status=0,
                elapsed_ms=elapsed, note=f"HTTPError: {e.__class__.__name__}: {e}",
            )

        self._used += 1
        self._exchanges.append(ex)

        if self.capture_dir is not None:
            _save_fixture(self.capture_dir, ex)

        _log.info(
            "intake.http.live",
            method=method, url=url, status=ex.status,
            elapsed_ms=int(ex.elapsed_ms), used=self._used, budget=self.budget,
        )
        if self.delay_s > 0:
            time.sleep(self.delay_s)
        return ex

    def probe_default_paths(self, paths: Iterable[str] = DEFAULT_PATHS_TO_PROBE) -> list[HTTPExchange]:
        out: list[HTTPExchange] = []
        for p in paths:
            try:
                out.append(self.get(p))
            except IntakeBudgetExceeded:
                break
        return out


def make_fetcher(target_url: str, *, budget: int = DEFAULT_BUDGET,
                  fixture_dir: Path | None = None,
                  capture_dir: Path | None = None) -> Fetcher:
    """Convenience constructor honouring env-var overrides."""
    if fixture_dir is None:
        env = os.environ.get("CRUCIBLE_INTAKE_FIXTURE_DIR")
        if env:
            fixture_dir = Path(env)
    if capture_dir is None:
        env = os.environ.get("CRUCIBLE_INTAKE_CAPTURE_TO")
        if env:
            capture_dir = Path(env)
    return Fetcher(
        base_url=target_url, budget=budget,
        fixture_dir=fixture_dir, capture_dir=capture_dir,
    )
