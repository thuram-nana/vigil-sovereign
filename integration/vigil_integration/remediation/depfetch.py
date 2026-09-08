"""remediation.depfetch — a GATED wheel-fetch that fills the deep-fix dependency cache (PCR / W1b).

W1a runs the REAL test suite only when the repo's third-party deps are already in a read-only cache
(wheelhouse). W1b fills that cache for ANY repo — WITHOUT ever weakening the fix/test sandbox. The design is
deliberate: the network step happens HERE, on the host, as an explicit, operator-approved, egress-guarded
`pip download` into the cache; the bwrap fix/test box keeps its never-liftable `--unshare-all` zero-egress
floor and installs OFFLINE (`--no-index --find-links`) from what this fetched. So "gated install" = a gated
FETCH + an offline INSTALL, never a network-capable sandbox.

Fail-closed + honest: with ``VIGIL_EGRESS_GUARD=require`` an unavailable guard REFUSES the fetch (never an
unguarded download); a guard-blocked download is reported, not hidden; if the fetch cannot populate the cache
the caller degrades to the compile-gate (a real suite that could not run is never reported passed). Pure
stdlib + subprocess; never imports framework/strix/sigil.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class FetchResult:
    ok: bool
    cache_dir: str
    count: int = 0        # number of downloaded artifacts (wheels/sdists) in the cache
    note: str = ""


def _download_specs(install_specs: "tuple[str, ...]") -> list[str]:
    """The pip-download form of the buildsys install specs: drop the editable marker ``-e`` (pip cannot
    DOWNLOAD an editable install), keeping ``.`` so the project's OWN declared deps are still fetched, plus
    the ``-r <file>`` requirement files and any package names (all already validated by buildsys)."""
    return [tok for tok in install_specs if tok != "-e"]


def fetch_deps(repo: str, cache_dir: str, *, install_specs: "tuple[str, ...]",
               index_url: str = "", timeout: float = 900.0,
               runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> FetchResult:
    """GATED `pip download` of the repo's deps into ``cache_dir`` (an OFFLINE wheelhouse for W1a). Egress is
    wrapped by the VIGIL egress guard (fail-closed in ``require`` mode). Total — never raises; a failure is a
    FetchResult(ok=False, …) so the caller degrades honestly."""
    from .buildsys import _validated_specs
    from ..live import egress_guard

    if not repo or "://" in repo or not os.path.isdir(repo):
        return FetchResult(False, cache_dir, 0, "no local repo to fetch deps for")
    specs = _validated_specs(tuple(install_specs or ()))
    dl = [s for s in _download_specs(specs) if s]
    if not any(s not in (".",) for s in dl) and "." not in dl:
        return FetchResult(False, cache_dir, 0, "no dependency specs to fetch")
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError as exc:
        return FetchResult(False, cache_dir, 0, f"cannot create cache dir: {exc}")

    argv: list[str] = [sys.executable, "-m", "pip", "download", *dl, "-d", cache_dir]
    if index_url and "://" in index_url:
        argv += ["--index-url", index_url]
    try:
        wrapped = egress_guard.wrap_argv(argv)   # gated: fail-closed in require mode
    except egress_guard.EgressGuardUnavailable as exc:
        return FetchResult(False, cache_dir, 0, f"egress guard required but unavailable — refusing the fetch ({exc})")

    try:
        proc = runner(wrapped, cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return FetchResult(False, cache_dir, 0, f"dep fetch timed out after {int(timeout)}s")
    except OSError as exc:
        return FetchResult(False, cache_dir, 0, f"could not run pip download: {type(exc).__name__}: {exc}")

    if egress_guard.blocked_egress(proc.returncode):
        return FetchResult(False, cache_dir, 0, "the egress guard BLOCKED the dep fetch (off-allowlist host)")
    try:
        arts = [f for f in os.listdir(cache_dir)
                if f.endswith((".whl", ".tar.gz", ".zip", ".tar.bz2"))]
    except OSError:
        arts = []
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-300:]
        return FetchResult(False, cache_dir, len(arts), f"pip download exit {proc.returncode}: {tail}")
    if not arts:
        return FetchResult(False, cache_dir, 0, "pip download produced no artifacts")
    return FetchResult(True, cache_dir, len(arts), f"fetched {len(arts)} artifact(s) into the offline cache")
