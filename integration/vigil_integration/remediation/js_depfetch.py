"""remediation.js_depfetch — a GATED npm/yarn/pnpm fetch that fills the JS/TS deep-fix dependency cache
(PCR / Wave D — the JS analog of remediation.depfetch's pip-download).

Wave D's JS real-test tier runs the repo's suite only when its node deps are already in a read-only cache/
store. This fills that cache for ANY JS/TS repo WITHOUT weakening the fix/test sandbox: the network step
happens HERE, on the host, as an explicit, operator-approved, egress-guarded package-manager install into the
cache; the bwrap fix/test box keeps its never-liftable ``--unshare-all`` zero-egress floor and installs
OFFLINE (``npm ci --offline`` / ``yarn --offline`` / ``pnpm --offline``) from what this fetched. So "gated
install" = a gated FETCH + an offline INSTALL, never a network-capable sandbox.

Two JS-specific safety musts beyond the pip case:
  * ``--ignore-scripts`` on every fetch — npm/yarn/pnpm run arbitrary lifecycle scripts (preinstall/install/
    postinstall) from the UNTRUSTED repo and its deps, a well-known supply-chain RCE vector; the fetch runs on
    the host (egress-gated, not fully sandboxed), so scripts are DISABLED here. (The offline install may run
    scripts, but that is inside the zero-egress bwrap box on a disposable clone.)
  * temp isolation — ``npm ci`` writes ``node_modules`` into its CWD, so the fetch runs in a throwaway temp
    dir holding only a COPY of the manifest + lockfile; the operator's repo is never touched.

Fail-closed + honest: with ``VIGIL_EGRESS_GUARD=require`` an unavailable guard REFUSES the fetch; a
guard-blocked download is reported, not hidden; if the cache cannot be populated the caller degrades to the
node --check floor (a real suite that could not run is never reported passed). Pure stdlib + subprocess;
never imports framework/strix/sigil. Total — never raises.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

# lockfile that must accompany each package manager (copied into the temp fetch dir alongside package.json)
_PM_LOCK = {"npm": ("package-lock.json", "npm-shrinkwrap.json"),
            "yarn": ("yarn.lock",), "pnpm": ("pnpm-lock.yaml",)}


@dataclass(frozen=True)
class FetchResult:
    ok: bool
    cache_dir: str
    count: int = 0        # number of cached artifacts (content-addressed files) under cache_dir
    note: str = ""


def _fetch_argv(pm: str, cache_dir: str) -> Optional[list[str]]:
    """The ONLINE, script-DISABLED install that populates ``cache_dir`` for ``pm``. FIXED literals + the
    caller-controlled cache path only; ``None`` for an unknown pm."""
    if pm == "npm":
        return ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", cache_dir]
    if pm == "yarn":
        return ["yarn", "install", "--ignore-scripts", "--frozen-lockfile", "--cache-folder", cache_dir]
    if pm == "pnpm":
        return ["pnpm", "install", "--ignore-scripts", "--frozen-lockfile", "--store-dir", cache_dir]
    return None


def _count_artifacts(cache_dir: str, *, cap: int = 20000) -> int:
    """Count content files under the cache/store (bounded). npm/yarn/pnpm caches are content-addressed, so a
    non-zero file count means the fetch populated them."""
    n = 0
    try:
        for _root, _dirs, files in os.walk(cache_dir):
            n += len(files)
            if n > cap:
                return n
    except OSError:
        return n
    return n


def fetch_js_deps(repo: str, cache_dir: str, *, pkg_manager: str, timeout: float = 900.0,
                  runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> FetchResult:
    """GATED npm/yarn/pnpm fetch of ``repo``'s deps into ``cache_dir`` (an OFFLINE store for the JS real-test
    tier). Runs in a throwaway temp dir (manifest + lockfile only, ``--ignore-scripts``), egress wrapped by the
    VIGIL egress guard (fail-closed in ``require`` mode). Total — never raises; a failure is a
    FetchResult(ok=False, …) so the caller degrades honestly to the node --check floor."""
    from ..live import egress_guard

    if not repo or "://" in repo or not os.path.isdir(repo):
        return FetchResult(False, cache_dir, 0, "no local repo to fetch deps for")
    pm = str(pkg_manager or "").strip()
    if pm not in _PM_LOCK:
        return FetchResult(False, cache_dir, 0, f"unknown/unsupported JS package manager: {pkg_manager!r}")
    if not os.path.isfile(os.path.join(repo, "package.json")):
        return FetchResult(False, cache_dir, 0, "no package.json to fetch deps for")
    lock = next((lk for lk in _PM_LOCK[pm] if os.path.isfile(os.path.join(repo, lk))), "")
    if not lock:
        return FetchResult(False, cache_dir, 0, f"{pm}: no lockfile present — cannot do a reproducible fetch")

    argv = _fetch_argv(pm, cache_dir)
    if not argv:
        return FetchResult(False, cache_dir, 0, f"no fetch command for {pm}")
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError as exc:
        return FetchResult(False, cache_dir, 0, f"cannot create cache dir: {exc}")

    work = ""
    try:
        # throwaway fetch dir: copy ONLY the manifest + lockfile so `npm ci` can't pollute the operator's repo
        try:
            work = tempfile.mkdtemp(prefix="vigil-jsdepfetch-")
            for name in ("package.json", lock):
                shutil.copy2(os.path.join(repo, name), os.path.join(work, name))
        except OSError as exc:
            return FetchResult(False, cache_dir, 0, f"could not stage manifest/lockfile: {exc}")

        try:
            wrapped = egress_guard.wrap_argv(argv)   # gated: fail-closed in require mode
        except egress_guard.EgressGuardUnavailable as exc:
            return FetchResult(False, cache_dir, 0, f"egress guard required but unavailable — refusing the fetch ({exc})")

        try:
            proc = runner(wrapped, cwd=work, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return FetchResult(False, cache_dir, 0, f"dep fetch timed out after {int(timeout)}s")
        except OSError as exc:
            return FetchResult(False, cache_dir, 0, f"could not run {pm}: {type(exc).__name__}: {exc}")

        if egress_guard.blocked_egress(proc.returncode):
            return FetchResult(False, cache_dir, 0, "the egress guard BLOCKED the dep fetch (off-allowlist host)")
        arts = _count_artifacts(cache_dir)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or "").strip()[-300:]
            return FetchResult(False, cache_dir, arts, f"{pm} fetch exit {proc.returncode}: {tail}")
        if not arts:
            return FetchResult(False, cache_dir, 0, f"{pm} fetch produced no cached artifacts")
        return FetchResult(True, cache_dir, arts, f"fetched {arts} cached artifact(s) via {pm} into the offline store")
    finally:
        if work:
            shutil.rmtree(work, ignore_errors=True)
