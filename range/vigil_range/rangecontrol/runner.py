"""The closed-set verb runner.

Range Control can run ONLY the templates registered in `SPECS`. Each template builds a fixed argv from the
range Config (the loopback target URL, the fixed slug `meridian`, and server-controlled paths) — never from
a browser-supplied string. Runs stream their combined stdout/stderr to the caller line by line.

This does not weaken any VIGIL gate: it shells the ordinary gated CLI (charter/scope/kill-switch all still
apply). It is a convenience launcher + viewer, like tools/livefire/range.sh with a UI.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..meridian.config import Config


def repo_root() -> Path:
    # runner.py = range/vigil_range/rangecontrol/runner.py → parents[3] is the repo root
    return Path(__file__).resolve().parents[3]


def _child_env() -> dict[str, str]:
    """Env for a spawned verb. Prepends the repo source to PYTHONPATH (works both from an editable offense
    venv and from a dev checkout) and points CRUCIBLE_ROOT at the engine sentinel so charters resolve."""
    root = repo_root()
    src = os.pathsep.join(str(root / p) for p in
                          ("engine/crucible", "packages/core/vigil_core", "integration", "range"))
    env = dict(os.environ)
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["CRUCIBLE_ROOT"] = str(root / "engine" / "crucible")
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _rc_dir(config: Config) -> str:
    d = os.path.join(config.base_dir, "rc")
    os.makedirs(d, exist_ok=True)
    return d


def target_url(config: Config, path: str = "/") -> str:
    return f"http://127.0.0.1:{config.target_port}{path}"


# --- server-side preparation (fixed inputs only; nothing from the browser) -------------------------
def _login_token(config: Config, username: str, password: str) -> Optional[str]:
    """Log in to the TARGET as a seeded user and capture the session cookie (for the two-identity IDOR run)."""
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    body = urllib.parse.urlencode({"username": username, "password": password, "next": "/"}).encode()
    req = urllib.request.Request(target_url(config, "/login"), data=body,
                                 headers={"User-Agent": "range-control/1.0"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    except OSError:
        return None
    for ck in cj:
        if ck.name == "session":
            return ck.value
    return None


def _drive_brute_force(config: Config, attempts: int = 10) -> None:
    """Drive failed logins against the TARGET so auth.log carries a brute-force signal for `detect`."""
    for _ in range(attempts):
        body = urllib.parse.urlencode({"username": "admin", "password": "wrong", "next": "/"}).encode()
        req = urllib.request.Request(target_url(config, "/login"), data=body,
                                     headers={"User-Agent": "range-control/1.0"})
        try:
            urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError:
            pass
        except OSError:
            return


def _synthetic_conn_log(config: Config) -> str:
    """Write a synthetic conn.log with a port-scan signature (one src → many dports) for `detect`."""
    path = os.path.join(_rc_dir(config), "conn.log")
    from ..meridian.logs import clf_now
    lines = [f"{clf_now()} src=10.0.0.9 dst=127.0.0.1 dport={p} proto=tcp\n" for p in range(20, 40)]
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    return path


# --- the closed set of runnable specs --------------------------------------------------------------
@dataclass(frozen=True)
class RunSpec:
    id: str
    label: str
    group: str                        # 'tour' | 'extra'
    description: str
    expect: str                       # what a successful run demonstrates
    build: Callable[[Config], list[str]]
    timeout: int = 400
    needs: tuple[str, ...] = field(default_factory=tuple)  # advisory: what the run relies on


def _py(*mod_args: str) -> list[str]:
    return [sys.executable, "-m", *mod_args]


def _fw(config: Config, *args: str) -> list[str]:
    return _py("framework.v2", "scan", *args)


def _reverifiable(config: Config) -> str:
    return os.path.join(_rc_dir(config), "records.reverify.json")


def _spec_recon(config: Config) -> list[str]:
    return _py("framework.v2", "scan", target_url(config), "--max-pages", "12", "--max-depth", "2")


def _spec_sqli_xss(config: Config) -> list[str]:
    return _fw(config, target_url(config, "/records/search?q=test"), "--max-pages", "2", "--max-depth", "0",
               "--format", "json", "--reverifiable-out", _reverifiable(config))


def _spec_idor(config: Config) -> list[str]:
    token = _login_token(config, "glovelace", "password") or "NO_SESSION"
    return _fw(config, target_url(config, "/api/applications?id=2"), "--access-control",
               "--ac-ref", "idor:id:2", "--ac-victim-header", f"Cookie: session={token}",
               "--max-pages", "2", "--max-depth", "0", "--format", "json")


def _spec_ssrf(config: Config) -> list[str]:
    return _fw(config, target_url(config, "/documents/fetch?url=http://placeholder.test/"),
               "--max-pages", "2", "--max-depth", "0", "--format", "json")


def _spec_verify(config: Config) -> list[str]:
    # framework.v2 verify re-executes each finding's retained oracle_context offline (prove-don't-guess)
    return _py("framework.v2", "verify", _reverifiable(config))


def _spec_detect(config: Config) -> list[str]:
    _drive_brute_force(config)
    conn = _synthetic_conn_log(config)
    return _py("vigil_integration.cli", "detect", "--access-log", config.access_log,
               "--auth-log", config.auth_log, "--conn-log", conn)


def _spec_harden_on(config: Config) -> list[str]:
    return _py("vigil_range.cli", "harden", "on", "--base-dir", config.base_dir)


def _spec_reprove(config: Config) -> list[str]:
    return _fw(config, target_url(config, "/records/search?q=test"), "--max-pages", "2", "--max-depth", "0",
               "--format", "json")


def _spec_harden_off(config: Config) -> list[str]:
    return _py("vigil_range.cli", "harden", "off", "--base-dir", config.base_dir)


def _spec_engage(config: Config) -> list[str]:
    return _py("vigil_integration.cli", "engage", target_url(config), "--slug", "meridian",
               "--scope", "127.0.0.1", "--base-dir", os.path.join(_rc_dir(config), "engage"))


SPECS: dict[str, RunSpec] = {s.id: s for s in [
    RunSpec("recon", "1 · Recon (crawl the surface)", "tour",
            "Crawl MERIDIAN from the seed and map the endpoints/forms/params.",
            "the crawler discovers the target surface", _spec_recon, timeout=300),
    RunSpec("sqli-xss", "2 · Confirm SQLi + XSS", "tour",
            "Audit the records search — the oracle confirms error-based SQLi and reflected XSS as FACTs.",
            "error_based_sqli | fact  and  xss | fact", _spec_sqli_xss),
    RunSpec("idor", "3 · Confirm IDOR/BOLA (two-identity)", "tour",
            "Two-identity access-control scan of the applications API.",
            "idor | fact at the id param", _spec_idor),
    RunSpec("ssrf", "4 · Confirm SSRF (out-of-band)", "tour",
            "Audit the document-fetch endpoint — the OOB oracle confirms SSRF.",
            "ssrf | fact at the url param", _spec_ssrf),
    RunSpec("verify", "5 · Verify offline (prove-don't-guess)", "tour",
            "Re-execute the retained oracle context from step 2 with no trust in the scanner.",
            "the SQLi/XSS FACTs re-verify offline", _spec_verify, timeout=180),
    RunSpec("detect", "6 · Defensive detect (Detection Mirror)", "tour",
            "Point vigil detect at MERIDIAN's own access/auth/conn logs.",
            "recon / injection / brute-force / port-scan signatures fire", _spec_detect, timeout=180),
    RunSpec("harden-on", "7 · Harden the target", "tour",
            "Flip MERIDIAN to hardened mode (every planted sink neutralized, routes kept).",
            "mode → hardened (applied live)", _spec_harden_on, timeout=60),
    RunSpec("reprove", "8 · Re-prove → CLOSED", "tour",
            "Re-audit the records search in hardened mode — the oracle runs and does not fire.",
            "0 confirmed SQLi/XSS FACTs (a sound CLOSED negative)", _spec_reprove),
    RunSpec("harden-off", "9 · Restore vulnerable mode", "tour",
            "Flip MERIDIAN back to vulnerable mode for the next run.",
            "mode → vuln", _spec_harden_off, timeout=60),
    RunSpec("engage", "Governed engage (OODA, approve-then-run)", "extra",
            "Run the full governed engagement. WARDEN gates autonomous fire — this may pause for approval.",
            "a governed engagement against the loopback target", _spec_engage, timeout=300),
]}


def run_stream(spec_id: str, config: Config) -> Iterator[bytes]:
    """Run one closed-set spec, yielding its combined stdout/stderr as UTF-8 chunks. Refuses any id not in
    the registry (no browser-supplied command can ever run)."""
    spec = SPECS.get(spec_id)
    if spec is None:
        yield f"[range-control] refused: unknown run '{spec_id}'\n".encode()
        return
    try:
        argv = spec.build(config)
    except Exception as exc:  # noqa: BLE001 — a build error must not crash the cockpit
        yield f"[range-control] could not prepare run: {type(exc).__name__}: {exc}\n".encode()
        return

    yield f"$ {' '.join(_display(argv))}\n\n".encode()
    try:
        proc = subprocess.Popen(argv, cwd=str(repo_root()), env=_child_env(),  # noqa: S603 — fixed argv
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except OSError as exc:
        yield f"[range-control] failed to start: {exc}\n".encode()
        return

    deadline = time.monotonic() + spec.timeout
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.encode("utf-8", "replace")
            if time.monotonic() > deadline:
                proc.kill()
                yield f"\n[range-control] run exceeded {spec.timeout}s — killed.\n".encode()
                break
    finally:
        try:
            rc = proc.wait(timeout=5)
            yield f"\n[range-control] exit code: {rc}\n".encode()
        except Exception:  # noqa: BLE001
            proc.kill()


def _display(argv: list[str]) -> list[str]:
    """A readable form of the argv for the console banner (collapses the interpreter to `python`)."""
    out = list(argv)
    if out and out[0] == sys.executable:
        out[0] = "python"
    return out
