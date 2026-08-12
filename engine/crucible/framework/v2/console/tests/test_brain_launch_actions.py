"""
Brain launch actions — `/api/planner/run` (read-only plan projection) and `/api/intel/run` (OFFLINE recon).

Both are EXECUTION surfaces on the Brain screen, so the asserted properties are the ones that keep them safe
(every test patches `subprocess.run` so the real CLI never runs — fast + deterministic, and it lets us
inspect the exact argv the action would spawn):

  * planner: FIXED argv `plan <slug>`; the ONLY request input is the slug, allowlist-validated (no
    traversal / injection); read-only (the CLI sends no traffic, drives no tools).
  * intel: FIXED argv `intel ingest --seed <domain> --slug <slug>` and it NEVER passes `--live` — the button
    structurally cannot egress; BOTH the slug and the seed (a dotted domain, not a URL/CIDR/path) are
    allowlist-validated.
  * both: BOUNDED (a `timeout=`) and fail-soft — a bad input / non-zero exit / timeout / non-dict body is an
    error or a no-op, never a raise; and NO subprocess is spawned when the input is rejected.
"""

from __future__ import annotations

import subprocess

from framework.v2.console import actions


def _capturing_run(returncode: int = 0, stdout: str = "ok"):
    seen: dict = {}

    def _run(cmd, *a, **kw):
        seen["cmd"] = list(cmd)
        seen["kwargs"] = kw
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    return _run, seen


def _never_run(*a, **k):
    raise AssertionError("a rejected input must not spawn a subprocess")


# --------------------------- planner (read-only projection) ---------------------------

def test_planner_argv_is_fixed_and_ignores_extra_body(monkeypatch) -> None:
    run, seen = _capturing_run(stdout="== ranked plan ==")
    monkeypatch.setattr(actions.subprocess, "run", run)
    r = actions.planner_compute({"slug": "acme-web", "seed": "http://evil/", "extra": "; rm -rf /",
                                 "live": True, "argv": ["--x"]})
    assert r["ok"] is True and r["plan"] == "== ranked plan =="
    assert seen["cmd"] == [actions.sys.executable, "-m", "framework.v2", "plan", "acme-web"]
    for bad in ("http://evil/", "; rm -rf /", "--x", "--live", "True"):
        assert not any(bad in str(tok) for tok in seen["cmd"]), f"{bad!r} leaked into argv"


def test_planner_rejects_bad_slug(monkeypatch) -> None:
    monkeypatch.setattr(actions.subprocess, "run", _never_run)   # must not spawn on a rejected slug
    for bad in ("", "../etc", "a/b", "a b", "..", "x" * 80):
        r = actions.planner_compute({"slug": bad})
        assert r["ok"] is False and "slug" in r["error"]


def test_planner_is_timeout_bounded(monkeypatch) -> None:
    run, seen = _capturing_run()
    monkeypatch.setattr(actions.subprocess, "run", run)
    actions.planner_compute({"slug": "acme"})
    t = seen["kwargs"].get("timeout")
    assert t is not None and t >= 60


def test_planner_fail_soft(monkeypatch) -> None:
    run, _ = _capturing_run(returncode=1, stdout="need a --spine world-model")
    monkeypatch.setattr(actions.subprocess, "run", run)
    assert actions.planner_compute({"slug": "acme"})["ok"] is False

    def _boom(cmd, *a, **k):
        raise subprocess.TimeoutExpired(cmd, k.get("timeout", 1))
    monkeypatch.setattr(actions.subprocess, "run", _boom)
    r = actions.planner_compute({"slug": "acme"})
    assert r["ok"] is False and ("exceeded" in r["error"] or "stopped" in r["error"])


def test_planner_tolerates_a_non_dict_body(monkeypatch) -> None:
    monkeypatch.setattr(actions.subprocess, "run", _never_run)   # non-dict → no slug → rejected before spawn
    for bad in ([], None, "x", 123, True):
        r = actions.planner_compute(bad)
        assert isinstance(r, dict) and r["ok"] is False


# --------------------------- intel (OFFLINE only) ---------------------------

def test_intel_argv_is_fixed_and_never_passes_live(monkeypatch) -> None:
    run, seen = _capturing_run(stdout="ingested")
    monkeypatch.setattr(actions.subprocess, "run", run)
    r = actions.intel_ingest_offline({"slug": "acme", "seed": "Example.COM", "live": True,
                                      "extra": "--live", "argv": ["--live"]})
    assert r["ok"] is True
    assert seen["cmd"] == [actions.sys.executable, "-m", "framework.v2", "intel", "ingest",
                           "--seed", "example.com", "--slug", "acme"]           # seed lower-cased, fixed shape
    assert "--live" not in seen["cmd"], "intel must NEVER egress from a one-click button"


def test_intel_rejects_non_domain_seed(monkeypatch) -> None:
    monkeypatch.setattr(actions.subprocess, "run", _never_run)   # a rejected seed must not spawn
    for bad in ("", "http://example.com", "example.com/path", "10.0.0.0/24", "not a domain",
                "javascript:alert(1)", "localhost", "a..b"):
        r = actions.intel_ingest_offline({"slug": "acme", "seed": bad})
        assert r["ok"] is False and "seed" in r["error"], f"seed {bad!r} should be rejected"


def test_intel_rejects_bad_slug(monkeypatch) -> None:
    monkeypatch.setattr(actions.subprocess, "run", _never_run)
    for bad in ("", "../etc", "a/b"):
        r = actions.intel_ingest_offline({"slug": bad, "seed": "example.com"})
        assert r["ok"] is False and "slug" in r["error"]


def test_intel_is_timeout_bounded_and_fail_soft(monkeypatch) -> None:
    run, seen = _capturing_run()
    monkeypatch.setattr(actions.subprocess, "run", run)
    actions.intel_ingest_offline({"slug": "acme", "seed": "example.com"})
    assert seen["kwargs"].get("timeout", 0) >= 60

    def _boom(cmd, *a, **k):
        raise subprocess.TimeoutExpired(cmd, k.get("timeout", 1))
    monkeypatch.setattr(actions.subprocess, "run", _boom)
    r = actions.intel_ingest_offline({"slug": "acme", "seed": "example.com"})
    assert r["ok"] is False and ("exceeded" in r["error"] or "stopped" in r["error"])


def test_intel_tolerates_a_non_dict_body(monkeypatch) -> None:
    monkeypatch.setattr(actions.subprocess, "run", _never_run)
    for bad in ([], None, "x", 123, True):
        r = actions.intel_ingest_offline(bad)
        assert isinstance(r, dict) and r["ok"] is False
