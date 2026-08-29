"""Wave 5 (parity) — the console posture wrappers: attest (mint a Certificate of Non-Exploitability, DETACHED
scan) + verify (offline re-verify a bundle, SYNC). The bundle NAME is a slug the server validates + resolves
strictly under <.console>/posture — path-traversal-safe, no argv passthrough. Verb correctness is the CLI
suite's; this checks the wrapper + the name gate."""
from __future__ import annotations

import subprocess

from framework.v2.console import actions


class _P:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _posture_home(monkeypatch, tmp_path):
    monkeypatch.setattr(actions, "console_dir", lambda: tmp_path)
    (tmp_path / "posture").mkdir(parents=True, exist_ok=True)
    return tmp_path / "posture"


# --- the name gate (path-traversal-safe) -----------------------------------------

def test_resolve_posture_name_is_path_traversal_safe(monkeypatch, tmp_path):
    _posture_home(monkeypatch, tmp_path)
    for bad in ("../../etc", "..", "/etc/passwd", "a/b", "a b", "", "a" * 65, "-lead", ".hidden"):
        assert actions._resolve_posture_name(bad) is None, f"{bad!r} should be rejected"
    good = actions._resolve_posture_name("prod-2026-08")
    assert good is not None and good.name == "prod-2026-08"
    assert good.parent == (tmp_path / "posture").resolve()
    # a trailing newline must NOT pass (\Z, not $) — else it lands in the dir/--engagement value
    assert actions._resolve_posture_name("valid\n") is None


def test_resolve_posture_name_rejects_a_symlink_escape(monkeypatch, tmp_path):
    """The load-bearing containment defense (p.parent==base AFTER .resolve()), NOT the regex: a slug-LEGAL
    name that is a planted symlink pointing OUT of the posture dir must be rejected. Mutation-sensitive —
    fails if the `p.parent != base` check is removed."""
    import os
    base = _posture_home(monkeypatch, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), str(base / "escape"))                 # 'escape' is a valid slug, but resolves out
    assert actions._resolve_posture_name("escape") is None


# --- attest: DETACHED scan -------------------------------------------------------

def test_attest_is_detached_with_fixed_argv(monkeypatch, tmp_path):
    base = _posture_home(monkeypatch, tmp_path)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    calls = {}
    monkeypatch.setattr(subprocess, "Popen", lambda a, **k: calls.update(argv=a, kw=k) or object())
    r = actions.run_posture_attest("prod-x")
    assert r["ok"] is True and r["initiated"] is True and r["name"] == "prod-x"
    assert calls["argv"][1:] == ["posture", "attest", "--out", str(base / "prod-x"), "--engagement", "prod-x"]
    assert calls["kw"].get("start_new_session") is True


def test_attest_rejects_a_bad_name(monkeypatch, tmp_path):
    _posture_home(monkeypatch, tmp_path)
    assert actions.run_posture_attest("../evil")["ok"] is False
    assert actions.run_posture_attest("")["ok"] is False


# --- verify: SYNC offline re-run -------------------------------------------------

def test_verify_syncs_the_bundle(monkeypatch, tmp_path):
    base = _posture_home(monkeypatch, tmp_path)
    (base / "prod-x").mkdir()                                       # the bundle must exist
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/usr/bin/true")
    seen = {}

    def _rec(a, **k):
        seen["argv"] = a
        return _P(0, "bundle verified: signature ok, hashes ok")
    monkeypatch.setattr(subprocess, "run", _rec)
    r = actions.run_posture_verify("prod-x")
    assert r["ok"] is True and r["name"] == "prod-x"
    assert seen["argv"][1:] == ["posture", "verify", "--bundle", str(base / "prod-x")]


def test_verify_missing_bundle_failclosed(monkeypatch, tmp_path):
    _posture_home(monkeypatch, tmp_path)
    r = actions.run_posture_verify("does-not-exist")               # valid slug, but no such bundle
    assert r["ok"] is False and "no posture bundle" in r["error"]


def test_verify_rejects_a_bad_name(monkeypatch, tmp_path):
    _posture_home(monkeypatch, tmp_path)
    assert actions.run_posture_verify("../../etc")["ok"] is False


# --- tier pin (mutation-sensitive) -----------------------------------------------

def test_wave5_route_tiers():
    from vigil_core.rbac import offense_perm_for
    assert offense_perm_for("/api/posture/attest") == "run_engagement"   # runs a scan → operator+
    assert offense_perm_for("/api/posture/verify") == "read"             # offline re-verify → any principal
