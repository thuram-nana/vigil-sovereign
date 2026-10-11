"""Fixes screen — the LOCAL-APPLY affordance (WAVE 1 backend).

Three invariants are pinned here:

  * ONLY-VERIFIED gate: a download/apply affordance exists iff a VERIFIED diff was PERSISTED
    (``<run_dir>/fixes/<ref>.patch``, written by ``deep_fix`` only on a verified-no-pr result). A
    non-verified finding 404s the diff download AND refuses ``apply_fix_local`` — enforced by what is on
    disk, never by UI state.
  * ARBITRARY-WRITE-CRITICAL path safety: ``apply_fix_local`` (copy mode) refuses ``..`` / a relative /
    a symlink-escape / a dest equal-to-or-inside the source / an ancestor of the source / a non-empty
    existing dir / a dest outside the allowlisted roots — each FAIL-CLOSED, BEFORE any spawn.
  * NON-DESTRUCTIVE default + zero-trust verdict: copy mode writes a fixed COPY (the source is never
    touched), in_place needs an explicit confirm, and the cleared/still-fires verdict comes from the
    deterministic oracle re-run over the APPLIED tree (``verify_fix`` with ``root=<dest>``), never from
    the apply step's self-report.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from framework.v2.console import actions, api, server
# NOTE: `vigil_integration` is the INTEGRATION plane; it is absent in the CRUCIBLE-core
# (vigil_core) CI job by design (two-env separation). The two tests that drive the real
# `vigil patch --apply-to` CLI verb importorskip it below, so the engine-only path-safety
# tests in this module still run in CRUCIBLE-core while the CLI tests run in the two-env job.

from .conftest import AUTH_HEADERS

_DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-print(1)\n+print(2)\n"


def _mk_run(tmp_path, monkeypatch, meta, *, seed_diff=None, ref="chk-1"):
    """A fake run dir (run_dir monkeypatched to it), optionally with a seeded VERIFIED diff."""
    rd = tmp_path / "run1"
    (rd / "fixes").mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    if seed_diff is not None:
        actions.fix_diff_path("run1", ref).write_text(seed_diff, encoding="utf-8")
    return rd


# ===================================================================================================
# (c) PATH-TRAVERSAL unit — apply_fix_local refuses every unsafe dest, fail-closed, WITHOUT spawning.
# ===================================================================================================
def test_apply_fix_local_refuses_traversal_and_escape(tmp_path, monkeypatch):
    source = tmp_path / "proj" / "app"
    source.mkdir(parents=True)
    (source / "x.py").write_text("print(1)\n", encoding="utf-8")
    proj = source.parent                              # the allowlisted source parent
    ws = tmp_path / "ws"
    ws.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    _mk_run(tmp_path, monkeypatch,
            {"mode": "codebase", "slug": "acme", "target": str(source), "base_dir": str(base)},
            seed_diff=_DIFF)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_detect_repo_kind", lambda *a, **k: "local")
    monkeypatch.setattr(actions, "_apply_workspace", lambda: str(ws))

    spawned = {"n": 0}

    def _no_spawn(*a, **k):
        spawned["n"] += 1
        raise AssertionError("apply_fix_local must NOT spawn the apply verb for an unsafe dest")

    monkeypatch.setattr(actions.subprocess, "run", _no_spawn)

    # symlink that escapes the allowlist, and a non-empty dir under the allowlisted parent
    outside = tmp_path / "outside"
    outside.mkdir()
    (proj / "link").symlink_to(outside, target_is_directory=True)
    nonempty = proj / "existing"
    nonempty.mkdir()
    (nonempty / "f").write_text("x", encoding="utf-8")

    cases = {
        "dotdot": str(proj / ".." / "evil"),
        "relative": "relative/dir",
        "absolute-outside-root": str(tmp_path / "elsewhere" / "fix"),
        "symlink-escape": str(proj / "link" / "fix"),
        "dest==source": str(source),
        "dest-inside-source": str(source / "sub"),
        "non-empty-dir": str(nonempty),
    }
    for name, dest in cases.items():
        r = actions.apply_fix_local("run1", "chk-1", dest_path=dest, mode="copy")
        assert r["ok"] is False, (name, r)
        assert "unsafe destination" in r["error"], (name, r)
    assert spawned["n"] == 0, "not one unsafe-dest case may reach the gated spawn"


def test_safe_apply_dest_rejections_are_specific(tmp_path, monkeypatch):
    # unit-level proof of each rejection REASON on the pure predicate
    src = tmp_path / "p" / "app"
    src.mkdir(parents=True)
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(actions, "_apply_workspace", lambda: str(ws))
    ok_dest, why = actions._safe_apply_dest(str(tmp_path / "p" / "app-fixed"), str(src))
    assert ok_dest and not why                        # the default <source>-fixed sibling is ACCEPTED
    assert actions._safe_apply_dest("", str(src))[0] == ""
    assert "absolute" in actions._safe_apply_dest("rel/x", str(src))[1]
    assert ".." in actions._safe_apply_dest(str(tmp_path / "p" / ".." / "e"), str(src))[1]
    assert "inside the source" in actions._safe_apply_dest(str(src / "c"), str(src))[1]
    assert "equals the source" in actions._safe_apply_dest(str(src), str(src))[1]
    assert "allowlisted root" in actions._safe_apply_dest(str(tmp_path / "zzz" / "x"), str(src))[1]


# ===================================================================================================
# only-verified gate + confirm gate
# ===================================================================================================
def test_apply_fix_local_refuses_without_a_verified_diff(tmp_path, monkeypatch):
    source = tmp_path / "proj" / "app"
    source.mkdir(parents=True)
    _mk_run(tmp_path, monkeypatch,
            {"mode": "codebase", "slug": "acme", "target": str(source), "base_dir": str(tmp_path)})
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_detect_repo_kind", lambda *a, **k: "local")
    r = actions.apply_fix_local("run1", "chk-1", dest_path=str(tmp_path / "proj" / "app-fixed"))
    assert r["ok"] is False and "no verified fix diff" in r["error"]


def test_apply_fix_local_in_place_requires_confirm(tmp_path, monkeypatch):
    source = tmp_path / "proj" / "app"
    source.mkdir(parents=True)
    _mk_run(tmp_path, monkeypatch,
            {"mode": "codebase", "slug": "acme", "target": str(source), "base_dir": str(tmp_path)},
            seed_diff=_DIFF)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_detect_repo_kind", lambda *a, **k: "local")
    monkeypatch.setattr(actions.subprocess, "run",
                        lambda *a, **k: pytest.fail("in_place without confirm must not spawn"))
    r = actions.apply_fix_local("run1", "chk-1", mode="in_place", confirm=False)
    assert r["ok"] is False and "confirm:true" in r["error"]


# ===================================================================================================
# (d) SMOKE — copy mode writes a fixed copy + re-verify renders; drift is a clean refusal.
# ===================================================================================================
def test_apply_fix_local_copy_mode_writes_fixed_copy_and_reverifies(tmp_path, monkeypatch):
    source = tmp_path / "proj" / "app"
    source.mkdir(parents=True)
    (source / "x.py").write_text("print(1)\n", encoding="utf-8")
    base = tmp_path / "base"
    base.mkdir()
    _mk_run(tmp_path, monkeypatch,
            {"mode": "codebase", "slug": "acme", "target": str(source), "base_dir": str(base)},
            seed_diff=_DIFF)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_detect_repo_kind", lambda *a, **k: "git-local")
    monkeypatch.setattr(actions, "_apply_workspace", lambda: str(tmp_path / "ws"))
    dest = tmp_path / "proj" / "app-fixed"
    real_run = subprocess.run   # saved BEFORE patching (actions.subprocess is the shared module object)

    def fake_run(argv, **kw):
        # faithfully simulate the gated `vigil patch --apply-to` verb: copytree + git apply (never --open-pr)
        assert argv[:2] == ["/bin/vigil", "patch"]
        assert "--open-pr" not in argv and "--apply-to" in argv and "--approve" in argv
        d = argv[argv.index("--apply-to") + 1]
        src = argv[argv.index("--target-repo") + 1]
        pf = argv[argv.index("--proposed-diff") + 1]
        shutil.copytree(src, d)
        real_run(["git", "-C", d, "apply", "-p1", pf], check=True)
        return SimpleNamespace(returncode=0, stdout="--- apply-to result ---\n{}", stderr="")

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    monkeypatch.setattr(actions, "verify_fix",
                        lambda run, ref, root="": {"ok": True, "cleared": True,
                                                   "still_fires_at": [], "moved": False, "repo": root})
    r = actions.apply_fix_local("run1", "chk-1", dest_path=str(dest), mode="copy")
    assert r["ok"] is True
    assert r["applied_path"] == os.path.realpath(str(dest))
    assert r["applied_paths"] == ["x.py"]
    assert r["reverify"] == {"cleared": True, "still_fires_at": [], "moved": False, "ran": True}
    assert (dest / "x.py").read_text(encoding="utf-8") == "print(2)\n"   # the fixed COPY is patched
    assert (source / "x.py").read_text(encoding="utf-8") == "print(1)\n"  # the SOURCE is untouched


def test_apply_fix_local_drift_is_a_clean_refusal(tmp_path, monkeypatch):
    source = tmp_path / "proj" / "app"
    source.mkdir(parents=True)
    _mk_run(tmp_path, monkeypatch,
            {"mode": "codebase", "slug": "acme", "target": str(source), "base_dir": str(tmp_path)},
            seed_diff=_DIFF)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_detect_repo_kind", lambda *a, **k: "local")
    monkeypatch.setattr(actions, "_apply_workspace", lambda: str(tmp_path / "ws"))
    # the verb exits 3 when `git apply --check` refused (drift) — nothing applied
    monkeypatch.setattr(actions.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=3, stdout="", stderr=""))
    reverified = {"n": 0}
    monkeypatch.setattr(actions, "verify_fix",
                        lambda *a, **k: reverified.__setitem__("n", reverified["n"] + 1) or {})
    r = actions.apply_fix_local("run1", "chk-1", dest_path=str(tmp_path / "proj" / "app-fixed"))
    assert r["ok"] is False and r["error"] == "source drifted since the scan; re-scan"
    assert reverified["n"] == 0                      # a drifted apply never re-verifies a (non-)applied tree


# ===================================================================================================
# REAL CLI local sink — exercise the genuine copytree + git apply --check + git apply + drift rollback.
# ===================================================================================================
def _fake_patch_args(**over):
    base = dict(apply_to="", in_place=False, proposed_diff="", finding_ref="chk-1")
    base.update(over)
    return SimpleNamespace(**base)


def test_cli_apply_to_copy_mode_real_git(tmp_path, monkeypatch):
    cli = pytest.importorskip("vigil_integration.cli")  # integration plane only; skipped in CRUCIBLE-core
    source = tmp_path / "src"
    source.mkdir()
    (source / "x.py").write_text("print(1)\n", encoding="utf-8")
    patch = tmp_path / "fix.patch"
    patch.write_text(_DIFF, encoding="utf-8")
    dest = tmp_path / "src-fixed"
    monkeypatch.setattr(cli, "_run_codescan_verify_self", lambda root, ref: {"cleared": True})
    finding = SimpleNamespace(target_repo=str(source), ref="chk-1")
    rc = cli._patch_apply_local(_fake_patch_args(apply_to=str(dest), proposed_diff=str(patch)), finding)
    assert rc == 0
    assert (dest / "x.py").read_text(encoding="utf-8") == "print(2)\n"   # fixed copy written + patched
    assert (source / "x.py").read_text(encoding="utf-8") == "print(1)\n"  # source untouched
    assert not (dest / ".git").exists()                                   # .git ignored by copytree


def test_cli_apply_to_drift_rolls_back_no_partial(tmp_path, monkeypatch):
    cli = pytest.importorskip("vigil_integration.cli")  # integration plane only; skipped in CRUCIBLE-core
    source = tmp_path / "src"
    source.mkdir()
    (source / "x.py").write_text("DIFFERENT\n", encoding="utf-8")   # the diff will NOT apply
    patch = tmp_path / "fix.patch"
    patch.write_text(_DIFF, encoding="utf-8")
    dest = tmp_path / "src-fixed"
    monkeypatch.setattr(cli, "_run_codescan_verify_self", lambda root, ref: {"cleared": True})
    finding = SimpleNamespace(target_repo=str(source), ref="chk-1")
    rc = cli._patch_apply_local(_fake_patch_args(apply_to=str(dest), proposed_diff=str(patch)), finding)
    assert rc == 3                                   # DRIFT — distinct exit code
    assert not dest.exists()                         # the --check ran against the SOURCE first: no copy made


# ===================================================================================================
# (d) SMOKE — GET /api/remediate/<run>/<ref>/diff over the REAL HTTP server.
# ===================================================================================================
@contextmanager
def _running(monkeypatch, console_root):
    (console_root / "runs").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(actions, "console_dir", lambda: console_root)
    httpd = server.serve(host="127.0.0.1", port=0)
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        th.join(timeout=5)


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or AUTH_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _post(url, body, headers=None):
    hdrs = {"X-Requested-With": "XMLHttpRequest", "Content-Type": "application/json", **(headers or AUTH_HEADERS)}
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_get_diff_streams_verified_patch_and_404s_when_absent(tmp_path, monkeypatch):
    console_root = tmp_path / ".console"
    with _running(monkeypatch, console_root) as base_url:
        # seed a VERIFIED diff for run "r1" / ref "chk-1"
        rd = console_root / "runs" / "r1"
        (rd / "fixes").mkdir(parents=True, exist_ok=True)
        (rd / "fixes" / "chk-1.patch").write_text(_DIFF, encoding="utf-8")
        status, headers, body = _get(base_url + "/api/remediate/r1/chk-1/diff")
        assert status == 200
        assert headers.get("Content-Type") == "text/x-patch"
        assert "attachment" in (headers.get("Content-Disposition") or "")
        assert headers.get("Cache-Control") == "no-store"
        assert body.decode("utf-8") == _DIFF
        # a finding with NO persisted verified diff → 404 (no apply affordance for an unverified fix)
        status2, _h, body2 = _get(base_url + "/api/remediate/r1/other-ref/diff")
        assert status2 == 404 and b"VERIFIED" in body2
        # an unsafe ref → fix_diff_path raises ValueError → clean 404 (never a traversal)
        status3, _h3, _b3 = _get(base_url + "/api/remediate/r1/..%2fetc/diff")
        assert status3 == 404


def test_post_apply_local_route_dispatches_through_the_gate(tmp_path, monkeypatch):
    # Route wiring: a same-origin + token POST to /api/remediate/<run>/<ref>/apply-local reaches
    # actions.apply_fix_local with the body params (dest_path/mode/confirm). The handler's internal
    # path-safety/only-verified/re-verify logic is covered by the direct-call tests above.
    captured = {}

    def _stub(run_id, finding_ref, dest_path="", mode="copy", confirm=False):
        captured.update(run=run_id, ref=finding_ref, dest=dest_path, mode=mode, confirm=confirm)
        return {"ok": True, "applied_path": dest_path, "applied_paths": ["x.py"],
                "reverify": {"cleared": True, "still_fires_at": [], "moved": False, "ran": True}}

    monkeypatch.setattr(actions, "apply_fix_local", _stub)
    with _running(monkeypatch, tmp_path / ".console") as base_url:
        status, body = _post(base_url + "/api/remediate/r1/chk-1/apply-local",
                             {"dest_path": str(tmp_path / "out"), "mode": "copy", "confirm": False})
        assert status == 200 and body["ok"] is True
        assert body["reverify"]["cleared"] is True
    assert captured == {"run": "r1", "ref": "chk-1", "dest": str(tmp_path / "out"),
                        "mode": "copy", "confirm": False}


def test_post_apply_local_cross_site_is_refused(tmp_path, monkeypatch):
    # No CSRF header (a cross-site form POST) → refused BEFORE the handler, even with a valid token.
    monkeypatch.setattr(actions, "apply_fix_local",
                        lambda *a, **k: pytest.fail("a cross-site POST must never reach the handler"))
    with _running(monkeypatch, tmp_path / ".console") as base_url:
        req = urllib.request.Request(base_url + "/api/remediate/r1/chk-1/apply-local",
                                     data=b"{}", headers={"X-SIGIL-Token": "console-test-token-a1b2c3",
                                                          "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403


# ===================================================================================================
# api.remediate_plan surfaces the affordance predicate (run-level + per-finding has_verified_diff).
# ===================================================================================================
def test_remediate_plan_surfaces_affordance_fields(tmp_path, monkeypatch):
    source = tmp_path / "proj" / "app"
    source.mkdir(parents=True)
    rd = tmp_path / "run1"
    (rd / "fixes").mkdir(parents=True, exist_ok=True)
    (rd / "meta.json").write_text(json.dumps(
        {"status": "done", "mode": "codebase", "slug": "acme", "target": str(source),
         "base_dir": str(tmp_path)}), encoding="utf-8")
    (rd / "report.json").write_text(json.dumps({"findings": [
        {"grounding": "fact", "check_id": "chk-1", "title": "SQLi", "bug_class": "sqli",
         "severity": "high", "remediation": "parameterize"},
        {"grounding": "fact", "check_id": "chk-2", "title": "XSS", "bug_class": "xss",
         "severity": "medium", "remediation": "escape"},
    ], "summary": "s"}), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_detect_repo_kind", lambda *a, **k: "git-local")
    # seed a verified diff for chk-1 ONLY
    actions.fix_diff_path("run1", "chk-1").write_text(_DIFF, encoding="utf-8")

    r = api.remediate_plan("run1")
    assert r["repo_kind"] == "git-local"
    assert r["remote_host_only"] is False
    assert r["source_root"] == os.path.realpath(str(source))
    assert r["default_dest"] == os.path.realpath(str(source)) + "-fixed"
    by_ref = {f["ref"]: f for f in r["fixable"]}
    assert by_ref["chk-1"]["has_verified_diff"] is True     # persisted verified diff → affordance
    assert by_ref["chk-2"]["has_verified_diff"] is False    # none persisted → no affordance
