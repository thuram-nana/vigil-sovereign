"""W16-7 — the raw HTTP evidence route + the dossier's stable-origin wiring (console side).

Two links of the deliverable chain that live in the console:

  * ``/api/http-evidence/<run>`` — the executor captures ``request.http`` / ``response.http`` /
    ``response.body`` per action; before W16-7 NO route or screen read it. This proves the route reads it
    (AC1), is wired into the server, is called by the UI, and is fail-closed on a bad/empty run.
  * ``build_dossier`` now shells ``vigil dossier --base-dir <stable live base>`` so ``provision_authority``
    seals ONE trust root across runs (AC4) instead of a per-run key. A tree without the fix omits the flag,
    so ``test_build_dossier_pins_the_stable_base_dir`` FAILS there.

Runs in the required ``CRUCIBLE core`` CI job (``pytest framework/v2``), which has framework on the path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework.v2.console import actions, api, server


def _repo_root() -> Path:
    for p in Path(__file__).resolve().parents:
        if (p / "packages" / "vigil-ui" / "app.js").is_file():
            return p
    raise AssertionError("could not locate the repo root (packages/vigil-ui/app.js)")


def _run_with_capture(tmp_path: Path, monkeypatch, *, slug: str = "") -> Path:
    """A run dir holding one action's raw executor capture. ``slug`` is left empty so the archive-root join
    stays None and the read is confined to the run dir (no dependence on any on-disk targets/<slug>)."""
    rd = tmp_path / "run1"
    ev = rd / "evidence" / "act-1"
    ev.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps({"slug": slug}), encoding="utf-8")
    (ev / "request.http").write_text("GET /search?q=1%27 HTTP/1.1\r\nHost: t\r\n\r\n", encoding="utf-8")
    (ev / "response.http").write_text("HTTP/1.1 500 Server Error\r\n\r\n", encoding="utf-8")
    (ev / "response.body").write_bytes(b"You have an error in your SQL syntax near ''' at line 1")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    return rd


# --------------------------------------------------------------------------------------------------
# AC1 — the raw HTTP evidence is reachable from an API route (asserted end to end)
# --------------------------------------------------------------------------------------------------


def test_http_evidence_route_is_wired_into_the_server() -> None:
    assert server._PREFIX_ROUTES.get("/api/http-evidence/") is api.http_evidence


def test_http_evidence_returns_the_captured_request_and_response(tmp_path, monkeypatch) -> None:
    _run_with_capture(tmp_path, monkeypatch)
    ev = api.http_evidence("run1")
    assert ev["count"] == 1
    ex = ev["exchanges"][0]
    assert ex["action_id"] == "act-1"
    assert set(ex["files"]) == {"request.http", "response.http", "response.body"}
    # the EXACT bytes the executor sent/received are surfaced in the (capped) preview
    assert "GET /search?q=1%27" in ex["files"]["request.http"]["preview"]
    assert "error in your SQL syntax" in ex["files"]["response.body"]["preview"]
    assert ex["files"]["response.body"]["bytes"] == len(
        b"You have an error in your SQL syntax near ''' at line 1")


def test_http_evidence_preview_is_capped_and_flagged(tmp_path, monkeypatch) -> None:
    rd = tmp_path / "run1"
    ev = rd / "evidence" / "act-1"
    ev.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps({"slug": ""}), encoding="utf-8")
    big = b"A" * (api._HTTP_EVIDENCE_PREVIEW_CAP + 4096)
    (ev / "response.body").write_bytes(big)
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    f = api.http_evidence("run1")["exchanges"][0]["files"]["response.body"]
    assert f["truncated"] is True
    assert len(f["preview"]) == api._HTTP_EVIDENCE_PREVIEW_CAP
    assert f["bytes"] == len(big)


def test_http_evidence_empty_run_is_not_a_500(tmp_path, monkeypatch) -> None:
    """Negative control: a run with no capture yields an empty exchange list, never an exception."""
    rd = tmp_path / "run2"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps({"slug": ""}), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    ev = api.http_evidence("run2")
    assert ev["count"] == 0 and ev["exchanges"] == []


def test_http_evidence_rejects_a_traversal_run_id() -> None:
    """Fail-closed: a URL-derived run id that would escape the runs dir raises (the server maps it to 404),
    and is refused BEFORE any file is read."""
    with pytest.raises(ValueError):
        api.http_evidence("../../etc")


def test_http_evidence_never_follows_a_symlinked_capture(tmp_path, monkeypatch) -> None:
    """Path-safety: a symlinked capture file is not read (it could point outside the run)."""
    rd = tmp_path / "run3"
    ev = rd / "evidence" / "act-9"
    ev.mkdir(parents=True)
    (rd / "meta.json").write_text(json.dumps({"slug": ""}), encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")
    (ev / "response.body").symlink_to(secret)
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    ev_out = api.http_evidence("run3")
    # the only file was a symlink → it is skipped → the action contributes nothing
    assert ev_out["count"] == 0
    blob = json.dumps(ev_out)
    assert "TOP SECRET" not in blob


# --------------------------------------------------------------------------------------------------
# AC1 — the raw HTTP evidence is reachable from a UI screen (doc-truth: the screen calls the route)
# --------------------------------------------------------------------------------------------------


def test_ui_screen_calls_the_http_evidence_route() -> None:
    appjs = (_repo_root() / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
    assert "/api/http-evidence/" in appjs, "the UI must call the http-evidence route"
    assert "p3HttpEvidence" in appjs, "the evidence screen must render the raw HTTP panel"
    assert "Raw HTTP evidence" in appjs, "the panel must be titled for the reader"


# --------------------------------------------------------------------------------------------------
# AC4 — build_dossier pins the STABLE governance-key home so the signature establishes origin
# --------------------------------------------------------------------------------------------------


def test_build_dossier_pins_the_stable_base_dir(tmp_path, monkeypatch) -> None:
    rd = tmp_path / "run1"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps({"slug": "acme"}), encoding="utf-8")
    monkeypatch.setattr(actions, "run_dir", lambda run_id, **kw: rd)
    monkeypatch.setattr(actions, "_vigil_bin", lambda: "/bin/vigil")
    monkeypatch.setattr(actions, "_live_base", lambda: "/stable/live/base")

    captured: dict = {}

    class _P:
        returncode = 0
        stdout = "wrote dossier"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        (rd / "dossier.zip").write_bytes(b"PK\x03\x04zip")
        return _P()

    monkeypatch.setattr(actions.subprocess, "run", fake_run)
    r = actions.build_dossier("run1")
    argv = captured["argv"]
    # the FIX: a stable --base-dir is passed (a pre-fix tree omits it → this assertion fails there)
    assert "--base-dir" in argv, "build_dossier must pin a stable governance-key home"
    assert argv[argv.index("--base-dir") + 1] == "/stable/live/base"
    assert r["ok"] is True and r["download"] == "/api/dossier/run1.zip"
