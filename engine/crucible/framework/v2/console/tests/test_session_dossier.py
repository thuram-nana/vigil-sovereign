"""B6 — `vigil dossier --session <id>` packages a whole SESSION (its run(s) + chat transcript + the
per-session graph partition pointer + the open threads) into ONE signed, re-verifiable handoff zip.

Doctrine under test:
  * the builder reuses the per-run ``build_dossier`` verbatim, so every ``runs/<run>/dossier.zip`` stays
    independently offline-re-verifiable, and wraps them + the session artifacts under ONE governance
    MANIFEST + signature + TRUST-ROOT-FINGERPRINT (the SAME tamper-evidence discipline as a run dossier);
  * the outer MANIFEST hashes every entry (flip any byte → the check fails) — tamper-evident by construction;
  * the graph partition shipped is the B2 pure ONE-WAY spine projection (payload digests, no raw payload);
  * the CLI resolves a session id → its run dirs, projects the graph, and produces the zip.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pytest

from framework.v2.agents import blackboard as bb_mod
from framework.v2.console import actions as actions_mod
from framework.v2.console import sessions
from framework.v2.report.dossier import build_session_dossier

# NB: the CLI leg (below) imports vigil_integration LAZILY per-test via pytest.importorskip, so the
# framework-only CI job (no vigil_integration) still runs the builder tests and skips only the CLI cases.


# ---- a stand-in spine (the projection consumes the row shape, never imports the class) --------------

@dataclass
class _Ev:
    id: int
    engagement_id: int
    kind: str
    agent_name: str
    payload: dict
    parent_id: Optional[int] = None
    supersedes_id: Optional[int] = None
    posted_at: str = "IGNORED"


class _FakeBlackboard:
    def __init__(self, by_slug: dict[str, list]) -> None:
        self._by = by_slug

    def read(self, *, engagement: str, include_superseded: bool = False, limit: int = 1000, **_: Any):
        return list(self._by.get(str(engagement), []))

    def close(self) -> None:
        pass


def _mk_run(base: Path, rid: str, *, slug: str = "acme", status: str = "running") -> Path:
    """A minimal run dir with pre-rendered reports (so build_dossier needs no findings renderer)."""
    rd = base / rid
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "executive.md").write_text("# executive\n", encoding="utf-8")
    (rd / "technical.md").write_text("# technical\n", encoding="utf-8")
    (rd / "remediation-roadmap.md").write_text("# roadmap\n", encoding="utf-8")
    (rd / "meta.json").write_text(json.dumps({"slug": slug, "status": status, "target": "127.0.0.1"}),
                                  encoding="utf-8")
    return rd


# ---- the builder ------------------------------------------------------------

def test_build_session_dossier_packages_runs_and_session_artifacts(tmp_path: Path) -> None:
    r1 = _mk_run(tmp_path / "runs", "20260101-000001-001", status="running")
    r2 = _mk_run(tmp_path / "runs", "20260101-000002-001", status="done")
    graph = {"partition": "sess-x",
             "nodes": [{"id": "event:7:1", "type": "event", "payload_digest": "sha256:deadbeef"},
                       {"id": "agent:scout", "type": "agent"}],
             "edges": [{"rel": "posted", "src": "agent:scout", "dst": "event:7:1"}]}
    out = tmp_path / "handoff.zip"
    res = build_session_dossier(
        session_id="sess-x", run_dirs=[str(r1), str(r2)], out_zip=str(out), engagement_slug="acme",
        base_dir=str(tmp_path / "gov"),
        session_meta={"id": "sess-x", "name": "acme audit", "run_ids": [r1.name, r2.name]},
        graph=graph, open_threads=[{"run_id": r1.name, "status": "running"}])
    assert res["ok"] and res["runs"] == 2 and res["graph_nodes"] == 2

    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
        assert {f"runs/{r1.name}/dossier.zip", f"runs/{r2.name}/dossier.zip",
                "session/session.json", "session/graph-partition.json", "session/open-threads.json",
                "session/run-index.json", "index.html", "README.md", "MANIFEST.json"} <= names
        # tamper-evidence: every manifest entry hash matches its content
        man = json.loads(z.read("MANIFEST.json"))
        assert man["dossier"] == "vigil-session-dossier/v1"
        for e in man["entries"]:
            assert hashlib.sha256(z.read(e["path"])).hexdigest() == e["sha256"]
        # the graph partition shipped is the pure projection we passed (no raw payload, just a digest)
        gp = json.loads(z.read("session/graph-partition.json"))
        assert gp["partition"] == "sess-x" and len(gp["nodes"]) == 2
        # each inner run dossier is itself a valid, independently-verifiable archive (its own MANIFEST)
        with zipfile.ZipFile(io.BytesIO(z.read(f"runs/{r1.name}/dossier.zip"))) as iz:
            assert "MANIFEST.json" in set(iz.namelist())


def test_build_session_dossier_is_deterministic(tmp_path: Path) -> None:
    r1 = _mk_run(tmp_path / "runs", "20260101-000001-001")
    graph = {"partition": "s", "nodes": [{"id": "event:7:1"}], "edges": []}
    common = dict(session_id="s", run_dirs=[str(r1)], engagement_slug="acme",
                  base_dir=str(tmp_path / "gov"), graph=graph,
                  session_meta={"id": "s", "run_ids": [r1.name]}, open_threads=[])
    a = build_session_dossier(out_zip=str(tmp_path / "a.zip"), **common)
    b = build_session_dossier(out_zip=str(tmp_path / "b.zip"), **common)
    # no wallclock in the hashed content ⇒ two builds over the same inputs → identical manifest
    assert a["manifest_sha256"] == b["manifest_sha256"]


def test_build_session_dossier_tolerates_a_missing_run(tmp_path: Path) -> None:
    r1 = _mk_run(tmp_path / "runs", "20260101-000001-001")
    res = build_session_dossier(
        session_id="s", run_dirs=[str(r1), str(tmp_path / "runs" / "ghost-run")],
        out_zip=str(tmp_path / "h.zip"), engagement_slug="acme", base_dir=str(tmp_path / "gov"))
    assert res["ok"] and res["runs"] == 1                       # the present run packaged, the ghost noted
    assert any("dir not found" in n for n in res["notes"])


# ---- the CLI: resolve a session id → its runs → a re-verifiable handoff zip -------------------------

def test_cli_dossier_session_resolves_and_builds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli = pytest.importorskip("vigil_integration.cli")   # CLI leg — skip where vigil_integration is absent
    # isolate the live plane (sessions + chats + graph) and the console run store at tmp
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)

    rid = "20260101-000000-001"
    _mk_run(actions_mod.console_dir() / "runs", rid, slug="acme", status="running")

    # a session that owns the run + a chat transcript
    sid = sessions.create_session(name="acme audit", kind="engagement")["session"]["id"]
    sessions.link_run(sid, rid, slug="acme")
    chats = tmp_path / "live" / "chats"
    chats.mkdir(parents=True, exist_ok=True)
    (chats / (sid + ".jsonl")).write_text(json.dumps({"role": "user", "text": "test my api"}) + "\n",
                                          encoding="utf-8")

    # a (fake) spine so the per-session graph partition is non-empty
    monkeypatch.setattr(bb_mod, "open_blackboard",
                        lambda **kw: _FakeBlackboard({"acme": [_Ev(1, 7, "recon", "scout", {"host": "t"})]}))

    out = tmp_path / "handoff.zip"
    args = argparse.Namespace(session=sid, run_dir="", out=str(out), slug="engagement",
                              base_dir=str(tmp_path / "gov"), timestamp="", terminal_history="")
    rc = cli._cmd_session_dossier(args)
    assert rc == 0 and out.is_file()

    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
        assert f"runs/{rid}/dossier.zip" in names                       # the session's run was resolved
        assert "session/graph-partition.json" in names
        # the graph partition is the pure spine projection (1 event + 1 agent node)
        gp = json.loads(z.read("session/graph-partition.json"))
        assert len(gp["nodes"]) == 2
        # the running run is an open thread; the chat transcript rode along
        ot = json.loads(z.read("session/open-threads.json"))
        assert any(t["run_id"] == rid for t in ot["open_threads"])
        assert "session/chat-transcript.jsonl" in names
        # tamper-evident: manifest hashes match, and the inner run dossier verifies standalone
        man = json.loads(z.read("MANIFEST.json"))
        assert all(hashlib.sha256(z.read(e["path"])).hexdigest() == e["sha256"] for e in man["entries"])


def test_cli_dossier_session_unknown_id_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli = pytest.importorskip("vigil_integration.cli")   # CLI leg — skip where vigil_integration is absent
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    args = argparse.Namespace(session="nope-nonexistent", run_dir="", out="", slug="engagement",
                              base_dir="", timestamp="", terminal_history="")
    assert cli._cmd_session_dossier(args) == 1                          # unknown session → clean non-zero
