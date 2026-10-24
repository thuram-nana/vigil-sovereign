"""Multi-gateway AEGIS tracking (Feature A): the Defense console discovers + controls EVERY running
gateway — UI-, CLI-, or cron-launched, observe or enforce — via a per-slug self-registration registry,
NOT a single pointer. These pin: enumeration + dead-pid pruning, per-slug mode-switch (works for ANY
gateway incl. CLI/cron), stop gated to UI-launched, the duplicate-slug refusal, the /api/aegis/status list
shape, and a REAL `aegis gateway` subprocess self-registering + being pruned on stop."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from framework.v2.common import paths
from framework.v2.console import actions, api


@pytest.fixture
def iso_registry(tmp_path, monkeypatch):
    """Isolate the whole slug-keyed control plane under a tmp DEPLOYMENT tree by pinning crucible_root:
    the authority dir, registry, mode/kill-switch files, and the verdicts-file confinement base all derive
    from it (so a verdicts_file under the tmp .vigil-live is allowed, exactly as on a real deployment)."""
    cr = tmp_path / "deploy" / "engine" / "crucible"
    cr.mkdir(parents=True)
    (tmp_path / "deploy" / ".vigil-live").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(paths, "crucible_root", lambda: cr)
    return cr


def _register(slug, pid, *, launched_by="cli", requested="enforce", effective="enforce", port=8080):
    vf = str(paths.crucible_root().parent.parent / ".vigil-live" / f"{paths._safe_slug(slug)}.jsonl")
    rec = {
        "schema": 1, "slug": slug, "pid": pid, "host": "127.0.0.1", "port": port,
        "upstream": "http://127.0.0.1:19010", "requested_mode": requested, "launched_by": launched_by,
        "verdicts_file": vf, "status_file": None, "started": time.time(),
        "effective_mode": effective,
        "enforcement": {"enforcing": effective == "enforce", "entitled": True,
                        "kill_switch_tripped": False, "downgraded": False, "downgrade_reason": None},
        "actors": [], "actor_count": 0,
    }
    p = paths.aegis_registry_path(slug)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec), encoding="utf-8")
    return p


def test_enumerates_live_and_prunes_dead(iso_registry):
    _register("gw-ui", os.getpid(), launched_by="ui", port=8090)
    _register("gw-cli", os.getpid(), launched_by="cli", port=8080)
    dead = _register("gw-dead", 999997, launched_by="cli", port=8070)   # pid 999997: not running
    gws = actions.aegis_list_gateways()
    by = {g["slug"]: g for g in gws}
    assert set(by) == {"gw-ui", "gw-cli"}, "the dead-pid gateway must be pruned from the list"
    assert not dead.exists(), "the dead gateway's stale record must be unlinked"
    assert by["gw-ui"]["stoppable"] is True and by["gw-ui"]["launched_by"] == "ui"
    assert by["gw-cli"]["stoppable"] is False and by["gw-cli"]["launched_by"] == "cli"
    # a dead pid is NEVER shown alive — the pid check gates listing in the same pass
    _register("gw-dead2", 999996)
    assert "gw-dead2" not in {g["slug"] for g in actions.aegis_list_gateways()}


def test_set_mode_works_for_any_gateway_including_cli(iso_registry):
    # The control channel is the slug-keyed mode file (re-read per request), not a pid — so a CLI/cron
    # gateway the console did NOT launch is still switchable from the UI.
    _register("gw-cli", os.getpid(), launched_by="cli", requested="enforce")
    r = actions.aegis_set_mode({"slug": "gw-cli", "mode": "observe"})
    assert r.get("switched") is True and r.get("to") == "observe" and r.get("slug") == "gw-cli"
    assert paths.aegis_mode_path("gw-cli").read_text(encoding="utf-8").strip() == "observe"
    assert actions.aegis_set_mode({"slug": "gw-cli", "mode": "bogus"}).get("error")


def test_stop_gated_to_ui_launched(iso_registry):
    _register("gw-cli", os.getpid(), launched_by="cli")
    out = actions.aegis_stop({"slug": "gw-cli"})
    assert out.get("stopped") is False and "outside the UI" in out.get("note", ""), \
        "a CLI/cron gateway must not be SIGTERM'd from the console (a keep-alive would respawn it)"
    assert paths.aegis_registry_path("gw-cli").exists(), "a refused stop must not prune the record"


def test_stop_and_mode_ambiguity_and_empty(iso_registry):
    assert actions.aegis_stop({}).get("stopped") is False          # none running
    assert actions.aegis_set_mode({"mode": "enforce"}).get("error")  # none running
    _register("a", os.getpid(), port=8081)
    _register("b", os.getpid(), port=8082)
    assert "specify which" in actions.aegis_stop({}).get("error", "")       # 2 running, no slug → ambiguous
    assert "specify which" in actions.aegis_set_mode({"mode": "enforce"}).get("error", "")


def test_setup_refuses_duplicate_live_slug(iso_registry):
    _register("aegis-gateway", os.getpid(), launched_by="cli")   # a gateway already holds the default slug
    out = actions.aegis_setup({"upstream": "http://127.0.0.1:19010", "mode": "observe",
                               "deployment_secret": "x" * 24, "slug": "aegis-gateway"})
    assert "already running" in out.get("error", ""), "a duplicate live slug must be refused BEFORE any spawn"
    assert out.get("running", {}).get("slug") == "aegis-gateway"


def test_api_status_list_shape(iso_registry):
    assert api.aegis_status()["running"] is False and api.aegis_status()["count"] == 0
    _register("gw1", os.getpid(), launched_by="ui", effective="enforce")
    st = api.aegis_status()
    assert st["running"] is True and st["count"] == 1
    assert isinstance(st["gateways"], list) and st["gateways"][0]["slug"] == "gw1"
    assert st["gateway"]["slug"] == "gw1" and st["effective_mode"] == "enforce"   # legacy mirror of the newest


def test_verdicts_path_per_slug_and_ambiguous(iso_registry):
    _register("gwA", os.getpid(), port=8091)
    vfa = actions.aegis_verdicts_path("gwA")
    assert vfa and vfa.endswith("gwA.jsonl")                       # confined path under the deploy tree
    assert actions.aegis_verdicts_path() == vfa                    # single → unambiguous
    _register("gwB", os.getpid(), port=8092)
    assert (actions.aegis_verdicts_path("gwB") or "").endswith("gwB.jsonl")
    assert actions.aegis_verdicts_path() is None                   # 2 running, no slug → ambiguous


def test_real_gateway_self_registers(tmp_path):
    """A REAL `aegis gateway` subprocess must self-register a per-slug record on startup — this is what
    makes a CLI/cron gateway (not launched by the console) visible to the Defense screen. (Dead-pid
    pruning is covered deterministically above; here we only prove the self-registration itself, locating
    the record by name under the child's CRUCIBLE_ROOT to avoid any cross-process path assumptions.)"""
    pytest.importorskip("httpx")   # the gateway forwards via httpx; skip where absent
    wt_engine = str(_engine_root())
    wt_int = wt_engine.replace("/engine/crucible", "/integration")
    cr = tmp_path / "root"
    cr.mkdir(parents=True, exist_ok=True)
    (cr / "CLAUDE.md").write_text("sentinel\n", encoding="utf-8")   # crucible_root() honours CRUCIBLE_ROOT
    env = dict(os.environ)                                          # only when the tree has the sentinel
    env["CRUCIBLE_ROOT"] = str(cr)
    env.pop("CRUCIBLE_ROOT_STRICT", None)
    env["PYTHONPATH"] = wt_engine + ":" + wt_int
    env["AEGIS_GW_LAUNCHED_BY"] = "cli"
    proc = subprocess.Popen(
        [sys.executable, "-m", "framework.v2", "aegis", "gateway", "--upstream", "http://127.0.0.1:9",
         "--host", "127.0.0.1", "--port", "18097", "--mode", "observe", "--slug", "selfreg-test"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, cwd=wt_engine)
    try:
        rec = None
        for _ in range(40):
            hits = list(cr.rglob("selfreg-test.json"))
            if hits:
                rec = json.loads(hits[0].read_text(encoding="utf-8"))
                break
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        assert rec is not None, "a real gateway must self-register a record on startup"
        assert rec["slug"] == "selfreg-test" and rec["launched_by"] == "cli" and rec["pid"] == proc.pid
    finally:
        proc.send_signal(signal.SIGTERM)
        for _ in range(25):
            if proc.poll() is not None:
                break
            time.sleep(0.2)
        if proc.poll() is None:
            proc.kill()


def _engine_root():
    # …/framework/v2/console/tests/test_*.py → parents[4] = …/engine/crucible
    import pathlib
    return pathlib.Path(__file__).resolve().parents[4]


# --- red-pen hardening regressions (a spoofed/stray registry record must not escalate) ----------------

def test_authority_dir_is_tightened_to_0700(tmp_path, monkeypatch):
    """The gateway self-registration must NOT leave the trust root group/other-accessible — a plain mkdir
    created .authority at the ambient umask (0775). ensure_authority_dir_secure creates it 0700 AND tightens
    a pre-existing loose one."""
    import os
    auth = tmp_path / ".authority"
    monkeypatch.setattr(paths, "authority_dir", lambda: auth)
    auth.mkdir(parents=True)
    os.chmod(auth, 0o775)                                   # simulate the regression
    paths.ensure_authority_dir_secure()
    assert (os.stat(auth).st_mode & 0o777) == 0o700, "a group/other-accessible authority dir must be tightened"


def test_verdicts_file_is_confined_to_the_deploy_tree(tmp_path, monkeypatch):
    """The live SSE streams verdicts_file verbatim, so aegis_verdicts_path must refuse a record pointing it
    at an arbitrary file (e.g. /etc/passwd) while still allowing the real .console/.vigil-live JSONLs."""
    deploy = tmp_path / "deploy"
    cr = deploy / "engine" / "crucible"
    cr.mkdir(parents=True)
    monkeypatch.setattr(paths, "crucible_root", lambda: cr)
    cron = deploy / ".vigil-live" / "aegis-verdicts.jsonl"
    cron.parent.mkdir(parents=True)
    cron.write_text("", encoding="utf-8")
    ui = cr / "framework" / "v2" / ".console" / "runs" / "r1" / "verdicts.jsonl"
    ui.parent.mkdir(parents=True)
    ui.write_text("", encoding="utf-8")
    assert actions._verdicts_file_allowed(str(cron)) is True       # cron, under the deploy root
    assert actions._verdicts_file_allowed(str(ui)) is True         # UI-launched, under crucible_root
    assert actions._verdicts_file_allowed("/etc/passwd") is False  # system path
    assert actions._verdicts_file_allowed(str(deploy / "x.txt")) is False          # not .jsonl
    assert actions._verdicts_file_allowed(str(tmp_path / "out" / "x.jsonl")) is False  # outside the tree


def test_set_mode_slug_traversal_is_confined(iso_registry):
    """A registry record whose RAW slug is a path traversal must NOT write its .mode file outside the
    authority dir — aegis_mode_path sanitises the slug (the control channel stays slug-keyed + in-dir)."""
    trav = "../../../../../../tmp/AEGIS_PWN_TEST"
    _register(trav, os.getpid(), launched_by="cli", requested="observe")
    r = actions.aegis_set_mode({"slug": trav, "mode": "enforce"})
    assert not r.get("error") and r.get("to") == "enforce"
    mp = paths.aegis_mode_path(trav).resolve()
    assert str(mp).startswith(str(paths.authority_dir().resolve())), "the .mode write must stay in the authority dir"
    assert not os.path.exists("/tmp/AEGIS_PWN_TEST.mode"), "the raw-slug traversal must not escape"
    assert mp.exists() and mp.read_text(encoding="utf-8").strip() == "enforce"


def test_stop_refuses_a_non_gateway_pid(iso_registry):
    """A spoofed record (launched_by='ui' + an arbitrary live pid) must NOT let Stop SIGTERM a
    non-gateway process — _pid_is_aegis_gateway gates the kill."""
    victim = subprocess.Popen(["sleep", "30"])
    try:
        _register("spoof", victim.pid, launched_by="ui")
        out = actions.aegis_stop({"slug": "spoof"})
        assert out.get("stopped") is False and "not a live AEGIS gateway" in out.get("note", "")
        time.sleep(0.2)
        assert victim.poll() is None, "the non-gateway process must NOT have been signalled"
    finally:
        victim.kill()
