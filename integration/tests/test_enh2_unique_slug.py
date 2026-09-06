"""ENH2 (B-unique-always): every AGENTIC chat launch gets a globally-UNIQUE slug, so two concurrent sends
own DISJOINT ``{slug}.spine`` hash-chains and can never fork one spine. Plus: the resume path reuses the
recorded unique slug; a restricted-mode (soft emergency-stop) launch is CONTAINED; and the storage-level
proof that two writers on one spine path corrupt it while a single writer verifies.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from framework.v2.console import actions as A


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(A, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    yield tmp_path


def _capture_spawn(monkeypatch):
    spawned: list = []
    monkeypatch.setattr(A, "_vigil_bin", lambda: "vigil")
    monkeypatch.setattr(A, "_spawn_background",
                        lambda run_id, rd, cmd, meta, **kw: spawned.append({"run_id": run_id, "cmd": cmd, "meta": meta}))
    return spawned


def _slug_of(cmd):
    return cmd[cmd.index("--slug") + 1]


def _spine_path(base_live: Path, slug: str) -> Path:
    # mirrors wiring.py: base/f"{slug}.spine"
    return base_live / f"{slug}.spine"


# --- the core invariant: two agentic launches -> distinct unique slugs -> disjoint spine paths ------
def test_two_agentic_launches_get_disjoint_unique_slugs(monkeypatch, tmp_path):
    spawned = _capture_spawn(monkeypatch)
    body = {"mode": "url", "target": "http://127.0.0.1:8080/", "objective": "check",
            "session_id": "s", "agentic": True, "slug": ""}
    o1 = A.launch_assessment(dict(body))
    o2 = A.launch_assessment(dict(body))
    assert o1.get("engine") == "integration" and o2.get("engine") == "integration"
    s1, s2 = o1["slug"], o2["slug"]
    assert s1 != s2, "two sends must get DISTINCT slugs"
    assert s1.startswith("loopback-") and s2.startswith("loopback-")
    assert s1 != "loopback" and s2 != "loopback", "never the shared bare 'loopback'"
    # the argv --slug values differ; the derived spine paths are DISTINCT.
    c1, c2 = spawned[0]["cmd"], spawned[1]["cmd"]
    assert _slug_of(c1) == s1 and _slug_of(c2) == s2 and _slug_of(c1) != _slug_of(c2)
    live = Path(A._live_base())
    assert _spine_path(live, s1) != _spine_path(live, s2)
    # --run-key is per-run (the run_id), so checkpoint partitions are disjoint too.
    assert c1[c1.index("--run-key") + 1] != c2[c2.index("--run-key") + 1]


def test_slug_change_does_not_alter_authorization_flags(monkeypatch):
    """M2-gate/authorization untouched by ENH2: only the --slug LABEL (+ --run-key) differs across launches;
    the authorization-relevant flags (--scope, the target) are byte-identical."""
    spawned = _capture_spawn(monkeypatch)
    body = {"mode": "url", "target": "http://127.0.0.1:8080/", "objective": "check",
            "session_id": "s", "agentic": True}
    A.launch_assessment(dict(body)); A.launch_assessment(dict(body))
    c1, c2 = spawned[0]["cmd"], spawned[1]["cmd"]
    assert c1[c1.index("--scope") + 1] == "127.0.0.1" == c2[c2.index("--scope") + 1]
    assert c1[1] == "engage" and c2[1] == "engage"
    assert c1[2] == c2[2] == "http://127.0.0.1:8080/", "the target must be identical across launches"


# --- helper units: injectivity, validity, path-safety, truncation ----------------------------------
def test_unique_slug_injective_over_many_run_ids():
    seen = {A._unique_engagement_slug("loopback", A._new_run_id()) for _ in range(3000)}
    assert len(seen) == 3000, "distinct run_ids must yield distinct slugs (self-contained random tail)"


def test_unique_slug_same_run_id_still_unique():
    # even two IDENTICAL run_ids (a same-millisecond _new_run_id collision) get distinct slugs — the random
    # tail carries the uniqueness, so it does NOT depend on _new_run_id being collision-free.
    rid = "20260906-000000-000"
    a = A._unique_engagement_slug("loopback", rid)
    b = A._unique_engagement_slug("loopback", rid)
    assert a != b and a.startswith("loopback-") and b.startswith("loopback-")


def test_unique_slug_valid_and_path_safe():
    for raw in ("loopback", "../../etc/passwd", "x" * 80, "", "weird slug!!"):
        s = A._unique_engagement_slug(raw, A._new_run_id())
        assert A._valid_slug(s), f"{raw!r} -> invalid slug {s!r}"
        assert "/" not in s and ".." not in s and len(s) <= 64


# --- resume reuses the recorded unique slug + --run-key --------------------------------------------
def test_retry_run_reuses_the_recorded_unique_slug(monkeypatch):
    spawned = _capture_spawn(monkeypatch)
    rid = A._new_run_id()
    slug = f"loopback-{rid}-abc123"[:64]
    cmd = ["vigil", "engage", "http://127.0.0.1/", "--slug", slug, "--run-key", rid, "--scope", "127.0.0.1"]
    A.run_dir(rid).mkdir(parents=True, exist_ok=True)   # the registry dir must exist before its meta is written
    A._write_meta(rid, slug=slug, cmd=cmd, status="paused", resumable=True, engine="integration",
                  target="http://127.0.0.1/", paused="awaiting_approval")
    r = A.retry_run(rid)
    assert r.get("ok") is not False, r
    assert spawned, "retry must spawn the resumed run"
    new_cmd = spawned[-1]["cmd"]
    assert new_cmd[new_cmd.index("--slug") + 1] == slug, "resume MUST reuse the recorded unique slug"
    assert new_cmd[new_cmd.index("--run-key") + 1] == rid, "resume MUST reuse the recorded run-key"
    assert "--resume" in new_cmd


# --- containment: a soft emergency-stop (restricted mode) blocks a new agentic launch --------------
def test_agentic_launch_refused_when_restricted(monkeypatch):
    import vigil_integration.restricted_mode as rm
    monkeypatch.setattr(rm, "is_restricted", lambda base_dir: True)
    spawned = _capture_spawn(monkeypatch)
    out = A.launch_assessment({"mode": "url", "target": "http://127.0.0.1:8080/", "objective": "x",
                               "session_id": "s", "agentic": True})
    assert out.get("error") and "restricted" in out["error"].lower(), out
    assert not spawned, "a restricted-mode launch must NOT spawn (contained, never widened)"


def test_agentic_launch_proceeds_when_not_restricted(monkeypatch):
    import vigil_integration.restricted_mode as rm
    monkeypatch.setattr(rm, "is_restricted", lambda base_dir: False)
    spawned = _capture_spawn(monkeypatch)
    out = A.launch_assessment({"mode": "url", "target": "http://127.0.0.1:8080/", "objective": "x",
                               "session_id": "s", "agentic": True})
    assert out.get("engine") == "integration" and spawned, "a non-restricted launch proceeds"


# --- storage-level proof: two writers on ONE spine path corrupt it; a single writer verifies -------
def test_two_writers_on_one_spine_fork_it_single_writer_verifies(tmp_path):
    from vigil_core import generate_keypair
    from vigil_integration.agent.state import AgentState
    from vigil_integration.live.spine_vigilcore import VigilCoreSpine

    def _st(i):
        return AgentState(engagement_slug="s", iteration=i, objective="o")

    # single writer over its OWN path → a clean, verifiable chain.
    solo = tmp_path / "solo.spine"
    kp = generate_keypair()
    w = VigilCoreSpine(kp, str(solo))
    for i in range(3):
        w.write_state(_st(i), seq=i)
    assert VigilCoreSpine(kp, str(solo), readonly=True).verify() is True

    # TWO writers over ONE shared path (both constructed on the empty tail, then both append) → the chain
    # forks (two seq-0 links / broken prev_hash) → verify() is False. This is exactly the corruption unique
    # slugs make impossible by construction.
    shared = tmp_path / "shared.spine"
    a = VigilCoreSpine(kp, str(shared))
    b = VigilCoreSpine(kp, str(shared))     # constructed BEFORE a writes → its tail view is also empty
    a.write_state(_st(0), seq=0)
    b.write_state(_st(0), seq=0)            # a second seq-0 append onto the same file → fork
    assert VigilCoreSpine(kp, str(shared), readonly=True).verify() is False, \
        "two runs sharing one {slug}.spine must corrupt the hash-chain"
