"""SIGIL graph determinism + provenance. Run: ~/.sigil/venv/bin/python tests/test_graph.py"""
import tempfile

from sigil.graph.rebuild import _accumulate, _project_rollup
from sigil.graph.schema import normalize_project
from sigil.spine.store import SpineStore

_SLUG = "-home-kali-Pictures-PENTEST-main"


def _spine():
    p = tempfile.mktemp(suffix=".jsonl")
    s = SpineStore(p)
    s.append(kind="session", source="cc", actor="system",
             payload={"session_id": "s1", "project": _SLUG, "text": "Build SIGIL"})
    s.append(kind="message", source="cc", actor="user",
             payload={"session_id": "s1", "project": _SLUG, "text": "hi"})
    s.append(kind="message", source="cc", actor="assistant",
             payload={"session_id": "s1", "project": _SLUG, "text": "ok"})
    s.append(kind="commit", source="git", actor="me",
             payload={"hash": "abc123", "repo": "PENTEST-main", "subject": "fix a bug"})
    s.append(kind="document", source="doc", actor="system",
             payload={"path": "/m/a.md", "project": _SLUG, "title": "A", "chunk": 0})
    return s


def test_accumulate_is_deterministic():
    s = _spine()
    assert _accumulate(s) == _accumulate(s), "two replays of one spine must derive identical entities"


def test_project_normalization_collapses_slug_and_repo():
    assert normalize_project(_SLUG) == "PENTEST-main", "transcript slug must map to repo basename"
    assert normalize_project("PENTEST-main") == "PENTEST-main", "repo basename passes through"


def test_slug_and_repo_land_on_one_project():
    s = _spine()
    sessions, docs, commits, _ = _accumulate(s)
    proj = _project_rollup(sessions, docs, commits)
    assert set(proj) == {"PENTEST-main"}, f"slug + repo must collapse to one project, got {set(proj)}"
    assert proj["PENTEST-main"]["sessions"] == 1
    assert proj["PENTEST-main"]["commits"] == 1
    assert proj["PENTEST-main"]["messages"] == 2  # two message events, not the session header


def test_nodes_carry_spine_provenance():
    s = _spine()
    sessions, docs, commits, _ = _accumulate(s)
    assert all("anchor_hash" in v and "anchor_seq" in v for v in sessions.values())
    assert all(v["anchor_hash"] for v in commits.values()), "every commit node must cite a spine entry_hash"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"  PASS  {fn.__name__}"); passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"  ERROR {fn.__name__}: {e}")
    print(f"{passed}/{len(fns)} graph guarantees hold")
