"""M4.5 — the STANDING TWIN refresh.

The twin refresh re-projects the latest signed spine into a STORED, ADVISORY worldmodel snapshot. These
tests pin the three properties the build signs up to, each with a positive control AND a safe-negative:

  * DETERMINISTIC + byte-identical: the same spine yields byte-identical snapshot JSON on re-run and is
    invariant to input record order (positive); a perturbed record changes it (negative — the test is not
    blind to content).
  * A VERBATIM re-projection, no new graph writer: the snapshot body EQUALS `store.to_dict(project_spine(...))`
    exactly, and the projector's sovereign rule (CONFIRMED ⇔ oracle-signed) survives into the snapshot — a
    bare `status="fact"` with no signed evidence stays a LEAD (the negative that proves nothing is laundered).
  * ADVISORY ONLY: the snapshot is never an oracle input and never mints a FACT — it carries no signature /
    evidence ref, its markers say so, and importing the module leaves `_ALL_ORACLES` at exactly 15.

Plus the CLI-registration guard (the verb is a real `_DISPATCH` key documented in CLI-REFERENCE.md) and the
optional foothold attack-path reports (a reachable crown jewel yields a path + chokepoint; an isolated
foothold yields none).
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from .. import store
from ..spine_projector import project_spine, records_from_dicts
from ..twin_refresh import (
    SNAPSHOT_BASENAME,
    SNAPSHOT_SCHEMA,
    build_twin_snapshot,
    main,
    to_json,
)


def _repo_root() -> Path:
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "docs" / "CLI-REFERENCE.md").is_file():
            return parent
    raise AssertionError("repo root (with docs/CLI-REFERENCE.md) not found above this test")


# A fixture spine exercising every record kind the projector understands: assets, a reachability relation
# (foothold -> crown jewel, so the attacker can reach it), a CONFIRMED finding (signed evidence+signature),
# a bare-fact finding (status=fact but NO signed evidence — must stay a LEAD), and a recon target.
_SPINE: list[dict] = [
    {"seq": 1, "hash": "h1", "kind": "asset", "node_id": "host:foothold", "node_kind": "host", "confidence": 0.9},
    {"seq": 2, "hash": "h2", "kind": "asset", "node_id": "db:crown", "node_kind": "datastore", "confidence": 0.9},
    {"seq": 3, "hash": "h3", "kind": "relation", "src": "host:foothold", "dst": "db:crown",
     "edge_kind": "reachable_from", "confidence": 0.8},
    {"seq": 4, "hash": "h4", "kind": "finding", "finding_ref": "F-1", "status": "fact",
     "evidence_ref": "ev-1", "signature_ref": "sig-1", "affects": ["db:crown"], "confidence": 0.95},
    {"seq": 5, "hash": "h5", "kind": "finding", "finding_ref": "F-2", "status": "fact",
     "targets": [{"type": "url", "value": "http://x/y"}]},
]

# An ISOLATED foothold spine — a crown jewel that the foothold cannot reach (edge points AWAY from the jewel).
_ISOLATED_SPINE: list[dict] = [
    {"seq": 1, "hash": "i1", "kind": "asset", "node_id": "host:island", "node_kind": "host", "confidence": 0.9},
    {"seq": 2, "hash": "i2", "kind": "asset", "node_id": "db:vault", "node_kind": "datastore", "confidence": 0.9},
]


# ── determinism / byte-identity ───────────────────────────────────────────────────────────────────────────
def test_snapshot_is_byte_identical_on_rerun():
    """The headline property: the same spine re-projects to byte-identical snapshot JSON."""
    a = to_json(build_twin_snapshot(_SPINE))
    b = to_json(build_twin_snapshot(_SPINE))
    assert a == b
    # ...and it is non-trivial (really projected the graph, not an empty doc).
    snap = json.loads(a)
    assert snap["graph"] == {"nodes": 5, "edges": 3}
    assert snap["schema"] == SNAPSHOT_SCHEMA


def test_snapshot_is_invariant_to_record_order():
    """The projector applies records in a total (seq, hash, body) order, so a shuffled spine yields the SAME
    snapshot — determinism does not depend on how the spine happened to be serialised."""
    canonical = to_json(build_twin_snapshot(_SPINE))
    rng = random.Random(1234)
    for _ in range(8):
        shuffled = list(_SPINE)
        rng.shuffle(shuffled)
        assert to_json(build_twin_snapshot(shuffled)) == canonical


def test_negative_control_a_changed_record_changes_the_snapshot():
    """Load-bearing negative: the determinism test is not blind to content — perturbing one record's
    confidence changes the snapshot bytes."""
    base = to_json(build_twin_snapshot(_SPINE))
    perturbed_rows = [dict(r) for r in _SPINE]
    perturbed_rows[0]["confidence"] = 0.123456  # a different belief on host:foothold
    assert to_json(build_twin_snapshot(perturbed_rows)) != base


def test_cli_stdout_is_byte_identical_on_rerun(tmp_path, capsys):
    """End-to-end through the CLI: `twin refresh --once --spine S --stdout` twice is byte-identical."""
    sp = tmp_path / "spine.json"
    sp.write_text(json.dumps({"records": _SPINE}), encoding="utf-8")
    assert main(["refresh", "--once", "--spine", str(sp), "--stdout"]) == 0
    first = capsys.readouterr().out
    assert main(["refresh", "--once", "--spine", str(sp), "--stdout"]) == 0
    second = capsys.readouterr().out
    assert first == second
    assert json.loads(first)["schema"] == SNAPSHOT_SCHEMA


# ── a verbatim re-projection: no new writer, sovereign rule preserved ──────────────────────────────────────
def test_snapshot_body_equals_the_projector_output_exactly():
    """The snapshot's worldmodel body is EXACTLY `store.to_dict(project_spine(records))` — proving the twin
    adds no second writer of the graph and cannot diverge from the projector."""
    world = project_spine(records_from_dicts(_SPINE))
    snap = build_twin_snapshot(_SPINE)
    assert snap["worldmodel"] == store.to_dict(world)
    # and the body round-trips back into a valid WorldModel (the stored snapshot is honest/loadable).
    reloaded = store.from_dict(snap["worldmodel"])
    assert reloaded.node_count == 5 and reloaded.edge_count == 3


def _finding_node(snap: dict, fid: str) -> dict:
    nodes = {n["id"]: n for n in snap["worldmodel"]["nodes"]}
    assert fid in nodes, f"{fid} not in snapshot nodes {sorted(nodes)}"
    return nodes[fid]


def test_confirmed_finding_is_grounded_but_bare_fact_stays_a_lead():
    """The projector's sovereign rule survives into the snapshot: a FACT with BOTH a signed evidence_ref and
    signature_ref projects CONFIRMED (oracle: provenance); a bare `status=fact` with no signed evidence is a
    LEAD (intel: provenance). The negative half is the anti-laundering guarantee."""
    snap = build_twin_snapshot(_SPINE)
    confirmed = _finding_node(snap, "finding:F-1")
    assert confirmed["attrs"]["confirmed"] is True
    assert confirmed["attrs"]["status"] == "fact"
    assert confirmed["provenance"].startswith("oracle:")

    bare = _finding_node(snap, "finding:F-2")   # status=fact but NO evidence/signature
    assert bare["attrs"]["confirmed"] is False
    assert bare["attrs"]["status"] == "lead"
    assert bare["provenance"].startswith("intel:")


# ── advisory only: never an oracle input, never mints a FACT ───────────────────────────────────────────────
def test_snapshot_is_advisory_and_carries_no_signature():
    snap = build_twin_snapshot(_SPINE)
    assert snap["advisory"] is True
    assert snap["mints_fact"] is False
    # the ENVELOPE carries no signature / evidence ref — a stored twin is not a signed artifact.
    assert "signature" not in snap and "signature_ref" not in snap
    assert "evidence_ref" not in snap and "certificate" not in snap


def test_importing_twin_refresh_keeps_all_oracles_at_15():
    """The advisory module registers NO OracleKind: importing it (and projecting through it) leaves the frozen
    unknown-class fallback at exactly 15 — the twin cannot be an oracle."""
    from framework.v2.verify import verifier as V
    build_twin_snapshot(_SPINE)   # exercise the full path
    assert len(V._ALL_ORACLES) == 15


def test_twin_refresh_module_imports_no_oracle_authority():
    """Structural (AST, so docstring prose about the invariant is fine): the twin module IMPORTS nothing from
    the verify/oracle layer and CALLS no mint function — it cannot be wired as a FACT source by accident."""
    import ast
    src = (Path(__file__).resolve().parents[1] / "twin_refresh.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    imported_modules: list[str] = []
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_modules += [a.name for a in node.names]
        elif isinstance(node, ast.Call):
            f = node.func
            called_names.add(f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else ""))
    assert not any("verify" in m.split(".") or m.endswith("verifier") for m in imported_modules), \
        f"twin_refresh must import nothing from the verify/oracle layer; imports={imported_modules}"
    for mint in ("certify_admitted", "certify", "mint_fact"):
        assert mint not in called_names, f"twin_refresh must not call {mint!r} (advisory, not an oracle)"


# ── optional foothold attack-path reports ─────────────────────────────────────────────────────────────────
def test_foothold_report_shows_a_reachable_crown_jewel():
    """Positive: with a foothold that reaches the crown jewel, the advisory attack-path report has a path and
    a chokepoint."""
    snap = build_twin_snapshot(_SPINE, footholds=["host:foothold"])
    assert sorted(snap["attack_paths"].keys()) == ["host:foothold"]
    rep = snap["attack_paths"]["host:foothold"]
    assert rep["crown_jewels"]["reachable"] == ["db:crown"]
    assert len(rep["shortest_attack_paths"]) >= 1
    assert len(rep["chokepoints"]) >= 1


def test_isolated_foothold_report_is_empty_but_present():
    """Safe-negative: a foothold that reaches no crown jewel yields a report with zero reachable jewels and no
    path — present and honest, not fabricated."""
    snap = build_twin_snapshot(_ISOLATED_SPINE, footholds=["host:island"])
    rep = snap["attack_paths"]["host:island"]
    assert rep["crown_jewels"]["reachable"] == []
    assert rep["shortest_attack_paths"] == []
    assert rep["chokepoints"] == []


def test_no_footholds_means_no_attack_paths_section():
    snap = build_twin_snapshot(_SPINE)
    assert "attack_paths" not in snap


# ── the generated_at envelope (the only clock, caller-supplied) ────────────────────────────────────────────
def test_generated_at_is_omitted_by_default_and_passed_through_when_given():
    assert "generated_at" not in build_twin_snapshot(_SPINE)
    ts = "2026-01-01T00:00:00Z"
    with_ts = build_twin_snapshot(_SPINE, generated_at=ts)
    assert with_ts["generated_at"] == ts
    # same ts -> byte-identical; the worldmodel body is unaffected by the envelope clock.
    assert to_json(build_twin_snapshot(_SPINE, generated_at=ts)) == to_json(with_ts)
    other = build_twin_snapshot(_SPINE, generated_at="2099-12-31T23:59:59Z")
    assert other["worldmodel"] == with_ts["worldmodel"]      # body identical
    assert to_json(other) != to_json(with_ts)                # only the envelope differs


# ── CLI file output + robustness ──────────────────────────────────────────────────────────────────────────
def test_cli_writes_owner_only_snapshot_file(tmp_path, capsys):
    sp = tmp_path / "spine.json"
    sp.write_text(json.dumps(_SPINE), encoding="utf-8")   # bare-list spine form
    out = tmp_path / "twinout"
    out.mkdir()
    assert main(["refresh", "--once", "--spine", str(sp), "--out", str(out)]) == 0
    fp = out / SNAPSHOT_BASENAME
    assert fp.is_file()
    # at-rest protection: secure_write makes it owner-only (0600).
    assert (fp.stat().st_mode & 0o777) == 0o600
    doc = json.loads(fp.read_text(encoding="utf-8"))
    assert doc["schema"] == SNAPSHOT_SCHEMA and doc["advisory"] is True


def test_cli_missing_spine_is_a_clean_error(tmp_path):
    assert main(["refresh", "--once", "--spine", str(tmp_path / "nope.json"), "--stdout"]) == 2


def test_cli_bad_kind_is_a_clean_error(tmp_path):
    sp = tmp_path / "spine.json"
    sp.write_text(json.dumps({"records": _SPINE}), encoding="utf-8")
    assert main(["refresh", "--once", "--spine", str(sp),
                 "--objective-kind", "not-a-real-kind", "--source", "host:foothold", "--stdout"]) == 2


def test_malformed_spine_rows_are_skipped_not_crashed():
    """Totality: a non-record element in the spine is skipped, not crashed on (the projector is total over a
    lossy loader)."""
    rows = [{"garbage": True}, 42, "nope", None] + _SPINE
    snap = build_twin_snapshot(rows)
    assert snap["graph"] == {"nodes": 5, "edges": 3}   # exactly the valid records projected


# ── CLI registration guard (the verb is wired + documented) ───────────────────────────────────────────────
def test_twin_is_a_registered_dispatch_verb():
    from framework.v2.__main__ import _DISPATCH
    assert "twin" in _DISPATCH


def test_twin_is_documented_in_cli_reference():
    doc = (_repo_root() / "docs" / "CLI-REFERENCE.md").read_text(encoding="utf-8")
    assert "`crucible twin`" in doc
