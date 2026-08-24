"""W8-3 — witness provisioning + the production-posture witness-set gate.

A witnessed anti-rollback checkpoint co-signed by ONE witness is rollback DETECTION via off-box retention,
NOT split-view PREVENTION — and solo is the shipped default (``sigil.spine.witness.witness_trust_root``
falls back to owner-only threshold 1). Split-view resistance needs a STRICT MAJORITY of DISTINCT witnesses,
the exact rule ``transparency.is_split_view_resistant`` already decides. This slice ships (a) provisioning
tooling that stands up an additional witness end-to-end with no hand-editing, and (b) a production-posture
control that REFUSES a solo (or non-distinct) witness set, REUSING that distinctness rule.

These tests prove, in the required "integration two-env boundary (P5)" CI job (pure integration plane — they
import neither ``sigil`` nor ``framework``):

* the shipped default (no roster) reports SOLO — detection, not prevention;
* provisioning two local witnesses end-to-end reaches DISTINCT-QUORUM with a recomputed strict-majority
  threshold and a 0600 roster, no hand-editing;
* THE NEGATIVE CONTROL — two witnesses that SHARE a canonical key are refused as NOT distinct (and the very
  same ``is_split_view_resistant`` returns False), so a roster cannot fake a quorum from one key;
* a sub-majority threshold and a non-canonical key are likewise refused (fail-closed);
* the provisioning tool itself REFUSES to register a duplicate canonical key (any base64 encoding), so the
  tooling can never build a non-distinct roster;
* THE PRODUCTION GATE refuses a solo witness set (this is the test that FAILS WITHOUT THE CHANGE — on a tree
  with no ``witness`` control the gate never evaluates it, so it can never appear in ``unmet``), passes it
  when DISTINCT-QUORUM, and is INERT (opt-in) when ``VIGIL_POSTURE`` is unset;
* FATAL-2: ``witness_provision`` co-loads no sovereign/offense engine.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_core import generate_keypair

from vigil_integration import doctor as dmod
from vigil_integration import witness_provision as wp
from vigil_integration.transparency import is_split_view_resistant

_REPO = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------------------
def _distinct_roster(path: Path, n: int) -> list:
    """Provision n distinct local witnesses via the SAME tooling an operator runs; return their pubkeys."""
    pubs = []
    for i in range(n):
        kp = generate_keypair()
        wp.register_authorizer(path, key_id=f"w{i}", public_key_b64=kp.public_key_b64)
        pubs.append(kp.public_key_b64)
    return pubs


# --------------------------------------------------------------------------------------------------------
# roster_posture: the distinctness verdict (REUSING is_split_view_resistant)
# --------------------------------------------------------------------------------------------------------
def test_absent_roster_is_solo(tmp_path):
    state, detail = wp.roster_posture(tmp_path / "none.json")
    assert state == "SOLO"
    assert "solo" in detail.lower() and "detection" in detail.lower()


def test_one_witness_is_solo(tmp_path):
    rp = tmp_path / "roster.json"
    _distinct_roster(rp, 1)
    assert wp.roster_posture(rp)[0] == "SOLO"


def test_provision_two_local_witnesses_reaches_distinct_quorum(tmp_path):
    rp = tmp_path / "roster.json"
    # provision END-TO-END: mint a key + register it, twice, no hand-editing.
    r1 = wp.provision_witness(key_path=tmp_path / "w0.key", roster_path=rp, key_id="w0")
    assert r1["posture"]["state"] == "SOLO"                 # one witness so far
    r2 = wp.provision_witness(key_path=tmp_path / "w1.key", roster_path=rp, key_id="w1")
    assert r2["posture"]["state"] == "DISTINCT-QUORUM"

    roster = wp.load_roster(rp)
    assert roster["threshold"] == 2 and len(roster["authorizers"]) == 2   # strict majority (2*2 > 2)
    # the distinctness verdict is the transparency log's own rule, not a re-implementation
    assert is_split_view_resistant(wp.roster_trust_root(roster)) is True
    # the roster + minted keys are owner-only (0600)
    assert stat.S_IMODE((tmp_path / "w0.key").stat().st_mode) == 0o600
    assert stat.S_IMODE(rp.stat().st_mode) == 0o600
    # three distinct witnesses still resolve to a strict majority (threshold 2, 2*2 > 3)
    wp.provision_witness(key_path=tmp_path / "w2.key", roster_path=rp, key_id="w2")
    roster3 = wp.load_roster(rp)
    assert roster3["threshold"] == 2 and wp.roster_posture(rp)[0] == "DISTINCT-QUORUM"


# --------------------------------------------------------------------------------------------------------
# THE NEGATIVE CONTROL — witnesses sharing a canonical key are NOT distinct
# --------------------------------------------------------------------------------------------------------
def test_shared_canonical_key_is_rejected_not_distinct(tmp_path):
    rp = tmp_path / "shared.json"
    kp = generate_keypair()
    # two DIFFERENT key_ids, the SAME public key — a roster trying to fake a 2-witness quorum from one key.
    wp.write_roster(rp, 2, [{"key_id": "a", "public_key_b64": kp.public_key_b64},
                            {"key_id": "b", "public_key_b64": kp.public_key_b64}])
    state, detail = wp.roster_posture(rp)
    assert state == "NOT-DISTINCT"
    assert "share" in detail.lower() or "distinct" in detail.lower()
    # THE SAME distinctness rule the transparency log uses returns False — this is a reuse, not a copy.
    assert is_split_view_resistant(wp.roster_trust_root(wp.load_roster(rp))) is False


def test_provision_tool_refuses_duplicate_canonical_key(tmp_path):
    # the tooling can never itself build a non-distinct roster: a second registration of the same public key
    # (even as a DIFFERENT key_id) is refused fail-closed.
    rp = tmp_path / "roster.json"
    kp = generate_keypair()
    wp.register_authorizer(rp, key_id="w0", public_key_b64=kp.public_key_b64)
    with pytest.raises(wp.RosterError, match="already registered|DISTINCT"):
        wp.register_authorizer(rp, key_id="w0-alias", public_key_b64=kp.public_key_b64)


def test_sub_majority_threshold_is_not_distinct_quorum(tmp_path):
    # three DISTINCT witnesses but a threshold of 1 is NOT a strict majority (2*1 > 3 is false) — mere
    # multiplicity is not enough, the quorum must intersect.
    rp = tmp_path / "roster.json"
    pubs = _distinct_roster(rp, 3)
    wp.write_roster(rp, 1, [{"key_id": f"w{i}", "public_key_b64": p} for i, p in enumerate(pubs)])
    state, _ = wp.roster_posture(rp)
    assert state == "NOT-DISTINCT"
    assert is_split_view_resistant(wp.roster_trust_root(wp.load_roster(rp))) is False


def test_non_canonical_key_fails_closed(tmp_path):
    # a roster whose shape parses but carries an unusable public key must FAIL CLOSED (NOT-DISTINCT), never
    # be silently treated as a distinct witness.
    rp = tmp_path / "roster.json"
    good = generate_keypair()
    wp.write_roster(rp, 2, [{"key_id": "good", "public_key_b64": good.public_key_b64},
                            {"key_id": "bad", "public_key_b64": "not-a-real-ed25519-key"}])
    assert wp.roster_posture(rp)[0] == "NOT-DISTINCT"


def test_corrupt_roster_is_unknown_not_a_crash(tmp_path):
    rp = tmp_path / "roster.json"
    rp.write_text("{ this is not json", encoding="utf-8")
    assert wp.roster_posture(rp)[0] == "UNKNOWN"


# --------------------------------------------------------------------------------------------------------
# THE PRODUCTION GATE — refuses solo/non-distinct, passes distinct-quorum, inert when unarmed
# --------------------------------------------------------------------------------------------------------
def test_production_gate_refuses_solo_witness(monkeypatch, tmp_path):
    """FAIL-WITHOUT-FIX: armed production + a solo witness set ⇒ the `witness` control is UNMET and named.
    On a tree with no `witness` control in REQUIRED_CONTROLS the gate never evaluates it, so it can never
    appear in the controls list or `unmet` — and this test errors/red."""
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    monkeypatch.setenv("VIGIL_WITNESS_ROSTER", str(tmp_path / "absent.json"))  # solo default
    res = dmod.evaluate_production_gate(tmp_path)
    assert res["armed"] is True and res["ok"] is False
    w = next(c for c in res["controls"] if c["control"] == "witness")
    assert w["state"] == "SOLO" and w["met"] is False
    assert "witness" in [u["control"] for u in res["unmet"]]
    # the operator refusal names the failing control distinctly.
    msg = dmod.production_gate_message(res, action="up")
    assert "witness:" in msg and "REFUSED" in msg


def test_production_gate_refuses_shared_key_witness(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    rp = tmp_path / "shared.json"
    kp = generate_keypair()
    wp.write_roster(rp, 2, [{"key_id": "a", "public_key_b64": kp.public_key_b64},
                            {"key_id": "b", "public_key_b64": kp.public_key_b64}])
    monkeypatch.setenv("VIGIL_WITNESS_ROSTER", str(rp))
    res = dmod.evaluate_production_gate(tmp_path)
    w = next(c for c in res["controls"] if c["control"] == "witness")
    assert w["state"] == "NOT-DISTINCT" and w["met"] is False
    assert "witness" in [u["control"] for u in res["unmet"]]


def test_production_gate_witness_met_with_distinct_quorum(monkeypatch, tmp_path):
    """NEGATIVE CONTROL for the gate: a distinct strict-majority roster MAKES the witness control MET, so the
    control is a real read of the roster state, not a constant refusal."""
    monkeypatch.setenv("VIGIL_POSTURE", "production")
    rp = tmp_path / "roster.json"
    _distinct_roster(rp, 2)
    monkeypatch.setenv("VIGIL_WITNESS_ROSTER", str(rp))
    res = dmod.evaluate_production_gate(tmp_path)
    w = next(c for c in res["controls"] if c["control"] == "witness")
    assert w["state"] == "DISTINCT-QUORUM" and w["met"] is True
    assert "witness" not in [u["control"] for u in res["unmet"]]


def test_gate_inert_when_posture_unset(monkeypatch, tmp_path):
    """ADDITIVE + OPT-IN: with VIGIL_POSTURE unset the witness precondition never blocks — a solo default is
    byte-identical to before (the non-production default is unchanged)."""
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    monkeypatch.setenv("VIGIL_WITNESS_ROSTER", str(tmp_path / "absent.json"))
    res = dmod.evaluate_production_gate(tmp_path)
    assert res["armed"] is False and res["ok"] is True and res["unmet"] == []


def test_doctor_probe_reports_witness_state(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_WITNESS_ROSTER", str(tmp_path / "absent.json"))
    assert dmod._posture_witness(tmp_path)[0] == "SOLO"
    rp = tmp_path / "roster.json"
    _distinct_roster(rp, 2)
    monkeypatch.setenv("VIGIL_WITNESS_ROSTER", str(rp))
    assert dmod._posture_witness(tmp_path)[0] == "DISTINCT-QUORUM"


# --------------------------------------------------------------------------------------------------------
# FATAL-2 — witness_provision co-loads no sovereign / offense engine
# --------------------------------------------------------------------------------------------------------
def test_witness_provision_imports_no_sigil_or_framework(tmp_path):
    probe = (
        "import sys, json\n"
        f"sys.path[:0] = [{str(_REPO / 'integration')!r}, {str(_REPO / 'gateway')!r}, "
        f"{str(_REPO / 'packages' / 'core' / 'vigil_core')!r}]\n"
        "from vigil_integration import witness_provision as wp\n"
        f"wp.roster_posture({str(tmp_path / 'none.json')!r})\n"
        "leaked = sorted(m for m in ('sigil', 'framework', 'strix') if m in sys.modules)\n"
        "print(json.dumps({'leaked': leaked}))\n"
    )
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, f"probe failed: {out.stderr}"
    res = json.loads(out.stdout.strip().splitlines()[-1])
    assert res["leaked"] == [], f"witness_provision co-loaded a forbidden plane: {res['leaked']}"


# --------------------------------------------------------------------------------------------------------
# the CLI drives the same code paths
# --------------------------------------------------------------------------------------------------------
def test_cli_add_and_register_and_status(tmp_path, capsys):
    rp = tmp_path / "roster.json"
    assert wp.main(["--roster", str(rp), "add", "--key", str(tmp_path / "w0.key"), "--key-id", "w0"]) == 0
    kp = generate_keypair()
    assert wp.main(["--roster", str(rp), "register", "--key-id", "w1",
                    "--pubkey", kp.public_key_b64]) == 0
    assert wp.roster_posture(rp)[0] == "DISTINCT-QUORUM"
    assert wp.main(["--roster", str(rp), "status"]) == 0
    assert "DISTINCT-QUORUM" in capsys.readouterr().out
    # register REFUSES a duplicate canonical key at the CLI (exit 2), fail-closed.
    assert wp.main(["--roster", str(rp), "register", "--key-id", "dup",
                    "--pubkey", kp.public_key_b64]) == 2
