"""repo-connect Slice 3-authz-B: the live offense gate wires the owner-provisioned m-of-n destruction gate.

conjunctive_decide DENIES any destructive action unless a threshold-destruction gate is wired (fail-closed).
Before this slice, ``live.wiring._build_gate`` wired NONE, so the live engine could never perform a destructive
action (e.g. the PR-bot fix-PR write) even with a valid owner quorum. These tests lock the wiring + its
OFF-by-default + fail-closed contract WITHOUT reconstructing a full signed EngagementAuthority on disk
(``build_offense_gate``'s own destruction-leg enforcement is already covered by ``test_conjunctive_gate``):

  * ``_load_destruction_for_gate`` returns (None, None) when unprovisioned (OFF), a real
    ``(DestructionAuthority, NonceLedger)`` when the owner has provisioned a destruction trust root, and
    (None, None) fail-closed on a broken / wrong-owner config (a misconfig never enables a write);
  * ``_build_gate`` THREADS whatever the loader returns into ``build_offense_gate`` (+ the engagement
    ``base_dir``), so an unprovisioned engagement stays byte-identical (destruction_authority=None ⇒ destructive
    denied) and a provisioned one arms the m-of-n conjunct.

Framework-free (``wiring`` imports framework lazily; ``build_offense_gate`` is monkeypatched here), so it runs
in the sovereign CI leg with no importorskip.
"""
from __future__ import annotations

from vigil_core import generate_keypair

from vigil_integration import conjunctive_gate
from vigil_integration.live.destruction_provision import generate_authority, write_trust_root
from vigil_integration.live.nonce_ledger import NonceLedger
from vigil_integration.live.wiring import Provisioned, _build_gate, _load_destruction_for_gate


def _prov() -> Provisioned:
    # build_offense_gate is monkeypatched in the wiring tests, so these fields only pass through.
    return Provisioned(keypair=generate_keypair(), trust_root=object(), signers=[],
                       authority_path="", slug="repo-x")


# ---- the loader: OFF by default, armed when provisioned, fail-closed on a broken/wrong config ----------

def test_load_destruction_off_by_default(tmp_path):
    assert _load_destruction_for_gate(str(tmp_path)) == (None, None)   # no trust root ⇒ OFF


def test_load_destruction_armed_when_provisioned(tmp_path):
    gen = generate_authority(threshold=2, worker_count=1)             # a real 2-of-2 owner+worker quorum
    write_trust_root(str(tmp_path), gen.trust_root_json)
    auth, ledger = _load_destruction_for_gate(str(tmp_path))
    assert auth is not None and isinstance(ledger, NonceLedger)
    assert "owner" in auth.mandatory_signer_ids                       # mandatory owner per the convention


def test_load_destruction_broken_trust_root_fails_closed(tmp_path):
    (tmp_path / "destruction-trust-root.json").write_text("not valid json {{{")
    assert _load_destruction_for_gate(str(tmp_path)) == (None, None)  # present-but-corrupt ⇒ OFF, not enabled


def test_load_destruction_wrong_owner_id_fails_closed(tmp_path):
    gen = generate_authority(threshold=2, worker_count=1, owner_id="alice")   # owner key_id != "owner"
    write_trust_root(str(tmp_path), gen.trust_root_json)
    assert _load_destruction_for_gate(str(tmp_path)) == (None, None)  # mandatory ("owner",) ∉ root ⇒ fail-closed


# ---- _build_gate THREADS the loaded destruction gate (+ base_dir) into build_offense_gate --------------

def _capture_build_offense_gate(monkeypatch) -> dict:
    captured: dict = {}

    def _fake(**kw):
        captured.update(kw)
        return lambda *a, **k: None    # a callable gate stand-in

    monkeypatch.setattr(conjunctive_gate, "build_offense_gate", _fake)
    return captured


def test_build_gate_off_by_default_threads_no_destruction(tmp_path, monkeypatch):
    captured = _capture_build_offense_gate(monkeypatch)
    gate = _build_gate(_prov(), base_dir=str(tmp_path))               # unprovisioned base_dir
    assert gate is not None
    assert captured["destruction_authority"] is None                 # ⇒ conjunctive_decide denies destructive
    assert captured["destruction_ledger"] is None
    assert captured["base_dir"] == str(tmp_path)                     # base_dir threaded through


def test_build_gate_threads_destruction_when_provisioned(tmp_path, monkeypatch):
    gen = generate_authority(threshold=2, worker_count=1)
    write_trust_root(str(tmp_path), gen.trust_root_json)
    captured = _capture_build_offense_gate(monkeypatch)
    gate = _build_gate(_prov(), base_dir=str(tmp_path))
    assert gate is not None
    assert captured["destruction_authority"] is not None             # the m-of-n conjunct is armed
    assert isinstance(captured["destruction_ledger"], NonceLedger)
