"""Gap 2 — durable fireteam escalation registry.

The ConfirmationRegistry was in-memory + per-wave: an over-cap escalation died with the process and no
separate resolver could read it. It now has a DURABLE backing — an append-only, 0600, secret-redacted JSONL
``EscalationLedger`` — and REHYDRATES its pending/resolved state from that ledger on construction. These
tests pin the four neg-controls from the fix spec, against the real ledger + registry (no framework, no
network — this whole file runs in the sovereign leg):

  (1) CROSS-PROCESS DURABILITY — register in one registry; a FRESH registry over the same ledger returns the
      escalation from ``pending_keys``/``resolution`` (a no-ledger registry returns EMPTY — the gap this fixes);
  (2) FAIL-CLOSED RESOLVE — a fresh reader's resolve with no approver / None / a non-approving verdict →
      REJECTED, and an already-REJECTED/EXPIRED key stays FINAL after a later "approval" (append-only, no
      replay-launder across a restart);
  (3) REDACTION PARITY — api_key= / Bearer / user:pass@host / --flag secrets in target/reason are scrubbed by
      redact_tool_args BEFORE they hit the ledger (asserted against the RAW file bytes);
  (4) HAND-RUN PARITY — with $VIGIL_PROOF_RUN_DIR unset the escalation is still durably recorded + readable
      (the ledger path is explicit, independent of the console progress env).
"""

from __future__ import annotations

import json
import os

import pytest

from vigil_core import generate_keypair

from vigil_integration.fireteam import (
    ConfirmationOutcome,
    ConfirmationRegistry,
    EscalationLedger,
    EscalationRequest,
    sign_escalation_approval,
)


# --- helpers ------------------------------------------------------------------------------------------


class _Appr:
    """A verdict object whose ``.approved`` the registry reads (True IFF the operator's signature binds)."""

    def __init__(self, approved: bool, reason: str = "") -> None:
        self.approved = approved
        self.reason = reason


def _approver_ok(_sig, _esc):
    return _Appr(True, "signed operator approval")


def _approver_no(_sig, _esc):
    return _Appr(False, "operator declined")


# A stable, pinned approver identity for the signed-approval (Path V) tests. In production this is the
# operator/owner ApprovalAuthority public key (approval_broker.load_authority); the private key lives only
# with the sovereign approver. Here we mint one keypair per test to prove the signature is the authority.
def _approver_identity(key_id: str = "owner"):
    kp = generate_keypair()
    return key_id, kp.public_key_b64, kp.private_key_b64


def _trusted(key_id: str, pub: str) -> dict:
    return {key_id: pub}


def _esc(wave="w1", member="m1", seq=1, *, tool="sqlmap", tier="A3", target="", reason=""):
    return EscalationRequest(wave_id=wave, member_id=member, seq=seq, tool_name=tool,
                             requested_tier=tier, target=target, reason=reason)


def _ledger(tmp_path, name="eng-a.escalations.jsonl"):
    return EscalationLedger(str(tmp_path / name))


# --- ledger primitive ---------------------------------------------------------------------------------


def test_ledger_append_replay_roundtrip(tmp_path):
    led = _ledger(tmp_path)
    assert led.append({"event": "register", "wave_id": "w", "member_id": "m", "seq": 1}) is True
    assert led.append({"event": "rejected", "wave_id": "w", "member_id": "m", "seq": 1}) is True
    rows = led.replay()
    assert [r["event"] for r in rows] == ["register", "rejected"]


def test_ledger_fail_open_bad_path_is_noop():
    # An empty/unusable path disables the store — append False, replay [] — never raises, and a registry
    # over it still works purely in-memory (durability degrades, correctness does not).
    led = EscalationLedger("")
    assert led.append({"event": "register"}) is False
    assert led.replay() == []
    reg = ConfirmationRegistry(ledger=led)
    key = reg.register(_esc())
    assert reg.pending_keys() == [key]         # in-memory still fine
    # but a fresh reader over the (disabled) store sees nothing — honestly not durable
    assert ConfirmationRegistry(ledger=EscalationLedger("")).pending_keys() == []


def test_ledger_replay_skips_torn_and_nonobject_lines(tmp_path):
    path = tmp_path / "torn.escalations.jsonl"
    path.write_text(
        json.dumps({"event": "register", "wave_id": "w", "member_id": "m", "seq": 1}) + "\n"
        + "{not json at all\n"
        + "\n"
        + json.dumps([1, 2, 3]) + "\n"                         # a JSON array is not a record → skipped
        + json.dumps({"event": "rejected", "wave_id": "w", "member_id": "m", "seq": 1}) + "\n",
        encoding="utf-8")
    rows = EscalationLedger(str(path)).replay()
    assert [r["event"] for r in rows] == ["register", "rejected"]


def test_ledger_is_mode_0600(tmp_path):
    led = _ledger(tmp_path)
    led.append({"event": "register", "wave_id": "w", "member_id": "m", "seq": 1})
    mode = os.stat(str(tmp_path / "eng-a.escalations.jsonl")).st_mode & 0o777
    assert mode == 0o600


# --- (1) cross-process durability ---------------------------------------------------------------------


def test_cross_process_durability_fresh_registry_reads_back(tmp_path):
    led = _ledger(tmp_path)
    writer = ConfirmationRegistry(ledger=led)
    key = writer.register(_esc(seq=7, target="http://10.0.0.5/login", reason="over-cap sqlmap"))
    assert key == ("w1", "m1", 7)

    # A FRESH registry over the SAME ledger (a separate process/resolver) rehydrates the pending escalation.
    reader = ConfirmationRegistry(ledger=led)
    assert reader.pending_keys() == [key]                     # durably read back
    assert reader.resolution(key) is None                     # still pending — no signed approval yet

    # THE GAP: a registry with NO durable backing is empty — that is exactly the pre-fix behaviour.
    assert ConfirmationRegistry().pending_keys() == []
    assert ConfirmationRegistry(ledger=EscalationLedger(str(tmp_path / "other.jsonl"))).pending_keys() == []


def test_rehydrated_escalation_carries_binding_key_and_fields(tmp_path):
    led = _ledger(tmp_path)
    ConfirmationRegistry(ledger=led).register(_esc(wave="w2", member="m9", seq=3, tool="hydra", tier="A3"))
    reader = ConfirmationRegistry(ledger=led)
    (key,) = reader.pending_keys()
    assert key == ("w2", "m9", 3)
    # resolve exercises the restored pending escalation (fail-closed with no approver)
    res = reader.resolve(key, "sig", approver=None)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


# --- (2) fail-closed resolve + append-only precedence -------------------------------------------------


def test_fresh_reader_resolve_is_fail_closed(tmp_path):
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))

    # no approver
    r1 = ConfirmationRegistry(ledger=led).resolve(key, "sig", approver=None)
    assert r1.outcome == ConfirmationOutcome.REJECTED and r1.approved is False
    # None approval, even with an approver wired
    key2 = ConfirmationRegistry(ledger=led).register(_esc(seq=2))
    r2 = ConfirmationRegistry(ledger=led).resolve(key2, None, approver=_approver_ok)
    assert r2.outcome == ConfirmationOutcome.REJECTED
    # a non-approving verdict
    key3 = ConfirmationRegistry(ledger=led).register(_esc(seq=3))
    r3 = ConfirmationRegistry(ledger=led).resolve(key3, "sig", approver=_approver_no)
    assert r3.outcome == ConfirmationOutcome.REJECTED


def test_recorded_reject_stays_final_after_a_later_approval(tmp_path):
    """A recorded REJECT is FINAL on disk: a later signed 'approval' from a fresh reader can NOT flip it — no
    replay-launder across a restart."""
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=5))
    # reader B rejects it (fail-closed, no approver) — durably recorded
    ConfirmationRegistry(ledger=led).resolve(key, "sig", approver=None)

    # reader C rehydrates the REJECT and tries to approve with a VALID approver → still REJECTED, FINAL
    reader_c = ConfirmationRegistry(ledger=led)
    assert reader_c.resolution(key).outcome == ConfirmationOutcome.REJECTED
    after = reader_c.resolve(key, "sig", approver=_approver_ok)
    assert after.outcome == ConfirmationOutcome.REJECTED and after.approved is False
    # and a fourth reader still sees REJECTED (the "approval" wrote no laundering record)
    assert ConfirmationRegistry(ledger=led).resolution(key).outcome == ConfirmationOutcome.REJECTED


def test_expired_stays_final_across_restart(tmp_path):
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))
    # expire it (past deadline) in reader B
    ConfirmationRegistry(ledger=led).resolve(key, "sig", approver=_approver_ok, seq=10_000)
    resB = ConfirmationRegistry(ledger=led).resolution(key)
    assert resB.outcome == ConfirmationOutcome.EXPIRED
    # a fresh reader's approval can't resurrect it
    assert ConfirmationRegistry(ledger=led).resolve(
        key, "sig", approver=_approver_ok).outcome == ConfirmationOutcome.EXPIRED


def test_append_only_precedence_register_after_reject_does_not_reopen(tmp_path):
    """A hand-tampered ledger with a register appended AFTER a reject must NOT reopen the key on replay."""
    path = tmp_path / "tamper.escalations.jsonl"
    reg_rec = {"event": "register", "wave_id": "w", "member_id": "m", "seq": 1,
               "tool_name": "sqlmap", "requested_tier": "A3", "target": "", "reason": "", "deadline_seq": 601}
    rej_rec = {"event": "rejected", "wave_id": "w", "member_id": "m", "seq": 1,
               "approved": False, "reason": "operator declined"}
    path.write_text(json.dumps(reg_rec) + "\n" + json.dumps(rej_rec) + "\n" + json.dumps(reg_rec) + "\n",
                    encoding="utf-8")
    reader = ConfirmationRegistry(ledger=EscalationLedger(str(path)))
    assert reader.pending_keys() == []                                    # the late register is ignored
    assert reader.resolution(("w", "m", 1)).outcome == ConfirmationOutcome.REJECTED


def test_tampered_reject_with_approved_true_never_restores_allow(tmp_path):
    """Deny-by-default on rehydration: a forged 'rejected' record carrying approved=true still restores as
    a NON-approved rejection (only an APPROVED-kind record with approved=true is an allow)."""
    path = tmp_path / "forge.escalations.jsonl"
    path.write_text(json.dumps({"event": "rejected", "wave_id": "w", "member_id": "m", "seq": 1,
                                "approved": True, "reason": "x"}) + "\n", encoding="utf-8")
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path))).resolution(("w", "m", 1))
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


def test_signed_approval_roundtrips_durably(tmp_path):
    """A GENUINE signed approval — an Ed25519 envelope over the exact escalation terminal, verified against a
    PINNED trusted approver key — is durable: reader B approves, reader C (same pinned key) reads back APPROVED.
    A boolean approver alone (no re-verifiable signature) can NO LONGER mint a durable allow (Tier-B fix)."""
    kid, pub, priv = _approver_identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=2))

    envelope = sign_escalation_approval(priv, key_id=kid, key=key)
    approved = ConfirmationRegistry(ledger=led, trusted_approvers=_trusted(kid, pub)).resolve(key, envelope)
    assert approved.outcome == ConfirmationOutcome.APPROVED and approved.approved is True

    # a fresh registry with the SAME pinned key re-verifies the embedded signature on replay → APPROVED
    assert ConfirmationRegistry(ledger=led, trusted_approvers=_trusted(kid, pub)).resolution(key).approved is True
    # HONEST BOUND: a reader that does NOT pin the approver key cannot verify the durable allow → it degrades
    # to REJECTED on replay (fail-safe: an un-trusting reader denies rather than trusts an unverifiable allow).
    assert ConfirmationRegistry(ledger=led).resolution(key).outcome == ConfirmationOutcome.REJECTED

    # a bare boolean approver over a ledger-backed registry (no signature) fail-closes now
    key2 = ConfirmationRegistry(ledger=led).register(_esc(seq=3))
    fake = ConfirmationRegistry(ledger=led).resolve(key2, "sig", approver=_approver_ok)
    assert fake.outcome == ConfirmationOutcome.REJECTED and fake.approved is False


# --- (3) redaction parity -----------------------------------------------------------------------------


def test_redaction_parity_secrets_scrubbed_before_store(tmp_path):
    """The four neg-control patterns — api_key= / Bearer / user:pass@host / --flag — are scrubbed by
    redact_tool_args BEFORE the escalation reaches the durable ledger. Asserted against the RAW file bytes."""
    led = _ledger(tmp_path)
    # user:pass@host lives in the target (a URL); the KV / Bearer / flag secrets live in the reason. Each is
    # the effective secret assignment in its field (see the residual test below for the one compositional gap).
    target = "http://admin:SENTINELPW@10.0.0.5/login?x=1"
    reason = "retry api_key=SENTINELAK with Bearer SENTINELBEARER and --token SENTINELFLAG"
    ConfirmationRegistry(ledger=led).register(_esc(seq=1, target=target, reason=reason))

    raw = (tmp_path / "eng-a.escalations.jsonl").read_text(encoding="utf-8")
    for secret in ("SENTINELPW", "SENTINELAK", "SENTINELBEARER", "SENTINELFLAG"):
        assert secret not in raw, f"secret {secret!r} survived into the durable ledger"

    # and the redacted escalation still rehydrates (structure preserved, secret gone)
    reader = ConfirmationRegistry(ledger=led)
    assert reader.pending_keys() == [("w1", "m1", 1)]


def test_resolution_reason_is_redacted_before_store(tmp_path):
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))
    # a non-approving verdict whose reason echoes a secret must be scrubbed in the durable record
    ConfirmationRegistry(ledger=led).resolve(key, "sig",
                                             approver=lambda s, e: _Appr(False, "declined; api_key=LEAKME123"))
    raw = (tmp_path / "eng-a.escalations.jsonl").read_text(encoding="utf-8")
    assert "LEAKME123" not in raw


def test_redaction_residual_nonsecret_prefix_is_a_known_shared_scrubber_limit(tmp_path):
    """HONESTY: redact_tool_args (the ONE mandated scrubber, shared with engine.py's escalation redaction and
    the live-feed spine) has a pre-existing compositional residual — a NON-secret ``word:`` / ``word=`` prefix
    immediately before a secret assignment swallows it (the KV value class crosses ``=``/``:``), so the trailing
    secret is not masked. This is a property of the shared scrubber, NOT of the durable ledger; the ledger
    applies the SAME scrubber engine.py already applies to the report row, so it is no worse. Documented here
    so the boundary is explicit rather than hidden. (The userinfo password is still masked by the URL arm.)"""
    led = _ledger(tmp_path)
    ConfirmationRegistry(ledger=led).register(
        _esc(seq=1, target="http://admin:MASKEDPW@h/x?api_key=RESIDUAL_AK"))
    raw = (tmp_path / "eng-a.escalations.jsonl").read_text(encoding="utf-8")
    assert "MASKEDPW" not in raw                 # the URL userinfo password IS masked
    assert "RESIDUAL_AK" in raw                  # the trailing query api_key is the known residual (swallowed)


# --- (4) hand-run parity ------------------------------------------------------------------------------


def test_hand_run_parity_no_proof_run_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_PROOF_RUN_DIR", raising=False)
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=4, target="http://h/x", reason="over cap"))
    # the ledger path is explicit — durability does NOT depend on the console progress env
    reader = ConfirmationRegistry(ledger=led)
    assert reader.pending_keys() == [key]
    assert reader.resolution(key) is None
