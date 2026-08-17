"""
Claim-6 Tier-B — MANDATORY SIGNED fireteam replay + ATOMIC resolver (the confirmed-defect acceptance gate).

The pre-Tier-B defect: :meth:`ConfirmationRegistry._apply_record` restored a TERMINAL APPROVED
(approved=True) DIRECTLY from an UNSIGNED :class:`EscalationLedger` record — the ledger's path-safety
(O_NOFOLLOW + S_ISREG + st_nlink==1) is INTEGRITY, not content-authorization, so a byte-legal
``{"event":"approved",...,"approved":true}`` line written to the 0600 ledger rehydrated as APPROVED with
no approver. Also, two resolvers over one ledger could reach DIVERGENT terminals (one APPROVED, one
REJECTED), both persisted — the durable "winner" was just file order.

The fix, exercised here against the real ledger + registry (no framework, no network — the sovereign leg):

  (1) FORGED / UNSIGNED terminal on replay -> fail-closed REJECTED (never APPROVED);
  (2) a signature bound to a DIFFERENT escalation key, or FLIPPED reject->approve, or from a NON-pinned key,
      or with TAMPERED bytes -> unbound/invalid -> REJECTED;
  (3) a GENUINE signed approval (produced against the pinned approver key) -> APPROVED on rehydrate;
  (4) RACING resolvers over one ledger -> exactly ONE coordinated terminal persists; the divergent one is
      refused at write (the atomic O_EXCL claim, not file order, decides — incl. append-only reject-first);
  (5) planted-node path-safety (symlink / hardlink st_nlink>1 / FIFO) -> the ledger append is REFUSED;
  (6) deny-by-default on reject/expire + append-only precedence preserved under the signed model.

HONEST BOUND asserted: the signature closes forged/unsigned/replayed/flipped/divergent terminals; it does
NOT defend a compromised approver private key (an attacker holding it signs a genuine approval).
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from vigil_core import generate_keypair, sign

from vigil_integration.fireteam import (
    ConfirmationOutcome,
    ConfirmationRegistry,
    EscalationLedger,
    EscalationRequest,
    escalation_approval_bytes,
    sign_escalation_approval,
)


# --- helpers ------------------------------------------------------------------------------------------


def _esc(wave="w1", member="m1", seq=1, *, tool="sqlmap", tier="A3", target="", reason=""):
    return EscalationRequest(wave_id=wave, member_id=member, seq=seq, tool_name=tool,
                             requested_tier=tier, target=target, reason=reason)


def _identity(key_id="owner"):
    kp = generate_keypair()
    return key_id, kp.public_key_b64, kp.private_key_b64


def _ledger(tmp_path, name="eng.escalations.jsonl"):
    return EscalationLedger(str(tmp_path / name))


def _terminal_lines(path):
    """The terminal (approved/rejected/expired) records physically present in the ledger file."""
    terms = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("event") in ("approved", "rejected", "expired"):
            terms.append(obj)
    return terms


# --- (1) the operator's exact forged case -------------------------------------------------------------


def test_forged_unsigned_approved_line_fails_closed_on_replay(tmp_path):
    """THE reproduction: an UNSIGNED ``approved`` line written to the 0600 ledger must rehydrate as
    REJECTED (fail-closed), NOT APPROVED — even with a trusted key pinned (there is no signature to verify)."""
    kid, pub, _priv = _identity()
    path = tmp_path / "forge.escalations.jsonl"
    path.write_text(json.dumps(
        {"event": "approved", "wave_id": "w1", "member_id": "m1", "seq": 7, "approved": True}) + "\n",
        encoding="utf-8")

    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(("w1", "m1", 7))
    assert res is not None
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False

    # and with NO trust root pinned, identically fail-closed (deny-by-default)
    res2 = ConfirmationRegistry(ledger=EscalationLedger(str(path))).resolution(("w1", "m1", 7))
    assert res2.outcome == ConfirmationOutcome.REJECTED and res2.approved is False


def test_forged_approved_with_bogus_envelope_fails_closed(tmp_path):
    """An ``approved`` line carrying a MADE-UP ``approval`` envelope (wrong key_id / junk signature) still
    fails closed — the signature does not verify against the pinned key."""
    kid, pub, _priv = _identity()
    path = tmp_path / "forge2.escalations.jsonl"
    path.write_text(json.dumps({
        "event": "approved", "wave_id": "w1", "member_id": "m1", "seq": 1, "approved": True,
        "approval": {"schema": "vigil.fireteam.escalation-approval.v1", "key_id": kid,
                     "alg": "ed25519", "signature_b64": "AA" * 43 + "="},  # 64-byte junk, not a real sig
    }) + "\n", encoding="utf-8")
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(("w1", "m1", 1))
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


# --- (2) unbound / flipped / non-pinned / tampered signatures -----------------------------------------


def test_signature_bound_to_a_different_key_is_unbound_rejected(tmp_path):
    """A genuine signature minted for escalation KEY-A cannot approve escalation KEY-B (cross-escalation
    replay): the signed bytes carry KEY-A's identity, so verification over KEY-B's bytes fails."""
    kid, pub, priv = _identity()
    key_a = ("w1", "m1", 1)
    key_b = ("w1", "m1", 2)
    envelope_for_a = sign_escalation_approval(priv, key_id=kid, key=key_a)

    path = tmp_path / "replay.escalations.jsonl"
    # plant a register for KEY-B and an approved record for KEY-B carrying KEY-A's envelope
    recs = [
        {"event": "register", "wave_id": "w1", "member_id": "m1", "seq": 2, "tool_name": "sqlmap",
         "requested_tier": "A3", "target": "", "reason": "", "deadline_seq": 602},
        {"event": "approved", "wave_id": "w1", "member_id": "m1", "seq": 2, "approved": True,
         "approval": envelope_for_a},
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(key_b)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


def test_reject_to_approve_flip_is_rejected(tmp_path):
    """A signature minted over the (key, "rejected", False) bytes cannot authorize an APPROVED terminal:
    replay reconstructs the bytes for (key, "approved", True), so the flipped signature does not verify."""
    kid, pub, priv = _identity()
    key = ("w1", "m1", 3)
    # sign over the REJECT terminal, then try to smuggle it into an APPROVED record
    flip_env = sign_escalation_approval(priv, key_id=kid, key=key, outcome="rejected", approved=False)
    path = tmp_path / "flip.escalations.jsonl"
    path.write_text(json.dumps(
        {"event": "approved", "wave_id": "w1", "member_id": "m1", "seq": 3, "approved": True,
         "approval": flip_env}) + "\n", encoding="utf-8")
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(key)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


def test_signature_from_a_non_pinned_key_is_rejected(tmp_path):
    """A valid signature by an approver whose key is NOT pinned as trusted is rejected (unknown key_id):
    only the pinned approver authorizes."""
    kid, pub, priv = _identity("owner")
    attacker_kid, _attacker_pub, attacker_priv = _identity("attacker")
    key = ("w1", "m1", 4)
    # the attacker signs a perfectly-bound approval, but under THEIR (un-pinned) key
    env = sign_escalation_approval(attacker_priv, key_id=attacker_kid, key=key)
    path = tmp_path / "nonpinned.escalations.jsonl"
    path.write_text(json.dumps(
        {"event": "approved", "wave_id": "w1", "member_id": "m1", "seq": 4, "approved": True,
         "approval": env}) + "\n", encoding="utf-8")
    # the registry pins ONLY the owner key
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(key)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


def test_tampered_signature_bytes_are_rejected(tmp_path):
    """A genuine envelope whose signature byte is flipped no longer verifies -> REJECTED."""
    kid, pub, priv = _identity()
    key = ("w1", "m1", 5)
    env = sign_escalation_approval(priv, key_id=kid, key=key)
    # corrupt one base64 char of the signature deterministically
    sig = env["signature_b64"]
    env["signature_b64"] = ("B" if sig[0] != "B" else "C") + sig[1:]
    path = tmp_path / "tamper.escalations.jsonl"
    path.write_text(json.dumps(
        {"event": "approved", "wave_id": "w1", "member_id": "m1", "seq": 5, "approved": True,
         "approval": env}) + "\n", encoding="utf-8")
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(key)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


# --- (3) a genuine signed approval survives replay ----------------------------------------------------


def test_genuine_signed_approval_survives_replay(tmp_path):
    """resolve() with a real signed envelope (Path V) -> APPROVED, and a FRESH registry with the same pinned
    key re-verifies the embedded signature on replay -> APPROVED."""
    kid, pub, priv = _identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=2))

    env = sign_escalation_approval(priv, key_id=kid, key=key)
    resolved = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).resolve(key, env)
    assert resolved.outcome == ConfirmationOutcome.APPROVED and resolved.approved is True

    fresh = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    assert fresh.resolution(key).outcome == ConfirmationOutcome.APPROVED
    assert fresh.resolution(key).approved is True

    # the durable record physically carries the signed envelope (so any pinned reader can re-verify offline)
    (approved_rec,) = _terminal_lines(tmp_path / "eng.escalations.jsonl")
    assert approved_rec["event"] == "approved"
    assert approved_rec["approval"]["key_id"] == kid and approved_rec["approval"]["signature_b64"]


def test_resolve_without_signer_over_ledger_fails_closed(tmp_path):
    """The offense engine holds NO private key: a resolve() over a ledger without a verifying envelope
    (a bare string / a boolean approver) can NOT mint a durable allow -> REJECTED."""
    kid, pub, _priv = _identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=9))
    res = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).resolve(key, "not-an-envelope")
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


# --- ADVISORY-1: engagement isolation is INTRINSIC, not the wave_id convention ------------------------


def test_cross_engagement_replay_with_colliding_wave_id_fails_closed(tmp_path):
    """A GENUINE owner approval minted for engagement A does NOT reopen as APPROVED when its record is
    replayed into engagement B's registry/ledger — even with an IDENTICAL bare (wave_id, member_id, seq)
    and the SAME pinned owner key. The engagement is bound into the signed bytes and sourced from the
    verifier's own registry config, so isolation does not depend on the ``wave_id = f'{slug}-w{seq}'``
    convention."""
    kid, pub, priv = _identity()              # the SAME owner key pins both engagements
    key = ("w1", "m1", 1)                       # identical bare key across both engagements

    led_a = EscalationLedger(str(tmp_path / "a.escalations.jsonl"))
    led_b = EscalationLedger(str(tmp_path / "b.escalations.jsonl"))

    # engagement A: register + a genuine owner approval bound to "eng-A" -> APPROVED (positive control)
    ConfirmationRegistry(ledger=led_a, engagement="eng-A").register(_esc(seq=1))
    env_a = sign_escalation_approval(priv, key_id=kid, key=key, engagement="eng-A")
    a_res = ConfirmationRegistry(ledger=led_a, trusted_approvers={kid: pub},
                                 engagement="eng-A").resolve(key, env_a)
    assert a_res.outcome == ConfirmationOutcome.APPROVED and a_res.approved is True

    # the attacker copies A's genuine approved record (A's envelope + identical key) into B's ledger, which
    # already has the same escalation pending
    ConfirmationRegistry(ledger=led_b, engagement="eng-B").register(_esc(seq=1))
    (a_approved,) = _terminal_lines(tmp_path / "a.escalations.jsonl")
    with open(str(tmp_path / "b.escalations.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(a_approved) + "\n")

    # engagement B (SAME pinned owner key) rehydrates the replayed record -> REJECTED, fail-closed
    b_reader = ConfirmationRegistry(ledger=led_b, trusted_approvers={kid: pub}, engagement="eng-B")
    assert b_reader.resolution(key).outcome == ConfirmationOutcome.REJECTED
    assert b_reader.resolution(key).approved is False

    # PROOF the rejection is PURELY the engagement binding: reading the SAME B-ledger bytes with engagement
    # "eng-A" re-verifies A's signature -> APPROVED (only the engagement string differs across accept/reject)
    a_over_b = ConfirmationRegistry(ledger=led_b, trusted_approvers={kid: pub}, engagement="eng-A")
    assert a_over_b.resolution(key).outcome == ConfirmationOutcome.APPROVED

    # and a direct resolve() in B with A's envelope also fails closed (Path V verifies under engagement B)
    led_c = EscalationLedger(str(tmp_path / "c.escalations.jsonl"))
    ConfirmationRegistry(ledger=led_c, engagement="eng-B").register(_esc(seq=1))
    c_res = ConfirmationRegistry(ledger=led_c, trusted_approvers={kid: pub},
                                 engagement="eng-B").resolve(key, env_a)
    assert c_res.outcome == ConfirmationOutcome.REJECTED and c_res.approved is False


# --- (4) racing resolvers reach exactly one coordinated terminal --------------------------------------


def test_racing_resolvers_one_coordinated_terminal_approve_wins(tmp_path):
    """Two registries over one ledger both see the escalation PENDING, then resolve concurrently. The first
    to win the atomic O_EXCL claim fixes the single terminal; the divergent resolver is REFUSED at write and
    adopts the coordinated winner. Here APPROVE (with a valid signature) is claimed first."""
    kid, pub, priv = _identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))

    # both A and B rehydrate the SAME pending escalation (neither has resolved it yet)
    reg_a = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    reg_b = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    assert reg_a.pending_keys() == [key] and reg_b.pending_keys() == [key]

    env = sign_escalation_approval(priv, key_id=kid, key=key)
    a_res = reg_a.resolve(key, env)                 # A wins the atomic claim -> APPROVED, appends
    assert a_res.outcome == ConfirmationOutcome.APPROVED

    b_res = reg_b.reject(key, "member declined")    # B loses the claim -> adopts the coordinated APPROVED
    assert b_res.outcome == ConfirmationOutcome.APPROVED and b_res.approved is True

    # exactly ONE terminal is durably persisted, and a fresh reader sees the coordinated APPROVED
    assert len(_terminal_lines(tmp_path / "eng.escalations.jsonl")) == 1
    assert ConfirmationRegistry(ledger=led,
                                trusted_approvers={kid: pub}).resolution(key).outcome == ConfirmationOutcome.APPROVED


def test_racing_resolvers_reject_first_is_final_over_a_later_signed_approve(tmp_path):
    """Append-only precedence via the atomic claim: if REJECT wins the claim first, a later — even VALID,
    signed — APPROVE is refused at write and adopts the coordinated REJECT (a recorded deny is FINAL)."""
    kid, pub, priv = _identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))

    reg_reject = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    reg_approve = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})

    r_res = reg_reject.reject(key, "operator declined")   # REJECT wins the atomic claim, appends
    assert r_res.outcome == ConfirmationOutcome.REJECTED

    env = sign_escalation_approval(priv, key_id=kid, key=key)
    a_res = reg_approve.resolve(key, env)                 # a VALID approval, but it LOST the race -> REJECTED
    assert a_res.outcome == ConfirmationOutcome.REJECTED and a_res.approved is False

    assert len(_terminal_lines(tmp_path / "eng.escalations.jsonl")) == 1
    assert ConfirmationRegistry(ledger=led,
                                trusted_approvers={kid: pub}).resolution(key).outcome == ConfirmationOutcome.REJECTED


def test_same_outcome_racing_is_idempotent(tmp_path):
    """Two resolvers reaching the SAME terminal (both reject) coordinate to a single durable terminal — a
    same-outcome retry is not a divergence."""
    kid, pub, _priv = _identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))
    reg1 = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    reg2 = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    assert reg1.reject(key).outcome == ConfirmationOutcome.REJECTED
    assert reg2.reject(key).outcome == ConfirmationOutcome.REJECTED
    assert len(_terminal_lines(tmp_path / "eng.escalations.jsonl")) == 1


def test_planted_cas_marker_denies_never_approves(tmp_path):
    """HONEST BOUND: the CAS marker is an integrity-only write-serialization guard, not signed. A PLANTED
    marker makes a legitimate resolver LOSE the race; it then re-reads the signature-gated ledger and, finding
    no durable terminal, fail-closes to REJECTED — a planted marker can DENY but never manufacture an allow."""
    kid, pub, priv = _identity()
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))
    # pre-plant the key's CAS marker (as an attacker with dir write access would)
    from vigil_integration.fireteam.confirmation import _key_digest
    cas_dir = str(tmp_path / "eng.escalations.jsonl.cas")
    os.makedirs(cas_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(cas_dir, _key_digest(key)), "w", encoding="utf-8") as fh:
        fh.write("planted")

    env = sign_escalation_approval(priv, key_id=kid, key=key)
    res = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).resolve(key, env)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False
    # nothing durable was written as an allow
    assert _terminal_lines(tmp_path / "eng.escalations.jsonl") == []


# --- (5) planted-node path-safety (extend the ledger append guard's coverage) -------------------------


def test_ledger_append_refuses_symlink_target(tmp_path):
    """A ledger path that is a SYMLINK must be refused (O_NOFOLLOW at the final component) — the append is a
    no-op, never a redirected write to the symlink's target."""
    real = tmp_path / "real.jsonl"
    real.write_text("", encoding="utf-8")
    link = tmp_path / "link.escalations.jsonl"
    os.symlink(str(real), str(link))
    led = EscalationLedger(str(link))
    assert led.append({"event": "register", "wave_id": "w", "member_id": "m", "seq": 1}) is False
    assert real.read_text(encoding="utf-8") == ""     # the symlink target was NOT written through


def test_ledger_append_refuses_hardlinked_file(tmp_path):
    """A ledger path with st_nlink>1 (a second hardlink name for the inode) is refused — a planted hardlink
    can neither wedge nor tee the append."""
    original = tmp_path / "original.jsonl"
    original.write_text("", encoding="utf-8")
    hard = tmp_path / "hard.escalations.jsonl"
    os.link(str(original), str(hard))                 # st_nlink == 2
    assert os.stat(str(hard)).st_nlink == 2
    led = EscalationLedger(str(hard))
    assert led.append({"event": "register", "wave_id": "w", "member_id": "m", "seq": 1}) is False


def test_ledger_append_refuses_fifo(tmp_path):
    """A ledger path that is a FIFO is refused (not S_ISREG, and O_NONBLOCK never blocks on a readerless
    FIFO) — a planted FIFO can neither wedge the writer nor absorb the record."""
    fifo = tmp_path / "fifo.escalations.jsonl"
    os.mkfifo(str(fifo))
    assert stat.S_ISFIFO(os.stat(str(fifo)).st_mode)
    led = EscalationLedger(str(fifo))
    assert led.append({"event": "register", "wave_id": "w", "member_id": "m", "seq": 1}) is False


# --- (6) deny-by-default + append-only precedence under the signed model ------------------------------


def test_reject_and_expire_stay_deny_by_default_under_signed_model(tmp_path):
    """reject / expire terminals never carry an allow, and a fresh registry (even with the approver key
    pinned) rehydrates them as non-approving."""
    kid, pub, _priv = _identity()
    led = _ledger(tmp_path)
    k1 = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).register(_esc(seq=1))
    ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).reject(k1, "declined")
    k2 = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).register(_esc(seq=2))
    ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).resolve(k2, "x", seq=10_000)  # expire

    reader = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub})
    assert reader.resolution(k1).outcome == ConfirmationOutcome.REJECTED and reader.resolution(k1).approved is False
    assert reader.resolution(k2).outcome == ConfirmationOutcome.EXPIRED and reader.resolution(k2).approved is False


def test_append_only_a_signed_approve_after_a_reject_never_reopens(tmp_path):
    """A hand-tampered ledger with a genuine-signed approved appended AFTER a reject must NOT reopen the key
    on replay (append-only precedence: the FIRST terminal is final)."""
    kid, pub, priv = _identity()
    key = ("w", "m", 1)
    env = sign_escalation_approval(priv, key_id=kid, key=key)
    path = tmp_path / "aoreopen.escalations.jsonl"
    recs = [
        {"event": "register", "wave_id": "w", "member_id": "m", "seq": 1, "tool_name": "sqlmap",
         "requested_tier": "A3", "target": "", "reason": "", "deadline_seq": 601},
        {"event": "rejected", "wave_id": "w", "member_id": "m", "seq": 1, "approved": False,
         "reason": "operator declined"},
        {"event": "approved", "wave_id": "w", "member_id": "m", "seq": 1, "approved": True, "approval": env},
    ]
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    res = ConfirmationRegistry(ledger=EscalationLedger(str(path)),
                               trusted_approvers={kid: pub}).resolution(key)
    assert res.outcome == ConfirmationOutcome.REJECTED and res.approved is False


def test_escalation_approval_bytes_bind_engagement_key_outcome_and_approved():
    """Unit: the signed bytes change with EACH of (engagement, key, outcome, approved), so a signature
    cannot slide across engagements, escalations, or terminals."""
    base = escalation_approval_bytes(("w", "m", 1), "approved", True, engagement="eng-A")
    assert base != escalation_approval_bytes(("w", "m", 1), "approved", True, engagement="eng-B")  # diff eng
    assert base != escalation_approval_bytes(("w", "m", 1), "approved", True, engagement="")       # diff eng
    assert base != escalation_approval_bytes(("w", "m", 2), "approved", True, engagement="eng-A")  # diff seq
    assert base != escalation_approval_bytes(("w", "x", 1), "approved", True, engagement="eng-A")  # diff member
    assert base != escalation_approval_bytes(("w", "m", 1), "rejected", True, engagement="eng-A")  # diff outcome
    assert base != escalation_approval_bytes(("w", "m", 1), "approved", False, engagement="eng-A")  # diff approved
    assert base.startswith(b"vigil-fireteam-escalation-approval-v2\x00")               # domain-tagged (v2)


def test_compromised_approver_key_is_the_stated_residual(tmp_path):
    """HONEST LIMIT (documented, not a bug): an attacker who holds the approver PRIVATE key can sign a
    genuine approval that the pinned public key verifies. This asserts the boundary explicitly."""
    kid, pub, priv = _identity()          # priv == the (here, compromised) approver private key
    led = _ledger(tmp_path)
    key = ConfirmationRegistry(ledger=led).register(_esc(seq=1))
    env = sign_escalation_approval(priv, key_id=kid, key=key)   # signed with the compromised key
    res = ConfirmationRegistry(ledger=led, trusted_approvers={kid: pub}).resolve(key, env)
    assert res.outcome == ConfirmationOutcome.APPROVED   # the signature closes forgery, NOT key compromise
