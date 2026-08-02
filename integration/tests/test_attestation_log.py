"""VF-1b — the Continuous Attestation Log (attestation_log), a monotonic series of signed remediation
re-proof ticks over the REAL prove_driver + a FakeAdapter (mirrors test_prove_driver.py).

The ticks are GENUINE signed four-state prove-certificates minted by the real orchestrator (the oracle
re-fire is real framework reverify) — a REMEDIATED tick embeds a re-executing RemediationCertificate exactly
like the base flow. The log hash-chains them (vigil_core.build_chain + governance sign_head), guards them
against rollback with a durable vigil_core.highwater floor (entry_count PRIMARY + last_seq), and derives the
VISION drift series. Adversarial matrix: a rolled-back head, a truncated tick log, a tampered tick (even with
the chain re-signed), a forged tick (bad signer), and a high-water downgrade attempt are all refused.

Needs framework (prove_driver's verify/mint + the per-tick REMEDIATED re-execute in verify_log) →
PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vigil_core import (
    AuthorizerKey, TrustRoot, build_chain, digest_payload, generate_keypair, identity_digest,
    prove_wielder, sign_capability, sign_head, sign_identity_attestation,
)
from vigil_core.highwater import HighWaterDowngrade, advance_highwater
from vigil_integration.remediation import attestation_log as al
from vigil_integration.remediation.attestation_log import (
    AttestationError, AttestationRefused, append_tick, verify_log,
)
from vigil_integration.remediation.prove_driver import (
    ControlObservation, Freshness, ProvePolicy, State, TrialObservation, prove_remediation,
)

OWNER = generate_keypair()
WIELDER = generate_keypair()
ATTACKER = generate_keypair()

ENG = "acme"
NOW = 1_000
BUG = "error_based_sqli"
POLICY = {"host": ["shop.acme.test"]}
SAMPLE = {"host": "shop.acme.test"}
PUBKEYS = {"gov0": OWNER.public_key_b64}
SIGNERS = [("gov0", OWNER.private_key_b64)]
TRUST_ROOT = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=OWNER.public_key_b64)])

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''"
_BENIGN = b"HTTP/1.1 200\r\n\r\n{\"results\": []}"


def _context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


class FakeAdapter:
    """A configurable LiveTargetAdapter (the test_prove_driver.py twin). Default → REMEDIATED; trial_fires
    → STILL_VULNERABLE; control_fires=False → INCONCLUSIVE."""

    def __init__(self, *, bug_class=BUG, destructive=False, identity=None, trial_fires=False,
                 trial_freshness=Freshness.F2_PATH_TRAVERSED, control_fires=True, control_reachable=True):
        self.bug_class = bug_class
        self.oracle_family = bug_class
        self.oracle_id = "oracle:" + bug_class
        self.oracle_version = "1.0"
        self.original_probe_recipe_digest = "sha256:probe"
        self.execution_profile_digest = "sha256:profile"
        self.destructive = destructive
        self._identity = identity or dict(SAMPLE)
        self._trial_fires = trial_fires
        self._trial_freshness = trial_freshness
        self._control_fires = control_fires
        self._control_reachable = control_reachable
        self.id_calls = 0

    def identity_sample(self):
        self.id_calls += 1
        return dict(self._identity)

    def run_positive_control(self, *, challenge, auth):
        ctx = _context(_SQL_ERROR if self._control_fires else _BENIGN)
        return ControlObservation(reachable=self._control_reachable, channel_alive=self._control_fires,
                                  oracle_context=ctx, freshness_level=self._trial_freshness,
                                  definition_digest="sha256:control")

    def run_exploit_trial(self, *, challenge, trial_index, auth):
        base = _SQL_ERROR if self._trial_fires else _BENIGN
        if self._trial_freshness >= Freshness.F2_PATH_TRAVERSED:
            base = base + b" echo=" + challenge.encode()   # embed the challenge into the JUDGED body
        return TrialObservation(reachable=True, valid=True, oracle_context=_context(base),
                                freshness_level=self._trial_freshness, nonce_echoed=True)


def _identity_att():
    return sign_identity_attestation(OWNER, engagement=ENG, policy=POLICY, not_after=9_000)


def _mint(adapter, *, signers=SIGNERS, run_id="run-1", freshness_nonce="fresh-nonce-xyz",
          finding_id="errsqli-1") -> dict:
    """Mint ONE real signed prove-certificate via the real orchestrator. run_id/nonce vary per tick so each
    tick has a distinct digest (a realistic re-proof series over the SAME finding)."""
    ident = _identity_att()
    cap = sign_capability(OWNER, engagement=ENG, identity_digest=identity_digest(ident),
                          class_allowlist=[adapter.bug_class], not_before=0, not_after=9_000,
                          rate_limit=10, revocation_id="rev-1", audience=WIELDER.public_key_b64)
    wp = prove_wielder(WIELDER, challenge="pop-1", capability=cap)
    out = prove_remediation(
        adapter=adapter, identity=ident, capability=cap, wielder_proof=wp,
        trusted_owner_pubkey=OWNER.public_key_b64, engagement=ENG, finding_id=finding_id,
        original_certificate_digest="sha256:orig", signers=signers, now=NOW, run_id=run_id,
        pop_challenge="pop-1", freshness_nonce=freshness_nonce, policy=ProvePolicy())
    return out.certificate


def _tick(state_kind: str, i: int) -> dict:
    """Mint a tick certificate of the requested kind with a per-tick-unique run_id/nonce."""
    kw = dict(run_id=f"run-{i}", freshness_nonce=f"nonce-{i}")
    if state_kind == State.REMEDIATED:
        return _mint(FakeAdapter(), **kw)
    if state_kind == State.STILL_VULNERABLE:
        return _mint(FakeAdapter(trial_fires=True), **kw)
    if state_kind == State.INCONCLUSIVE:
        return _mint(FakeAdapter(control_fires=False), **kw)
    raise AssertionError(state_kind)


def _append(log_dir, cert):
    return append_tick(log_dir, cert, engagement_slug=ENG, signers=SIGNERS,
                       trust_root=TRUST_ROOT, signer_pubkeys=PUBKEYS)


def _verify(log_dir):
    return verify_log(log_dir, trust_root=TRUST_ROOT, signer_pubkeys=PUBKEYS)


def _labels(series):
    return [s.label for s in series]


# ============================ real certs are minted as expected ============================
def test_the_driver_mints_the_expected_states():
    assert _mint(FakeAdapter())["state"] == State.REMEDIATED
    assert _mint(FakeAdapter(trial_fires=True))["state"] == State.STILL_VULNERABLE
    assert _mint(FakeAdapter(control_fires=False))["state"] == State.INCONCLUSIVE


# ============================ happy path: the monotonic drift series ============================
def test_series_present_proven_fixed_still_proven_then_regressed(tmp_path):
    log = tmp_path / "attlog"
    kinds = [State.STILL_VULNERABLE, State.REMEDIATED, State.REMEDIATED, State.STILL_VULNERABLE]
    for i, k in enumerate(kinds):
        res = _append(log, _tick(k, i))
        assert res.state == k
        assert res.seq == i                                  # 0-indexed monotonic seq
    ok, reason, series = _verify(log)
    assert ok, reason
    assert _labels(series) == [al.LABEL_PRESENT, al.LABEL_PROVEN_FIXED,
                               al.LABEL_STILL_PROVEN, al.LABEL_REGRESSED]
    assert [s.state for s in series] == kinds


def test_inconclusive_tick_is_recorded_but_does_not_advance_proven(tmp_path):
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.INCONCLUSIVE, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ok, reason, series = _verify(log)
    assert ok, reason
    # the INCONCLUSIVE tick neither promotes nor demotes: the 3rd tick is STILL-proven, not proven-fixed.
    assert _labels(series) == [al.LABEL_PROVEN_FIXED, al.LABEL_INCONCLUSIVE, al.LABEL_STILL_PROVEN]


def test_empty_log_verifies_as_empty(tmp_path):
    ok, reason, series = _verify(tmp_path / "empty")
    assert ok and series == []


# ============================ ADVERSARIAL ============================
def _read_ticks(log):
    return [json.loads(x) for x in (log / al._TICKS_FILE).read_text(encoding="utf-8").splitlines() if x.strip()]


def _resign_head_over(log, ticks):
    entries = build_chain([digest_payload(t) for t in ticks])
    head = sign_head(entries, engagement_slug=ENG, signers=SIGNERS)
    (log / al._HEAD_FILE).write_text(head.model_dump_json(), encoding="utf-8")


def _write_ticks_raw(log, ticks):
    body = "".join(json.dumps(t, sort_keys=True, separators=(",", ":")) + "\n" for t in ticks)
    (log / al._TICKS_FILE).write_text(body, encoding="utf-8")


def test_rolled_back_head_is_rejected_by_the_durable_floor(tmp_path):
    # Build a 3-tick log (floor entry_count=3, last_seq=2). An attacker who can overwrite the log+head but
    # NOT the durable floor truncates to 2 ticks and RE-SIGNS a genuinely-valid smaller head — the in-band
    # signature alone cannot catch that. The persisted floor does: verify_head(prev_highwater) / check_highwater.
    log = tmp_path / "attlog"
    for i, k in enumerate([State.STILL_VULNERABLE, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks = _read_ticks(log)
    _write_ticks_raw(log, ticks[:2])          # drop the last tick
    _resign_head_over(log, ticks[:2])         # a VALID owner-signed head over the shorter chain
    # floor (highwater.json) is left at the high mark — the attacker could not rewrite it (or an OOB verifier
    # retained it). verify_log must reject the rollback.
    ok, reason, series = _verify(log)
    assert not ok and ("rolled back" in reason or "ROLLBACK" in reason or "high-water" in reason.lower()), reason


def test_truncated_tick_log_is_rejected(tmp_path):
    # Remove the last tick from the log but leave head.json committing the full count → the persisted head no
    # longer matches the rebuilt chain (head↔chain binding) → rejected.
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks = _read_ticks(log)
    _write_ticks_raw(log, ticks[:2])          # head.json still commits 3
    ok, reason, series = _verify(log)
    assert not ok and ("truncated" in reason.lower() or "rewritten" in reason.lower()
                       or "rolled back" in reason.lower()), reason


def test_full_truncation_to_empty_is_rejected_by_the_floor(tmp_path):
    # BLOCK-1 regression: an attacker empties ticks.jsonl AND removes head.json but CANNOT touch the durable
    # floor (attacker-(i) / an OOB verifier holding the floor). verify_log must NOT report a clean empty log —
    # the floor remembers entry_count>0, so this is a rollback (a full erasure of a signed attested series).
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    (log / al._TICKS_FILE).write_text("", encoding="utf-8")   # empty the tick log
    (log / al._HEAD_FILE).unlink()                            # remove the signed head
    # highwater.json is UNTOUCHED (entry_count=3)
    ok, reason, series = _verify(log)
    assert not ok and "rollback" in reason.lower() and series == [], reason


def test_one_to_zero_truncation_is_rejected_by_entry_count(tmp_path):
    # The entry_count-vs-last_seq degeneracy at the boundary: a 1-tick log has last_seq=0 (same as empty), so a
    # 1->0 truncation is caught ONLY by the entry_count floor — and only if the floor is consulted before the
    # empty short-circuit (the BLOCK-1 fix).
    log = tmp_path / "attlog"
    _append(log, _tick(State.REMEDIATED, 0))
    (log / al._TICKS_FILE).write_text("", encoding="utf-8")
    (log / al._HEAD_FILE).unlink()
    ok, reason, series = _verify(log)
    assert not ok and "rollback" in reason.lower(), reason


def test_genuinely_empty_log_with_no_floor_still_verifies_empty(tmp_path):
    # The fix must not over-reject: a never-appended log (no ticks, no head, NO floor) is genuinely empty.
    ok, reason, series = _verify(tmp_path / "never-used")
    assert ok and series == [] and "empty" in reason.lower()


def test_tampered_tick_is_rejected_even_if_the_chain_is_re_signed(tmp_path):
    # A tampered tick changes its digest → the head no longer binds it. An attacker WITH the governance key
    # could re-chain + re-sign the head over the tampered set (verify_head then passes) — but the per-tick
    # prove-cert signature still catches the tamper: verify_prove_certificate rejects it.
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks = _read_ticks(log)
    ticks[0]["verdict"]["reason_code"] = "totally_made_up"   # breaks the tick's own signature
    _write_ticks_raw(log, ticks)
    _resign_head_over(log, ticks)             # make verify_head PASS so the per-tick check is what fires
    ok, reason, series = _verify(log)
    assert not ok and "re-verification" in reason, reason


def test_forged_tick_bad_signer_is_refused_at_admission(tmp_path):
    # A cert signed by the ATTACKER under key_id 'gov0' (a forgery) — internally consistent but not the pinned
    # governance key. append_tick refuses it at the door; it never enters the chain.
    log = tmp_path / "attlog"
    _append(log, _tick(State.REMEDIATED, 0))            # a genuine first tick
    forged = _mint(FakeAdapter(), signers=[("gov0", ATTACKER.private_key_b64)], run_id="run-x")
    with pytest.raises(AttestationRefused):
        _append(log, forged)
    # the forged tick did NOT get persisted — the log is still the single genuine tick.
    ok, reason, series = _verify(log)
    assert ok and len(series) == 1, reason


def test_tampered_cert_before_admission_is_refused(tmp_path):
    # A directly-tampered (unsigned-consistent) cert handed to append_tick is refused at admission.
    log = tmp_path / "attlog"
    good = _tick(State.REMEDIATED, 0)
    good["state"] = State.STILL_VULNERABLE           # verdict/sig no longer agree
    with pytest.raises(AttestationRefused):
        _append(log, good)


def test_high_water_downgrade_attempt_raises(tmp_path):
    # After a real series, a direct attempt to advance the durable floor DOWNWARD (a lower head) raises the
    # typed HighWaterDowngrade — the exact guard append_tick relies on to stay upward-only.
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    hw_path = log / al._HIGHWATER_FILE
    with pytest.raises(HighWaterDowngrade):
        advance_highwater(hw_path, SimpleNamespace(entry_count=1, last_seq=0))


def test_wrong_trust_root_fails_verify(tmp_path):
    # A verifier pinning the WRONG governance key rejects the head signature (caller-pinned trust, like the
    # proof bundle) — the log carries no trust root of its own.
    log = tmp_path / "attlog"
    _append(log, _tick(State.REMEDIATED, 0))
    other = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=ATTACKER.public_key_b64)])
    ok, reason, series = verify_log(log, trust_root=other, signer_pubkeys=PUBKEYS)
    assert not ok, reason
