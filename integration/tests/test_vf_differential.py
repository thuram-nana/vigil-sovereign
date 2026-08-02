"""VF-1d — DIFFERENTIAL test: the STANDALONE ``verify_vf`` agrees with the in-tree VIGIL verifiers.

The property under test is the whole point of VF-1d: a third party can re-derive the remediation
lifecycle — vulnerable → proven-fixed → still-proven, witnessed, no-later-than T — with ZERO VIGIL code
(``docs/proof-carrying-finding/verify_vf.py``, stdlib + one Ed25519 lib), and its verdict is IDENTICAL to
what VIGIL's own verifiers say, on:

  (a) a REAL, genuinely-minted artifact (a REMEDIATED + a STILL_VULNERABLE prove-cert via the real
      prove_driver + FakeAdapter; a real attestation log via append_tick; a real witnessed checkpoint via
      witness_attestation_head); and
  (b) a battery of single-byte / single-field TAMPERS (flip state, strip signer, wrong pinned key,
      truncate a tick, roll back the floor, drop / corrupt a witness sig, sub-majority quorum, …), plus
      re-SIGNED structural tampers that exercise the deeper (post-signature) checks.

Any DISAGREEMENT between the standalone and the VIGIL verdict = a spec ambiguity or a bug, and the test
FAILS. It also asserts BYTE-PARITY of the re-implemented canonical bytes / signing bytes against the real
producers, and proves standalone-cleanliness by running ``verify_vf --prove-standalone`` in a subprocess
whose interpreter cannot import any VIGIL module.

THE DOCUMENTED BOUNDARY (why the two verifiers still agree): the standalone verifier NEVER re-fires the
oracle — it checks signatures, binding, cross-binding, chain, anti-rollback, quorum, and the median clock.
Oracle silence/fire is the one layer that needs the framework. Every tamper below breaks a SIGNATURE, a
BINDING, or a STRUCTURAL invariant that BOTH verifiers check — none is an oracle-re-fire-only defect, so
the boundary never causes a disagreement.

Needs framework (the prove_driver oracle re-fire + the REMEDIATED embedded re-execute in the VIGIL side)
→ PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_core import (
    AuthorizerKey, SignedChainHead, TrustRoot, build_chain, canonical_json, digest_payload,
    generate_keypair, identity_digest, prove_wielder, sign, sign_capability, sign_head,
    sign_identity_attestation,
)
from vigil_core.canonical import evidence_signing_bytes as vigil_evidence_bytes
from vigil_core.chain import _head_payload as vigil_head_payload
from vigil_integration.transparency import checkpoint_of
from vigil_integration.remediation import attestation_log as al
from vigil_integration.remediation import remediation_cert as rc
from vigil_integration.remediation.attestation_log import append_tick, verify_log
from vigil_integration.remediation.attestation_witness import (
    TimedWitnessSignature,
    _timed_signing_bytes as vigil_timed_bytes,
    verify_timed_witnessed,
    witness_attestation_head,
)
from vigil_integration.remediation.prove_driver import (
    ControlObservation, Freshness, ProvePolicy, State, TrialObservation,
    _cert_signing_bytes as vigil_prove_bytes,
    prove_remediation, verify_prove_certificate,
)

# --- load the STANDALONE verifier. Importing it in-process (offense venv) is legitimate: verify_vf imports
#     ONLY stdlib + cryptography, so loading it pulls in no VIGIL code (the --prove-standalone subprocess
#     below proves the stronger property that no VIGIL module is even importable in a clean interpreter). ---
_PCF_DIR = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding"
_VERIFIER = _PCF_DIR / "verify_vf.py"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify_vf", _VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VF = _load_standalone()

# ---------------------------------------------------------------------------------------------------
# keys, trust roots, and the FakeAdapter (twin of test_prove_driver.py / test_attestation_log.py)
# ---------------------------------------------------------------------------------------------------
OWNER = generate_keypair()
WIELDER = generate_keypair()
ATTACKER = generate_keypair()
W0, W1, W2 = generate_keypair(), generate_keypair(), generate_keypair()

ENG = "acme"
NOW = 1_000
BUG = "error_based_sqli"
POLICY = {"host": ["shop.acme.test"]}
SAMPLE = {"host": "shop.acme.test"}
PUBKEYS = {"gov0": OWNER.public_key_b64}
SIGNERS = [("gov0", OWNER.private_key_b64)]
TRUST_ROOT = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=OWNER.public_key_b64)])
TRUST_ROOT_D = TRUST_ROOT.model_dump(mode="json")

# strict-majority 2-of-3 witness quorum (the canonical split-view-resistant set).
QUORUM = TrustRoot(threshold=2, authorizers=[
    AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
    AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64),
    AuthorizerKey(key_id="w2", name="w2", public_key_b64=W2.public_key_b64)])
QUORUM_D = QUORUM.model_dump(mode="json")

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
    """Default → REMEDIATED; trial_fires → STILL_VULNERABLE; control_fires=False → INCONCLUSIVE. When
    echoing at F2+, embeds the challenge in the JUDGED body so the core can verify freshness."""

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
            base = base + b" echo=" + challenge.encode()
        return TrialObservation(reachable=True, valid=True, oracle_context=_context(base),
                                freshness_level=self._trial_freshness, nonce_echoed=True)


def _mint(adapter, *, signers=SIGNERS, run_id="run-1", freshness_nonce="fresh-nonce-xyz",
          finding_id="errsqli-1") -> dict:
    ident = sign_identity_attestation(OWNER, engagement=ENG, policy=POLICY, not_after=9_000)
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
    kw = dict(run_id=f"run-{i}", freshness_nonce=f"nonce-{i}")
    if state_kind == State.REMEDIATED:
        return _mint(FakeAdapter(), **kw)
    if state_kind == State.STILL_VULNERABLE:
        return _mint(FakeAdapter(trial_fires=True), **kw)
    if state_kind == State.INCONCLUSIVE:
        return _mint(FakeAdapter(control_fires=False), **kw)
    raise AssertionError(state_kind)


def _clone(obj):
    return json.loads(json.dumps(obj))


def _resign_prove(cert: dict) -> dict:
    """Re-sign a (mutated) prove-cert with the OWNER key, so we can test the POST-signature structural
    checks in isolation (a validly-signed but structurally-inconsistent cert)."""
    body = {k: v for k, v in cert.items() if k != "signer"}
    cert["signer"] = {"key_id": "gov0", "signature": sign(OWNER.private_key_b64, vigil_prove_bytes(body))}
    return cert


# ---------------------------------------------------------------------------------------------------
# the differential matrix — every row records (component, case, vigil_verdict, standalone_verdict).
# each test asserts agreement inline; the collected rows are printed by test_zz_report_matrix.
# ---------------------------------------------------------------------------------------------------
MATRIX: list[tuple[str, str, object, object]] = []


def _agree(component: str, case: str, vigil, standalone):
    MATRIX.append((component, case, vigil, standalone))
    assert vigil == standalone, f"DISAGREEMENT [{component}/{case}]: vigil={vigil!r} standalone={standalone!r}"


# ===================================================================================================
# 1. PROVE-CERT differential (REMEDIATED + STILL_VULNERABLE + tampers)
# ===================================================================================================
def _prove_verdicts(cert: dict, pubkeys=PUBKEYS):
    v_ok, _ = verify_prove_certificate(cert, signer_pubkeys=pubkeys)
    s_ok, _ = VF.verify_prove_cert(cert, signer_pubkeys=pubkeys)
    return v_ok, s_ok


def test_prove_cert_valid_remediated_and_still_vulnerable_agree():
    rem = _mint(FakeAdapter())
    assert rem["state"] == State.REMEDIATED
    v, s = _prove_verdicts(rem)
    _agree("prove_cert", "valid-REMEDIATED", v, s)
    assert v is True

    sv = _mint(FakeAdapter(trial_fires=True))
    assert sv["state"] == State.STILL_VULNERABLE
    v, s = _prove_verdicts(sv)
    _agree("prove_cert", "valid-STILL_VULNERABLE", v, s)
    assert v is True

    inc = _mint(FakeAdapter(control_fires=False))
    assert inc["state"] == State.INCONCLUSIVE
    v, s = _prove_verdicts(inc)
    _agree("prove_cert", "valid-INCONCLUSIVE", v, s)
    assert v is True


def test_prove_cert_raw_tampers_agree():
    """Single-byte / field tampers WITHOUT re-signing — caught at the signature layer by both."""
    base = _mint(FakeAdapter())

    # flip state (bytes change → signature breaks)
    t = _clone(base); t["state"] = State.STILL_VULNERABLE
    _agree("prove_cert", "flip-state", *_prove_verdicts(t))

    # strip signer block
    t = _clone(base); t.pop("signer", None)
    _agree("prove_cert", "strip-signer", *_prove_verdicts(t))

    # wrong pinned key (bytes unchanged; verify against the attacker's key)
    _agree("prove_cert", "wrong-pinned-key", *_prove_verdicts(base, {"gov0": ATTACKER.public_key_b64}))

    # signer key_id not in the pinned set
    _agree("prove_cert", "unknown-signer-keyid", *_prove_verdicts(base, {"other": OWNER.public_key_b64}))

    # strip the embedded remediation cert (REMEDIATED)
    t = _clone(base); t["evidence"]["embedded_remediation_cert"] = None
    _agree("prove_cert", "strip-embedded", *_prove_verdicts(t))

    # flip a single signature byte
    t = _clone(base)
    raw = bytearray(base64.b64decode(t["signer"]["signature"])); raw[-1] ^= 0x01
    t["signer"]["signature"] = base64.b64encode(bytes(raw)).decode()
    _agree("prove_cert", "flip-signature-byte", *_prove_verdicts(t))

    # flip a byte inside the embedded patched context (breaks the OUTER signature)
    t = _clone(base)
    t["evidence"]["embedded_remediation_cert"]["patched_oracle_context"]["error_observed"] = "benign"
    _agree("prove_cert", "tamper-embedded-context", *_prove_verdicts(t))


def test_prove_cert_resigned_structural_tampers_agree():
    """Validly RE-SIGNED but structurally-inconsistent certs — caught at the POST-signature checks by
    both (verdict agreement, cross-binding, embedded presence)."""
    base = _mint(FakeAdapter())

    # verdict.remediation_state disagrees with state (re-signed so the sig is valid)
    t = _resign_prove((lambda c: (c["verdict"].__setitem__("remediation_state", State.INCONCLUSIVE), c)[1])(_clone(base)))
    _agree("prove_cert", "resigned-verdict-state-mismatch", *_prove_verdicts(t))

    # verdict.oracle_fired disagrees with state
    t = _clone(base); t["verdict"]["oracle_fired"] = True; _resign_prove(t)
    _agree("prove_cert", "resigned-oracle_fired-mismatch", *_prove_verdicts(t))

    # REMEDIATED with the embedded cert removed (re-signed)
    t = _clone(base); t["evidence"]["embedded_remediation_cert"] = None; _resign_prove(t)
    _agree("prove_cert", "resigned-remediated-no-embedded", *_prove_verdicts(t))

    # cross-binding break: embedded.finding_ref != outer finding_id (outer re-signed; embedded left as-is)
    t = _clone(base)
    t["evidence"]["embedded_remediation_cert"]["finding_ref"] = "some-other-finding"
    _resign_prove(t)
    _agree("prove_cert", "resigned-crossbind-finding_ref", *_prove_verdicts(t))

    # cross-binding break: embedded freshness_nonce != outer freshness_challenge
    t = _clone(base)
    t["evidence"]["embedded_remediation_cert"]["controls"]["freshness_nonce"] = "not-the-challenge"
    _resign_prove(t)
    _agree("prove_cert", "resigned-crossbind-nonce", *_prove_verdicts(t))

    # a STILL_VULNERABLE cert relabelled to REMEDIATED (no embedded → rejected) — re-signed
    sv = _mint(FakeAdapter(trial_fires=True))
    t = _clone(sv); t["state"] = State.REMEDIATED
    t["verdict"]["remediation_state"] = State.REMEDIATED; t["verdict"]["oracle_fired"] = False
    _resign_prove(t)
    _agree("prove_cert", "resigned-SV-relabelled-REMEDIATED", *_prove_verdicts(t))


# ===================================================================================================
# 2. ATTESTATION SERIES differential (a real log + rollback / truncation / tamper / forgery)
# ===================================================================================================
def _load_log(log: Path):
    tp = log / al._TICKS_FILE
    ticks = [json.loads(x) for x in tp.read_text(encoding="utf-8").splitlines() if x.strip()] if tp.exists() else []
    hp = log / al._HEAD_FILE
    head = json.loads(hp.read_text(encoding="utf-8")) if hp.exists() else None
    fp = log / al._HIGHWATER_FILE
    floor = json.loads(fp.read_text(encoding="utf-8")) if fp.exists() else None
    return ticks, head, floor


def _att_verdicts(log: Path, trust_root=TRUST_ROOT, trust_root_d=TRUST_ROOT_D, pubkeys=PUBKEYS):
    v_ok, _vr, v_series = verify_log(log, trust_root=trust_root, signer_pubkeys=pubkeys)
    ticks, head, floor = _load_log(log)
    s_ok, _sr, s_series = VF.verify_attestation_series(
        ticks, head, floor, trust_root=trust_root_d, signer_pubkeys=pubkeys)
    v_labels = [(x.state, x.label, x.reason_code) for x in v_series]
    s_labels = [(x["state"], x["label"], x["reason_code"]) for x in s_series]
    return (v_ok, v_labels), (s_ok, s_labels)


def _append(log, cert):
    return append_tick(log, cert, engagement_slug=ENG, signers=SIGNERS,
                       trust_root=TRUST_ROOT, signer_pubkeys=PUBKEYS)


def _write_ticks_raw(log, ticks):
    body = "".join(json.dumps(t, sort_keys=True, separators=(",", ":")) + "\n" for t in ticks)
    (log / al._TICKS_FILE).write_text(body, encoding="utf-8")


def _resign_head_over(log, ticks):
    entries = build_chain([digest_payload(t) for t in ticks])
    head = sign_head(entries, engagement_slug=ENG, signers=SIGNERS)
    (log / al._HEAD_FILE).write_text(head.model_dump_json(), encoding="utf-8")


def test_attestation_series_valid_drift_agrees(tmp_path):
    log = tmp_path / "attlog"
    kinds = [State.STILL_VULNERABLE, State.REMEDIATED, State.REMEDIATED, State.STILL_VULNERABLE]
    for i, k in enumerate(kinds):
        _append(log, _tick(k, i))
    v, s = _att_verdicts(log)
    _agree("attestation", "valid-present->fixed->still->regressed", v, s)
    assert v[0] is True
    assert [lbl for (_st, lbl, _rc) in s[1]] == [
        al.LABEL_PRESENT, al.LABEL_PROVEN_FIXED, al.LABEL_STILL_PROVEN, al.LABEL_REGRESSED]


def test_attestation_series_inconclusive_does_not_advance_agrees(tmp_path):
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.INCONCLUSIVE, State.REMEDIATED]):
        _append(log, _tick(k, i))
    v, s = _att_verdicts(log)
    _agree("attestation", "valid-inconclusive-neutral", v, s)
    assert [lbl for (_st, lbl, _rc) in s[1]] == [
        al.LABEL_PROVEN_FIXED, al.LABEL_INCONCLUSIVE, al.LABEL_STILL_PROVEN]


def test_attestation_series_empty_agrees(tmp_path):
    v, s = _att_verdicts(tmp_path / "never-used")
    _agree("attestation", "empty-log", v, s)
    assert v[0] is True and s[0] is True


def test_attestation_series_rolled_back_head_and_floor_agrees(tmp_path):
    # 3-tick log; truncate to 2 + re-sign a genuinely-valid smaller head; leave the durable floor high.
    log = tmp_path / "attlog"
    for i, k in enumerate([State.STILL_VULNERABLE, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks, _h, _f = _load_log(log)
    _write_ticks_raw(log, ticks[:2])
    _resign_head_over(log, ticks[:2])            # floor (highwater.json) stays at entry_count=3
    v, s = _att_verdicts(log)
    _agree("attestation", "rollback-floor-catches", v, s)
    assert v[0] is False and s[0] is False


def test_attestation_series_truncated_ticks_head_commits_full_agrees(tmp_path):
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks, _h, _f = _load_log(log)
    _write_ticks_raw(log, ticks[:2])             # head.json still commits 3 → head↔chain binding breaks
    v, s = _att_verdicts(log)
    _agree("attestation", "truncated-ticks-headchain-break", v, s)
    assert v[0] is False and s[0] is False


def test_attestation_series_full_truncation_to_empty_agrees(tmp_path):
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    (log / al._TICKS_FILE).write_text("", encoding="utf-8")
    (log / al._HEAD_FILE).unlink()               # floor untouched (entry_count=3)
    v, s = _att_verdicts(log)
    _agree("attestation", "full-truncation-floor-catches", v, s)
    assert v[0] is False and s[0] is False


def test_attestation_series_one_to_zero_truncation_agrees(tmp_path):
    log = tmp_path / "attlog"
    _append(log, _tick(State.REMEDIATED, 0))     # 1-tick log: last_seq=0 (same as empty) → entry_count catches
    (log / al._TICKS_FILE).write_text("", encoding="utf-8")
    (log / al._HEAD_FILE).unlink()
    v, s = _att_verdicts(log)
    _agree("attestation", "1->0-truncation-entry_count-catches", v, s)
    assert v[0] is False and s[0] is False


def test_attestation_series_tampered_tick_resigned_head_agrees(tmp_path):
    # Tamper a tick + re-sign the head over the tampered set (verify_head passes) — the per-tick prove-cert
    # signature is what catches it in both verifiers.
    log = tmp_path / "attlog"
    for i, k in enumerate([State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks, _h, _f = _load_log(log)
    ticks[0]["verdict"]["reason_code"] = "totally_made_up"
    _write_ticks_raw(log, ticks)
    _resign_head_over(log, ticks)
    v, s = _att_verdicts(log)
    _agree("attestation", "tampered-tick-resigned-head", v, s)
    assert v[0] is False and s[0] is False


def test_attestation_series_wrong_trust_root_agrees(tmp_path):
    log = tmp_path / "attlog"
    _append(log, _tick(State.REMEDIATED, 0))
    other = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=ATTACKER.public_key_b64)])
    v_ok, _vr, _vs = verify_log(log, trust_root=other, signer_pubkeys=PUBKEYS)
    ticks, head, floor = _load_log(log)
    s_ok, _sr, _ss = VF.verify_attestation_series(
        ticks, head, floor, trust_root=other.model_dump(mode="json"), signer_pubkeys=PUBKEYS)
    _agree("attestation", "wrong-head-trust-root", v_ok, s_ok)
    assert v_ok is False and s_ok is False


def test_attestation_series_forged_tick_bad_signer_agrees(tmp_path):
    # A tick signed by the ATTACKER under key_id 'gov0' — a forgery both verifiers reject on re-verification.
    log = tmp_path / "attlog"
    _append(log, _tick(State.REMEDIATED, 0))
    forged = _mint(FakeAdapter(), signers=[("gov0", ATTACKER.private_key_b64)], run_id="run-x")
    ticks, head, floor = _load_log(log)
    ticks = ticks + [forged]
    _write_ticks_raw(log, ticks)
    _resign_head_over(log, ticks)                # make head verify so the per-tick admission is what fires
    v, s = _att_verdicts(log)
    _agree("attestation", "forged-tick-bad-signer", v, s)
    assert v[0] is False and s[0] is False


# ===================================================================================================
# 3. WITNESSED TIMED CHECKPOINT differential (quorum + median T + tampers)
# ===================================================================================================
def _mk_witnessed(head: SignedChainHead, times=(100, 200, 300)):
    twc = witness_attestation_head(head=head, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")],
                                   observed_times=list(times))
    cp_obj = twc.as_checkpoint()
    cp_dict = twc.checkpoint
    vigil_sigs = list(twc.witness_signatures)
    sig_dicts = [s.model_dump(mode="json") for s in twc.witness_signatures]
    return cp_obj, cp_dict, vigil_sigs, sig_dicts


def _wit_verdicts(cp_obj, cp_dict, vigil_sigs, sig_dicts, tr=QUORUM, tr_d=QUORUM_D, mds=None):
    v_ok, v_T, _vr = verify_timed_witnessed(cp_obj, vigil_sigs, witness_trust_root=tr, min_distinct_signers=mds)
    s_ok, s_T, _sr = VF.verify_timed_witnessed(cp_dict, sig_dicts, witness_trust_root=tr_d, min_distinct_signers=mds)
    return (v_ok, v_T), (s_ok, s_T)


def _corrupt_b64(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64)); raw[-1] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def test_witnessed_valid_and_median_agrees():
    head = SignedChainHead(last_seq=7, entry_count=8, head_hash="deadbeef",
                           cumulative_merkle_root="mroot", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(head, times=(100, 200, 300))
    v, s = _wit_verdicts(cp_obj, cp_dict, vs, sd)
    _agree("witnessed", "valid-3of3-median", v, s)
    assert v == (True, 200)


def test_witnessed_drop_below_quorum_agrees():
    head = SignedChainHead(last_seq=2, entry_count=3, head_hash="h", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(head)
    # present only ONE sig → 1 < threshold 2 → both reject
    v, s = _wit_verdicts(cp_obj, cp_dict, vs[:1], sd[:1])
    _agree("witnessed", "drop-below-quorum", v, s)
    assert v == (False, None)


def test_witnessed_corrupt_one_still_quorum_agrees():
    head = SignedChainHead(last_seq=2, entry_count=3, head_hash="h", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(head, times=(100, 200, 300))
    # corrupt the THIRD witness sig → 2 valid remain → both still accept, same T (median of 100,200 = 200)
    vs2 = vs[:2] + [TimedWitnessSignature(key_id="w2", observed_time=300,
                                          signature_b64=_corrupt_b64(vs[2].signature_b64))]
    sd2 = _clone(sd); sd2[2]["signature_b64"] = _corrupt_b64(sd[2]["signature_b64"])
    v, s = _wit_verdicts(cp_obj, cp_dict, vs2, sd2)
    _agree("witnessed", "corrupt-one-still-quorum", v, s)
    assert v == (True, 200)


def test_witnessed_corrupt_one_strict_roster_rejects_agrees():
    head = SignedChainHead(last_seq=2, entry_count=3, head_hash="h", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(head)
    vs2 = vs[:2] + [TimedWitnessSignature(key_id="w2", observed_time=300,
                                          signature_b64=_corrupt_b64(vs[2].signature_b64))]
    sd2 = _clone(sd); sd2[2]["signature_b64"] = _corrupt_b64(sd[2]["signature_b64"])
    # a strict verifier demanding the FULL roster (3) refuses the 2-valid set
    v, s = _wit_verdicts(cp_obj, cp_dict, vs2, sd2, mds=3)
    _agree("witnessed", "corrupt-one-strict-roster", v, s)
    assert v == (False, None)


def test_witnessed_tampered_checkpoint_agrees():
    signed = SignedChainHead(last_seq=2, entry_count=3, head_hash="original-head", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(signed)
    # show a DIFFERENT checkpoint (head_hash swapped) with the original sigs → all invalid → both reject
    tampered = SignedChainHead(last_seq=2, entry_count=3, head_hash="attacker-swapped-head", engagement_slug=ENG)
    t_obj = checkpoint_of(tampered)
    t_dict = t_obj.to_dict()
    v, s = _wit_verdicts(t_obj, t_dict, vs, sd)
    _agree("witnessed", "tampered-checkpoint", v, s)
    assert v == (False, None)


def test_witnessed_sub_majority_and_duplicate_key_agree():
    head = SignedChainHead(last_seq=2, entry_count=3, head_hash="h", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(head)

    # sub-majority (threshold 1, n=3) → not split-view resistant
    sub = TrustRoot(threshold=1, authorizers=QUORUM.authorizers)
    v, s = _wit_verdicts(cp_obj, cp_dict, vs, sd, tr=sub, tr_d=sub.model_dump(mode="json"))
    _agree("witnessed", "sub-majority-quorum", v, s)
    assert v == (False, None)

    # duplicate public key (two key_ids share W0's pubkey) → defeats intersection → refused
    dup = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
        AuthorizerKey(key_id="w0-alias", name="w0-alias", public_key_b64=W0.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64)])
    v2, s2 = _wit_verdicts(cp_obj, cp_dict, vs, sd, tr=dup, tr_d=dup.model_dump(mode="json"))
    _agree("witnessed", "duplicate-key-quorum", v2, s2)
    assert v2 == (False, None)


def test_witnessed_single_dishonest_extreme_time_agrees():
    head = SignedChainHead(last_seq=2, entry_count=3, head_hash="h", engagement_slug=ENG)
    cp_obj, cp_dict, vs, sd = _mk_witnessed(head, times=(1000, 1001, 10**18))
    v, s = _wit_verdicts(cp_obj, cp_dict, vs, sd)
    _agree("witnessed", "single-dishonest-extreme-time", v, s)
    assert v == (True, 1001)   # median of the 3 is the honest middle value, not the extreme


# ===================================================================================================
# 4. BYTE-PARITY — the re-implemented canonical / signing bytes equal the real producers', byte-for-byte
# ===================================================================================================
def test_byte_parity_with_the_producers():
    sample = {"z": 1, "a": {"c": 3, "b": 2}, "m": [3, 2, 1], "s": "acme"}
    assert VF.canonical_json(sample) == canonical_json(sample), "canonical_json bytes differ"
    assert VF.digest_payload(sample) == digest_payload(sample), "digest_payload differs"

    cert = _mint(FakeAdapter())
    body = {k: v for k, v in cert.items() if k != "signer"}
    assert VF._prove_cert_signing_bytes(body) == vigil_prove_bytes(body), "prove-cert signing bytes differ"

    emb = cert["evidence"]["embedded_remediation_cert"]
    emb_body = {k: v for k, v in emb.items() if k != "signature"}
    assert VF._rem_cert_signing_bytes(emb_body) == rc._cert_signing_bytes(emb_body), "rem-cert signing bytes differ"
    ctx = emb["patched_oracle_context"]
    assert VF._context_digest(ctx) == rc._context_digest(ctx), "rem-cert context digest differs"

    # chain head signing bytes
    entries = build_chain([digest_payload(cert)])
    head = sign_head(entries, engagement_slug=ENG, signers=SIGNERS)
    head_dict = json.loads(head.model_dump_json())
    assert VF.evidence_signing_bytes(VF._head_payload(head_dict)) == \
        vigil_evidence_bytes(vigil_head_payload(head)), "head signing bytes differ"
    # and the entry hash
    assert VF._entry_hash(0, VF.GENESIS_PREV, digest_payload(cert)) == entries[0].entry_hash

    # timed-witness signing bytes
    cp = checkpoint_of(head)
    assert VF._timed_signing_bytes(cp.to_dict(), 12345) == vigil_timed_bytes(cp, 12345), \
        "timed-witness signing bytes differ"

    # trust-root fingerprint parity
    assert VF.trust_root_fingerprint(TRUST_ROOT_D) == "sha256:" + digest_payload(TRUST_ROOT_D)


# ===================================================================================================
# 5. STANDALONE-CLEANLINESS — verify_vf --prove-standalone in a VIGIL-unimportable subprocess
# ===================================================================================================
def _clean_env() -> dict:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)   # never inherit integration:engine/crucible:packages/core:gateway
    env.pop("PYTHONHOME", None)
    env.pop("VIRTUAL_ENV", None)
    return env


_SYS_PY = "/usr/bin/python3"


def _sys_py_is_clean(cwd: Path) -> bool:
    """The system interpreter must have cryptography but NOT any VIGIL module. Checked from a NEUTRAL cwd —
    a repo-root cwd would let ``gateway`` / other top-level dirs import as cwd namespace packages, which is
    exactly why the real verify below also runs from a neutral directory. (vigil_core is an editable install
    in the pytest interpreter, so /usr/bin/python3 with a stripped env + neutral cwd is the genuinely-clean
    interpreter.)"""
    try:
        proc = subprocess.run(
            [_SYS_PY, "-c",
             "import importlib.util as u;"
             "print(bool(u.find_spec('cryptography')),"
             "any(u.find_spec(m) for m in ('framework','vigil_core','vigil_integration','strix','gateway')))"],
            cwd=str(cwd), env=_clean_env(), capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.stdout.strip() == "True False"


def _write_full_bundle(tmp: Path) -> tuple[Path, Path, Path, Path]:
    """Write a real bundle (prove_cert + attestation + witnessed) and the out-of-band trust files."""
    log = tmp / "attlog"
    for i, k in enumerate([State.STILL_VULNERABLE, State.REMEDIATED, State.REMEDIATED]):
        _append(log, _tick(k, i))
    ticks, head, floor = _load_log(log)

    prove_cert = _mint(FakeAdapter())
    sch = SignedChainHead.model_validate_json((log / al._HEAD_FILE).read_text(encoding="utf-8"))
    twc = witness_attestation_head(head=sch, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")],
                                   observed_times=[1000, 1001, 1002])

    bundle = {
        "prove_cert": prove_cert,
        "attestation": {"ticks": ticks, "head": head, "floor": floor},
        "witnessed": {"checkpoint": twc.checkpoint,
                      "witness_signatures": [s.model_dump(mode="json") for s in twc.witness_signatures]},
    }
    bpath = tmp / "bundle.json"
    bpath.write_text(json.dumps(bundle), encoding="utf-8")
    keys = tmp / "keys.json"; keys.write_text(json.dumps(PUBKEYS), encoding="utf-8")
    tr = tmp / "trust-root.json"; tr.write_text(json.dumps(TRUST_ROOT_D), encoding="utf-8")
    wtr = tmp / "witness-trust-root.json"; wtr.write_text(json.dumps(QUORUM_D), encoding="utf-8")
    return bpath, keys, tr, wtr


def _run_standalone(bundle: Path, keys: Path, tr: Path, wtr: Path, *, cwd: Path, prove=True):
    argv = [_SYS_PY, str(_VERIFIER), "verify", "--bundle", str(bundle),
            "--signer-pubkeys", str(keys), "--trust-root", str(tr), "--witness-trust-root", str(wtr),
            "--fingerprint", "sha256:" + digest_payload(TRUST_ROOT_D),
            "--witness-fingerprint", "sha256:" + digest_payload(QUORUM_D)]
    if prove:
        argv += ["--prove-standalone"]
    return subprocess.run(argv, cwd=str(cwd), env=_clean_env(), capture_output=True, text=True, timeout=180)


def test_prove_standalone_subprocess_validates_and_rejects(tmp_path):
    work = tmp_path / "work"; work.mkdir()
    neutral = tmp_path / "neutral"; neutral.mkdir()
    if not _sys_py_is_clean(neutral):
        pytest.skip(f"{_SYS_PY} lacks cryptography or can import a VIGIL module — no genuinely-clean interpreter")
    bundle, keys, tr, wtr = _write_full_bundle(work)

    # 1. a genuine bundle verifies in a clean, VIGIL-unimportable subprocess (--prove-standalone asserts it).
    proc = _run_standalone(bundle, keys, tr, wtr, cwd=neutral, prove=True)
    assert "confirmed VIGIL-free" in proc.stdout, f"env not proven clean:\n{proc.stdout}\n{proc.stderr}"
    assert proc.returncode == 0, f"a sound bundle must verify (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    assert "bundle SOUND" in proc.stdout

    # belt-and-braces: the same clean env genuinely cannot import any VIGIL module.
    check = subprocess.run(
        [_SYS_PY, "-c", "import importlib.util as u;"
         "print(any(u.find_spec(m) for m in ('framework','vigil_core','vigil_integration','strix','gateway')))"],
        cwd=str(neutral), env=_clean_env(), capture_output=True, text=True)
    assert check.stdout.strip() == "False", f"a VIGIL module was importable in the 'clean' env: {check.stdout}"

    # 2. a single flipped prove-cert signature byte flips the whole bundle to NOT SOUND (exit 2).
    doc = json.loads(bundle.read_text())
    raw = bytearray(base64.b64decode(doc["prove_cert"]["signer"]["signature"])); raw[-1] ^= 0x01
    doc["prove_cert"]["signer"]["signature"] = base64.b64encode(bytes(raw)).decode()
    tampered = tmp_path / "tampered.json"; tampered.write_text(json.dumps(doc), encoding="utf-8")
    bad = _run_standalone(tampered, keys, tr, wtr, cwd=neutral, prove=True)
    assert bad.returncode == 2, f"a flipped signature MUST fail:\n{bad.stdout}\n{bad.stderr}"
    assert "bundle NOT SOUND" in bad.stdout

    # 3. a wrong out-of-band fingerprint pin is refused before any crypto.
    wrongpin = subprocess.run(
        [_SYS_PY, str(_VERIFIER), "verify", "--bundle", str(bundle), "--signer-pubkeys", str(keys),
         "--trust-root", str(tr), "--witness-trust-root", str(wtr), "--fingerprint", "sha256:" + "0" * 64],
        cwd=str(neutral), env=_clean_env(), capture_output=True, text=True, timeout=180)
    assert wrongpin.returncode == 2 and "MISMATCH" in wrongpin.stdout, wrongpin.stdout


# ===================================================================================================
# 6. report the full differential matrix (printed with -s; asserts every row agreed)
# ===================================================================================================
def test_zz_report_matrix():
    assert MATRIX, "no differential rows were collected — the matrix tests did not run"
    print("\n==================== VF-1d DIFFERENTIAL MATRIX (VIGIL vs standalone) ====================")
    print(f"{'component':<12} {'case':<42} {'VIGIL':<24} {'standalone':<24} agree")
    for component, case, vigil, standalone in MATRIX:
        agree = "OK" if vigil == standalone else "DISAGREE"
        print(f"{component:<12} {case:<42} {str(vigil):<24} {str(standalone):<24} {agree}")
        assert vigil == standalone, f"{component}/{case}"
    print(f"==================== {len(MATRIX)} rows, all agree ====================")
