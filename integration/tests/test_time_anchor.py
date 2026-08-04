"""TRUTHENOVATION A1 — the EXTERNAL TIME ANCHOR (RFC3161), offline + real openssl.

Proves the anchor MECHANISM end-to-end without a network or a third party: a self-signed LOCAL TSA
(:class:`time_anchor.LocalTSA`) mints a REAL RFC3161 token over :func:`transparency.checkpoint_hash`, and
both the in-tree verifier (:func:`attestation_witness.verify_timed_witnessed`) and the STANDALONE VIGIL-free
verifier (``docs/proof-carrying-finding/verify_vf.py``) check it via the system ``openssl ts``. It asserts:

  * openssl ``ts`` is PRESENT in this environment — a hard gate, never a silent skip (it is on ubuntu-latest);
  * roundtrip — a minted token verifies over the checkpoint hash and its genTime (read from the SIGNED token,
    within a tight window of real mint time) SUPERSEDES the quorum-median bound;
  * no-pin opt-out — with no ``tsa_cert_pin`` the honest median bound stands (the anchored T is never asserted
    without verifying it) — no overclaim;
  * BINDING — a token minted over checkpoint A, presented alongside a *validly re-signed* checkpoint B, FAILS
    CLOSED (the anchor binds ``checkpoint_hash``; a present-but-non-binding anchor never falls back silently to
    the weaker median even when the witness quorum is valid);
  * wrong/unpinned TSA cert → rejected; malformed base64 anchor → fail-closed;
  * SIDECAR / determinism — anchoring does NOT perturb the checkpoint dict, the witness signatures, or
    ``checkpoint_hash``; the (genTime-varying) token enters no signed digest;
  * the STANDALONE verifier recomputes a byte-identical ``checkpoint_hash`` and checks the anchor offline,
    VIGIL-free — a tampered checkpoint dict fails there too.

Framework-FREE (vigil_core + vigil_integration.transparency/attestation_witness/time_anchor + stdlib +
cryptography), so it runs in the P5 no-framework integration leg (``PYTHONPATH=integration:gateway``). openssl
is an external process, not a Python dependency.
"""
from __future__ import annotations

import base64
import importlib.util
import time
from pathlib import Path

import pytest

from vigil_core import AuthorizerKey, SignedChainHead, TrustRoot, generate_keypair
from vigil_integration.transparency import Checkpoint, checkpoint_hash, checkpoint_of
from vigil_integration.remediation.attestation_witness import (
    timed_cosign,
    verify_timed_witnessed,
    verify_timed_witnessed_checkpoint,
    witness_attestation_head,
)
from vigil_integration.time_anchor import (
    LocalTSA,
    RemoteTSA,
    TimeAnchorError,
    anchor_checkpoint,
    openssl_ts_available,
    verify_anchor,
)

# --- three independently-keyed witnesses → a strict-majority 2-of-3 (split-view-resistant) quorum ---------
W0, W1, W2 = generate_keypair(), generate_keypair(), generate_keypair()


def _auth(kp, key_id):
    return AuthorizerKey(key_id=key_id, name=key_id, public_key_b64=kp.public_key_b64)


QUORUM = TrustRoot(threshold=2, authorizers=[_auth(W0, "w0"), _auth(W1, "w1"), _auth(W2, "w2")])


def _head(head_hash="head-hash-abc", last_seq=2, entry_count=3, merkle="merkle-root-xyz") -> SignedChainHead:
    return SignedChainHead(
        last_seq=last_seq, entry_count=entry_count, head_hash=head_hash,
        cumulative_merkle_root=merkle, engagement_slug="acme")


def _cp(head_hash="head-hash-abc") -> Checkpoint:
    return checkpoint_of(_head(head_hash=head_hash))


def _sigs(cp: Checkpoint, times=(100, 200, 300)):
    return [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=times[0]),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=times[1]),
        timed_cosign(cp, witness_keypair=W2, key_id="w2", observed_time=times[2]),
    ]


# --- load the STANDALONE VIGIL-free verifier by path (the option the VF spec calls out) -------------------
_PCF_DIR = Path(__file__).resolve().parents[2] / "docs" / "proof-carrying-finding"


def _load_standalone():
    spec = importlib.util.spec_from_file_location("standalone_verify_vf_a1", _PCF_DIR / "verify_vf.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VF = _load_standalone()


# ======================================= the openssl gate (no silent skip) ================================
def test_openssl_ts_is_present_no_silent_skip():
    """A1 is only genuinely gated if these tests RUN. openssl ts is on ubuntu-latest CI runners — assert it
    (a loud failure if a runner ever lacks it), NEVER pytest.skip (which would hide an unverified mechanism)."""
    assert openssl_ts_available(), "openssl with the `ts` subcommand must be present to verify A1 in CI"
    assert VF.openssl_ts_available(), "the standalone verifier also needs openssl ts"


# ======================================= roundtrip + supersede the median =================================
def test_anchor_roundtrip_supersedes_median_and_gentime_is_real():
    cp = _cp()
    tsa = LocalTSA(_local_dir())
    before = int(time.time())
    twc = witness_attestation_head(head=_head(), witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")],
                                   observed_times=[100, 200, 300], tsa=tsa)
    after = int(time.time())

    # the anchor is a SIDECAR base64 string, not a checkpoint field.
    assert twc.external_time_anchor is not None
    assert "external_time_anchor" not in twc.checkpoint

    # WITHOUT the pin: the verifier opts out of the stronger check — the honest MEDIAN stands (no overclaim).
    ok_m, T_m, reason_m = verify_timed_witnessed_checkpoint(twc, witness_trust_root=QUORUM)
    assert ok_m and T_m == 200, reason_m
    assert "median" in reason_m

    # WITH the pin: the anchor genTime SUPERSEDES the median (200) — and genTime is the real mint time read
    # from the SIGNED token (within a tight window of before/after), NOT the verifier wall clock.
    ok, T, reason = verify_timed_witnessed_checkpoint(twc, witness_trust_root=QUORUM, tsa_cert_pin=tsa.cert_pin)
    assert ok, reason
    assert T != 200                                   # superseded — not the median
    assert before - 3 <= T <= after + 3, (before, T, after)
    assert "SUPERSEDES" in reason and "external anchor genTime" in reason


def test_verify_anchor_direct_roundtrip_and_gentime_signed():
    cp = _cp()
    tsa = LocalTSA(_local_dir())
    before = int(time.time())
    token = anchor_checkpoint(cp, tsa=tsa)             # self-verifies before returning (fail-closed)
    after = int(time.time())
    ok, gen = verify_anchor(cp, token, tsa_cert_pin=tsa.cert_pin)
    assert ok and gen is not None
    assert before - 3 <= gen <= after + 3             # genTime = real mint time, from the signed TSTInfo


# ======================================= BINDING — the key adversarial case ===============================
def test_anchor_binds_hash_fails_closed_even_with_a_valid_quorum():
    """A token minted over checkpoint A, presented alongside a *validly re-signed* checkpoint B, must FAIL
    CLOSED: the anchor binds ``checkpoint_hash``, and a present-but-non-binding anchor is never silently
    downgraded to the weaker median even though the witness quorum over B is itself valid."""
    tsa = LocalTSA(_local_dir())
    cp_a = _cp(head_hash="original-head")
    token_b64 = base64.b64encode(anchor_checkpoint(cp_a, tsa=tsa)).decode("ascii")

    cp_b = _cp(head_hash="attacker-swapped-head")      # a DIFFERENT checkpoint (different checkpoint_hash)
    sigs_b = _sigs(cp_b)                               # a VALID 2-of-3 quorum over B

    # control: the quorum over B verifies on its own (no anchor) — isolates the anchor as the failing part.
    ok_q, T_q, _ = verify_timed_witnessed(cp_b, sigs_b, witness_trust_root=QUORUM)
    assert ok_q and T_q == 200

    # with the A-minted anchor over the B checkpoint + the real pin: the imprint no longer matches → FAIL.
    ok, T, reason = verify_timed_witnessed(
        cp_b, sigs_b, witness_trust_root=QUORUM, external_time_anchor=token_b64, tsa_cert_pin=tsa.cert_pin)
    assert not ok and T is None
    assert "did NOT verify" in reason and "fail-closed" in reason

    # control: over the ORIGINAL checkpoint A (validly signed) the same anchor verifies.
    ok2, T2, reason2 = verify_timed_witnessed(
        cp_a, _sigs(cp_a), witness_trust_root=QUORUM, external_time_anchor=token_b64, tsa_cert_pin=tsa.cert_pin)
    assert ok2 and T2 is not None and "SUPERSEDES" in reason2


def test_wrong_tsa_cert_pin_is_rejected():
    cp = _cp()
    tsa_a = LocalTSA(_local_dir("a"))
    tsa_b = LocalTSA(_local_dir("b"))                  # a DIFFERENT self-signed TSA
    token = anchor_checkpoint(cp, tsa=tsa_a)
    ok, gen = verify_anchor(cp, token, tsa_cert_pin=tsa_b.cert_pin)   # wrong pin → chain failure
    assert not ok and gen is None
    ok2, gen2 = verify_anchor(cp, token, tsa_cert_pin=tsa_a.cert_pin)  # control: correct pin verifies
    assert ok2 and gen2 is not None


def test_malformed_base64_anchor_fails_closed():
    cp = _cp()
    tsa = LocalTSA(_local_dir())
    ok, T, reason = verify_timed_witnessed(
        cp, _sigs(cp), witness_trust_root=QUORUM,
        external_time_anchor="!!!not-base64!!!", tsa_cert_pin=tsa.cert_pin)
    assert not ok and T is None and "not valid base64" in reason


def test_missing_pin_path_fails_closed_in_verify_anchor():
    cp = _cp()
    tsa = LocalTSA(_local_dir())
    token = anchor_checkpoint(cp, tsa=tsa)
    ok, gen = verify_anchor(cp, token, tsa_cert_pin=str(_local_dir("nope") / "absent.pem"))
    assert not ok and gen is None


# ======================================= SIDECAR / determinism ============================================
def test_anchor_is_a_sidecar_that_perturbs_nothing_signed():
    """Anchoring must not change the checkpoint dict, the witness signatures, or ``checkpoint_hash`` — the
    token (whose genTime varies run-to-run) enters NO signed digest, so chains stay byte-deterministic."""
    tsa = LocalTSA(_local_dir())
    head = _head(head_hash="sidecar-head")

    plain = witness_attestation_head(head=head, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")],
                                     observed_times=[100, 200, 300])                     # no tsa
    anchored = witness_attestation_head(head=head, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")],
                                        observed_times=[100, 200, 300], tsa=tsa)          # + tsa

    # identical checkpoint dict AND identical witness signatures — the anchor did not touch the signed bytes.
    assert anchored.checkpoint == plain.checkpoint
    assert [s.model_dump() for s in anchored.witness_signatures] == \
           [s.model_dump() for s in plain.witness_signatures]
    # the sidecar is present on the anchored one only.
    assert plain.external_time_anchor is None and anchored.external_time_anchor is not None

    # checkpoint_hash is identical with and without the anchor (it is computed over the checkpoint only).
    assert checkpoint_hash(anchored.as_checkpoint()) == checkpoint_hash(plain.as_checkpoint())


# ======================================= STANDALONE VIGIL-free verifier ====================================
def test_standalone_verifier_checks_anchor_offline_and_hash_is_byte_identical():
    cp = _cp(head_hash="standalone-head")
    tsa = LocalTSA(_local_dir())
    token_b64 = base64.b64encode(anchor_checkpoint(cp, tsa=tsa)).decode("ascii")
    cp_dict = cp.to_dict()

    # the standalone verifier recomputes a BYTE-IDENTICAL checkpoint_hash (same domain + canonicalization).
    assert VF.checkpoint_hash(cp_dict) == checkpoint_hash(cp)

    # it verifies the anchor offline (only openssl + stdlib + cryptography — no VIGIL import) and extracts T.
    ok, gen = VF.verify_external_time_anchor(cp_dict, token_b64, tsa_cert_pin=tsa.cert_pin)
    assert ok and gen is not None
    # byte-identity end-to-end: the standalone T equals the in-tree verifier's T.
    ok_in, gen_in = verify_anchor(cp, base64.b64decode(token_b64), tsa_cert_pin=tsa.cert_pin)
    assert ok_in and gen_in == gen

    # a TAMPERED checkpoint dict hashes differently → the anchor no longer binds → FAIL, standalone too.
    tampered = dict(cp_dict, head_hash="tampered-in-the-bundle")
    ok_t, gen_t = VF.verify_external_time_anchor(tampered, token_b64, tsa_cert_pin=tsa.cert_pin)
    assert not ok_t and gen_t is None


# ======================================= genTime forgery (red-pen BLOCK-1 regression) =====================
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _read_len(buf: bytes, i: int):
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    nb = first & 0x7F
    return int.from_bytes(buf[i:i + nb], "big"), i + nb


def _inject_unsigned_status_timestamp(token: bytes, text: str) -> bytes:
    """DER-surgery a UTF8String into the RFC3161 response's UNSIGNED ``PKIStatusInfo.statusString`` — the
    part ``ts -verify`` does NOT cover. Leaves the signed ``TimeStampToken`` byte-for-byte intact (so the
    signature still verifies), but makes openssl's ``-text`` render an attacker ``Time stamp:`` line BEFORE
    the signed one. This is the exact backdating vector the red-pen found."""
    assert token[0] == 0x30
    outer_len, body_start = _read_len(token, 1)
    body = token[body_start:body_start + outer_len]
    assert body[0] == 0x30                                  # first child = PKIStatusInfo SEQUENCE
    psi_len, psi_body_start = _read_len(body, 1)
    psi_content = body[psi_body_start:psi_body_start + psi_len]
    rest = body[psi_body_start + psi_len:]                  # the signed TimeStampToken (untouched)
    u = text.encode()
    utf8 = bytes([0x0C]) + _der_len(len(u)) + u             # UTF8String
    freetext = bytes([0x30]) + _der_len(len(utf8)) + utf8   # PKIFreeText SEQUENCE OF UTF8String
    new_psi_content = psi_content + freetext
    new_psi = bytes([0x30]) + _der_len(len(new_psi_content)) + new_psi_content
    new_body = new_psi + rest
    return bytes([0x30]) + _der_len(len(new_body)) + new_body


def test_backdating_via_unsigned_status_is_defeated():
    """An attacker injects an unsigned ``PKIStatusInfo`` ``Time stamp: Jan 1 2000`` line; ``ts -verify`` still
    passes (the signed token is untouched), but genTime MUST be read only from the signature-covered token —
    so the extracted/verified T is the REAL signed mint time, never the injected backdate."""
    import subprocess
    cp = _cp()
    tsa = LocalTSA(_local_dir())
    before = int(time.time())
    token = anchor_checkpoint(cp, tsa=tsa)
    after = int(time.time())
    evil = _inject_unsigned_status_timestamp(token, "\nTime stamp: Jan 1 00:00:00 2000 GMT")
    forged_epoch = 946684800                                 # 2000-01-01T00:00:00Z

    # precondition: the injected response STILL verifies (the signature covers only the token) — so the
    # defence must be in genTime extraction, not in rejecting the token.
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        p = Path(td) / "evil.tsr"
        p.write_bytes(evil)
        rv = subprocess.run(["openssl", "ts", "-verify", "-digest", checkpoint_hash(cp), "-sha256",
                             "-in", str(p), "-CAfile", tsa.cert_pin], capture_output=True, text=True)
    assert "Verification: OK" in (rv.stdout + rv.stderr), "attack precondition: signature stays valid"

    # in-tree verify_anchor returns the REAL signed genTime, NOT the 2000 backdate.
    ok, gen = verify_anchor(cp, evil, tsa_cert_pin=tsa.cert_pin)
    assert ok and gen is not None
    assert gen != forged_epoch
    assert before - 3 <= gen <= after + 3

    # through the superseding path: the no-later-than T is the real signed time, not the backdate.
    ok2, T, reason = verify_timed_witnessed(
        cp, _sigs(cp), witness_trust_root=QUORUM,
        external_time_anchor=base64.b64encode(evil).decode("ascii"), tsa_cert_pin=tsa.cert_pin)
    assert ok2 and T != forged_epoch and before - 3 <= T <= after + 3, reason

    # the STANDALONE VIGIL-free verifier is defended identically.
    ok3, gen3 = VF.verify_external_time_anchor(
        cp.to_dict(), base64.b64encode(evil).decode("ascii"), tsa_cert_pin=tsa.cert_pin)
    assert ok3 and gen3 == gen and gen3 != forged_epoch


# ======================================= the honest residual (RemoteTSA) ===================================
def test_remote_tsa_is_the_independence_path_and_is_present_but_offline():
    """The genuine-independence path is a real third-party RFC3161 URL (:class:`RemoteTSA`). Its independence
    cannot be exercised in an offline test (the A1 residual) — we only assert the mechanism is present and
    fails closed when unreachable, so no test pretends a local TSA establishes third-party independence."""
    remote = RemoteTSA(url="http://127.0.0.1:9/rfc3161", cert_pin="/nonexistent-pin.pem")
    with pytest.raises(TimeAnchorError):
        remote.mint(b"\x30\x00")                       # port 9/discard is closed → unreachable → fail-closed


# --- per-test isolated workdirs for the LocalTSA material (system temp, cleaned at module teardown; NOT in
#     the repo tree so it never perturbs git status) --------------------------------------------------------
import tempfile  # noqa: E402

_TMP_ROOT = Path(tempfile.mkdtemp(prefix="a1-tsa-"))
_counter = {"n": 0}


def _local_dir(tag: str = "") -> Path:
    _counter["n"] += 1
    d = _TMP_ROOT / f"tsa-{_counter['n']}-{tag}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def teardown_module(module):
    import shutil
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)
