"""Deterministic, offline tests for vigil_core.aegis_sealing — AS-2h (KMS+AAD sealing, zero-gap rotation).

The three acceptance criteria of the slice are proven directly:

  * NO EVENT GAP across a rotation — a report MAC'd under the OUTGOING epoch still verifies throughout the
    overlap, while a report MAC'd under the INCOMING epoch verifies too; at no point is either rejected.
  * OLD SECRET REFUSED after the overlap closes — once ``close_overlap`` retires the outgoing epoch, a report
    MAC'd under it no longer verifies and its secret is gone.
  * AAD MISMATCH FAILS CLOSED — a sealed secret opened under any other (kind, org, scope, epoch) binding, or
    under a tampered binding, raises rather than returning a value.

Plus: KMS-sealed custody exercised through the REAL KmsKekBackend driven by a fake in-memory `aws` runner
(the real AWS CMK is owner-gated/deferred — no key is committed); determinism of the sign/verify path; the
fail-closed rotation guards; and the DEFAULT-OFF AS-6a delivery seam (deferred unless the flag + a real seam
are both present).
"""
from __future__ import annotations

import base64

import pytest

from vigil_core.kek import TpmResult
from vigil_core.kek_backends import KmsKekBackend
from vigil_core.sealing import SealError, new_kek
from vigil_core.aegis_sealing import (
    DeferredDelivery, DeliveryReceipt, SEALING_DELIVER_ENV, SealedSecret, SealingError, SecretBundle,
    SecretKind, SecretRing, build_bundle, connector_aad, delivery_enabled, deliver_bundle, open_secret,
    open_secret_as, seal_secret, secret_aad, secret_mac,
)

KEK = b"\x11" * 32
S1 = b"secret-one-aaaaaaaaaaaaaaaaaa"      # >= 16 bytes
S2 = b"secret-two-bbbbbbbbbbbbbbbbbb"
S3 = b"secret-three-cccccccccccccccc"
PAYLOAD = b'{"report_id":"abc","decision":"block"}'


# ============================================================================================
# AAD convention (plan-faithful) + component guards
# ============================================================================================
def test_connector_aad_matches_plan_convention():
    # The plan fixes the connector AAD as exactly `aegis-conn\0<org>\0<conn>`.
    assert connector_aad("orgX", "slack") == b"aegis-conn\x00orgX\x00slack"
    # The AS-2h rotation binding appends `\0e<epoch>`.
    assert connector_aad("orgX", "slack", epoch=4) == b"aegis-conn\x00orgX\x00slack\x00e4"


def test_secret_aad_per_kind_and_epoch():
    assert secret_aad(SecretKind.REPORT, "o1", "h1") == b"aegis-report\x00o1\x00h1"
    assert secret_aad(SecretKind.ORIGIN, "o1", "h1", epoch=0) == b"aegis-origin\x00o1\x00h1\x00e0"
    # pseudonym is tenant-wide: an empty scope is allowed and distinct from a non-empty one.
    assert secret_aad(SecretKind.PSEUDONYM, "o1") == b"aegis-pseudonym\x00o1\x00"
    # different kinds / orgs / scopes / epochs never alias
    seen = {
        secret_aad(SecretKind.REPORT, "o1", "h1", epoch=1),
        secret_aad(SecretKind.ORIGIN, "o1", "h1", epoch=1),
        secret_aad(SecretKind.REPORT, "o2", "h1", epoch=1),
        secret_aad(SecretKind.REPORT, "o1", "h2", epoch=1),
        secret_aad(SecretKind.REPORT, "o1", "h1", epoch=2),
    }
    assert len(seen) == 5


def test_aad_component_guards_fail_closed():
    with pytest.raises(SealingError):
        secret_aad(SecretKind.REPORT, "", "h")           # empty org
    with pytest.raises(SealingError):
        secret_aad(SecretKind.REPORT, "o\x00rg", "h")    # NUL in a component
    with pytest.raises(SealingError):
        secret_aad(SecretKind.REPORT, "o", "h", epoch=-1)   # negative epoch
    with pytest.raises(SealingError):
        secret_aad(SecretKind.REPORT, "o", "h", epoch=True)  # bool is not an epoch
    with pytest.raises(SealingError):
        secret_aad("report", "o", "h")                   # kind must be a SecretKind  # type: ignore[arg-type]


# ============================================================================================
# seal / open at rest + AAD mismatch fails closed
# ============================================================================================
def test_seal_open_roundtrip():
    sealed = seal_secret(KEK, SecretKind.REPORT, "o1", "h1", 1, S1)
    assert isinstance(sealed, SealedSecret)
    assert open_secret(KEK, sealed) == S1


def test_open_under_wrong_kek_fails_closed():
    sealed = seal_secret(KEK, SecretKind.REPORT, "o1", "h1", 1, S1)
    with pytest.raises(SealError):
        open_secret(b"\x22" * 32, sealed)


def test_aad_mismatch_fails_closed_across_binding():
    sealed = seal_secret(KEK, SecretKind.REPORT, "o1", "h1", 1, S1)
    # same KEK + same blob, but every wrong binding dimension must fail closed:
    for kind, org, scope, epoch in [
        (SecretKind.ORIGIN, "o1", "h1", 1),     # wrong kind
        (SecretKind.REPORT, "o2", "h1", 1),     # wrong org
        (SecretKind.REPORT, "o1", "h2", 1),     # wrong scope/host
        (SecretKind.REPORT, "o1", "h1", 2),     # wrong epoch
    ]:
        with pytest.raises(SealError):
            open_secret_as(KEK, sealed.blob, kind, org, scope, epoch=epoch)
    # the correct binding still opens
    assert open_secret_as(KEK, sealed.blob, SecretKind.REPORT, "o1", "h1", epoch=1) == S1


def test_tampered_binding_field_fails_closed():
    sealed = seal_secret(KEK, SecretKind.REPORT, "o1", "h1", 1, S1)
    forged = SealedSecret(kind=sealed.kind, org=sealed.org, scope=sealed.scope, epoch=2, blob=sealed.blob)
    with pytest.raises(SealError):
        open_secret(KEK, forged)   # the carried epoch was flipped → recomputed AAD no longer matches


def test_seal_rejects_weak_secret():
    with pytest.raises(SealingError):
        seal_secret(KEK, SecretKind.REPORT, "o1", "h1", 1, b"short")


# ============================================================================================
# ACCEPTANCE 1 — rotation leaves NO event gap (overlap)
# ============================================================================================
def test_no_event_gap_across_rotation():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)

    # A report emitted (and MAC'd) BEFORE the rotation, in flight across the cut.
    e_old, tag_old = ring.sign(PAYLOAD)
    assert e_old == 1
    assert ring.verify(PAYLOAD, e_old, tag_old) is True

    # Begin rotation: incoming epoch 2 becomes current; epoch 1 stays accepted → OVERLAP.
    ring.begin_rotation(2, S2)
    assert ring.current_epoch == 2
    assert ring.in_overlap() is True
    assert ring.accepted_epochs == frozenset({1, 2})

    # NO GAP: the in-flight epoch-1 report STILL verifies during the overlap…
    assert ring.verify(PAYLOAD, e_old, tag_old) is True
    # …and a freshly-signed report now rides epoch 2 and also verifies.
    e_new, tag_new = ring.sign(PAYLOAD)
    assert e_new == 2
    assert ring.verify(PAYLOAD, e_new, tag_new) is True


# ============================================================================================
# ACCEPTANCE 2 — the OLD secret is REFUSED after the overlap closes
# ============================================================================================
def test_old_secret_refused_after_overlap_closes():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    _, tag_old = ring.sign(PAYLOAD)              # tag under epoch 1
    ring.begin_rotation(2, S2)
    _, tag_new = ring.sign(PAYLOAD)              # tag under epoch 2

    retired = ring.close_overlap()
    assert retired == (1,)
    assert ring.accepted_epochs == frozenset({2})
    assert ring.in_overlap() is False

    # The OLD epoch-1 report is now REFUSED (not merely a bad MAC — the epoch is no longer accepted).
    assert ring.verify(PAYLOAD, 1, tag_old) is False
    # The current epoch-2 report still verifies — no gap, just the old key retired.
    assert ring.verify(PAYLOAD, 2, tag_new) is True
    # The retired secret is gone from the ring.
    with pytest.raises(SealingError):
        ring.secret_at(1)


def test_multi_step_overlap_partial_retire():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    ring.begin_rotation(2, S2)
    ring.begin_rotation(3, S3)
    assert ring.accepted_epochs == frozenset({1, 2, 3})
    # retire only epoch 1; epochs 2 and 3 remain accepted (a staged, partial overlap close).
    assert ring.close_overlap(retire_below=2) == (1,)
    assert ring.accepted_epochs == frozenset({2, 3})
    assert ring.current_epoch == 3


# ============================================================================================
# Rotation state-machine guards (fail-closed)
# ============================================================================================
def test_sign_before_activate_refused():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    with pytest.raises(SealingError):
        ring.sign(PAYLOAD)
    with pytest.raises(SealingError):
        _ = ring.current_epoch


def test_double_activate_refused():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    with pytest.raises(SealingError):
        ring.activate(2, S2)


def test_non_monotone_or_reused_rotation_refused():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(5, S1)
    with pytest.raises(SealingError):
        ring.begin_rotation(5, S2)      # not strictly greater
    with pytest.raises(SealingError):
        ring.begin_rotation(4, S2)      # goes backwards
    ring.begin_rotation(6, S2)
    with pytest.raises(SealingError):
        ring.begin_rotation(6, S3)      # reused epoch (already in the ring)
    # the ring is unchanged by the refused transitions
    assert ring.current_epoch == 6
    assert ring.accepted_epochs == frozenset({5, 6})


def test_same_secret_rotation_is_a_noop_and_refused():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    with pytest.raises(SealingError):
        ring.begin_rotation(2, S1)      # same secret bytes → not a rotation


def test_cannot_retire_the_current_epoch():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    ring.begin_rotation(2, S2)
    with pytest.raises(SealingError):
        ring.close_overlap(retire_below=3)   # above current → would drop the live secret, open a gap
    assert ring.accepted_epochs == frozenset({1, 2})   # the refused close left the ring unchanged
    # a close whose floor is the earliest accepted epoch retires nothing (a no-op close is allowed)
    assert ring.close_overlap(retire_below=1) == ()
    assert ring.accepted_epochs == frozenset({1, 2})


# ============================================================================================
# Determinism of the sign/verify path (no clock, no RNG)
# ============================================================================================
def test_secret_mac_is_deterministic_and_epoch_separated():
    a = secret_mac(S1, SecretKind.REPORT, "o1", "h1", 1, PAYLOAD)
    b = secret_mac(S1, SecretKind.REPORT, "o1", "h1", 1, PAYLOAD)
    assert a == b                                   # deterministic
    # the SAME secret under a different epoch yields a different tag (domain separation)…
    assert secret_mac(S1, SecretKind.REPORT, "o1", "h1", 2, PAYLOAD) != a
    # …and under a different kind/org/scope too.
    assert secret_mac(S1, SecretKind.ORIGIN, "o1", "h1", 1, PAYLOAD) != a
    assert secret_mac(S1, SecretKind.REPORT, "o2", "h1", 1, PAYLOAD) != a


def test_two_rings_same_inputs_sign_identically():
    r1 = SecretRing(SecretKind.REPORT, "o1", "h1")
    r2 = SecretRing(SecretKind.REPORT, "o1", "h1")
    r1.activate(7, S1)
    r2.activate(7, S1)
    assert r1.sign(PAYLOAD) == r2.sign(PAYLOAD)      # no per-instance RNG/clock on the signed path


def test_verify_rejects_wrong_epoch_and_malformed_tag():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    epoch, tag = ring.sign(PAYLOAD)
    assert ring.verify(PAYLOAD, 99, tag) is False        # epoch not accepted
    assert ring.verify(PAYLOAD, epoch, b"bad") is False   # bad tag
    assert ring.verify(PAYLOAD, epoch, "nottbytes") is False  # type: ignore[arg-type]
    assert ring.verify(b"other", epoch, tag) is False    # different payload


# ============================================================================================
# KMS-sealed custody via the REAL KmsKekBackend + a fake in-memory `aws` runner (real KMS deferred)
# ============================================================================================
def _fake_aws_runner():
    """A minimal fake `aws kms` that envelope-wraps the KEK deterministically. The CLI emits BASE64 on
    stdout (as `--output text --query CiphertextBlob/Plaintext` does). No real AWS, no committed key."""
    def run(argv, stdin):
        if "sts" in argv and "get-caller-identity" in argv:
            return TpmResult(0, b"1\trole\tAID\n")
        if "kms" in argv and "encrypt" in argv:
            return TpmResult(0, base64.b64encode(b"CT|" + (stdin or b"")) + b"\n")
        if "kms" in argv and "decrypt" in argv:
            blob = stdin or b""
            if not blob.startswith(b"CT|"):
                return TpmResult(1, b"")
            return TpmResult(0, base64.b64encode(blob[3:]) + b"\n")
        return TpmResult(1, b"")
    return run


def test_kms_sealed_secret_roundtrip(tmp_path):
    backend = KmsKekBackend(key_id="arn:aws:kms:eu-west-1:1:key/AAA", region="eu-west-1",
                            runner=_fake_aws_runner())
    backend.provision(tmp_path)                 # mint + KMS-wrap a fresh KEK (only ciphertext on disk)
    kek = backend.load(tmp_path)                # KMS-unwrap it back
    assert len(kek) == 32
    # seal an AEGIS secret under the KMS-custodied KEK, with AAD binding, and open it back.
    sealed = seal_secret(kek, SecretKind.ORIGIN, "o1", "h1", 1, S1)
    assert open_secret(kek, sealed) == S1
    # a different KMS-custodied KEK cannot open it (fail-closed).
    assert kek != KEK
    with pytest.raises(SealError):
        open_secret(KEK, sealed)


# ============================================================================================
# AS-6a delivery seam — DEFAULT-OFF / deferred stub
# ============================================================================================
def _ring_bundle():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    ring.begin_rotation(2, S2)
    return ring, build_bundle(ring, KEK)


def test_build_bundle_seals_all_accepted_epochs():
    ring, bundle = _ring_bundle()
    assert isinstance(bundle, SecretBundle)
    assert bundle.current_epoch == 2
    assert bundle.accepted_epochs == (1, 2)
    assert {s.epoch for s in bundle.sealed} == {1, 2}
    # each sealed secret in the bundle opens back to its operational secret under the KEK + its own binding.
    by_epoch = {s.epoch: s for s in bundle.sealed}
    assert open_secret(KEK, by_epoch[1]) == S1
    assert open_secret(KEK, by_epoch[2]) == S2


def test_delivery_default_off_is_deferred(monkeypatch):
    monkeypatch.delenv(SEALING_DELIVER_ENV, raising=False)
    assert delivery_enabled() is False
    _, bundle = _ring_bundle()

    class _RealSeam:
        def deliver(self, b: SecretBundle) -> DeliveryReceipt:
            return DeliveryReceipt(delivered=True, status="delivered", detail="pushed")

    # flag OFF → deferred even when a real seam is supplied (byte-identical no-op).
    r = deliver_bundle(bundle, _RealSeam())
    assert r.delivered is False and r.status == "deferred"
    # the default stub alone is also deferred.
    assert DeferredDelivery().deliver(bundle).delivered is False


def test_delivery_on_with_real_seam_delivers(monkeypatch):
    monkeypatch.setenv(SEALING_DELIVER_ENV, "1")
    assert delivery_enabled() is True
    _, bundle = _ring_bundle()

    class _RealSeam:
        def __init__(self):
            self.got = None

        def deliver(self, b: SecretBundle) -> DeliveryReceipt:
            self.got = b
            return DeliveryReceipt(delivered=True, status="delivered", detail="pushed to unit")

    seam = _RealSeam()
    r = deliver_bundle(bundle, seam)
    assert r.delivered is True and r.status == "delivered"
    assert seam.got is bundle
    # flag ON but NO seam injected → still deferred (fail-closed; AS-6a not wired).
    assert deliver_bundle(bundle, None).delivered is False


@pytest.mark.parametrize("token,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("", False), ("0", False), ("off", False), ("nope", False),
])
def test_delivery_flag_tokens(monkeypatch, token, expected):
    monkeypatch.setenv(SEALING_DELIVER_ENV, token)
    assert delivery_enabled() is expected


# ============================================================================================
# Remaining defensive guards (fail-closed on malformed input)
# ============================================================================================
def test_component_type_and_length_guards():
    with pytest.raises(SealingError):
        secret_aad(SecretKind.REPORT, 123, "h")           # org not a str  # type: ignore[arg-type]
    with pytest.raises(SealingError):
        secret_aad(SecretKind.REPORT, "o", "x" * 257)     # scope too long


def test_seal_and_mac_type_guards():
    with pytest.raises(SealingError):
        seal_secret(KEK, SecretKind.REPORT, "o", "h", 1, 123)    # secret not bytes  # type: ignore[arg-type]
    with pytest.raises(SealingError):
        secret_mac(123, SecretKind.REPORT, "o", "h", 1, PAYLOAD)  # secret not bytes  # type: ignore[arg-type]
    with pytest.raises(SealingError):
        secret_mac(S1, SecretKind.REPORT, "o", "h", 1, 123)       # payload not bytes  # type: ignore[arg-type]


def test_open_secret_rejects_non_sealed():
    with pytest.raises(SealingError):
        open_secret(KEK, b"not a SealedSecret")   # type: ignore[arg-type]


def test_guards_on_inactive_ring():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    with pytest.raises(SealingError):
        ring.begin_rotation(1, S1)        # cannot rotate before activate
    with pytest.raises(SealingError):
        ring.close_overlap()              # nothing to close
    assert ring.is_accepted(1) is False


def test_verify_total_on_non_bytes_payload():
    ring = SecretRing(SecretKind.REPORT, "o1", "h1")
    ring.activate(1, S1)
    epoch, tag = ring.sign(PAYLOAD)
    assert ring.verify(12345, epoch, tag) is False   # non-bytes payload → False, never raises  # type: ignore[arg-type]
