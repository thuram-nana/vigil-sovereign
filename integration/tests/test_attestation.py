"""WS6 — the always-on usage-attestation ledger (who/when a gated action ran, tied to a signed chain).

The through-line every test defends is the SOVEREIGN INVARIANT the red-pen attacks:

  * EVERY gated action mints an attestation FIRST — no attestation (no signer / unbound operator /
    malformed input / un-recorded) ⇒ ``require_attestation`` returns a fail-closed DENY, never proceeds.
  * The ledger is append-only + hash-chained + Ed25519-signed: a TAMPERED, REORDERED, DELETED, or FORGED
    entry FAILS ``verify_ledger``.
  * The monotonic WHEN anchor never decreases — an entry cannot be back-dated.
  * The operator identity is bound + signed (non-repudiable); a record whose ``key_id`` is not the bound
    operator's fingerprint, or whose signer is untrusted, or whose operator is missing, FAILS.
  * Total on malformed input; no wallclock/RNG in the chain (Ed25519 signing is deterministic; ordering is
    ``seq``/``prev_hash`` only — ``at``/``monotonic`` are signed DATA).
"""

from __future__ import annotations

import os

from vigil_core.crypto import generate_keypair, sign
from vigil_core.models import Signature

from vigil_integration.attestation import (
    AttestationVerdict,
    MonotonicAnchor,
    OperatorIdentity,
    UsageAttestation,
    fingerprint,
    ledger_when,
    ledger_who,
    load_or_create_operator_keypair,
    make_ledger_writer,
    operator_key_resolver,
    operator_signer,
    read_ledger,
    read_monotonic_anchor,
    record_usage,
    require_attestation,
    resolve_operator,
    verify_ledger,
)
from vigil_integration.attestation.ledger import _content, _record_hash, _signing_bytes

# --- fixtures: a real operator keypair + its signer/resolver (no live kernel/TPM) --------------------


def _kp():
    return generate_keypair()


def _operator(kp, *, login="kali", name="Water Hacker", email="op@example.test", host="kali"):
    return OperatorIdentity(os_login=login, git_name=name, git_email=email,
                            key_fingerprint=fingerprint(kp.public_key_b64), hostname=host)


def _mint_chain(kp, op, *, n=3, monotonics=None):
    """Mint an ``n``-record chain threading prev_hash + seq + explicit monotonic anchors (no disk/TPM)."""
    signer = operator_signer(keypair=kp)
    monos = monotonics if monotonics is not None else [10 * (i + 1) for i in range(n)]
    prev = "0" * 64
    out = []
    for i in range(n):
        att = record_usage(
            operator=op, action="nmap -sV 127.0.0.1", target="http://127.0.0.1:18080/",
            phase="informational", at=f"2026-07-21T00:0{i}:00Z", prev_hash=prev, signer=signer,
            seq=i, anchor=MonotonicAnchor(value=monos[i], grounded="software"),
        )
        assert att is not None
        out.append(att)
        prev = att.record_hash
    return out


# --- happy path: mint → verify → replay -------------------------------------------------------------


def test_mint_binds_who_when_what_and_signs():
    kp = _kp()
    op = _operator(kp)
    att = record_usage(operator=op, action="httpx 127.0.0.1", target="http://127.0.0.1:18080/",
                       phase="informational", at="2026-07-21T12:00:00Z", prev_hash="0" * 64,
                       signer=operator_signer(keypair=kp), seq=0,
                       anchor=MonotonicAnchor(value=42, grounded="tpm"))
    assert att is not None
    assert att.operator.os_login == "kali" and att.operator.git_email == "op@example.test"
    assert att.operator.key_fingerprint == fingerprint(kp.public_key_b64)
    assert att.signature.key_id == att.operator.key_fingerprint     # identity ↔ signature binding
    assert att.at == "2026-07-21T12:00:00Z" and att.monotonic == 42 and att.grounded == "tpm"
    assert att.phase == "informational"


def test_full_ledger_verifies_and_replays():
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=4)
    res = verify_ledger(chain, resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is True and res.count == 4
    assert res.operators == (fingerprint(kp.public_key_b64),)
    # replay is in chain order regardless of input order
    who = ledger_who(list(reversed(chain)))
    assert [w.seq for w in who] == [0, 1, 2, 3]
    assert all(w.operator.git_email == "op@example.test" for w in who)
    when = ledger_when(chain)
    assert [w.monotonic for w in when] == [10, 20, 30, 40]


def test_verify_is_order_independent():
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=3)
    shuffled = [chain[2], chain[0], chain[1]]
    assert verify_ledger(shuffled, resolve_key=operator_key_resolver(keypair=kp)).ok is True


# --- secret-free: action/target are redacted before they land in the ledger -------------------------


def test_action_and_target_are_redacted():
    kp = _kp()
    op = _operator(kp)
    att = record_usage(
        operator=op, action="curl -H 'Authorization: Bearer DEADBEEFSECRET' --api-key SUPERSECRET x",
        target="https://user:hunter2pass@127.0.0.1:18080/admin", phase="exploitation",
        at="2026-07-21T12:00:00Z", prev_hash="0" * 64, signer=operator_signer(keypair=kp), seq=0,
        anchor=MonotonicAnchor(value=1, grounded="software"),
    )
    assert att is not None
    assert "DEADBEEFSECRET" not in att.action and "SUPERSECRET" not in att.action
    assert "hunter2pass" not in att.target
    # and the redacted record still verifies (redaction happens before signing)
    assert verify_ledger([att], resolve_key=operator_key_resolver(keypair=kp)).ok is True


# --- the fail-closed engagement gate ----------------------------------------------------------------


def test_require_attestation_allows_and_records():
    kp = _kp()
    op = _operator(kp)
    sink: list[UsageAttestation] = []
    v = require_attestation(operator=op, action="nmap", target="http://127.0.0.1:18080/",
                            phase="informational", at="2026-07-21T12:00:00Z", prev_hash="0" * 64,
                            signer=operator_signer(keypair=kp), seq=0,
                            anchor=MonotonicAnchor(value=5, grounded="software"),
                            writer=sink.append)
    assert isinstance(v, AttestationVerdict)
    assert v.allowed is True and v.outcome == "allow" and v.attestation is not None
    assert len(sink) == 1 and sink[0].record_hash == v.attestation.record_hash


def test_require_attestation_denies_with_no_signer():
    op = _operator(_kp())
    v = require_attestation(operator=op, action="nmap", target="http://127.0.0.1:18080/",
                            phase="informational", at="2026-07-21T12:00:00Z", prev_hash="0" * 64,
                            signer=None, seq=0, anchor=MonotonicAnchor(value=5, grounded="software"))
    assert v.allowed is False and v.outcome == "deny" and v.attestation is None


def test_require_attestation_denies_when_write_fails():
    kp = _kp()
    op = _operator(kp)

    def _boom(_att):
        raise OSError("ledger volume is read-only")

    v = require_attestation(operator=op, action="nmap", target="http://127.0.0.1:18080/",
                            phase="informational", at="2026-07-21T12:00:00Z", prev_hash="0" * 64,
                            signer=operator_signer(keypair=kp), seq=0,
                            anchor=MonotonicAnchor(value=5, grounded="software"), writer=_boom)
    assert v.allowed is False and v.outcome == "deny" and v.attestation is None


def test_record_usage_denies_unbound_operator():
    kp = _kp()
    # a fingerprint but NO human handle → not bound → cannot mint
    unbound = OperatorIdentity(key_fingerprint=fingerprint(kp.public_key_b64))
    assert unbound.is_bound() is False
    att = record_usage(operator=unbound, action="x", target="http://127.0.0.1/", phase="p",
                       at="t", prev_hash="0" * 64, signer=operator_signer(keypair=kp), seq=0,
                       anchor=MonotonicAnchor(value=1, grounded="software"))
    assert att is None


def test_record_usage_denies_signer_key_not_bound_operator():
    """A signer whose key_id is NOT the bound operator's fingerprint cannot mint (someone else's key)."""
    kp_op = _kp()
    kp_other = _kp()
    op = _operator(kp_op)
    att = record_usage(operator=op, action="x", target="http://127.0.0.1/", phase="p", at="t",
                       prev_hash="0" * 64, signer=operator_signer(keypair=kp_other), seq=0,
                       anchor=MonotonicAnchor(value=1, grounded="software"))
    assert att is None


# --- THE SOVEREIGN INVARIANT: tamper / reorder / delete / forge / back-date all FAIL ----------------


def test_INVARIANT_tampered_record_fails_verification():
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=3)
    # flip a WHAT field on the middle record WITHOUT re-hashing → record hash no longer recomputes
    chain[1] = chain[1].model_copy(update={"action": "rm -rf / --no-preserve-root"})
    res = verify_ledger(chain, resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is False and "hash mismatch" in res.reason


def test_INVARIANT_deleted_entry_breaks_the_chain():
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=4)
    del chain[2]                                  # excise a middle record → prev_hash link / seq gap
    res = verify_ledger(chain, resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is False and ("chain break" in res.reason or "seq gap" in res.reason)


def test_INVARIANT_reordered_prev_hash_fails():
    kp = _kp()
    op = _operator(kp)
    # two records with SWAPPED seq numbers but each other's prev_hash relationship broken: rebuild a
    # forged record0' that claims seq=1's monotonic but keeps genesis prev — the second link won't match.
    c = _mint_chain(kp, op, n=3)
    # renumber record2 as seq 1 (a reorder): its prev_hash points at the real record1, but at seq 1 the
    # verifier expects prev == genesis-record0's hash → mismatch OR seq gap.
    forged = c[2].model_copy(update={"seq": 1})
    # note record2's stored hash no longer matches its (changed) seq content → caught as hash mismatch too
    res = verify_ledger([c[0], forged], resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is False


def test_INVARIANT_forged_signature_fails():
    """A record signed by a DIFFERENT key but claiming the bound operator's fingerprint is rejected."""
    kp = _kp()
    kp_evil = _kp()
    op = _operator(kp)
    content = _content(seq=0, prev_hash="0" * 64, operator=op, action="a", target="http://127.0.0.1/",
                       phase="p", at="t", monotonic=1, grounded="software")
    forged = UsageAttestation(
        seq=0, prev_hash="0" * 64, operator=op, action="a", target="http://127.0.0.1/", phase="p",
        at="t", monotonic=1, grounded="software", record_hash=_record_hash(content),
        signature=Signature(key_id=op.key_fingerprint,                      # claims to be the operator…
                            signature_b64=sign(kp_evil.private_key_b64, _signing_bytes(content))),  # …but isn't
    )
    res = verify_ledger([forged], resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is False and "invalid signature" in res.reason


def test_INVARIANT_untrusted_key_and_no_resolver_fail_closed():
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=2)
    # a valid chain, but NO trust anchor wired → cannot verify signatures → deny-by-default
    assert verify_ledger(chain, resolve_key=None).ok is False
    # a resolver that knows a DIFFERENT operator → this fingerprint is untrusted
    other_resolver = operator_key_resolver(keypair=_kp())
    res = verify_ledger(chain, resolve_key=other_resolver)
    assert res.ok is False and "untrusted operator key" in res.reason


def test_INVARIANT_key_id_not_binding_operator_fails():
    kp = _kp()
    op = _operator(kp)
    # operator claims a DIFFERENT fingerprint than the signature's key_id → binding broken
    op_variant = op.model_copy(update={"key_fingerprint": "f" * 64})
    content = _content(seq=0, prev_hash="0" * 64, operator=op_variant, action="a",
                       target="http://127.0.0.1/", phase="p", at="t", monotonic=1, grounded="software")
    rec = UsageAttestation(
        seq=0, prev_hash="0" * 64, operator=op_variant, action="a", target="http://127.0.0.1/",
        phase="p", at="t", monotonic=1, grounded="software", record_hash=_record_hash(content),
        signature=Signature(key_id=fingerprint(kp.public_key_b64),
                            signature_b64=sign(kp.private_key_b64, _signing_bytes(content))),
    )
    # resolver trusts BOTH fingerprints so the failure is the binding check, not an untrusted key
    def _resolve(kid):
        if kid == "f" * 64 or kid == fingerprint(kp.public_key_b64):
            return kp.public_key_b64
        return None
    res = verify_ledger([rec], resolve_key=_resolve)
    assert res.ok is False and "does not bind the operator" in res.reason


def test_INVARIANT_back_dated_monotonic_fails():
    kp = _kp()
    op = _operator(kp)
    # record 1 carries a LOWER monotonic than record 0 — a back-date attempt; both are validly signed
    chain = _mint_chain(kp, op, n=2, monotonics=[100, 50])
    res = verify_ledger(chain, resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is False and "back-dating" in res.reason


def test_INVARIANT_malformed_row_fails_verification():
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=2)
    res = verify_ledger([chain[0], {"garbage": True}], resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is False and "malformed" in res.reason


# --- the monotonic WHEN anchor: TPM/software grounding, never decreases ------------------------------


def test_anchor_tpm_grounded_when_probe_present(tmp_path):
    counter = str(tmp_path / "mono.counter")
    a = read_monotonic_anchor(state_path=counter, tpm_probe=lambda: 5000)
    assert a.grounded == "tpm" and a.value == 5000


def test_anchor_software_fallback_when_no_tpm(tmp_path):
    counter = str(tmp_path / "mono.counter")
    a = read_monotonic_anchor(state_path=counter, tpm_probe=lambda: None)
    b = read_monotonic_anchor(state_path=counter, tpm_probe=lambda: None)
    assert a.grounded == "software" and b.grounded == "software"
    assert b.value > a.value                                # strictly advances, persisted across calls


def test_anchor_never_decreases_even_when_tpm_regresses(tmp_path):
    counter = str(tmp_path / "mono.counter")
    read_monotonic_anchor(state_path=counter, tpm_probe=lambda: 9000)        # floor jumps to 9000 (tpm)
    # a TPM that now reads BELOW the floor (rewind attempt / stuck counter) must not regress the anchor
    a = read_monotonic_anchor(state_path=counter, tpm_probe=lambda: 10)
    assert a.value > 9000 and a.grounded == "software"
    # a truthy bool from a misbehaving probe is not a counter value → software fallback, still advancing
    b = read_monotonic_anchor(state_path=counter, tpm_probe=lambda: True)
    assert b.value > a.value and b.grounded == "software"


def test_anchor_total_on_raising_probe(tmp_path):
    counter = str(tmp_path / "mono.counter")

    def _boom():
        raise RuntimeError("tpm chip fault")

    a = read_monotonic_anchor(state_path=counter, tpm_probe=_boom)           # must not propagate
    assert a.grounded == "software" and a.value >= 1


# --- live wiring: persisted keypair, resolved identity, durable JSONL ledger -------------------------


def test_keypair_is_persisted_and_reused(tmp_path):
    path = str(tmp_path / "operator.key")
    kp1 = load_or_create_operator_keypair(path=path)
    kp2 = load_or_create_operator_keypair(path=path)          # second call reloads the SAME key
    assert kp1.public_key_b64 == kp2.public_key_b64
    assert kp1.private_key_b64 == kp2.private_key_b64
    assert (os.stat(path).st_mode & 0o777) == 0o600           # private key file is not world-readable


def test_resolve_operator_binds_identity_to_keypair(tmp_path):
    path = str(tmp_path / "operator.key")
    kp = load_or_create_operator_keypair(path=path)
    op = resolve_operator(keypair_path=path, os_login="kali", hostname="kali",
                          git_reader=lambda k: {"user.name": "Water Hacker",
                                                "user.email": "op@example.test"}.get(k, ""))
    assert op.is_bound() is True
    assert op.key_fingerprint == fingerprint(kp.public_key_b64)
    assert op.git_name == "Water Hacker" and op.hostname == "kali"


def test_durable_ledger_roundtrip_and_torn_line_tolerance(tmp_path):
    kp = _kp()
    op = _operator(kp)
    ledger = tmp_path / "usage.jsonl"
    writer = make_ledger_writer(ledger)
    prev = "0" * 64
    signer = operator_signer(keypair=kp)
    for i in range(3):
        att = record_usage(operator=op, action=f"tool-{i}", target="http://127.0.0.1:18080/",
                           phase="informational", at=f"t{i}", prev_hash=prev, signer=signer, seq=i,
                           anchor=MonotonicAnchor(value=i + 1, grounded="software"))
        writer(att)
        prev = att.record_hash
    # a torn/garbage line appended by a crash is tolerated on read
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write('{"seq": 3, "hash": "torn\n')
    back = read_ledger(ledger)
    assert len(back) == 3
    assert verify_ledger(back, resolve_key=operator_key_resolver(keypair=kp)).ok is True


def test_end_to_end_gate_records_and_verifies(tmp_path):
    """require_attestation → durable ledger → read_ledger → verify_ledger, using real live wiring."""
    path = str(tmp_path / "operator.key")
    kp = load_or_create_operator_keypair(path=path)
    op = resolve_operator(keypair_path=path, os_login="kali", hostname="kali",
                          git_reader=lambda k: "Water Hacker" if k == "user.name" else "op@example.test")
    ledger = tmp_path / "usage.jsonl"
    writer = make_ledger_writer(ledger)
    prev = "0" * 64
    for i in range(2):
        v = require_attestation(operator=op, action=f"nuclei -u 127.0.0.1 #{i}",
                                target="http://127.0.0.1:18080/", phase="informational", at=f"t{i}",
                                prev_hash=prev, signer=operator_signer(keypair=kp), seq=i,
                                anchor=MonotonicAnchor(value=i + 1, grounded="software"), writer=writer)
        assert v.allowed is True
        prev = v.attestation.record_hash
    res = verify_ledger(read_ledger(ledger), resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is True and res.count == 2


# --- totality: garbage never raises -----------------------------------------------------------------


def test_totality_on_garbage_inputs():
    kp = _kp()
    # record_usage on garbage → None, never raises
    assert record_usage(operator=123, action=object(), target=None, phase=None, at=None,
                        prev_hash=None, signer=operator_signer(keypair=kp), seq="x",
                        anchor=None, anchor_state_path=None) is None
    # verify_ledger / replay on garbage → total
    assert verify_ledger(object(), resolve_key={}).ok is True        # non-iterable → empty → vacuous
    assert verify_ledger(None).ok is True
    assert ledger_who(object()) == []
    assert ledger_when("not-a-list") == []
    assert read_ledger("/nonexistent/path/usage.jsonl") == []


# --- RED-PEN regressions: close each WS6-attestation finding at the whole-class level ----------------


def test_INVARIANT_tail_truncation_caught_by_pinned_head_and_count():
    """Finding-1: dropping the most-recent record(s) leaves a valid PREFIX that STILL internally chains —
    so un-pinned verify accepts it (documented internal-consistency-only scope). The external anchor a
    caller pins (expected_head / expected_count) is what catches the dropped tail (repudiation defense)."""
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=4)
    resolver = operator_key_resolver(keypair=kp)
    head = chain[-1].record_hash
    # the full ledger verifies against its own pinned head + count
    assert verify_ledger(chain, resolve_key=resolver, expected_head=head, expected_count=4).ok is True
    # DROP the tail record → a prefix. UN-pinned → still "ok" (the exact scoped gap, now documented).
    truncated = chain[:3]
    assert verify_ledger(truncated, resolve_key=resolver).ok is True
    # PINNED head → the dropped tail is caught
    r_head = verify_ledger(truncated, resolve_key=resolver, expected_head=head)
    assert r_head.ok is False and "head" in r_head.reason
    # PINNED count → the dropped tail is caught
    r_count = verify_ledger(truncated, resolve_key=resolver, expected_count=4)
    assert r_count.ok is False and "not the caller-pinned" in r_count.reason
    # a malformed pin is ignored (total), never a crash and never a false failure on the full chain
    assert verify_ledger(chain, resolve_key=resolver, expected_count="not-an-int").ok is True
    assert verify_ledger(chain, resolve_key=resolver, expected_head=12345).ok is True


def test_INVARIANT_total_wipe_caught_by_pin():
    """Finding-1: a total wipe → an empty ledger. Un-pinned it verifies vacuously (documented); a pinned
    head or a pinned POSITIVE count catches the wipe. Only an explicit expected_count=0 (with no head) is
    the pin an empty ledger legitimately satisfies."""
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=3)
    resolver = operator_key_resolver(keypair=kp)
    head = chain[-1].record_hash
    assert verify_ledger([], resolve_key=resolver).ok is True                       # un-pinned: vacuous
    assert verify_ledger([], resolve_key=resolver, expected_head=head).ok is False    # wipe caught
    assert verify_ledger([], resolve_key=resolver, expected_count=3).ok is False      # wipe caught
    assert verify_ledger([], resolve_key=resolver, expected_count=0).ok is True       # explicitly-empty


def test_phase_and_at_free_strings_are_redacted():
    """Finding-2 whole-class: EVERY free string committed to the signed ledger — not just action/target
    but phase (WHAT) and the WHEN string at — is routed through the one F3 redactor, so no credential
    lands in the append-only record whichever field carries it."""
    kp = _kp()
    op = _operator(kp)
    att = record_usage(
        operator=op, action="curl", target="http://127.0.0.1/",
        phase="password=hunter2SECRET", at="Bearer LEAKEDTOKEN123456",
        prev_hash="0" * 64, signer=operator_signer(keypair=kp), seq=0,
        anchor=MonotonicAnchor(value=1, grounded="software"),
    )
    assert att is not None
    assert "hunter2SECRET" not in att.phase          # phase redacted
    assert "LEAKEDTOKEN123456" not in att.at          # the WHEN string redacted
    # redaction happens BEFORE signing, so the redacted record still verifies
    assert verify_ledger([att], resolve_key=operator_key_resolver(keypair=kp)).ok is True


def test_verify_total_on_pathological_mapping_resolver():
    """Finding-3: a Mapping resolver whose iteration raises must degrade to 'no trusted resolver wired'
    (fail-closed DENY), honouring verify_ledger's 'never raises' contract — not propagate the exception."""
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=2)

    class EvilMap(dict):
        def keys(self):
            raise RuntimeError("evil")

        def __iter__(self):
            raise RuntimeError("evil")

    res = verify_ledger(chain, resolve_key=EvilMap())
    assert res.ok is False and "no trusted operator key resolver" in res.reason


def test_require_attestation_denies_without_a_writer():
    """Finding-4: the engagement gate is fail-closed on durability — a valid signer but NO writer must
    DENY, so a gated action can never proceed on an attestation that was never durably recorded."""
    kp = _kp()
    op = _operator(kp)
    v = require_attestation(operator=op, action="nmap", target="http://127.0.0.1:18080/",
                            phase="informational", at="2026-07-21T12:00:00Z", prev_hash="0" * 64,
                            signer=operator_signer(keypair=kp), seq=0,
                            anchor=MonotonicAnchor(value=5, grounded="software"), writer=None)
    assert v.allowed is False and v.outcome == "deny" and v.attestation is None
    assert "durable ledger writer" in v.reason


def test_equal_monotonic_success_reason_is_non_decreasing():
    """Finding-5 (cosmetic): equal consecutive monotonic values are valid (the anchor is non-decreasing,
    not strictly increasing); the success reason must not claim 'monotonically advance'."""
    kp = _kp()
    op = _operator(kp)
    chain = _mint_chain(kp, op, n=2, monotonics=[50, 50])
    res = verify_ledger(chain, resolve_key=operator_key_resolver(keypair=kp))
    assert res.ok is True
    assert "monotonically advance" not in res.reason
    assert "non-decreasing" in res.reason or "never back-date" in res.reason


def test_verify_ledger_total_on_malformed_signature():
    # RE-CHECK HIGH: verify_ledger must be TOTAL — a forged/malformed signature (or a malformed resolver
    # pubkey) is a verification FAILURE (ok=False), never an uncaught cryptography IntegrityError.
    from vigil_integration.attestation import ledger as _L
    from vigil_integration.attestation.models import UsageAttestation, OperatorIdentity, GENESIS_PREV
    from vigil_core.models import Signature

    op = OperatorIdentity(os_login="kali", git_name="t", git_email="t@t", key_fingerprint="ab" * 32,
                          hostname="h")
    content = _L._content(seq=0, prev_hash=GENESIS_PREV, operator=op, action="a", target="t",
                          phase="informational", at="x", monotonic=1, grounded="software")
    rec = UsageAttestation(seq=0, prev_hash=GENESIS_PREV, operator=op, action="a", target="t",
                           phase="informational", at="x", monotonic=1, grounded="software",
                           record_hash=_L._record_hash(content),
                           signature=Signature(key_id="ab" * 32, signature_b64="!!!not-base64!!!"))
    for resolve_key in ({"ab" * 32: "!!not-a-key!!"}, {"ab" * 32: "A" * 43 + "="}):
        v = _L.verify_ledger([rec], resolve_key=resolve_key)   # must NOT raise
        assert v.ok is False and "seq 0" in v.reason
