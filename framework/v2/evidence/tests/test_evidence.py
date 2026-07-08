"""
Cryptographic evidence integrity — a certificate is sound only if it is authentic
(m-of-n signature), bound (the signature is for THIS oracle_context by digest), its raw
artifacts are unaltered, AND the pure oracle still reproduces the verdict. Any single
tamper — a flipped evidence byte, a lifted signature, a dropped chain entry, a rolled-
back head — must be caught. Everything is offline and deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
import pytest

from framework.v2.evidence import (
    ArtifactRef,
    append_entry,
    build_certificate,
    build_chain,
    manifest_dir,
    sign_certificate,
    sign_head,
    verify_bundle,
    verify_certificate,
    verify_chain,
    verify_head,
)
from framework.v2.evidence.manifest import verify_manifest
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding

_BASE = {"status": 200, "body": "No results found."}
_DIVERGENT = {"status": 200,
              "body": "id=1 name=alice role=user\nid=2 name=bob role=admin\nid=3 name=carol role=user"}


def _ctx(mutated: dict) -> FindingContext:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})


def _finding(mutated: dict) -> dict:
    ctx = _ctx(mutated)
    confirmed = confirm_finding(finding={"bug_class": "boolean_sqli"}, context=ctx)
    return {
        "check_id": "boolean-sqli", "bug_class": "boolean_sqli",
        "confirmed_by": confirmed.confirmed_by.value if confirmed else "differential_response",
        "confidence": confirmed.confidence if confirmed else 0.9,
        "oracle_context": ctx.model_dump(mode="json"),
    }


def _trust_root(threshold: int, n: int):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"Authoriser {i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


# ---- the four layers, happy path -------------------------------------------


def test_signed_certificate_verifies_all_four_layers() -> None:
    tr, signers = _trust_root(threshold=2, n=3)
    f = _finding(_DIVERGENT)
    cert = build_certificate(f, engagement_slug="acme", seq=0)
    signed = sign_certificate(cert, signers[:2])   # 2 of 3
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.authentic and v.bound and v.artifacts_ok and v.reproduced and v.ok
    assert len(v.valid_signers) == 2


# ---- tamper detection -------------------------------------------------------


def test_binding_fails_when_signature_lifted_onto_other_evidence() -> None:
    tr, signers = _trust_root(2, 3)
    f = _finding(_DIVERGENT)
    signed = sign_certificate(build_certificate(f, seq=0), signers[:2])
    # present a DIFFERENT oracle_context — the digest no longer matches
    other = _finding(_BASE)["oracle_context"]
    v = verify_certificate(signed, oracle_context=other, trust_root=tr)
    assert v.authentic and not v.bound and not v.ok


def test_reproduction_fails_for_a_non_firing_context() -> None:
    # a certificate honestly built + signed over a NON-divergent context: authentic +
    # bound, but the differential oracle does NOT fire → reproduced False → not sound.
    tr, signers = _trust_root(2, 3)
    f = dict(_finding(_BASE))
    f["confirmed_by"] = "differential_response"   # claims a differential it can't reproduce
    signed = sign_certificate(build_certificate(f, seq=0), signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert v.bound and not v.reproduced and not v.ok


def test_threshold_not_met_is_inauthentic() -> None:
    tr, signers = _trust_root(threshold=2, n=3)
    f = _finding(_DIVERGENT)
    signed = sign_certificate(build_certificate(f, seq=0), signers[:1])   # only 1 of 2 needed
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert not v.authentic and not v.ok


def test_signature_from_untrusted_key_does_not_count() -> None:
    tr, _ = _trust_root(1, 2)
    _, rogue = _trust_root(1, 1)              # a key NOT in tr
    f = _finding(_DIVERGENT)
    signed = sign_certificate(build_certificate(f, seq=0), rogue)
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)
    assert not v.authentic


# ---- artifact manifest ------------------------------------------------------


def test_artifact_manifest_binds_and_detects_tampering(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    adir = root / "action-1"
    adir.mkdir(parents=True)
    (adir / "response.body").write_bytes(b"id=2 name=bob role=admin")
    tr, signers = _trust_root(2, 3)
    f = _finding(_DIVERGENT)
    cert = build_certificate(f, seq=0, evidence_root=root, action_id="action-1")
    assert cert.artifacts and cert.artifacts[0].path == "action-1/response.body"
    signed = sign_certificate(cert, signers[:2])

    good = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr, evidence_root=root)
    assert good.artifacts_ok and good.ok

    (adir / "response.body").write_bytes(b"id=2 name=bob role=user")   # flip the raw bytes
    bad = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr, evidence_root=root)
    assert not bad.artifacts_ok and not bad.ok


def test_manifest_is_deterministic_and_missing_dir_is_empty(tmp_path: Path) -> None:
    assert manifest_dir(tmp_path / "nope") == []
    d = tmp_path / "e"
    d.mkdir()
    (d / "b.txt").write_text("b")
    (d / "a.txt").write_text("a")
    m1 = manifest_dir(d)
    m2 = manifest_dir(d)
    assert [x.path for x in m1] == ["a.txt", "b.txt"] and m1 == m2   # sorted + stable


# ---- the tamper-evident chain ----------------------------------------------


def test_chain_links_and_detects_reorder_and_tamper() -> None:
    digests = [f"{i:064x}" for i in range(4)]
    chain = build_chain(digests)
    ok, _ = verify_chain(chain)
    assert ok
    # reorder two entries → break
    swapped = [chain[0], chain[2], chain[1], chain[3]]
    assert not verify_chain(swapped)[0]
    # tamper a cert_digest in place → entry_hash mismatch
    tampered = list(chain)
    tampered[2] = tampered[2].model_copy(update={"cert_digest": "deadbeef" * 8})
    assert not verify_chain(tampered)[0]
    # append is monotonic + links
    nxt = append_entry(chain, "ff" * 32)
    assert nxt.seq == 4 and nxt.prev_hash == chain[-1].entry_hash


def test_signed_head_anchors_chain_and_rejects_truncation_and_rollback() -> None:
    tr, signers = _trust_root(2, 3)
    chain = build_chain([f"{i:064x}" for i in range(5)])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    ok, _ = verify_head(head, chain, tr)
    assert ok
    # drop the last entry but keep the old head → head no longer matches the chain
    ok2, _ = verify_head(head, chain[:-1], tr)
    assert not ok2
    # rollback: a head whose last_seq is below the accepted high-water is refused
    ok3, note = verify_head(head, chain, tr, prev_highwater=99)
    assert not ok3 and "rollback" in note.lower()


def test_head_signature_must_meet_threshold() -> None:
    tr, signers = _trust_root(threshold=2, n=3)
    chain = build_chain([f"{i:064x}" for i in range(3)])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:1])   # only 1 sig
    ok, note = verify_head(head, chain, tr)
    assert not ok and "signature" in note.lower()


# ---- additive: building a certificate does not mutate the finding ----------


def test_build_certificate_does_not_mutate_finding() -> None:
    f = _finding(_DIVERGENT)
    snapshot = json.dumps(f, sort_keys=True)
    build_certificate(f, seq=0)
    assert json.dumps(f, sort_keys=True) == snapshot


# ---- review fixes: fail-closed everywhere ----------------------------------


def test_claimed_artifacts_fail_closed_without_evidence_root(tmp_path: Path) -> None:
    # a cert that CLAIMS artifacts must NOT verify sound when the artifacts are not
    # checked (the default verify path with no evidence_root).
    root = tmp_path / "e"
    (root / "a1").mkdir(parents=True)
    (root / "a1" / "response.body").write_bytes(b"x")
    tr, signers = _trust_root(2, 3)
    f = _finding(_DIVERGENT)
    cert = build_certificate(f, seq=0, evidence_root=root, action_id="a1")
    signed = sign_certificate(cert, signers[:2])
    v = verify_certificate(signed, oracle_context=f["oracle_context"], trust_root=tr)  # no evidence_root
    assert not v.artifacts_ok and not v.ok


def test_verify_bundle_detects_a_suppressed_certificate() -> None:
    tr, signers = _trust_root(2, 3)
    fs = [_finding(_DIVERGENT), _finding(_DIVERGENT)]
    certs = [sign_certificate(build_certificate(fs[0], seq=0), signers[:2]),
             sign_certificate(build_certificate(fs[1], seq=1), signers[:2])]
    chain = build_chain([c.certificate.cert_digest for c in certs])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    contexts = {"boolean-sqli": fs[0]["oracle_context"]}   # same ref for both

    full = verify_bundle(certs, chain, head, contexts=contexts, trust_root=tr)
    assert full.ok and full.cert_set_bound

    # attacker deletes a certificate but leaves the chain + head untouched
    suppressed = verify_bundle(certs[:1], chain, head, contexts=contexts, trust_root=tr)
    assert not suppressed.cert_set_bound and not suppressed.ok


def test_verify_bundle_rejects_rollback_below_highwater() -> None:
    tr, signers = _trust_root(2, 3)
    certs = [sign_certificate(build_certificate(_finding(_DIVERGENT), seq=0), signers[:2])]
    chain = build_chain([c.certificate.cert_digest for c in certs])
    head = sign_head(chain, engagement_slug="acme", signers=signers[:2])
    contexts = {"boolean-sqli": _finding(_DIVERGENT)["oracle_context"]}
    r = verify_bundle(certs, chain, head, contexts=contexts, trust_root=tr, prev_highwater=99)
    assert not r.chain_ok and not r.ok and "rollback" in r.chain_note.lower()


def test_manifest_refuses_path_traversal_and_absolute() -> None:
    # parse-time: an escaping ArtifactRef path is rejected outright
    with pytest.raises(Exception):
        ArtifactRef(path="../../etc/passwd", sha256="0" * 64, size=1)
    with pytest.raises(Exception):
        ArtifactRef(path="/etc/passwd", sha256="0" * 64, size=1)
    # verify-time: even if a hostile path reaches verify_manifest, it is refused, not read
    res = verify_manifest([ArtifactRef.model_construct(path="../../../etc/passwd", sha256="0" * 64, size=1)],
                          root=Path("/tmp/does-not-matter"))
    assert res and res[0][1] is False and "escapes" in res[0][2]
