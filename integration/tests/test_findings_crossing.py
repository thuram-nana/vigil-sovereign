"""K4-4 — cross a cust_ run's confirmed FACTs to the sovereign spine (the PRODUCE/CROSS half).

A bare ``run_engagement`` (the engage_worker path) produces its confirmed FACTs only as in-memory, UNSIGNED
re-verifiable findings; nothing crosses to the sovereign plane on its own. ``cross_confirmed_findings`` closes
that gap: each oracle-confirmed FACT is RE-ADJUDICATED over its retained ``oracle_context`` (the deterministic
oracle must re-fire over the executor-captured bytes BEFORE signing), minted as a governance-signed
``SignedEvidence`` bound to the ``cust_`` engagement slug, and emitted as one inert envelope to the finding
spool. These pin: a re-firing FACT crosses as a SIGNED, cust_-slug-bound envelope; a finding that does NOT
re-fire degrades to a LEAD and NEVER crosses (no fabricated signed FACTs); signers are required (fail-closed).

The sovereign CONSUME/PROJECT half (SpoolWatcher ingest -> FindingReceiver scope-bind -> assessment_findings
per-org projection) is covered by the sovereign suites (test_spool_watcher / test_finding_receiver /
test_ui_assessments). Those project on exactly the ``certificate.engagement_slug`` this cross binds (the
one-way ``_customer_slug(org, host)`` hash), so the two halves compose: orgA's set contains this slug, orgB's
never can. Runs on the framework-inclusive integration leg (the real oracle re-fire): PYTHONPATH=
integration:engine/crucible.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from vigil_integration.jobs.findings_crossing import cross_confirmed_findings      # noqa: E402
from vigil_integration.live.wiring import provision_authority                      # noqa: E402

BUG = "error_based_sqli"
ORG, HOST = "org_a", "apme.cm"
# a real MySQL error-based-SQLi signature the error_signature oracle fires on (mirrors test_vf_end_to_end).
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"
_BENIGN = b'HTTP/1.1 200\r\n\r\n{"results": [], "ok": true}'


def _customer_slug(org_id: str, host: str) -> str:
    # mirror apps/sigil/sigil/ui/target_authorization._customer_slug (sigil is NOT on this leg's PYTHONPATH).
    return "cust_" + hashlib.sha256((org_id + "\x00" + host).encode("utf-8")).hexdigest()[:24]


def _error_context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


def _finding(body: bytes, *, ref="F1"):
    return {"check_id": ref, "bug_class": BUG, "oracle_context": _error_context(body)}


def _incoming(spool):
    return sorted(Path(spool, "incoming").glob("*.json"))


def test_confirmed_fact_crosses_as_a_signed_cust_slug_bound_envelope():
    slug = _customer_slug(ORG, HOST)
    prov = provision_authority(slug=slug, scope=[HOST], base_dir=tempfile.mkdtemp())
    spool = tempfile.mkdtemp()
    out = cross_confirmed_findings([_finding(_SQL_ERROR)], engagement_slug=slug,
                                   signers=prov.signers, spool_dir=spool)
    assert out.crossed == 1 and out.leads == 0 and out.errors == 0, out
    files = _incoming(spool)
    assert len(files) == 1 and out.envelope_paths == [str(files[0])]
    env = json.loads(files[0].read_text(encoding="utf-8"))
    assert env["certificate"]["engagement_slug"] == slug        # bound to the cust_ slug the projection keys on
    assert env["signatures"] and env["signatures"][0]["signature_b64"]   # governance-signed (anchor-1)


def test_a_finding_that_does_not_re_fire_is_a_lead_and_never_crosses():
    slug = _customer_slug(ORG, HOST)
    prov = provision_authority(slug=slug, scope=[HOST], base_dir=tempfile.mkdtemp())
    spool = tempfile.mkdtemp()
    out = cross_confirmed_findings([_finding(_BENIGN)], engagement_slug=slug,
                                   signers=prov.signers, spool_dir=spool)
    assert out.crossed == 0 and out.leads == 1, out              # oracle stayed silent -> LEAD
    assert _incoming(spool) == []                                # a LEAD never crosses the sovereignty seam


def test_mixed_batch_crosses_only_the_re_firing_facts():
    slug = _customer_slug(ORG, HOST)
    prov = provision_authority(slug=slug, scope=[HOST], base_dir=tempfile.mkdtemp())
    spool = tempfile.mkdtemp()
    out = cross_confirmed_findings(
        [_finding(_SQL_ERROR, ref="F1"), _finding(_BENIGN, ref="F2"), _finding(_SQL_ERROR, ref="F3")],
        engagement_slug=slug, signers=prov.signers, spool_dir=spool)
    assert out.crossed == 2 and out.leads == 1 and len(_incoming(spool)) == 2, out


def test_signers_are_required_fail_closed():
    with pytest.raises(ValueError):
        cross_confirmed_findings([], engagement_slug="cust_x", signers=[], spool_dir=tempfile.mkdtemp())


def test_the_crossed_envelope_verifies_under_the_provisioned_governance_key():
    # the crossed envelope's m-of-n signature is VALID over evidence_signing_bytes(certificate) under the
    # provisioned offense-governance key — exactly the anchor-1 the sovereign FindingReceiver.ingest checks
    # before it scope-binds + appends. Proves the cross output is genuinely verifiable, not merely non-empty.
    from framework.v2.evidence.certify import evidence_signing_bytes
    from vigil_core import verify_one
    slug = _customer_slug(ORG, HOST)
    prov = provision_authority(slug=slug, scope=[HOST], base_dir=tempfile.mkdtemp())
    spool = tempfile.mkdtemp()
    cross_confirmed_findings([_finding(_SQL_ERROR)], engagement_slug=slug, signers=prov.signers, spool_dir=spool)
    env = json.loads(_incoming(spool)[0].read_text(encoding="utf-8"))
    msg = evidence_signing_bytes(env["certificate"])
    assert verify_one(prov.keypair.public_key_b64, msg, env["signatures"][0]["signature_b64"])
