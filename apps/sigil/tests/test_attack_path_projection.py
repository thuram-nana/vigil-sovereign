"""APEX PR-L (Area 11) — the sovereign projection of the inert attack-path chain + out-of-band (blind-vuln)
attestation, plus its self-red-pen.

PR-L is the CONSUMER-side UI slice: an attack-path narrative (SVG) and a blind-vuln confirmation badge rendered
in ``customer_app/app.js``. The server half tested here is the projection that FEEDS that UI: ``assessments.
_finding_json`` surfaces the inert, signed ``attack_path`` / ``oob_attestation`` cert fields ONLY behind their own
default-OFF flags (``VIGIL_CUSTOMER_ATTACK_PATH`` / ``VIGIL_CUSTOMER_BLIND_VULN``). Load-bearing invariants (a
false-green either leaks one tenant's chain/attestation to another, lets a flag-off read surface the field, or
lets the projection fabricate/validate/promote — which it must never do; the UI only DRAWS what the signed data
already established):

  * BYTE-IDENTICAL WHEN OFF: with a flag unset, ``assessment_findings`` NEVER carries that field even when the
    certificate HAS it. Mutation-verify: drop the field's entry from ``assessments._GATED_FIELDS`` and the
    matching flag-off test REDS (the field leaks unconditionally).
  * INDEPENDENT FLAGS: attack-path on + blind-vuln off surfaces ``attack_path`` but NOT ``oob_attestation``, and
    vice versa — the two gates are distinct (neither guard stands in for the other).
  * TENANT ISOLATION (self-red-pen): a findings read for org B NEVER carries org A's chain or attestation,
    because the read is scoped to the org's OWN server-derived slug set (``_customer_slug`` is a one-way hash).
  * INERT PASSTHROUGH: the projection is a pure allowlisted deep copy of signed DATA — it never validates,
    scores, or promotes a chain/attestation, never raises on a malformed one, and fabricates nothing when the
    field is absent (honest absence, never a synthesised "clean").
  * NO ALIASING: the surfaced block is a deep copy, so a caller mutating a read never corrupts the spine record
    or a later read.
  * FOLD-CACHE IDENTITY: each gating flag is part of the cached findings index's identity. Flipping a flag between
    two reads of one spine under the fold cache gives each read exactly the uncached read for its own value
    (test_each_gate_flips_between_two_reads_under_the_fold_cache); the index is folded under the values its read
    keyed it by, never a flag re-read mid-fold
    (test_the_cached_index_is_projected_under_the_values_its_read_keyed_it_by); and a flag-OFF cached read drops
    that block even from an index built with it ON, a second independent refusal
    (test_a_flag_off_cached_read_drops_the_block_even_from_an_index_built_on).
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.governor.asset_ownership import METHOD_DNS_TXT, AssetOwnershipRegistry
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore
from sigil.ui import assessments as _assess
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner
from sigil.ui.target_authorization import _customer_slug

NOW = 1000.0
ATTACK_FLAG = "VIGIL_CUSTOMER_ATTACK_PATH"
BLIND_FLAG = "VIGIL_CUSTOMER_BLIND_VULN"


def _store():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return s


def _prov(store, owner):
    return Provisioner(
        store,
        customers=CustomerRegistry(store, owner_key=owner),
        orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner),
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: NOW)


def _member(orgs, org, user, role, it):
    orgs.create_org(org, org.upper(), owner="owner", issued_at=float(next(it)))
    orgs.grant_membership(org, user, role, issued_at=float(next(it)))


def _prove(store, org, host, it):
    reg = AssetOwnershipRegistry(store)
    ch = reg.issue_challenge(org, host, issued_at=float(next(it)))
    reg.verify_and_record(org, host, method=METHOD_DNS_TXT, observed=[ch.marker], now=10.0, ttl_seconds=1e12)
    return _customer_slug(org, host)


def _attack_path(destination="customer records in the orders database", impact="data access", secret=""):
    """An inert attack-path block in the shape the chaining phase would serialize onto a finding cert: ordered
    steps, each RESTATING a fired oracle (src/edge/dst + oracle/finding_ref provenance), ending in impact."""
    return {
        "schema": 1,
        "destination": destination,
        "impact": impact,
        "steps": [
            {"src": "unauthenticated request" + secret, "edge": "SSRF", "dst": "cloud metadata endpoint",
             "technique": "gopher:// to 169.254.169.254", "oracle": "ssrf_oob_oracle", "finding_ref": "f-ssrf"},
            {"src": "cloud metadata endpoint", "edge": "credential theft", "dst": "IAM session credentials",
             "technique": "iam/security-credentials", "oracle": "metadata_read_oracle", "finding_ref": "f-ssrf"},
            {"src": "IAM session credentials", "edge": "authorized API call", "dst": "S3 object read",
             "technique": "s3:GetObject", "oracle": "s3_read_oracle", "finding_ref": "f-s3"},
        ],
    }


def _oob(secret=""):
    """An inert out-of-band attestation in the shape the OOB collector path would serialize onto a finding cert:
    the independent pinned-collector receipt core + its key id (NO private key material)."""
    return {
        "schema": 1,
        "method": "dns",
        "collector_key_id": "oob-collector-ed25519-7f3a9c" + secret,
        "canary": "a1b2c3d4e5f6a7b8c9d0",
        "received_at": 1699900000,
        "receipt_digest": "sha256:9c1e4f2a7b8d6e5c3a1f0b9d8e7c6a5b4d3c2e1f",
        "note": "confirmed by an independent, out-of-band signed callback",
    }


def _finding(store, slug, ref, *, bug_class="ssrf", severity="critical", attack_path=None, oob=None,
             presentation=None):
    cert = {"engagement_slug": slug, "finding_ref": ref, "bug_class": bug_class,
            "surface": "https://x/" + ref, "confidence": "high", "severity": severity,
            "title": "Finding " + ref, "summary": "s " + ref}
    if attack_path is not None:
        cert["attack_path"] = attack_path
    if oob is not None:
        cert["oob_attestation"] = oob
    if presentation is not None:
        cert["presentation"] = presentation
    store.append(kind="finding", source="offense", actor="ORACLE",
                 payload={"certificate": cert, "finding_ref": ref,
                          "signatures": [{"key_id": "gov", "signature_b64": "x"}]})


def _org_with_finding(p, it, *, attack_path=None, oob=None, presentation=None):
    _member(p.orgs, "acme", "alice", "operator", it)
    slug = _prove(p.store, "acme", "acme.example", it)
    _finding(p.store, slug, "f1", attack_path=attack_path, oob=oob, presentation=presentation)
    return slug


def _only_finding(store, org="acme"):
    out = _assess.assessment_findings(store, org, now=NOW)
    assert out["count"] == 1, out
    return out["findings"][0]


# ---- attack_path gating (surfaced on, byte-identical off) ------------------------------------------------------
def test_attack_path_surfaced_when_on(monkeypatch):
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.delenv(BLIND_FLAG, raising=False)
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), attack_path=_attack_path())
    row = _only_finding(store)
    ap = row.get("attack_path")
    assert isinstance(ap, dict) and ap["destination"].startswith("customer records")
    assert [s["edge"] for s in ap["steps"]] == ["SSRF", "credential theft", "authorized API call"]
    # every step restates a fired oracle (no un-grounded edge) — the soundness contract the UI relies on
    assert all(s.get("oracle") for s in ap["steps"])


def test_attack_path_byte_identical_when_off(monkeypatch):
    # The cert HAS an attack_path, but with the flag OFF the read must never surface it. Mutation-verify: drop
    # "attack_path" from assessments._GATED_FIELDS and this test REDS.
    monkeypatch.delenv(ATTACK_FLAG, raising=False)
    monkeypatch.delenv(BLIND_FLAG, raising=False)
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), attack_path=_attack_path())
    assert "attack_path" not in _only_finding(store), "flag OFF must not surface the attack_path block"


# ---- oob_attestation gating (surfaced on, byte-identical off) --------------------------------------------------
def test_oob_attestation_surfaced_when_on(monkeypatch):
    monkeypatch.setenv(BLIND_FLAG, "1")
    monkeypatch.delenv(ATTACK_FLAG, raising=False)
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), oob=_oob())
    att = _only_finding(store).get("oob_attestation")
    assert isinstance(att, dict) and att["method"] == "dns"
    assert att["collector_key_id"].startswith("oob-collector")
    assert "private" not in repr(att).lower() and "sign(" not in repr(att)   # never key material


def test_oob_attestation_byte_identical_when_off(monkeypatch):
    # The cert HAS an oob_attestation, but with the flag OFF the read must never surface it. Mutation-verify:
    # drop "oob_attestation" from assessments._GATED_FIELDS and this test REDS.
    monkeypatch.delenv(BLIND_FLAG, raising=False)
    monkeypatch.delenv(ATTACK_FLAG, raising=False)
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), oob=_oob())
    assert "oob_attestation" not in _only_finding(store), "flag OFF must not surface the oob_attestation block"


# ---- the two gates are INDEPENDENT -----------------------------------------------------------------------------
def test_flags_are_independent(monkeypatch):
    # attack-path ON, blind-vuln OFF: only attack_path surfaces. A finding carries BOTH blocks.
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.delenv(BLIND_FLAG, raising=False)
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), attack_path=_attack_path(), oob=_oob())
    row = _only_finding(store)
    assert "attack_path" in row and "oob_attestation" not in row

    # the mirror image: blind-vuln ON, attack-path OFF -> only oob surfaces.
    monkeypatch.delenv(ATTACK_FLAG, raising=False)
    monkeypatch.setenv(BLIND_FLAG, "1")
    store2 = _store()
    p2 = _prov(store2, ensure_owner_keypair())
    _org_with_finding(p2, iter(range(1, 10_000)), attack_path=_attack_path(), oob=_oob())
    row2 = _only_finding(store2)
    assert "oob_attestation" in row2 and "attack_path" not in row2


def test_both_blocks_and_presentation_coexist(monkeypatch):
    # All three PR-A/PR-L blocks on together: each surfaces, none interferes with the others' gate.
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    pres = {"schema": 1, "plain_impact": {"what": "x", "category_consequence": "", "established": "",
                                          "description_on_file": True}, "remediation": "fix", "priority": {}}
    _org_with_finding(p, iter(range(1, 10_000)), attack_path=_attack_path(), oob=_oob(), presentation=pres)
    row = _only_finding(store)
    assert "attack_path" in row and "oob_attestation" in row and "presentation" in row


# ---- honest absence + inert passthrough ------------------------------------------------------------------------
def test_absent_field_is_never_fabricated(monkeypatch):
    # Flags ON, but the finding carries NEITHER block: the keys are simply absent (never None, never invented).
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)))     # no attack_path, no oob
    row = _only_finding(store)
    assert "attack_path" not in row and "oob_attestation" not in row


def test_malformed_blocks_pass_through_inertly_not_fatal(monkeypatch):
    # The projection is a pure inert passthrough: a malformed/empty block is surfaced AS-IS (the UI decides
    # renderability — a chain with no drawable steps simply does not render), and never raises.
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), attack_path={"steps": []}, oob={})
    row = _only_finding(store)
    assert row.get("attack_path") == {"steps": []}
    # an empty-dict oob is falsy-but-present: it rode the allowlist unchanged (the UI's isEmptyObj drops the badge)
    assert row.get("oob_attestation") == {}


# ---- NO aliasing: the surfaced block is a deep copy ------------------------------------------------------------
def test_surfaced_blocks_are_deep_copies(monkeypatch):
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    _org_with_finding(p, iter(range(1, 10_000)), attack_path=_attack_path(), oob=_oob())
    first = _only_finding(store)
    first["attack_path"]["steps"].append({"src": "MUTATED", "dst": "MUTATED"})
    first["oob_attestation"]["method"] = "MUTATED"
    second = _only_finding(store)                    # a fresh read must be untouched by the mutation above
    assert len(second["attack_path"]["steps"]) == 3 and second["oob_attestation"]["method"] == "dns"


# ---- SELF-RED-PEN: a cross-tenant chain / attestation can NEVER leak -------------------------------------------
def test_cross_tenant_chain_and_oob_never_leak(monkeypatch):
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    # Org A (acme) has a chained, out-of-band-confirmed finding carrying SECRET markers.
    _member(p.orgs, "acme", "alice", "operator", it)
    a_slug = _prove(store, "acme", "acme.example", it)
    _finding(store, a_slug, "secret", attack_path=_attack_path(secret="-ACMESECRET"), oob=_oob(secret="ACMESECRET"))
    # Org B (globex) exists with its OWN proven host but NO findings.
    _member(p.orgs, "globex", "bob", "operator", it)
    _prove(store, "globex", "globex.example", it)

    b = _assess.assessment_findings(store, "globex", now=NOW)
    assert b["count"] == 0
    assert "ACMESECRET" not in repr(b), "org A's chain/attestation leaked into org B's read"

    # Control: A itself DOES see its own chain + attestation (the read is not vacuously empty).
    a_row = _only_finding(store, org="acme")
    assert "ACMESECRET" in repr(a_row["oob_attestation"]) and "ACMESECRET" in repr(a_row["attack_path"])


# ---- PROVEN ONLY: the blocks ride only a certificate-bearing (proven) finding ----------------------------------
def test_only_a_proven_finding_carries_the_blocks(monkeypatch):
    # A kind="finding" record with NO certificate (an agent-authored note) carries no engagement slug, so it is
    # never in the org's set and is never projected — the chain/attestation can only ride a PROVEN finding.
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it)
    _prove(store, "acme", "acme.example", it)
    # a certificate-less finding that nonetheless carries a would-be chain at the payload top level
    store.append(kind="finding", source="bastion", actor="agent",
                 payload={"finding_ref": "ghost", "attack_path": _attack_path(), "oob_attestation": _oob()})
    out = _assess.assessment_findings(store, "acme", now=NOW)
    assert out["count"] == 0 and "attack_path" not in repr(out)


# ---- the fold-cache path: every gating flag is part of the cached index's identity -----------------------------
_GATE_FLAGS = (("attack_path", ATTACK_FLAG), ("oob_attestation", BLIND_FLAG))
_GATE_IDS = [f for f, _flag in _GATE_FLAGS]


def _chained_store():
    """One org whose finding carries all three gated blocks (attack path, out-of-band attestation, presentation)."""
    store = _store()
    p = _prov(store, ensure_owner_keypair())
    pres = {"schema": 1, "plain_impact": {"what": "x", "category_consequence": "", "established": "",
                                          "description_on_file": True}, "remediation": "fix", "priority": {}}
    _org_with_finding(p, iter(range(1, 10_000)), attack_path=_attack_path(), oob=_oob(), presentation=pres)
    return store


def _identity(entry) -> "dict[str, bool]":
    """The gating-flag values an assessments index entry is keyed by (the tail of its cache key)."""
    return dict(entry.key[-len(_assess._GATED_FIELDS):])


@pytest.mark.parametrize("first", [True, False], ids=["on-then-off", "off-then-on"])
@pytest.mark.parametrize("field,flag", _GATE_FLAGS, ids=_GATE_IDS)
def test_each_gate_flips_between_two_reads_under_the_fold_cache(monkeypatch, field, flag, first):
    """REGRESSION (the "fold cache ON" CI leg's bug class, for PR-L's flags). The cached findings index projects each
    finding under the gating flags; were a flag left out of the index's cache identity, an index built with it ON
    would keep surfacing the block after it went OFF, and one built OFF would keep hiding it after it came back ON.
    With the fold cache forced ON (so every CI leg runs this), starting from each value: every cached read equals the
    UNCACHED read for its own value, a second read under the same value reuses the entry (the cache still caches),
    and each entry is keyed by — and its view folded under — its read's own value."""
    from sigil.spine import fold_cache
    for _f, other in _GATE_FLAGS:
        monkeypatch.delenv(other, raising=False)
    monkeypatch.delenv("VIGIL_APEX_PRESENTATION", raising=False)
    store = _chained_store()

    def read(on: bool, *, cached: bool) -> dict:
        monkeypatch.setenv(flag, "1" if on else "")
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1" if cached else "")
        return _assess.assessment_findings(store, "acme", now=NOW)

    truth = {on: read(on, cached=False) for on in (False, True)}              # the uncached scan, per value
    assert field in truth[True]["findings"][0] and field not in truth[False]["findings"][0]
    fold_cache.clear_all()
    built = []
    for on in (first, not first, first, not first):   # ON -> OFF: a stale index LEAKS the block; OFF -> ON: LOSES it
        assert read(on, cached=True) == truth[on], f"{flag} {'ON' if on else 'OFF'}"
        (entry,) = _assess._ASSESSMENTS_FOLD._entries.values()                    # the cached path answered
        assert read(on, cached=True) == truth[on]
        (again,) = _assess._ASSESSMENTS_FOLD._entries.values()
        assert again is entry                                                     # ... and reused its entry
        built.append((on, entry))
    for on, entry in built:                             # each entry keyed by, and folded under, its read's own value
        assert _identity(entry)[field] is on and entry.state.gates[field] is on


@pytest.mark.parametrize("field", _GATE_IDS)
def test_the_cached_index_is_projected_under_the_values_its_read_keyed_it_by(monkeypatch, field):
    """Every gating flag is read ONCE per fold-cache read and bound into the view the index is folded into
    (``_AssessmentsView.gates``), never re-read while folding: a flag that changes mid-fold cannot leave an entry whose
    rows disagree with the values in its cache identity (every later read under those values reuses them)."""
    from sigil.spine import fold_cache
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    fold_cache.clear_all()
    store = _chained_store()
    looks = iter([True])                                       # ON for the read's own look, OFF for any later one
    monkeypatch.setitem(_assess._GATED_FIELDS, field, lambda: next(looks, False))
    assert field in _only_finding(store)
    (entry,) = _assess._ASSESSMENTS_FOLD._entries.values()
    assert _identity(entry)[field] is True and entry.state.gates[field] is True
    assert all(field in j for rows in entry.state.findings.values() for _seq, j in rows)


@pytest.mark.parametrize("field,flag", _GATE_FLAGS, ids=_GATE_IDS)
def test_a_flag_off_cached_read_drops_the_block_even_from_an_index_built_on(monkeypatch, field, flag):
    """The second, independent refusal: a fold-cache read drops, from every row it returns, each gated block whose
    flag is OFF for it — so even an index built with the flag ON, were the flags ever lost from its cache identity
    (simulated here), cannot surface that block while its flag is off. The other block, whose flag stays on, is
    still served (the refusal is per block)."""
    from sigil.spine import fold_cache
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1")
    monkeypatch.setenv(ATTACK_FLAG, "1")
    monkeypatch.setenv(BLIND_FLAG, "1")
    fold_cache.clear_all()
    store = _chained_store()
    real = _assess.cached_unsigned_read
    monkeypatch.setattr(_assess, "cached_unsigned_read", lambda *a, identity=(), **kw: real(*a, **kw))
    assert field in _only_finding(store)
    (entry,) = _assess._ASSESSMENTS_FOLD._entries.values()
    monkeypatch.delenv(flag)
    (other,) = [f for f, _flag in _GATE_FLAGS if f != field]
    for rows in (_assess.assessment_findings(store, "acme", now=NOW)["findings"],
                 _assess.all_findings_for_org(store, "acme", now=NOW)):
        assert rows and all(field not in f and other in f for f in rows), rows
    (again,) = _assess._ASSESSMENTS_FOLD._entries.values()
    assert again is entry and entry.state.gates[field] is True      # served from the flag-ON index, and refused


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
