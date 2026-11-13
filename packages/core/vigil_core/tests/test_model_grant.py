"""PRICING M1b — the owner-signed per-run MODEL GRANT token (vigil_core.model_grant).

The offense plane presents this token to the sovereign model gateway in place of the provider API key, so it must be
unforgeable (owner signature over a distinct domain), tamper-evident (every field signed, canonical body only) and
total to decode (a hostile token is refused with a reason, never raised).

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the domain tag from the signed bytes                     -> test_a_signature_for_another_purpose_never_verifies
  * skip the signature check                                      -> test_a_tampered_or_foreign_token_is_refused
  * drop the canonical-form check                                 -> test_a_non_canonical_body_is_refused
  * accept an effort outside high / xhigh / max                   -> test_the_grant_schema_is_strict
"""
from __future__ import annotations

import base64
import json

import pytest

from vigil_core import generate_keypair, sign
from vigil_core import model_grant as mg
from vigil_core.canonical import canonical_json
from vigil_core.spine_domains import DOMAIN_TAGS

OWNER = generate_keypair()
OTHER = generate_keypair()


def _grant(**kw) -> mg.ModelGrant:
    base = dict(grant_id=mg.new_grant_id(), org_id="org_acme", engagement_slug="cust_abc", nonce="n-1",
                model="claude-opus-4-8", effort="xhigh", cap_nano_usd=750_000_000, not_after=1_800_086_400.0,
                issued_at=1_800_000_000.0)
    base.update(kw)
    return mg.ModelGrant(**base)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def test_a_token_round_trips_under_the_owner_key():
    g = _grant()
    token = mg.encode_token(g, OWNER.private_key_b64)
    assert token.startswith("vmg1.") and token.count(".") == 2 and len(token) < 1024
    got, reason = mg.decode_token(token, OWNER.public_key_b64)
    assert (got, reason) == (g, "")
    assert len(mg.new_grant_id()) == 32 and mg.new_grant_id() != mg.new_grant_id()


def test_a_tampered_or_foreign_token_is_refused():
    g = _grant()
    token = mg.encode_token(g, OWNER.private_key_b64)
    assert mg.decode_token(token, OTHER.public_key_b64)[0] is None                   # wrong owner
    assert mg.decode_token(mg.encode_token(g, OTHER.private_key_b64), OWNER.public_key_b64)[0] is None
    prefix, body, sig = token.split(".")
    raised = json.loads(base64.urlsafe_b64decode(body + "==="))
    raised["cap_nano_usd"] = 10 ** 12                                                  # raise the cap
    forged = ".".join([prefix, _b64u(canonical_json(raised)), sig])
    got, reason = mg.decode_token(forged, OWNER.public_key_b64)
    assert got is None and "does not verify" in reason
    assert mg.decode_token(token, None)[0] is None and mg.decode_token(token, "")[0] is None


@pytest.mark.parametrize("bad", [
    None, 42, "", "vmg1", "vmg1.a", "vmg1.a.b.c", "vmg2.aaaa.bbbb", "vmg1.!!!!.bbbb", "vmg1.aaaa.bbbb",
    "vmg1." + "a" * 5000 + ".b",
])
def test_malformed_tokens_are_refused_never_raised(bad):
    got, reason = mg.decode_token(bad, OWNER.public_key_b64)
    assert got is None and reason


def test_a_signature_for_another_purpose_never_verifies():
    g = _grant()
    body = canonical_json(g.model_dump(mode="json"))
    assert mg.model_grant_signing_bytes(g) == DOMAIN_TAGS["model-grant"] + body
    for purpose in ("credit-launch-lease", "engagement-completion", "monitoring-authority"):
        sig = base64.b64decode(sign(OWNER.private_key_b64, DOMAIN_TAGS[purpose] + body))
        assert mg.decode_token(f"vmg1.{_b64u(body)}.{_b64u(sig)}", OWNER.public_key_b64)[0] is None
    bare = base64.b64decode(sign(OWNER.private_key_b64, body))                       # no domain at all
    assert mg.decode_token(f"vmg1.{_b64u(body)}.{_b64u(bare)}", OWNER.public_key_b64)[0] is None


def test_a_non_canonical_body_is_refused():
    g = _grant()
    loose = json.dumps(g.model_dump(mode="json"), indent=1).encode()                 # same fields, other bytes
    sig = base64.b64decode(sign(OWNER.private_key_b64, DOMAIN_TAGS["model-grant"] + loose))
    got, reason = mg.decode_token(f"vmg1.{_b64u(loose)}.{_b64u(sig)}", OWNER.public_key_b64)
    assert got is None and "canonical" in reason


def test_the_grant_schema_is_strict():
    for kw in ({"effort": "low"}, {"effort": "ultracode"}, {"grant_id": "XYZ"}, {"cap_nano_usd": -1},
               {"cap_nano_usd": 10 ** 16}, {"not_after": float("inf")}, {"issued_at": 0.0}, {"org_id": ""}):
        with pytest.raises(ValueError):
            _grant(**kw)
    with pytest.raises(ValueError):
        mg.ModelGrant(**{**_grant().model_dump(), "extra": 1})
    # a signed body with a field the schema refuses is refused at decode, not raised
    doc = {**_grant().model_dump(mode="json"), "effort": "low"}
    body = canonical_json(doc)
    sig = base64.b64decode(sign(OWNER.private_key_b64, DOMAIN_TAGS["model-grant"] + body))
    got, reason = mg.decode_token(f"vmg1.{_b64u(body)}.{_b64u(sig)}", OWNER.public_key_b64)
    assert got is None and "not a valid model grant" in reason


def test_one_grant_has_exactly_one_token_string():
    token = mg.encode_token(_grant(), OWNER.private_key_b64)
    prefix, body, sig = token.split(".")
    assert mg.decode_token(token, OWNER.public_key_b64)[0] is not None
    # base64url with non-zero trailing bits decodes to the same bytes: such a spelling is refused
    last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for part in (1, 2):
        parts = [prefix, body, sig]
        original = parts[part]
        twins = [original[:-1] + c for c in last if c != original[-1]
                 and base64.urlsafe_b64decode(original[:-1] + c + "===") == base64.urlsafe_b64decode(original + "===")]
        assert twins or part == 1                       # a 64-byte signature always has twins; a body may not
        for twin in twins:
            parts[part] = twin
            got, reason = mg.decode_token(".".join(parts), OWNER.public_key_b64)
            assert got is None and "canonical base64url" in reason


def test_a_meter_id_is_one_launch_and_only_one():
    assert mg.meter_id("cust_abc", "n-1") == _grant().meter_id and len(_grant().meter_id) == 32
    assert mg.meter_id("cust_abc", "n-1") != mg.meter_id("cust_abc", "n-2")          # a relaunch is another meter
    assert mg.meter_id("cust_abc", "n-1") != mg.meter_id("cust_abd", "n-1")
    assert mg.meter_id("ab", "c") != mg.meter_id("a", "bc")                          # the two are kept apart
    for slug, nonce in (("a\x00b", "c"), ("a", "b\x00c")):
        with pytest.raises(ValueError):
            mg.meter_id(slug, nonce)
    for kw in ({"engagement_slug": "a\x00b"}, {"nonce": "b\x00c"}, {"nonce": "line\nbreak"}, {"engagement_slug": "t\tab"}):
        with pytest.raises(ValueError):
            _grant(**kw)


def test_a_grant_expires_after_it_is_issued():
    for kw in ({"not_after": 1_800_000_000.0}, {"not_after": 1_700_000_000.0}):
        with pytest.raises(ValueError, match="expire after"):
            _grant(**kw)
    # and a signed body that says otherwise is refused at decode
    doc = {**_grant().model_dump(mode="json"), "not_after": 1_700_000_000.0}
    body = canonical_json(doc)
    sig = base64.b64decode(sign(OWNER.private_key_b64, DOMAIN_TAGS["model-grant"] + body))
    got, reason = mg.decode_token(f"vmg1.{_b64u(body)}.{_b64u(sig)}", OWNER.public_key_b64)
    assert got is None and "not a valid model grant" in reason


def test_a_grant_lasts_at_most_a_week():
    issued = 1_800_000_000.0
    assert _grant(not_after=issued + mg.MAX_GRANT_LIFETIME_S).not_after == issued + mg.MAX_GRANT_LIFETIME_S
    with pytest.raises(ValueError, match="at most a week"):
        _grant(not_after=issued + mg.MAX_GRANT_LIFETIME_S + 1)
    assert mg.MAX_GRANT_LIFETIME_S == 7 * 86_400 + 3_600           # the launch lease's longest life, plus slack
