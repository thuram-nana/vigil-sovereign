"""PR-H Area 7 — SAML 2.0 assertion verification (`ui.saml`).

Load-bearing invariants (a false-green here is a full auth bypass):
  * XML HARDENING: a DOCTYPE/DTD (⇒ XXE / billion-laughs / external-entity) is refused;
  * EXACTLY ONE assertion + NO duplicate ID (the structural XSW core);
  * SIGNATURE BINDING: a valid signature must cover the processed assertion OR the enveloping Response — a
    signature over any OTHER id (a wrapper) is refused; no valid signature ⇒ refused;
  * ISSUER / AUDIENCE / RECIPIENT / DESTINATION must match the org's config (org-scoping);
  * TIME WINDOWS (Conditions + SubjectConfirmationData NotOnOrAfter/NotBefore, skew) enforced; missing
    NotOnOrAfter refused;
  * REPLAY: an assertion ID is single-use;
  * the shipped signature backend FAILS CLOSED without a vetted XML-DSig library.

The crypto itself is treated as a verified dependency: tests inject a `sig_verifier` stub that attests WHICH
element ids are validly signed, so the structural/XSW/temporal/audience/replay logic is exercised without
depending on byte-correct exclusive-c14n (which the environment cannot provide; see the module honest boundary).

GUARD ISOLATION: a refusal test proves its guard only if NO OTHER guard refuses the same document — otherwise it
stays green with its own guard deleted. So every load-bearing guard has an isolating test: an otherwise-valid
document that only that guard refuses (asserted by the guard's own message), next to a same-shape control that
verifies once the one hostile feature is removed. Each was proven by mutating its guard (the test reds).
"""
from __future__ import annotations

import dataclasses
import sys
import tempfile
import xml.etree.ElementTree as ET

import pytest

from sigil.governor.sso_config import SsoConfig
from sigil.ui import saml
from sigil.ui.saml import SamlError

# Assertion timestamps are year-2001 (epoch ~1e9); NOW sits inside the validity window.
NOW = 1_000_400_000.0
EXPIRED = 1_000_500_000.0
TOO_EARLY = 1_000_200_000.0

CFG = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active",
                idp_entity_id="https://idp.example", idp_certs_pem=("PEMCERT",),
                sp_entity_id="https://sp.vigil/acme", acs_url="https://app.vigil/acs/acme", clock_skew_seconds=60)


def _assertion(aid="a1", aud="https://sp.vigil/acme", rcpt="https://app.vigil/acs/acme",
               nooa="2001-09-14T00:00:00Z", nb="2001-09-13T00:00:00Z", issuer="https://idp.example",
               nameid="user@acme", groups=("admins",), with_subject=True, with_conditions=True,
               with_scd=True, with_nameid=True, cond_nooa=None, scd_nooa=None):
    # `cond_nooa` / `scd_nooa` override ONE NotOnOrAfter bound (None = `nooa`; "" = omit the attribute), so a test
    # can make exactly one of the two time guards the only one that refuses.
    cond_nooa = nooa if cond_nooa is None else cond_nooa
    scd_nooa = nooa if scd_nooa is None else scd_nooa
    grp = "".join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)
    subj = ""
    if with_subject:
        nid = f'<saml:NameID>{nameid}</saml:NameID>' if with_nameid else ''
        scd_attr = f' NotOnOrAfter="{scd_nooa}"' if scd_nooa else ''
        scd = (f'<saml:SubjectConfirmation><saml:SubjectConfirmationData Recipient="{rcpt}"'
               f'{scd_attr}/></saml:SubjectConfirmation>') if with_scd else ''
        subj = f'<saml:Subject>{nid}{scd}</saml:Subject>'
    cond = ""
    if with_conditions:
        nbattr = f' NotBefore="{nb}"' if nb else ''
        cond_attr = f' NotOnOrAfter="{cond_nooa}"' if cond_nooa else ''
        cond = (f'<saml:Conditions{nbattr}{cond_attr}><saml:AudienceRestriction>'
                f'<saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions>')
    return (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}">'
            f'<saml:Issuer>{issuer}</saml:Issuer>{subj}{cond}'
            f'<saml:AttributeStatement><saml:Attribute Name="groups">{grp}</saml:Attribute>'
            f'</saml:AttributeStatement></saml:Assertion>')


def _response(assertions=None, dest="https://app.vigil/acs/acme", rid="r1", **kw):
    body = assertions if assertions is not None else _assertion(**kw)
    destattr = f' Destination="{dest}"' if dest is not None else ''
    return (f'<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'ID="{rid}"{destattr}>{body}</samlp:Response>').encode()


def _led():
    return saml.SamlReplayLedger(tempfile.mktemp())


def _verify(xml, signed=("a1",), now=NOW, cfg=CFG, ledger=None):
    return saml.verify_saml_response(xml, config=cfg, now=now, replay_ledger=ledger or _led(),
                                     sig_verifier=lambda b, c: frozenset(signed))


# --- accept paths -----------------------------------------------------------------------------------

def test_valid_assertion_accepts():
    idn = _verify(_response())
    assert idn.name_id == "user@acme" and idn.assertion_id == "a1" and idn.groups == ("admins",)


def test_signature_over_response_root_binds():
    # a single assertion enveloped by a signed Response: binding holds (no wrapping gap).
    assert _verify(_response(), signed=("r1",)).name_id == "user@acme"


# --- the XSW structural core ------------------------------------------------------------------------

def test_forged_unsigned_assertion_refused():
    with pytest.raises(SamlError):
        _verify(_response(), signed=())


def test_xsw_signature_over_a_different_id_refused():
    # the signature validly covers 'attacker-wrapper', but the processed assertion is 'a1' → no binding.
    with pytest.raises(SamlError):
        _verify(_response(), signed=("attacker-wrapper",))


def test_multiple_assertions_refused():
    two = _assertion(aid="a1") + _assertion(aid="a2", nameid="evil@acme")
    with pytest.raises(SamlError):
        _verify(_response(assertions=two), signed=("a1",))


def test_duplicate_id_refused():
    dup = _assertion(aid="a1") + _assertion(aid="a1")
    with pytest.raises(SamlError):
        _verify(_response(assertions=dup), signed=("a1",))


def test_assertion_without_id_refused():
    a = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>https://idp.example</saml:Issuer></saml:Assertion>'
    with pytest.raises(SamlError):
        _verify(_response(assertions=a), signed=("a1",))


# The duplicate-ID guard in its REAL XSW shape. `test_duplicate_id_refused` uses TWO assertions, so with
# `_collect_ids` deleted `_single_assertion` still refuses it. Here the document holds EXACTLY ONE <saml:Assertion>
# plus a second element reusing an id the verifier attests: the signature reference resolves to the hidden, validly
# signed original while the processor reads the forged twin — only `_collect_ids` sees the collision.
_DUP_HOLDERS = {
    # the IdP-signed original Response wrapped away in <Extensions>; the forged root Response reuses its ID
    "wrapped-signed-response": ('<samlp:Response ID="{}"/>', "r1"),
    # a decoy element reusing the processed assertion's own ID
    "decoy-sharing-the-assertion-id": ('<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="{}"/>', "a1"),
}


@pytest.mark.parametrize("shape", sorted(_DUP_HOLDERS))
def test_duplicate_id_beside_exactly_one_assertion_is_refused_by_collect_ids(shape):
    holder, dup = _DUP_HOLDERS[shape]

    def doc(holder_id: str) -> bytes:
        return _response(assertions=f'<samlp:Extensions>{holder.format(holder_id)}</samlp:Extensions>'
                                    + _assertion(nameid="evil@acme"))
    with pytest.raises(SamlError, match="duplicate ID"):
        _verify(doc(dup), signed=(dup,))
    # isolation control: rename ONLY the duplicate and the same document verifies (one assertion, a binding
    # signature) — so nothing but `_collect_ids` refuses the shape above.
    assert _verify(doc(dup + "-unique"), signed=(dup,)).name_id == "evil@acme"


def test_a_response_without_any_assertion_is_refused_by_the_single_assertion_guard():
    # without this guard the bare index would raise IndexError — not a SamlError, so it would escape the
    # SamlError -> SsoLoginError mapping the provisioner's refusal accounting (failure count + audit) relies on.
    with pytest.raises(SamlError, match="no <saml:Assertion>"):
        _verify(_response(assertions=""))


class _SpendsAnything:
    """A replay-ledger stand-in that would spend ANY id (even a blank one): with it, only verify's own guard
    can refuse an id-less assertion (the real ledger's blank-id refusal is pinned separately below)."""

    def try_spend(self, *_a, **_k):
        return True


def test_an_assertion_without_id_is_refused_by_its_own_guard():
    # test_assertion_without_id_refused is refused by the signature binding (no id is attested); here the enveloping
    # Response IS signed and the ledger spends anything, so only the no-ID guard stands.
    with_id = _assertion()
    no_id = _response(assertions=with_id.replace(' ID="a1"', "", 1))
    with pytest.raises(SamlError, match="has no ID"):
        _verify(no_id, signed=("r1",), ledger=_SpendsAnything())
    # isolation control: the same assertion WITH its id verifies under the same signature and ledger
    assert _verify(_response(assertions=with_id), signed=("r1",), ledger=_SpendsAnything()).name_id == "user@acme"


@pytest.mark.parametrize("attested", ["attacker-a1-wrapper", ["a1"]], ids=["str", "list"])
def test_a_verifier_answer_that_is_not_a_set_is_refused(attested):
    # a str answer would turn `assertion_id in signed_ids` into a SUBSTRING test ('a1' in 'attacker-a1-wrapper')
    with pytest.raises(SamlError, match="non-set"):
        saml.verify_saml_response(_response(), config=CFG, now=NOW, replay_ledger=_led(),
                                  sig_verifier=lambda b, c: attested)


def _rooted(tag: str) -> bytes:
    return (f'<samlp:{tag} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="w1">'
            f'{_assertion()}</samlp:{tag}>').encode()


def test_a_signature_over_a_root_that_is_not_a_response_does_not_bind():
    with pytest.raises(SamlError, match="no valid signature binds"):
        _verify(_rooted("ArtifactResponse"), signed=("w1",))
    # isolation control: the identical body under a <samlp:Response> root binds through that root's signature
    assert _verify(_rooted("Response"), signed=("w1",)).name_id == "user@acme"


def test_an_attested_empty_id_never_binds_an_id_less_response():
    no_root_id = _response().replace(b' ID="r1"', b"", 1)
    with pytest.raises(SamlError, match="no valid signature binds"):
        _verify(no_root_id, signed=("",))
    # isolation control: the same id-less Response verifies once the assertion's own id is attested
    assert _verify(no_root_id, signed=("a1",)).name_id == "user@acme"


# --- XML hardening ----------------------------------------------------------------------------------

def test_doctype_refused():
    xml = (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "x">]>'
           b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>')
    with pytest.raises(SamlError):
        _verify(xml)


def test_billion_laughs_refused():
    xml = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
           b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">&lol2;</samlp:Response>')
    with pytest.raises(SamlError):
        _verify(xml)


def test_external_entity_xxe_refused():
    xml = (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ext SYSTEM "file:///etc/passwd">]>'
           b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">&ext;</samlp:Response>')
    with pytest.raises(SamlError):
        _verify(xml)


def test_oversize_and_empty_refused():
    with pytest.raises(SamlError):
        saml._parse_hardened(b"x" * (saml._MAX_SAML_BYTES + 1))
    with pytest.raises(SamlError):
        saml._parse_hardened(b"")


@pytest.mark.parametrize("doctype,nameid", [
    ('<!DOCTYPE samlp:Response [<!ENTITY who "user@acme">]>', "&who;"),   # an internal entity supplies the identity
    ("<!DOCTYPE samlp:Response>", "user@acme"),                           # a bare DOCTYPE, no entity at all
], ids=["internal-entity", "bare-doctype"])
def test_a_doctype_on_an_otherwise_valid_response_is_refused_by_the_dtd_guard(doctype, nameid):
    # the DTD tests above carry no assertion (and the XXE one an undefined external entity), so without the
    # parser's DOCTYPE refusal they are still refused — by `_single_assertion` / the parser. This Response is otherwise
    # valid.
    xml = _response(nameid=nameid).replace(b'<?xml version="1.0"?>', b'<?xml version="1.0"?>' + doctype.encode(), 1)
    with pytest.raises(SamlError, match="DOCTYPE"):
        _verify(xml)
    # isolation control: the same Response without the DTD verifies
    assert _verify(_response()).name_id == "user@acme"


@pytest.mark.parametrize("encoding", ["x-no-such-codec", "shift_jis"], ids=["unknown-codec", "multi-byte-codec"])
def test_an_undecodable_encoding_declaration_is_a_clean_saml_refusal(encoding):
    # an otherwise-valid Response whose XML declaration names an encoding expat cannot decode: the refusal is a
    # SamlError like every other, never the codec's LookupError / ValueError escaping the verifier (the sign-in tail
    # counts and audits a refused verification on a SamlError — `test_sso_edge` pins that end to end)
    xml = _response().replace(b'<?xml version="1.0"?>', f'<?xml version="1.0" encoding="{encoding}"?>'.encode(), 1)
    with pytest.raises(SamlError, match="not well-formed"):
        _verify(xml)
    # isolation control: the same Response under its plain declaration verifies
    assert _verify(_response()).name_id == "user@acme"


def _shape(el):
    return (el.tag, list(el.attrib.items()), el.text, el.tail, [_shape(c) for c in el])


_MIXED = ('<r xmlns="urn:d" xmlns:p="urn:p" xmlns:q="urn:q" xml:lang="en" p:k="1" plain="v">'
          '  lead &#x41;&amp;&lt;&gt;&quot;&apos; <![CDATA[<raw> & ]]>café'
          '<p:c q:z="2">in<!-- a comment -->side</p:c>tail<?pi data?>more<e/>\n'
          '<q:n>deep<x>y</x>z</q:n></r>')


@pytest.mark.parametrize("doc", [
    _response(),
    _MIXED.encode("utf-8"),
    ('<?xml version="1.0" encoding="UTF-16"?>' + _MIXED).encode("utf-16"),
    b'<?xml version="1.0" encoding="ISO-8859-1"?><r a="caf\xe9">\xe9t\xe9</r>',
], ids=["saml-response", "mixed-utf8", "mixed-utf16", "latin1"])
def test_the_hardened_parse_builds_exactly_the_tree_elementtree_builds(doc):
    # the DTD refusal lives in the ONE parse that builds the tree; that tree must be exactly ElementTree's (the
    # structural / XSW checks read it): namespaced names, attributes in order, text / tail around comments, PIs,
    # CDATA and character references, and every encoding expat decodes
    assert _shape(saml._parse_hardened(doc)) == _shape(ET.fromstring(doc))


def _padded(total: int) -> bytes:
    """A valid Response grown to exactly `total` bytes by an inert XML comment."""
    base = _response()
    pad = total - len(base) - len(b"<!---->")
    return base.replace(b"</samlp:Response>", b"<!--" + b"x" * pad + b"--></samlp:Response>", 1)


def test_an_oversize_but_otherwise_valid_response_is_refused_by_the_size_cap():
    # test_oversize_and_empty_refused's oversize input is not XML at all (the parser refuses it anyway)
    with pytest.raises(SamlError, match="size cap"):
        _verify(_padded(saml._MAX_SAML_BYTES + 1))
    # isolation control: one byte less — exactly at the cap — the same Response verifies
    assert _verify(_padded(saml._MAX_SAML_BYTES)).name_id == "user@acme"


def test_malformed_xml_refused():
    with pytest.raises(SamlError):
        _verify(b"<not-closed>")


# --- org-scoping: issuer / audience / recipient / destination --------------------------------------

def test_wrong_issuer_refused():
    with pytest.raises(SamlError):
        _verify(_response(issuer="https://evil-idp"))


def test_cross_org_audience_refused():
    # an assertion minted for another org's SP entity id must not verify for acme (org-scoping).
    with pytest.raises(SamlError):
        _verify(_response(aud="https://sp.vigil/other"))


def test_wrong_recipient_refused():
    with pytest.raises(SamlError):
        _verify(_response(rcpt="https://evil/acs"))


def test_wrong_destination_refused():
    with pytest.raises(SamlError):
        _verify(_response(dest="https://evil/acs"))


# --- time windows -----------------------------------------------------------------------------------

def test_expired_refused():
    with pytest.raises(SamlError):
        _verify(_response(), now=EXPIRED)


def test_not_yet_valid_refused():
    with pytest.raises(SamlError):
        _verify(_response(), now=TOO_EARLY)


def test_missing_not_on_or_after_refused():
    a = ('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">'
         '<saml:Issuer>https://idp.example</saml:Issuer>'
         '<saml:Subject><saml:NameID>u</saml:NameID><saml:SubjectConfirmation>'
         '<saml:SubjectConfirmationData Recipient="https://app.vigil/acs/acme"/></saml:SubjectConfirmation></saml:Subject>'
         '<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.vigil/acme</saml:Audience>'
         '</saml:AudienceRestriction></saml:Conditions></saml:Assertion>')
    with pytest.raises(SamlError):
        _verify(_response(assertions=a))


LATER = "2001-09-20T00:00:00Z"                              # well after EXPIRED


@pytest.mark.parametrize("still_valid,guard", [
    ("scd_nooa", "Conditions NotOnOrAfter has passed"),
    ("cond_nooa", "SubjectConfirmationData NotOnOrAfter has passed"),
], ids=["conditions-expired", "subject-confirmation-expired"])
def test_each_not_on_or_after_bound_refuses_on_its_own(still_valid, guard):
    # test_expired_refused expires BOTH bounds, so either guard masks the other's removal; here only one has passed
    with pytest.raises(SamlError, match=guard):
        _verify(_response(**{still_valid: LATER}), now=EXPIRED)
    # isolation control: with both bounds LATER the same assertion verifies at the same instant
    assert _verify(_response(cond_nooa=LATER, scd_nooa=LATER), now=EXPIRED).name_id == "user@acme"


@pytest.mark.parametrize("missing,guard", [
    ("cond_nooa", "Conditions/NotOnOrAfter is missing"),
    ("scd_nooa", "SubjectConfirmationData/NotOnOrAfter is missing"),
], ids=["conditions", "subject-confirmation"])
def test_each_not_on_or_after_is_required_on_its_own(missing, guard):
    # test_missing_not_on_or_after_refused omits BOTH; here exactly one is absent (the control below has both)
    with pytest.raises(SamlError, match=guard):
        _verify(_response(**{missing: ""}))
    assert _verify(_response()).name_id == "user@acme"


def test_clock_skew_tolerated():
    # just-expired within skew (60s): NOW == nooa + 30 should still pass.
    import datetime
    nooa_epoch = datetime.datetime(2001, 9, 14, tzinfo=datetime.timezone.utc).timestamp()
    assert _verify(_response(), now=nooa_epoch + 30).name_id == "user@acme"
    with pytest.raises(SamlError):                           # beyond skew → refused
        _verify(_response(), now=nooa_epoch + 120)


# --- replay -----------------------------------------------------------------------------------------

def test_replay_refused():
    led = _led()
    assert _verify(_response(), ledger=led).name_id == "user@acme"
    with pytest.raises(SamlError):
        _verify(_response(), ledger=led)                     # same assertion id, second time → replay


def test_distinct_assertion_ids_both_accepted():
    led = _led()
    assert _verify(_response(aid="a1"), signed=("a1",), ledger=led).name_id == "user@acme"
    assert _verify(_response(aid="a2"), signed=("a2",), ledger=led).name_id == "user@acme"


def test_the_replay_ledger_never_spends_a_blank_id(tmp_path):
    led = saml.SamlReplayLedger(tmp_path / "replay")
    for blank in ("", "   ", None):
        assert led.try_spend(blank, 1e12, now=NOW) is False
    assert not (tmp_path / "replay").exists() or not any((tmp_path / "replay").iterdir())   # nothing was spent
    assert led.try_spend("a1", 1e12, now=NOW) is True and led.try_spend("a1", 1e12, now=NOW) is False   # control


def test_the_replay_ledger_is_bounded(tmp_path):
    led = saml.SamlReplayLedger(tmp_path / "replay", max_outstanding=2)
    assert led.try_spend("a1", NOW + 60, now=NOW) and led.try_spend("a2", NOW + 60, now=NOW)
    with pytest.raises(SamlError, match="capacity"):
        led.try_spend("a3", NOW + 60, now=NOW)
    # once the spent ids are past NotOnOrAfter (+ grace) they are reaped, and there is room again
    assert led.try_spend("a3", NOW + 60, now=NOW + 60 + led._GRACE + 1)


# the NotOnOrAfter `_assertion` stamps by default (2001-09-14T00:00:00Z), as epoch seconds
NOOA = 1_000_425_600.0
_GRACE = int(saml.SamlReplayLedger._GRACE)


@pytest.mark.parametrize("skew", [0, 60, _GRACE, _GRACE + 1, saml._MAX_CLOCK_SKEW_SECONDS],
                         ids=lambda v: f"skew-{v}")
def test_one_assertion_never_verifies_twice_at_any_allowed_skew(skew):
    # The time guards accept an assertion until NotOnOrAfter + skew, so its spent marker must outlive exactly that
    # instant: a ledger that reaped it at NotOnOrAfter + a fixed grace would re-accept it once skew > grace.
    cfg = dataclasses.replace(CFG, clock_skew_seconds=skew)
    led = _led()
    last = NOOA + skew - 0.5                                     # inside the window's final second (still accepted)
    assert _verify(_response(), now=NOW, cfg=cfg, ledger=led).assertion_id == "a1"
    for t in sorted({NOW + 1, NOOA - 1, NOOA, NOOA + skew // 2, NOOA + _GRACE + 1, last, NOOA + skew,
                     NOOA + skew + _GRACE + 1}):
        with pytest.raises(SamlError, match="replay refused" if t <= last else "NotOnOrAfter has passed"):
            _verify(_response(), now=t, cfg=cfg, ledger=led)
    # same-shape control: a FRESH assertion id still verifies at the last instant, so every refusal above inside the
    # window was the replay ledger's
    assert _verify(_response(aid="a2"), signed=("a2",), now=last, cfg=cfg, ledger=led).assertion_id == "a2"


_MAX_SKEW = saml._MAX_CLOCK_SKEW_SECONDS


@pytest.mark.parametrize("first,then", [(0, _MAX_SKEW), (60, _MAX_SKEW), (100, _MAX_SKEW), (60, 60),
                                        (_MAX_SKEW, 0)], ids=lambda v: f"{v}")
def test_one_assertion_never_verifies_twice_when_the_skew_changes_between_presentations(first, then):
    # The owner may re-sign the config with a LARGER skew (still within the bound) after an assertion was spent. The
    # marker must therefore outlive every window an allowed skew could open — not just the one in force at the first
    # spend, else it is reaped at NotOnOrAfter + first + grace while the new skew still accepts the assertion.
    led = _led()
    assert _verify(_response(), now=NOW, cfg=dataclasses.replace(CFG, clock_skew_seconds=first),
                   ledger=led).assertion_id == "a1"
    cfg = dataclasses.replace(CFG, clock_skew_seconds=then)
    last = NOOA + then - 0.5                                     # the replayed config's window's final second
    for t in sorted({NOOA, NOOA + first + _GRACE + 1, NOOA + (first + then) / 2, last, NOOA + then,
                     NOOA + _MAX_SKEW + _GRACE + 1}):
        with pytest.raises(SamlError, match="replay refused" if t <= last else "NotOnOrAfter has passed"):
            _verify(_response(), now=t, cfg=cfg, ledger=led)
    # same-shape control: a FRESH assertion id verifies at that last instant under the new skew
    assert _verify(_response(aid="a2"), signed=("a2",), now=last, cfg=cfg, ledger=led).assertion_id == "a2"


def test_the_verifier_refuses_a_clock_skew_over_its_bound():
    over = dataclasses.replace(CFG, clock_skew_seconds=saml._MAX_CLOCK_SKEW_SECONDS + 1)
    with pytest.raises(SamlError, match="clock skew exceeds"):
        _verify(_response(), cfg=over)
    at_bound = dataclasses.replace(CFG, clock_skew_seconds=saml._MAX_CLOCK_SKEW_SECONDS)
    assert _verify(_response(), cfg=at_bound).name_id == "user@acme"     # control: the bound itself is allowed


def test_the_skew_bound_is_in_lockstep_with_the_config():
    from sigil.governor import sso_config
    assert saml._MAX_CLOCK_SKEW_SECONDS == sso_config.MAX_CLOCK_SKEW_SECONDS


# --- missing structure ------------------------------------------------------------------------------

def test_missing_subject_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_subject=False))


def test_missing_nameid_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_nameid=False))


def test_missing_conditions_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_conditions=False))


def test_missing_scd_refused():
    with pytest.raises(SamlError):
        _verify(_response(with_scd=False))


# --- the signature backend FAILS CLOSED without a vetted library -----------------------------------

def test_default_backend_fails_closed_without_signxml():
    # In this environment signxml is not installed, so the shipped backend returns NO verified ids ⇒ refused.
    with pytest.raises(SamlError):
        saml.verify_saml_response(_response(), config=CFG, now=NOW, replay_ledger=_led())


def test_protocol_mismatch_refused():
    oidc_cfg = SsoConfig(org_id="acme", protocol="oidc", issued_at=1.0, state="active")
    with pytest.raises(SamlError):
        _verify(_response(), cfg=oidc_cfg)


def test_config_without_cert_refused():
    nocert = SsoConfig(org_id="acme", protocol="saml", issued_at=1.0, state="active", idp_certs_pem=(),
                       sp_entity_id="https://sp.vigil/acme", acs_url="https://app.vigil/acs/acme")
    with pytest.raises(SamlError):
        _verify(_response(), cfg=nocert)


def test_a_non_saml_config_is_refused_even_when_it_carries_saml_material():
    # test_protocol_mismatch_refused's OIDC config carries no IdP cert, so the cert guard masks this one
    with pytest.raises(SamlError, match="no active SAML config"):
        _verify(_response(), cfg=dataclasses.replace(CFG, protocol="oidc"))


def test_a_config_without_a_cert_is_refused_even_by_a_verifier_that_attests():
    # test_config_without_cert_refused's config also lacks the IdP entity id, so the issuer guard masks this one
    with pytest.raises(SamlError, match="no IdP signing certificate"):
        _verify(_response(), cfg=dataclasses.replace(CFG, idp_certs_pem=()))


# --- FATAL-2 ----------------------------------------------------------------------------------------

def test_fatal2_no_framework_import():
    import sigil.ui.saml  # noqa: F401
    assert "framework" not in sys.modules and "strix" not in sys.modules
