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


_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


def _assertion(aid="a1", aud="https://sp.vigil/acme", rcpt="https://app.vigil/acs/acme",
               nooa="2001-09-14T00:00:00Z", nb="2001-09-13T00:00:00Z", issuer="https://idp.example",
               nameid="user@acme", groups=("admins",), with_subject=True, with_conditions=True,
               with_scd=True, with_nameid=True, cond_nooa=None, scd_nooa=None, cm=_BEARER, restrictions=None):
    # `cond_nooa` / `scd_nooa` override ONE NotOnOrAfter bound (None = `nooa`; "" = omit the attribute), so a test
    # can make exactly one of the two time guards the only one that refuses.
    cond_nooa = nooa if cond_nooa is None else cond_nooa
    scd_nooa = nooa if scd_nooa is None else scd_nooa
    grp = "".join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)
    subj = ""
    if with_subject:
        nid = f'<saml:NameID>{nameid}</saml:NameID>' if with_nameid else ''
        scd_attr = f' NotOnOrAfter="{scd_nooa}"' if scd_nooa else ''
        scd = (f'<saml:SubjectConfirmation Method="{cm}">'
               f'<saml:SubjectConfirmationData Recipient="{rcpt}"'
               f'{scd_attr}/></saml:SubjectConfirmation>') if with_scd else ''
        subj = f'<saml:Subject>{nid}{scd}</saml:Subject>'
    cond = ""
    if with_conditions:
        nbattr = f' NotBefore="{nb}"' if nb else ''
        cond_attr = f' NotOnOrAfter="{cond_nooa}"' if cond_nooa else ''
        # `restrictions` = the AudienceRestriction elements, each a tuple of its Audience values (None = one, `aud`)
        restr = "".join('<saml:AudienceRestriction>' + "".join(f'<saml:Audience>{x}</saml:Audience>' for x in r)
                        + '</saml:AudienceRestriction>' for r in (restrictions or ((aud,),)))
        cond = f'<saml:Conditions{nbattr}{cond_attr}>{restr}</saml:Conditions>'
    return (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}">'
            f'<saml:Issuer>{issuer}</saml:Issuer>{subj}{cond}'
            f'<saml:AttributeStatement><saml:Attribute Name="groups">{grp}</saml:Attribute>'
            f'</saml:AttributeStatement></saml:Assertion>')


_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"


def _response(assertions=None, dest="https://app.vigil/acs/acme", rid="r1", status_code=_SUCCESS, **kw):
    # `status_code` = the top-level Response StatusCode Value (None = omit the Status element)
    body = assertions if assertions is not None else _assertion(**kw)
    status = (f'<samlp:Status><samlp:StatusCode Value="{status_code}"/></samlp:Status>'
              if status_code is not None else '')
    destattr = f' Destination="{dest}"' if dest is not None else ''
    return (f'<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            f'ID="{rid}"{destattr}>{status}{body}</samlp:Response>').encode()


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
            f'<samlp:Status><samlp:StatusCode Value="{_SUCCESS}"/></samlp:Status>{_assertion()}</samlp:{tag}>').encode()


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
         '<saml:Subject><saml:NameID>u</saml:NameID>'
         '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
         '<saml:SubjectConfirmationData Recipient="https://app.vigil/acs/acme"/></saml:SubjectConfirmation></saml:Subject>'
         '<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.vigil/acme</saml:Audience>'
         '</saml:AudienceRestriction></saml:Conditions></saml:Assertion>')
    with pytest.raises(SamlError):
        _verify(_response(assertions=a))


LATER = "2001-09-15T00:00:00Z"            # after EXPIRED (+ skew), within the bounded assertion lifetime of it


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


def test_one_org_can_neither_fill_nor_refuse_another_orgs_replay_ledger(tmp_path):
    # ONE ledger directory serves every org, partitioned per org: "evil" fills ITS partition with ordinary
    # successful sign-ins (cap 2 here, 65536 in production) and is refused at capacity, while "victim" still
    # verifies against the same directory — and a replay is still refused inside each org's own partition.
    led = saml.SamlReplayLedger(tmp_path / "replay", max_outstanding=2)
    evil, victim = dataclasses.replace(CFG, org_id="evil"), dataclasses.replace(CFG, org_id="victim")
    for aid in ("e1", "e2"):
        assert _verify(_response(aid=aid), signed=(aid,), cfg=evil, ledger=led).assertion_id == aid
    with pytest.raises(SamlError, match="capacity"):
        _verify(_response(aid="e3"), signed=("e3",), cfg=evil, ledger=led)
    assert _verify(_response(aid="v1"), signed=("v1",), cfg=victim, ledger=led).assertion_id == "v1"
    with pytest.raises(SamlError, match="replay refused"):
        _verify(_response(aid="v1"), signed=("v1",), cfg=victim, ledger=led)
    with pytest.raises(SamlError):                               # the full partition refuses its own replay too
        _verify(_response(aid="e2"), signed=("e2",), cfg=evil, ledger=led)
    # the partitions are named by a hash of the org id, never the id itself
    assert sorted(p.name for p in (tmp_path / "replay").iterdir()) == sorted(led._partition(o).name
                                                                             for o in ("evil", "victim"))
    assert all("evil" not in p.name and "victim" not in p.name for p in (tmp_path / "replay").iterdir())


def test_a_concurrent_sweep_never_reaps_a_marker_another_spend_is_still_writing(tmp_path, monkeypatch):
    # Spender A is paused right after it created its file and before it wrote anything; spender B's spend (and so its
    # sweep) runs inside that window. A's marker must survive it: a sweep that read A's still-empty marker as
    # garbage and reaped it let A's assertion be spent — and verified — a second time.
    import os
    import threading
    led = saml.SamlReplayLedger(tmp_path / "replay")
    created, resume = threading.Event(), threading.Event()
    real_open = os.open

    def pausing_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if threading.current_thread().name == "spender-A" and flags & os.O_CREAT and not created.is_set():
            created.set()
            resume.wait(10)
        return fd
    monkeypatch.setattr(saml.os, "open", pausing_open)
    out: dict = {}
    a = threading.Thread(name="spender-A", target=lambda: out.update(a=led.try_spend("A", NOW + 300, now=NOW)))
    a.start()
    assert created.wait(10)
    out["b"] = led.try_spend("B", NOW + 300, now=NOW)            # B sweeps while A's file exists, still unwritten
    resume.set()
    a.join(10)
    assert out == {"a": True, "b": True}
    assert led.try_spend("A", NOW + 300, now=NOW + 1) is False     # A's marker survived: its replay is refused
    assert led.try_spend("B", NOW + 300, now=NOW + 1) is False
    assert sorted(p.name for p in led._partition("").iterdir()) == sorted(led._marker(led._partition(""), x).name
                                                                          for x in ("A", "B"))   # no temp left


def test_an_in_flight_temp_file_never_counts_and_is_reaped_only_once_stale(tmp_path):
    import os
    import time
    led = saml.SamlReplayLedger(tmp_path / "replay", max_outstanding=2)
    assert led.try_spend("a1", NOW + 60, now=NOW)
    part = led._partition("")
    stale, fresh = part / (led._TMP_PREFIX + "0" * 32), part / (led._TMP_PREFIX + "1" * 32)
    stale.write_text("")
    fresh.write_text("")
    old = time.time() - led._TMP_STALE - 60
    os.utime(stale, (old, old))
    assert led.try_spend("a2", NOW + 60, now=NOW)                # two temp files beside a1 never fill a cap of 2
    assert not stale.exists() and fresh.exists()                 # a crashed spend's stale leftover is reaped
    assert led._marker(part, "a1").exists() and led._marker(part, "a2").exists()   # the markers are untouched


def _iso(epoch: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_LIFETIME = saml._MAX_ASSERTION_LIFETIME_SECONDS


@pytest.mark.parametrize("cond_far,scd_far", [(True, True), (False, True), (True, False)],
                         ids=["both", "subject-confirmation", "conditions"])
def test_an_assertion_deliverable_beyond_the_bounded_lifetime_is_refused(cond_far, scd_far):
    # The IdP chooses NotOnOrAfter and the replay marker must outlive the EARLIEST one, so an assertion still
    # deliverable more than the bounded lifetime from now is refused — only the earliest bound matters (a far
    # Conditions window beside a short SubjectConfirmation, the common IdP shape, is fine).
    far, near = _iso(NOW + _LIFETIME + 1), _iso(NOW + 300)
    xml = _response(cond_nooa=far if cond_far else near, scd_nooa=far if scd_far else near)
    if cond_far and scd_far:
        with pytest.raises(SamlError, match="bounded assertion lifetime"):
            _verify(xml)
        # same-shape control: exactly AT the bound it verifies
        at = _iso(NOW + _LIFETIME)
        assert _verify(_response(cond_nooa=at, scd_nooa=at)).name_id == "user@acme"
    else:
        assert _verify(xml).name_id == "user@acme"


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

@pytest.mark.parametrize("pad", [" ", "　", " ", "\u0085", " ", " ", "\t", "\n"],
                         ids=lambda p: f"U+{ord(p):04X}")
def test_a_nameid_padded_with_whitespace_is_refused_never_trimmed(pad):
    # A NameID that differs from a member's only by surrounding whitespace (a no-break / ideographic / em space, a
    # line separator, ...) is a DIFFERENT IdP identifier that merely renders like the member's: refused, never
    # trimmed into it. A whitespace-only NameID is no identity at all.
    for padded in (pad + "user@acme", "user@acme" + pad):
        with pytest.raises(SamlError, match="begins or ends with whitespace"):
            _verify(_response(nameid=padded))
    with pytest.raises(SamlError, match="has no NameID"):
        _verify(_response(nameid=pad * 3))
    assert _verify(_response(nameid="user@acme")).name_id == "user@acme"         # same-shape control


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


def test_the_bounded_assertion_lifetime_is_twenty_four_hours():
    # the bound is pinned by its VALUE (the lifetime tests above read the constant, so they hold at any value): an
    # assertion deliverable 24 h + 1 s from now is refused, one deliverable exactly 24 h from now verifies
    assert saml._MAX_ASSERTION_LIFETIME_SECONDS == 86_400
    far = _iso(NOW + 86_400 + 1)
    with pytest.raises(SamlError, match="bounded assertion lifetime"):
        _verify(_response(cond_nooa=far, scd_nooa=far))
    at = _iso(NOW + 86_400)
    assert _verify(_response(cond_nooa=at, scd_nooa=at)).name_id == "user@acme"


# --- the Response status, EACH audience restriction, the bearer confirmation ---------------------------------------

@pytest.mark.parametrize("code", ["urn:oasis:names:tc:SAML:2.0:status:Responder",
                                  "urn:oasis:names:tc:SAML:2.0:status:Requester",
                                  "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", "", None,
                                  "urn:x:status:Success", " urn:oasis:names:tc:SAML:2.0:status:Success "],
                         ids=["responder", "requester", "authn-failed", "blank", "no-status", "suffix-lookalike",
                              "padded"])
def test_a_response_whose_status_is_not_success_is_refused(code):
    # a signed assertion wrapped in a Response that reports a non-Success status (or none) is not a sign-in
    with pytest.raises(SamlError, match="status is not Success"):
        _verify(_response(status_code=code))
    # same-shape control: the identical document with a Success status verifies
    assert _verify(_response()).name_id == "user@acme"


def test_only_the_top_level_status_code_is_read():
    # a nested (second-level) Success under a top-level Responder is still a failed sign-in
    body = _assertion()
    nested = ('<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">'
              '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:StatusCode>'
              '</samlp:Status>')
    xml = (f'<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
           f'ID="r1" Destination="https://app.vigil/acs/acme">{nested}{body}</samlp:Response>').encode()
    with pytest.raises(SamlError, match="status is not Success"):
        _verify(xml)


@pytest.mark.parametrize("restrictions", [(("https://other-sp",), ("https://sp.vigil/acme",)),
                                          (("https://sp.vigil/acme",), ("https://other-sp",)),
                                          (("https://sp.vigil/acme",), ())],
                         ids=["first-names-another-sp", "second-names-another-sp", "second-is-empty"])
def test_our_sp_must_be_in_each_audience_restriction(restrictions):
    # SAML core 2.5.1.4: EVERY AudienceRestriction must be met — one that does not name our SP refuses the assertion
    with pytest.raises(SamlError, match="every AudienceRestriction"):
        _verify(_response(restrictions=restrictions))
    # same-shape control: two restrictions that BOTH name our SP (one among others) verify
    ok = (("https://other-sp", "https://sp.vigil/acme"), ("https://sp.vigil/acme",))
    assert _verify(_response(restrictions=ok)).name_id == "user@acme"


def test_no_audience_restriction_at_all_is_refused():
    a = _assertion().replace(
        '<saml:AudienceRestriction><saml:Audience>https://sp.vigil/acme</saml:Audience></saml:AudienceRestriction>', '')
    with pytest.raises(SamlError, match="every AudienceRestriction"):
        _verify(_response(assertions=a))


@pytest.mark.parametrize("cm", ["urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
                                "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches", "", "urn:x:bearer",
                                "URN:OASIS:NAMES:TC:SAML:2.0:CM:BEARER", " urn:oasis:names:tc:SAML:2.0:cm:bearer "],
                         ids=["holder-of-key", "sender-vouches", "blank", "lookalike", "upper-case", "padded"])
def test_only_a_bearer_subject_confirmation_is_accepted(cm):
    with pytest.raises(SamlError, match="no bearer <SubjectConfirmation>"):
        _verify(_response(cm=cm))
    assert _verify(_response()).name_id == "user@acme"          # same-shape control: the bearer method verifies


def test_the_recipient_is_read_from_the_bearer_confirmation_not_another_one():
    # a holder-of-key confirmation naming our ACS beside a bearer one naming another ACS: the bearer one decides
    hok = ('<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key">'
           '<saml:SubjectConfirmationData Recipient="https://app.vigil/acs/acme" NotOnOrAfter="2001-09-14T00:00:00Z"/>'
           '</saml:SubjectConfirmation>')
    a = _assertion(rcpt="https://elsewhere/acs").replace("</saml:NameID>", "</saml:NameID>" + hok, 1)
    with pytest.raises(SamlError, match="Recipient does not match"):
        _verify(_response(assertions=a))
    a = _assertion().replace("</saml:NameID>", "</saml:NameID>" + hok.replace("acs/acme", "acs/other"), 1)
    assert _verify(_response(assertions=a)).name_id == "user@acme"   # control: the bearer one names our ACS


# --- the time guards at their exact boundaries (skew 60 s; NOW = 2001-09-13T16:53:20Z) -----------------------------

def test_an_assertion_not_yet_valid_beyond_the_skew_is_refused():
    """Conditions NotBefore: refused only once it lies MORE than the skew after now."""
    with pytest.raises(SamlError, match="not yet valid"):
        _verify(_response(nb=_iso(NOW + 61)))
    assert _verify(_response(nb=_iso(NOW + 60))).name_id == "user@acme"           # exactly at the skew: valid
    assert _verify(_response(nb=_iso(NOW - 600))).name_id == "user@acme"


def test_the_subject_confirmation_not_on_or_after_boundary_is_exact():
    """SubjectConfirmationData NotOnOrAfter: refused from (NotOnOrAfter + skew) on, accepted one second before —
    with the Conditions window still open, so this guard alone decides."""
    later = "2001-09-14T00:00:00Z"
    with pytest.raises(SamlError, match="SubjectConfirmationData NotOnOrAfter has passed"):
        _verify(_response(scd_nooa=_iso(NOW - 60), cond_nooa=later))
    assert _verify(_response(scd_nooa=_iso(NOW - 59), cond_nooa=later)).name_id == "user@acme"
    with pytest.raises(SamlError, match="SubjectConfirmationData NotOnOrAfter has passed"):
        _verify(_response(scd_nooa=_iso(NOW - 200), cond_nooa=later))
