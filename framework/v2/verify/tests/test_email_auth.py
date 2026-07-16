"""verify.email_auth — the email-auth-posture oracle (FORGE Domain 10, the first FORGE-built stream).

Pins the domain charter's contract:
  * FIRES on a PUBLISHED policy that provably permits spoofing — no DMARC (observed), DMARC ``p=none``,
    or SPF ``+all``.
  * SILENT on the mandatory benign twin — a hardened domain (``p=reject``/``p=quarantine``, SPF ``-all``).
  * REFUSES rather than asserts: an unobserved absence, an unparseable record, and ``spf_missing`` (a
    gating chain — DKIM+DMARC may still protect the domain) never fire.
  * Held OUT of the frozen fallback so ``make gate`` stays byte-identical.
  * A confirmed finding emits a REAL signed PCF v0.1 certificate that re-verifies offline.
"""

from __future__ import annotations

import pytest

from framework.v2.verify.email_auth import (
    confirm_dns_policy,
    confirm_email_auth_posture,
    ingest_dns_policy,
)
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import _decode_txt_escapes, _resolve_txt_record
from framework.v2.verify.verifier import _ALL_ORACLES
from framework.v2.sensors.email_auth import parse_email_auth_export

_HARDENED_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@gov.example; pct=100"
_HARDENED_SPF = "v=spf1 include:_spf.gov.example -all"


# ---- FIRES: a published policy that provably permits spoofing ----

def test_no_dmarc_on_an_organizational_domain_is_a_fact():
    # an ORG domain has no parent to inherit from, so an observed absence really is "no policy"
    r = confirm_email_auth_posture({"rule": "dmarc_missing", "domain": "gov.example",
                                    "dmarc_observed": True, "is_org_domain": True})
    assert r.confirmed
    assert any(s.kind == OracleKind.EMAIL_AUTH_POSTURE and s.fired for s in r.signals)


# ---- RED-PEN BLOCK-1 regression: the RFC 7489 §6.6.3 inheritance chain ----
# The benign twin MUST be parameterized over DOMAIN SHAPE (org vs subdomain), not only record content —
# that is the axis on which the original rule was unsound (it fired on a hardened subdomain).

_SUB = {"rule": "dmarc_missing", "domain": "mail.gov.example", "dmarc_observed": True,
        "org_domain": "gov.example", "org_dmarc_observed": True}


@pytest.mark.parametrize("org_record", ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine",
                                        "v=DMARC1; p=reject; pct=100; rua=mailto:d@gov.example"])
def test_a_subdomain_inheriting_an_enforcing_org_policy_does_not_fire(org_record):
    # THE cardinal case: a subdomain that correctly publishes nothing is FULLY protected by its org domain
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed


@pytest.mark.parametrize("org_record,why", [
    ("v=DMARC1; p=reject; sp=none", "sp= overrides p= FOR SUBDOMAINS (RFC 7489 §6.3)"),
    ("v=DMARC1; p=none", "the org policy itself is none"),
])
def test_a_subdomain_inheriting_a_non_enforcing_policy_is_a_fact(org_record, why):
    assert confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, why


def test_no_dmarc_anywhere_in_the_chain_is_a_fact():
    assert confirm_email_auth_posture(_SUB).confirmed   # org lookup observed, no org record either


def test_an_unresolved_inheritance_chain_refuses():
    # a subdomain whose org-domain policy was NOT retained/observed: absence proves NOTHING -> REFUSE
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "mail.gov.example", "dmarc_observed": True}).confirmed
    # …and an org record with no parseable policy is likewise unresolved
    assert not confirm_email_auth_posture(
        {**_SUB, "org_dmarc_record": "v=DMARC1; rua=mailto:x@y"}).confirmed


# ---- RED-PEN BLOCK-2 regression: attestations are STRICT (never bool()-coerced) ----

@pytest.mark.parametrize("bad", ["false", "no", "0", 0, 1, "true", "True", [], {}])
def test_a_non_true_observed_attestation_never_promotes(bad):
    # a truthy-but-not-True value must NOT launder into a fact — the coercion happened BEFORE minting, so
    # a laundered attestation would re-fire forever under signature.
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "g", "dmarc_observed": bad, "is_org_domain": True}).confirmed


@pytest.mark.parametrize("bad", ["false", "no", 0, 1, "true"])
def test_a_non_true_org_attestation_never_promotes(bad):
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "mail.gov.example", "dmarc_observed": True,
         "org_dmarc_observed": bad}).confirmed


def test_the_retained_certificate_cannot_carry_a_laundered_attestation():
    # the RETAINED context (what gets signed + re-fires forever) must not contain a coerced True
    from framework.v2.verify.email_auth import email_auth_context
    ctx = email_auth_context({"rule": "dmarc_missing", "domain": "g", "dmarc_observed": "false",
                              "is_org_domain": "true"})
    ctl = ctx["email_auth_control"]
    assert "dmarc_observed" not in ctl and "is_org_domain" not in ctl


def test_the_seam_is_total_on_a_non_mapping():
    for junk in ("str", 42, None, []):
        assert not confirm_email_auth_posture(junk).confirmed


# ---- RED-PEN BLOCK-4/5 regression: the RECORD-ENCODING axis ----
# A DNS TXT record is a QUOTED character-string on the wire (`dig +short` emits quotes) and RFC 1035
# §3.3.14 splits a long one into ADJACENT strings a resolver concatenates. Parsing the presentation form
# directly let a closing quote HIDE a protective `sp=` tag while leaving a permissive `p=` visible — the
# twin must therefore be parameterized over ENCODING, not only over record content and domain shape.

_PROTECTED_ORG = "v=DMARC1; p=none; sp=reject"      # org monitors its own mail, REJECTS subdomains
_EXPOSED_ORG = "v=DMARC1; p=reject; sp=none"        # org enforces its own mail, exempts subdomains


# What a real apex TXT set actually carries alongside a policy record — the cardinality axis.
_NEIGHBOUR = '"google-site-verification=Xy3pl0AcQ"'
_NEIGHBOUR2 = '"MS=ms94722371"'


def _faithful_encodings(record: str) -> list[tuple[str, str]]:
    """Generate the benign twin from the TXT input GRAMMAR — not from a hand-list of the forms the author
    already thought of.

    Three RED-PEN rounds each found the defect on the ONE axis the twin did not carry (record content ->
    domain shape -> character-string encoding -> record CARDINALITY). That is not bad luck: a twin built
    from the author's own model of the input space can only ever CONFIRM that model. So the axes here are
    the grammar's, not the author's — character-string SHAPE (a single string / adjacent strings a resolver
    concatenates), QUOTING (bare / quoted), zone-file SCAFFOLDING (none / RR header / `( )` continuation),
    and record CARDINALITY (alone / among the neighbour records a real apex carries, in either RRset order,
    which DNS does not promise to keep stable).

    Every form below FAITHFULLY encodes the same one policy record, so every one MUST reach the same
    verdict as the bare form. A form that reads a DIFFERENT policy, or silently drops a tag, is a defect."""
    head, _, tail = record.partition("; sp=")
    shapes = [("one string", f'"{record}"')]
    if tail:
        shapes.append(("adjacent strings", f'"{head};" " sp={tail}"'))   # RFC 1035 §3.3.14
    forms = [("bare", record)]
    for shape, quoted in shapes:
        forms += [
            (f"quoted (dig +short), {shape}", quoted),
            (f"zone-file RR header+ttl, {shape}", f"_dmarc.gov.example. 3600 IN TXT {quoted}"),
            (f"zone-file ( ) continuation, {shape}", f"_dmarc.gov.example. 3600 IN TXT (\n    {quoted}\n)"),
            (f"among neighbours, policy first, {shape}", f"{quoted}\n{_NEIGHBOUR}"),
            (f"among neighbours, policy last, {shape}", f"{_NEIGHBOUR}\n{quoted}"),
            (f"among 2 neighbours, {shape}", f"{_NEIGHBOUR}\n{quoted}\n{_NEIGHBOUR2}"),
        ]
    return forms


def _ambiguous_encodings(record: str) -> list[tuple[str, str]]:
    """Blobs that do NOT resolve to exactly one policy record. None of them may FIRE — a verdict read off a
    spliced or truncated record asserts a policy that NO record published. THE BLOCK-6 case: joining across
    record boundaries both DESTROYS a tag (unquoted `sp=reject` silently discarded -> a hardened org fires)
    and FABRICATES one (two DMARC records spliced -> a `p=` nobody wrote, its verdict decided by RRset
    order). Refusal is the only sound answer — for the exposed record exactly as much as the protected one,
    since the oracle cannot tell which it is holding until it has resolved the record."""
    head, _, tail = record.partition("; sp=")
    return [
        ("unquoted tail mixed among strings", f'"{head};" sp={tail}'),
        ("unquoted head mixed among strings", f'{head}; "sp={tail}"'),
        ("duplicate policy records", f'"{record}"\n"v=DMARC1; p=quarantine"'),
        ("duplicate policy records, reversed", f'"v=DMARC1; p=quarantine"\n"{record}"'),
        ("unbalanced quote", f'"{record}'),
        ("unbalanced zone-file paren", f'_dmarc.gov.example. 3600 IN TXT (\n    "{record}"'),
        # A record this cannot canonicalise must never be read as "the domain publishes no policy" —
        # selection failing is the SAME error class as a tag's value regex failing (BLOCK-4): the record is
        # right there in the evidence. Absence is asserted only from a producer that retained NOTHING.
        ("non-DNS quoting", f"'{record}'"),
        ("neighbours only, no policy record", f"{_NEIGHBOUR}\n{_NEIGHBOUR2}"),
    ]


@pytest.mark.parametrize("label,org_record", _faithful_encodings(_PROTECTED_ORG))
def test_a_protected_subdomain_never_fires_in_any_faithful_record_encoding(label, org_record):
    # THE BLOCK-4 case: in EVERY faithful wire encoding, an org `sp=reject` protects the subdomain -> no fact.
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, label


@pytest.mark.parametrize("label,org_record", _faithful_encodings(_EXPOSED_ORG))
def test_an_exposed_subdomain_still_fires_in_any_faithful_record_encoding(label, org_record):
    # …and normalisation must not silence the genuine weakness either (no safe-but-useless refusal).
    assert confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, label


_AMBIGUOUS = [(f"{label} / {'protected' if rec is _PROTECTED_ORG else 'exposed'}", blob)
              for rec in (_PROTECTED_ORG, _EXPOSED_ORG)
              for label, blob in _ambiguous_encodings(rec)]


@pytest.mark.parametrize("label,org_record", _AMBIGUOUS)
def test_an_unresolvable_record_set_never_fires(label, org_record):
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, label


# ---- RED-PEN round-4 residuals: refuse rather than mint a FALSE EVIDENCE SENTENCE ----
# None of these was a false FACT — each was self-correcting in direction (an invalid or empty record does
# leave the domain spoofable). They are fixed anyway, because a fired certificate that says "no DMARC
# record is published" about a domain that published one is an untrue claim inside signed text, and the
# signature makes it durable. Refusing costs a detection; overclaiming costs the certificate's meaning.

@pytest.mark.parametrize("label,org_record", [
    # an EMPTY record EXISTS — that is not "the producer retained nothing", the only thing absence may
    # be read from. (Reported as violating this module's own stated invariant. It did.)
    ("empty quoted record", '""'),
    ("empty zone-file record", '_dmarc.gov.example. 3600 IN TXT ""'),
    # RFC 1035 §3.3.14 faithfully concatenates what the publisher meant as two records, into one
    # syntactically invalid policy string. `p=` is then readable anywhere in it.
    ("two version tags spliced into one record", '"v=DMARC1; p=reject" "v=DMARC1; p=none"'),
])
def test_a_record_that_exists_but_carries_no_resolvable_policy_refuses(label, org_record):
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed, label


@pytest.mark.parametrize("ttl", ["3600", "1h", "1D", "1w", "1h30m"])
def test_bind_unit_suffixed_ttls_are_read_not_refused(ttl):
    # a legitimate zone-file export must not silently refuse (it failed safe, but a rule that quietly
    # does nothing on real input is the inertness the honest-ledger invariant exists to prevent).
    assert confirm_email_auth_posture(
        {**_SUB, "org_dmarc_record": f'_dmarc.gov.example. {ttl} IN TXT "{_EXPOSED_ORG}"'}).confirmed
    assert not confirm_email_auth_posture(
        {**_SUB, "org_dmarc_record": f'_dmarc.gov.example. {ttl} IN TXT "{_PROTECTED_ORG}"'}).confirmed


def test_a_tag_value_string_is_never_swallowed_as_zone_file_scaffolding():
    # `_ZONE_RR_HEADER_RE` is the ONLY unquoted content permitted before a record; an owner name cannot
    # contain `=`, so a tag-value string can never pose as one.
    assert not confirm_email_auth_posture(
        {**_SUB, "org_dmarc_record": 'sp=reject TXT "v=DMARC1; p=none"'}).confirmed


@pytest.mark.parametrize("sep", ["\n", "\r\n", "\r"])
def test_every_line_ending_separates_records(sep):
    # a lone CR (classic-Mac) must split records exactly as LF and CRLF do — if it does not, two records
    # splice into one and the splice decides the verdict.
    blob = f'"{_PROTECTED_ORG}"{sep}"v=DMARC1; p=quarantine"'
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": blob}).confirmed, sep


@pytest.mark.parametrize("org_record", [
    "v=DMARC1; p=none; sp=reject.",     # trailing dot — sp= present, value unparseable
    "v=DMARC1; p=none; sp=rejct",       # typo'd value
    "v=DMARC1; p=none; sp=",            # empty value
])
def test_an_unparseable_sp_tag_refuses_instead_of_falling_through_to_p(org_record):
    """The BLOCK-4 root cause: 'the sp= value regex did not match' must NEVER be read as 'there is no sp=
    tag'. A failed parse is not proof of absence — falling through to `p=` reads the WRONG tag and asserts
    the negative (the same error class as assuming a missing record means no policy). REFUSE."""
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org_record}).confirmed


@pytest.mark.parametrize("rule,field,record,want", [
    ("dmarc_none", "dmarc_record", '"v=DMARC1; p=none"', True),
    ("dmarc_none", "dmarc_record", '"v=DMARC1; p=reject"', False),
    ("dmarc_none", "dmarc_record", '"v=DMARC1;" " p=none"', True),
    ("spf_permissive", "spf_record", '"v=spf1 +all"', True),
    ("spf_permissive", "spf_record", '"v=spf1 -all"', False),
    ("spf_permissive", "spf_record", '"v=spf1 mx" " +all"', True),
])
def test_the_other_rules_read_the_wire_encoding_correctly(rule, field, record, want):
    assert confirm_email_auth_posture({"rule": rule, "domain": "g", field: record}).confirmed is want


# ---- RED-PEN LOW regression: contradictory / unauditable evidence refuses ----

def test_contradictory_org_evidence_refuses():
    # attested an ORG domain AND handed an org policy to inherit -> refuse, don't take the firing branch
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "g", "dmarc_observed": True, "is_org_domain": True,
         "org_dmarc_record": "v=DMARC1; p=reject"}).confirmed


# ---- Independent-sweep CRITICAL #2 (producer discards evidence): the contradiction guard must be
# ---- reachable from the REAL producer path, not only from a hand-built control fed to the oracle.
# The guard was correct and unit-tested, but `ingest_dns_policy` dropped the org fields on the is_org_domain
# branch, so the guard never saw the evidence and a subdomain hardened by an org sp=reject/p=reject FIRED
# end-to-end. These tests route the SAME contradiction through ingest / the real sensor export.

@pytest.mark.parametrize("org_policy", [
    "v=DMARC1; p=reject; sp=reject",   # subdomain fully protected
    "v=DMARC1; p=reject",              # inherited p=reject protects the subdomain
    "v=DMARC1; p=quarantine; sp=quarantine",
])
def test_a_contradictory_export_refuses_through_ingest_dns_policy(org_policy):
    # ingest must retain the org policy UNCONDITIONALLY so the oracle can adjudicate the contradiction
    facts = confirm_dns_policy("mail.gov.example", dmarc_observed=True, is_org_domain=True,
                               org_domain="gov.example", org_dmarc_record=org_policy,
                               org_dmarc_observed=True)
    assert facts == [], org_policy
    # and the org fields survive ingest (the producer is lossless)
    ctl = ingest_dns_policy("mail.gov.example", dmarc_observed=True, is_org_domain=True,
                            org_domain="gov.example", org_dmarc_record=org_policy,
                            org_dmarc_observed=True)[0]
    assert ctl.get("org_dmarc_record") == org_policy and ctl.get("is_org_domain") is True


def test_a_contradictory_export_refuses_through_the_real_sensor():
    export = ('{"domains":[{"domain":"mail.gov.example","dmarc_observed":true,"is_org_domain":true,'
              '"org_domain":"gov.example","org_dmarc":"v=DMARC1; p=reject; sp=reject",'
              '"org_dmarc_observed":true}]}')
    controls = parse_email_auth_export(export)
    assert controls, "the sensor must parse the contradictory export"
    assert not confirm_email_auth_posture(controls[0]).confirmed


def test_the_producer_fix_does_not_suppress_a_genuine_org_domain_weakness():
    # an ORG domain that truly publishes no DMARC (no org policy, no org_dmarc_observed) is a real weakness
    # and must STILL fire — the lossless-retention fix must not over-refuse.
    facts = confirm_dns_policy("gov.example", dmarc_observed=True, is_org_domain=True,
                               org_domain="gov.example")
    assert [f["rule"] for f in facts] == ["dmarc_missing"]


# ---- Independent-sweep CRITICAL #1 (escape-decode): RFC 1035 §5.1 presentation escapes must be decoded to
# ---- wire octets BEFORE any tag is read, or a `dig +short` `\009` TAB hides a protective tag.
# The escape-encoding axis is ORTHOGONAL to the existing shape/quoting/cardinality axes — a twin built from
# the author's model of the input space could only confirm it (the lesson from three prior rounds), so this
# axis is derived from the RFC 1035 §5.1 grammar and cross-checked against an independent reference decoder.

def _reference_decode(s: str) -> str:
    """An independent RFC 1035 §5.1 decoder, written differently from the implementation, as a test oracle."""
    result, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s) + 1 and s[i + 1:i + 4].isdigit() and int(s[i + 1:i + 4] or "999") <= 255:
            result.append(chr(int(s[i + 1:i + 4])))
            i += 4
        elif s[i] == "\\" and i + 1 < len(s):
            result.append(s[i + 1])
            i += 2
        else:
            result.append(s[i])
            i += 1
    return "".join(result)


@pytest.mark.parametrize("wire", [
    "v=DMARC1; p=none; sp=reject", 'v=DMARC1;\tp=reject', "google-site-verification=abc",
    'a\\b"c', "v=spf1 -all", "", "\t\t;;", "p=none;sp=quarantine",
])
def test_the_decoder_matches_an_independent_reference_over_escaped_forms(wire):
    # encode every octet as a mix of \DDD and passthrough, then assert both decoders recover the wire bytes
    encoded_ddd = "".join(f"\\{ord(ch):03d}" for ch in wire)          # fully-escaped
    for enc in (wire, encoded_ddd):
        assert _decode_txt_escapes(enc) == _reference_decode(enc)
    assert _decode_txt_escapes(encoded_ddd) == wire                   # \DDD round-trips to the octets


@pytest.mark.parametrize("sep", ["\\009", "\\009\\009", " \\009 ", "\\032", "\t"])
def test_a_protected_subdomain_never_fires_with_an_escaped_separator(sep):
    # a hardened org whose sp=reject is preceded by a spec-legal separator octet (escaped \009/\032 TAB/SP,
    # or a real TAB) must NOT fire — the separator must resolve to real whitespace, not hide the sp= tag.
    org = f'"v=DMARC1; p=none;{sep}sp=reject"'
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": org}).confirmed, sep


@pytest.mark.parametrize("field,record,fires", [
    ("org_dmarc_record", '"v=DMARC1; p=none;\\009sp=reject"', False),   # protected: escaped TAB before sp
    ("org_dmarc_record", '"v=DMARC1; p=none; sp\\009=\\009reject"', False),  # escapes around '='
    ("org_dmarc_record", '"v=DMARC1; p=none;" "\\009sp=reject"', False),  # split across strings
    ("org_dmarc_record", '"v=DMARC1; p=none;\\009sp=none"', True),      # exposed: escaped, still fires
])
def test_escaped_org_records_resolve_to_wire_bytes(field, record, fires):
    assert confirm_email_auth_posture({**_SUB, field: record}).confirmed is fires, record


@pytest.mark.parametrize("rule,field,record,fires", [
    ("dmarc_none", "dmarc_record", '"v=DMARC1;\\009p=none"', True),     # exposed p=none via escaped sep
    ("dmarc_none", "dmarc_record", '"v=DMARC1;\\009p=reject"', False),  # hardened, escaped sep
    ("spf_permissive", "spf_record", '"v=spf1\\009+all"', True),        # exposed +all via escaped sep
    ("spf_permissive", "spf_record", '"v=spf1\\009-all"', False),       # hardened -all via escaped sep
])
def test_escaped_own_domain_records_read_the_true_qualifier(rule, field, record, fires):
    assert confirm_email_auth_posture(
        {"rule": rule, "domain": "gov.example", field: record}).confirmed is fires, record


def test_the_decoder_is_total_and_never_raises_on_pathological_escapes():
    for pathological in ("\\", "\\\\", "\\0", "\\00", "\\256", "\\999", "\\9x", "a\\", "\\z\\", "\\255",
                         "\\000", "\\; \\059 \\061"):
        assert isinstance(_decode_txt_escapes(pathological), str)   # no exception, always a string


# ---- MEDIUM (green-wash gap): the R3 "unquoted content BETWEEN character-strings" guard was untested;
# ---- its removal reintroduces the round-3 cardinal false positive while the suite stays green.

@pytest.mark.parametrize("blob", [
    '"v=DMARC1; p=none;" sp=reject "x"',        # unquoted sp=reject sits BETWEEN two character-strings
    '"v=DMARC1; p=none" p=reject "y"',
])
def test_unquoted_content_between_character_strings_refuses(blob):
    # _resolve_txt_record must return None (refuse) rather than silently concatenating across the gap and
    # dropping the unquoted protective content.
    assert _resolve_txt_record(blob) is None, blob
    assert not confirm_email_auth_posture({**_SUB, "org_dmarc_record": blob}).confirmed, blob


def test_an_unnamed_org_domain_refuses_so_the_certificate_stays_auditable():
    # a fired cert must NAME the domain whose policy was looked up, or a third party cannot audit it
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "mail.g", "dmarc_observed": True,
         "org_dmarc_observed": True}).confirmed


@pytest.mark.parametrize("record", [
    "v=DMARC1; p=none",
    "v=DMARC1;p=none;rua=mailto:x@y",
    "V=DMARC1; P=None; sp=reject",          # case-insensitive
    "v=DMARC1; adkim=s; p = none ; pct=100",  # spacing
])
def test_dmarc_p_none_is_a_fact(record):
    assert confirm_email_auth_posture(
        {"rule": "dmarc_none", "domain": "gov.example", "dmarc_record": record}).confirmed


@pytest.mark.parametrize("record", [
    "v=spf1 include:_spf.example.com +all",
    "v=spf1 mx all",                 # a bare `all` defaults to the PASS qualifier (+all)
    "v=spf1 a:mail.example.com  +all ",
])
def test_spf_pass_all_is_a_fact(record):
    assert confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example", "spf_record": record}).confirmed


# ---- SILENT on the mandatory benign twin (a hardened domain) ----

@pytest.mark.parametrize("record", [_HARDENED_DMARC, "v=DMARC1; p=quarantine", "v=DMARC1;p=QUARANTINE;pct=50"])
def test_enforcing_dmarc_does_not_fire(record):
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_none", "domain": "gov.example", "dmarc_record": record}).confirmed


@pytest.mark.parametrize("record", [_HARDENED_SPF, "v=spf1 mx ~all", "v=spf1 a ?all", "v=spf1 -all"])
def test_non_pass_all_spf_does_not_fire(record):
    assert not confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example", "spf_record": record}).confirmed


# ---- RED-PEN BLOCK-7 regression: SPF's real record set is MULTI-record ----
# An apex almost always carries site-verification TXT records alongside SPF, and `dig +short TXT` prints
# them all. Joining across those record boundaries destroyed the `all` token's terminator, silently making
# the rule INERT on the commonest real export (a genuinely broken `+all` domain was MISSED) — a rule that
# appears to work while doing nothing is exactly what the honest-ledger invariant exists to prevent.
# RFC 7208 §4.5 record selection is what makes a real export readable: pick the `v=spf1` record, discard
# the neighbours, and never splice.

@pytest.mark.parametrize("fires,record", [
    (True, "v=spf1 +all"),
    (False, "v=spf1 include:_spf.example.com ~all"),
])
@pytest.mark.parametrize("order", ["policy first", "policy last", "policy between"])
def test_spf_is_read_from_a_real_multi_record_apex_set(fires, record, order):
    blob = {"policy first": f'"{record}"\n{_NEIGHBOUR}',
            "policy last": f'{_NEIGHBOUR}\n"{record}"',
            "policy between": f'{_NEIGHBOUR}\n"{record}"\n{_NEIGHBOUR2}'}[order]
    result = confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example", "spf_record": blob})
    assert result.confirmed is fires, f"{order}: {blob!r}"


@pytest.mark.parametrize("blob", [
    '"v=spf1 mx -all"\n"v=spf1 +all"',          # duplicate v=spf1 -> RFC 7208 §4.5 PermError, no policy
    '"v=spf1 +all"\n"v=spf1 mx -all"',          # …and the verdict may not depend on RRset order
    '"v=spf1 mx" +all',                          # unquoted content mixed among character-strings
])
def test_an_unresolvable_spf_record_set_never_fires(blob):
    assert not confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example", "spf_record": blob}).confirmed


def test_a_neighbour_record_can_never_supply_the_all_token():
    # the third BLOCK-6 instance: a neighbour ending in `all ` spliced ahead of a HARD-FAIL spf record and
    # fired `+all` on a correctly-hardened domain.
    assert not confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "gov.example",
         "spf_record": '"some-token=x all"\n"v=spf1 mx -all"'}).confirmed


def test_the_benign_twin_domain_yields_no_facts_end_to_end():
    # a correctly-configured domain: enforcing DMARC + a hard-fail SPF -> NOTHING is promoted
    assert confirm_dns_policy("gov.example", dmarc_record=_HARDENED_DMARC, spf_record=_HARDENED_SPF,
                              dmarc_observed=True) == []


# ---- REFUSES (absence/ambiguity is never asserted) ----

def test_unobserved_absence_refuses():
    # the producer did not attest the lookup happened -> "missing" is unproven
    assert not confirm_email_auth_posture({"rule": "dmarc_missing", "domain": "gov.example"}).confirmed


def test_dmarc_missing_with_a_record_present_does_not_fire():
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_missing", "domain": "g", "dmarc_observed": True,
         "dmarc_record": _HARDENED_DMARC}).confirmed


@pytest.mark.parametrize("record", ["", "garbage", "v=DMARC1; rua=mailto:x@y"])   # no p= tag
def test_unparseable_dmarc_refuses(record):
    assert not confirm_email_auth_posture(
        {"rule": "dmarc_none", "domain": "g", "dmarc_record": record}).confirmed


def test_spf_missing_is_a_gating_chain_and_never_fires():
    # DKIM+DMARC may still protect the domain -> absence of SPF is NOT a standalone fact
    assert not confirm_email_auth_posture({"rule": "spf_permissive", "domain": "g"}).confirmed
    assert not confirm_email_auth_posture({"rule": "spf_missing", "domain": "g"}).confirmed
    assert not confirm_email_auth_posture(
        {"rule": "spf_permissive", "domain": "g", "spf_record": "v=spf1 include:_spf.x"}).confirmed  # no `all`


def test_unknown_rule_and_malformed_are_safe():
    for ctl in ({}, {"rule": "message_dkim_fail"}, {"rule": ""}):
        assert not confirm_email_auth_posture(ctl).confirmed


# ---- the offline ingest ----

def test_ingest_emits_candidates_and_never_asserts_unobserved_absence():
    assert [c["rule"] for c in ingest_dns_policy("g", dmarc_record="v=DMARC1; p=none",
                                                 spf_record="v=spf1 -all")] == ["dmarc_none", "spf_permissive"]
    # no DMARC + the lookup WAS observed -> a dmarc_missing candidate
    assert [c["rule"] for c in ingest_dns_policy("g", dmarc_observed=True)] == ["dmarc_missing"]
    # no DMARC and the lookup was NOT observed -> no candidate at all (absence unproven)
    assert ingest_dns_policy("g") == []


# ---- gate discipline + the PCF foundation (why this domain is real functionality) ----

def test_email_auth_posture_is_not_in_the_frozen_fallback():
    assert OracleKind.EMAIL_AUTH_POSTURE not in _ALL_ORACLES
    assert len(_ALL_ORACLES) == 15


def test_a_confirmed_finding_emits_a_real_pcf_certificate_that_verifies_offline():
    """The point of building this domain ON the PCF foundation: its finding is a signed, re-runnable
    Proof-Carrying Finding by construction — not a prototype."""
    pytest.importorskip("cryptography")
    from framework.v2.entitlement.crypto import generate_keypair
    from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
    from framework.v2.evidence.certify import build_certificate, sign_certificate
    from framework.v2.evidence.pcf import to_pcf, verify_pcf
    from framework.v2.verify.email_auth import email_auth_context
    from framework.v2.verify.reverify import reverify_context

    ctl = {"rule": "dmarc_none", "domain": "gov.example", "dmarc_record": "v=DMARC1; p=none"}
    oc = email_auth_context(ctl)
    rr = reverify_context(oc, bug_class="email_auth_misconfiguration")
    assert rr.reproduced and rr.ok                      # the oracle re-fires offline over the retained record

    keys = [generate_keypair() for _ in range(3)]
    tr = TrustRoot(schema_version=1, threshold=2, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys[:2])]
    finding = {"check_id": "email-dmarc-none-gov.example", "bug_class": "email_auth_misconfiguration",
               "confirmed_by": rr.confirmed_by, "confidence": rr.confidence, "oracle_context": oc}
    pcf = to_pcf(sign_certificate(build_certificate(finding, seq=1), signers), oracle_context=oc)

    assert pcf["claim"]["class"] == "email_auth_misconfiguration"
    assert pcf["oracle"]["id"] == OracleKind.EMAIL_AUTH_POSTURE.value and pcf["oracle"]["version"]
    assert pcf["grounding"] == "FACT" and pcf["verdict"]["fired"] is True
    assert verify_pcf(pcf, tr).verified                 # re-established offline by a third party
