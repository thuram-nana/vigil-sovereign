"""Consumer PR-H (Area 7) — SAML 2.0 Web-SSO assertion verification (the identity proof; NEVER authority).

Doctrine, identical to `ui.oidc`: a SAML assertion proves WHO the user is; it NEVER carries a role. The caller
(`ui.scim` / the provisioner) maps the verified identity to an OWNER-SIGNED membership whose role comes from the
owner-signed `governor.sso_config`, capped at the ceiling — the IdP authenticates, the owner still authorizes.

WHAT THIS MODULE VERIFIES, FAIL-CLOSED (every check must pass or the assertion is refused):

  1. XML HARDENING — a DOCTYPE/DTD is refused outright at the expat level, inside the one parse that builds the
     tree (so NO internal/external entity can be declared or expanded: XXE and billion-laughs are closed by
     construction), plus a byte-size cap; every parse failure is a refusal.
  2. EXACTLY ONE ASSERTION in the whole document, and NO two elements share an `ID` — the structural core of the
     signature-wrapping (XSW) defence: an attacker cannot smuggle a second, forged assertion for the processor
     to read while the signature covers a hidden original.
  3. SIGNATURE BINDING — the cryptographic signature (verified by the pluggable `sig_verifier` backend) must
     validly cover EITHER the one processed assertion itself OR the enveloping Response; because step 2 proved
     there is exactly one assertion in the document, a valid signature over the assertion/Response provably
     covers the element we read (no wrapping gap). A signature over any OTHER id does not satisfy the binding.
  4. ISSUER == the org's configured `idp_entity_id`.
  5. AUDIENCE restriction CONTAINS the org's `sp_entity_id` (org-scoping — org A's assertion fails org B).
  6. RECIPIENT / DESTINATION == the org's `acs_url`.
  7. TIME WINDOWS — Conditions NotBefore/NotOnOrAfter and SubjectConfirmationData NotOnOrAfter, within the
     configured clock skew (itself BOUNDED: a config over `_MAX_CLOCK_SKEW_SECONDS` is refused). A missing
     NotOnOrAfter is refused (it bounds the replay window).
  8. SP-INITIATED BINDING (when the caller passes `expected_in_response_to`, as the HTTP edge always does) — the
     SubjectConfirmationData `InResponseTo` (inside the SIGNED assertion) MUST equal the ID of the AuthnRequest
     this browser's login minted, and the Response's own `InResponseTo`, when present, must too. So an
     unsolicited (IdP-initiated) response, or a response to ANOTHER login, is refused — the unsigned Response
     attribute alone is never trusted for this, the signed one is.
  9. REPLAY — the assertion `ID` is spent single-use in a durable atomic ledger, kept until the earliest
     NotOnOrAfter PLUS the LARGEST skew any config may carry (`_MAX_CLOCK_SKEW_SECONDS`) has passed — not the
     skew in force at the first presentation, which the owner may raise (up to that bound) before a second one —
     so a second presentation refuses at any allowed skew, also when the skew changed in between. That retention
     is BOUNDED: an assertion still deliverable more than `_MAX_ASSERTION_LIFETIME_SECONDS` from now is refused,
     and the ledger is PARTITIONED per org (each org's markers, cap and sweep its own), so no tenant's IdP can
     fill — or slow — another org's ledger.

The SP-initiated request side lives here too: `new_request_id` + `build_authn_request` +
`authn_request_redirect_url` produce the (unsigned) AuthnRequest for the SAML HTTP-Redirect binding — pure
stdlib (zlib raw DEFLATE + base64), so the keyless edge can mint it without any key.

THE SIGNATURE CRYPTO BACKEND (honest boundary, VIGIL-LIMIT:LIMIT-sso-saml-xmldsig-backend-unprovisioned — an
owner provisioning step: install a vetted XML-DSig library in the sovereign venv). Byte-correct XML-DSig verification
needs EXCLUSIVE XML canonicalisation (`xml-exc-c14n#`); Python's stdlib `ElementTree.canonicalize` implements
only C14N 2.0, and no vetted XML-DSig library (`signxml` / `xmlsec`) is vendored in this environment. Rolling an
exclusive-c14n by hand — with no trusted conformance vectors to test it against — is exactly the unprovable
"fake-fixture" antipattern this codebase forbids, so this module does NOT do it. Instead the crypto is a
PLUGGABLE backend `sig_verifier(xml_bytes, cert_pems) -> frozenset[str]` returning the element ids whose
signature validly verifies under one of the owner-configured certs. The shipped default
(`signxml_sig_verifier`) uses `signxml` when it is importable and otherwise FAILS CLOSED (returns the empty set
⇒ every assertion refused). So with the flag off, or without a vetted backend, SAML login is inert/refusing —
never falsely accepting. The structural / temporal / audience / replay / XSW-binding layer above is complete and
fully tested (a test injects a verifier that attests which ids are "signed", which is how the XSW-binding and
accept paths are exercised without depending on byte-correct c14n).

FATAL-2: SOVEREIGN-side, imports NO `framework` / `strix`. Stdlib + `sigil.config`/`sigil.reuse` only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, NamedTuple, Optional
from xml.sax.saxutils import escape, quoteattr

from ..reuse import assert_no_offense

assert_no_offense()

# SAML / XML-DSig namespaces.
_NS_ASSERT = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_PROTO = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"

_A = lambda local: f"{{{_NS_ASSERT}}}{local}"      # noqa: E731 — tiny tag builders, local to this module
_P = lambda local: f"{{{_NS_PROTO}}}{local}"       # noqa: E731
_D = lambda local: f"{{{_NS_DS}}}{local}"          # noqa: E731

# A SAML Response is a few KiB; cap the input so a hostile IdP/relay cannot stream an unbounded body.
_MAX_SAML_BYTES = 4 * 1024 * 1024

# The largest clock skew (seconds) the verifier honors — mirrors `governor.sso_config.MAX_CLOCK_SKEW_SECONDS` (which
# refuses it at sign time and in the fold); a lockstep test keeps the two equal. Re-checked here so the time windows
# and the replay ledger's retention stay bounded whatever config object reaches the verifier.
_MAX_CLOCK_SKEW_SECONDS = 600

# The longest an assertion may still be deliverable (seconds): one whose EARLIEST NotOnOrAfter lies further than this
# past `now` is refused. NotOnOrAfter is chosen by the IdP — the org's own, possibly hostile, tenant's — and a spent
# assertion's replay marker must live until it (+ the largest skew), so without this bound a far-future NotOnOrAfter
# would pin markers for as long. Real IdPs issue minutes (a bearer SubjectConfirmationData is typically 5 minutes);
# a day is far beyond any of them, and caps a marker's life at this + `_MAX_CLOCK_SKEW_SECONDS` + the ledger's grace.
_MAX_ASSERTION_LIFETIME_SECONDS = 24 * 3600

# The signature-verifier backend contract: given the raw signed bytes and the owner-configured IdP certs (PEM),
# return the set of element `ID`s whose enveloped signature validly verifies under one of those certs. An empty
# set means "no valid signature" (fail-closed).
SigVerifier = Callable[[bytes, tuple], "frozenset[str]"]


class SamlError(Exception):
    """A fail-closed SAML refusal. The route maps it to a 401; it never leaks assertion internals."""


class SamlIdentity(NamedTuple):
    """The verified identity an assertion asserts — IDENTITY ONLY (no role). `groups` are the IdP-asserted group
    names the caller feeds to `scim.resolve_role` to SELECT among the owner-signed config map (never authority)."""
    name_id: str
    assertion_id: str
    attributes: dict
    groups: tuple
    session_index: str = ""


# ---------------------------------------------------------------------------------------------------
# XML hardening — ONE expat parse that refuses a DTD (no entities can then exist) AND builds the tree; size cap.
# ---------------------------------------------------------------------------------------------------

class _DtdFound(Exception):
    """Internal sentinel raised the instant expat sees a `<!DOCTYPE` — it fires at the DOCTYPE *start*, BEFORE
    any entity declaration in the internal subset is read or expanded, and pyexpat stops the parser there, so
    billion-laughs and XXE are closed at the source (no entity ever exists to expand or resolve)."""


def _refuse_dtd(*_a) -> None:
    raise _DtdFound()


def _universal(name: str) -> str:
    """expat's namespaced name (`uri}local`, with the `}` separator) → ElementTree's `{uri}local`; a name with no
    namespace is unchanged — exactly ElementTree's own expat-backed parser's mapping."""
    return "{" + name if "}" in name else name


def _parse_hardened(xml_bytes: bytes) -> ET.Element:
    """Parse `xml_bytes` into an ElementTree root, FAIL-CLOSED, in ONE expat parse that both refuses a DTD and
    builds the tree. The refusal is that parse's own `StartDoctypeDeclHandler`, which raises at the DOCTYPE start
    (pyexpat stops parsing there), so NO internal or external entity can be declared — XXE and billion-laughs are
    closed by construction — and the root returned is the product of that very parse: there is no second,
    unguarded parse of the same bytes (`ElementTree.fromstring` cannot carry the guard: its C-accelerated
    `XMLParser` exposes no expat handler hook). The parse events feed `ElementTree.TreeBuilder` the way
    ElementTree's own expat-backed `XMLParser` does (namespace-aware, `}` separator, attributes in document order,
    comments and PIs dropped), so the root is the tree `ElementTree.fromstring` builds for the same bytes —
    `test_saml` pins that equivalence. With no DTD only the five predefined entities exist, so any other `&foo;`
    is expat's undefined-entity error. EVERY failure — malformed XML, an undefined entity, an XML declaration naming
    an encoding expat cannot decode (the codec's LookupError / ValueError) — is a `SamlError`, so the caller's
    refusal path (counted and audited) always runs. A byte-size cap bounds the input."""
    if not isinstance(xml_bytes, (bytes, bytearray)):
        raise SamlError("SAML input must be bytes")
    if len(xml_bytes) > _MAX_SAML_BYTES:
        raise SamlError("SAML document exceeds the size cap")
    if len(xml_bytes) == 0:
        raise SamlError("empty SAML document")
    from xml.parsers import expat
    builder = ET.TreeBuilder()

    def _start(tag: str, attr_list: list) -> None:
        # ordered_attributes ⇒ [name, value, name, value, ...] in document order
        builder.start(_universal(tag), {_universal(attr_list[i]): attr_list[i + 1]
                                        for i in range(0, len(attr_list), 2)})

    p = expat.ParserCreate(None, "}")
    p.buffer_text = True
    p.ordered_attributes = True
    p.StartDoctypeDeclHandler = _refuse_dtd
    p.EntityDeclHandler = _refuse_dtd                  # unreachable without a DTD; refused again regardless
    p.ExternalEntityRefHandler = lambda *_a: 0          # 0 ⇒ refuse external entity resolution
    p.StartElementHandler = _start
    p.EndElementHandler = lambda tag: builder.end(_universal(tag))
    p.CharacterDataHandler = builder.data
    try:
        p.Parse(bytes(xml_bytes), True)
        root = builder.close()
    except _DtdFound:
        raise SamlError("refusing a SAML document that declares a DOCTYPE/DTD (XXE / entity-expansion defence)")
    except Exception as e:  # noqa: BLE001 — malformed XML / undefined entity / undecodable encoding → refusal
        raise SamlError("SAML document is not well-formed XML") from e
    if root is None:
        raise SamlError("SAML document has no root element")
    return root


def _collect_ids(root: ET.Element) -> dict:
    """Every element carrying an `ID` attribute → {id: element}, FAIL-CLOSED on a DUPLICATE id (a classic XSW
    primitive — two elements sharing an id let a signature reference resolve to the wrong one)."""
    ids: dict = {}
    for el in root.iter():
        v = el.get("ID")
        if v is None:
            continue
        if v in ids:
            raise SamlError("duplicate ID in SAML document (signature-wrapping defence)")
        ids[v] = el
    return ids


def _single_assertion(root: ET.Element) -> ET.Element:
    """The ONE `<saml:Assertion>` in the document, FAIL-CLOSED on zero or more than one (the XSW structural
    core: with exactly one assertion in the whole document the attacker cannot present a second forged one)."""
    assertions = [el for el in root.iter(_A("Assertion"))]
    if not assertions:
        raise SamlError("no <saml:Assertion> in the SAML document")
    if len(assertions) > 1:
        raise SamlError(f"refusing {len(assertions)} assertions (exactly one is required; XSW defence)")
    return assertions[0]


# ---------------------------------------------------------------------------------------------------
# SAML timestamp parsing (ISO-8601 UTC) — fail-closed.
# ---------------------------------------------------------------------------------------------------

def _parse_instant(value: Optional[str], what: str) -> float:
    """Parse a SAML xsd:dateTime (e.g. `2024-01-01T00:00:00Z` / with fractional seconds) to an epoch float,
    FAIL-CLOSED. A missing/unparseable/non-UTC-resolvable instant raises — the time guards must never silently
    pass on a value they could not understand."""
    s = str(value or "").strip()
    if not s:
        raise SamlError(f"SAML {what} is missing")
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as e:
        raise SamlError(f"SAML {what} is not a valid instant") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# ---------------------------------------------------------------------------------------------------
# Replay ledger — atomic single-use per assertion ID (mirrors ui.oidc.OidcStateStore's marker idiom).
# ---------------------------------------------------------------------------------------------------

class SamlReplayLedger:
    """A durable, atomic single-use ledger over assertion `ID`s. `try_spend(assertion_id, accept_until, scope=org)`
    O_EXCL-creates a marker named `sha256(id)` (fixed hex, no traversal/newline injection); the exclusive create
    is the serialization point, so of N concurrent presentations exactly ONE wins and the rest are refused
    (replay). The ledger is PARTITIONED by `scope` (the verifier passes the config's org): each org's markers live
    in that org's own sub-directory (named by a hash of the org id, never the id itself) with its OWN sweep and
    its OWN cap, so a tenant — whose IdP chooses its assertions' NotOnOrAfter — can fill only its own partition,
    never refuse another org's sign-ins at capacity nor make another org's spend sweep its markers. A per-spend
    sweep + a hard cap bound each partition. `accept_until` is an instant after which NO
    presentation of that assertion can pass the temporal guard at any allowed skew — the verifier passes its
    earliest NotOnOrAfter PLUS `_MAX_CLOCK_SKEW_SECONDS`, never the skew in force at the first spend (the owner
    may raise it, up to that bound, before a replay arrives) — and a marker is reaped only once that instant is
    more than a grace in the past, so by then the temporal guard refuses the assertion whatever skew the config
    carries (a marker reaped while any allowed window is still open would let it verify twice). Stdlib only."""

    _DEFAULT_MAX = 65536
    _GRACE = 300.0

    def __init__(self, path, *, max_outstanding: int = _DEFAULT_MAX) -> None:
        self.dir = Path(path)
        self.max_outstanding = int(max_outstanding)

    def _partition(self, scope: str) -> Path:
        return self.dir / hashlib.sha256(("scope\x00" + str(scope or "")).encode("utf-8")).hexdigest()

    @staticmethod
    def _marker(part: Path, assertion_id: str) -> Path:
        return part / hashlib.sha256(assertion_id.encode("utf-8")).hexdigest()

    def _sweep(self, part: Path, now: float) -> int:
        live = 0
        try:
            entries = list(os.scandir(part))
        except OSError:
            return 0
        for entry in entries:
            try:
                rec = json.loads(Path(entry.path).read_text(encoding="utf-8"))
                expiry = float(rec["exp"])
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                self._unlink(entry.path)
                continue
            if now > expiry + self._GRACE:
                self._unlink(entry.path)
            else:
                live += 1
        return live

    @staticmethod
    def _unlink(path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def try_spend(self, assertion_id: str, accept_until: float, *, now: Optional[float] = None,
                  scope: str = "") -> bool:
        """True iff this assertion ID is spent for the FIRST time in `scope`'s partition (accept); False if already
        spent there (replay → refuse). The marker is kept until `accept_until` (+ grace). Fail-closed on a blank id.
        A full partition, or a real I/O error at the exclusive-create, raises (the caller refuses)."""
        aid = str(assertion_id or "").strip()
        if not aid:
            return False
        part = self._partition(scope)
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        part.mkdir(exist_ok=True, mode=0o700)
        t = time.time() if now is None else float(now)
        if self._sweep(part, t) >= self.max_outstanding:
            raise SamlError("SAML replay ledger at capacity")
        marker = self._marker(part, aid)
        payload = json.dumps({"exp": float(accept_until)}, ensure_ascii=False)
        try:
            fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False                                  # already spent → replay refused
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        return True


# ---------------------------------------------------------------------------------------------------
# The signature-verifier backend (pluggable; default FAILS CLOSED without a vetted XML-DSig library).
# ---------------------------------------------------------------------------------------------------

def signxml_sig_verifier(xml_bytes: bytes, cert_pems: tuple) -> "frozenset[str]":
    """The shipped default backend. Uses `signxml` (a vetted XML-DSig implementation) when it is importable,
    returning the set of element ids whose enveloped signature validly verifies under one of `cert_pems`.
    When `signxml` is NOT available (this environment), it FAILS CLOSED — returns the empty set, so every
    assertion is refused — rather than guess at exclusive-c14n by hand. See the module honest-boundary note."""
    try:
        from signxml import XMLVerifier
    except Exception:  # noqa: BLE001 — not vendored here ⇒ fail closed (no signature is ever "valid")
        return frozenset()
    verified_ids: set[str] = set()
    for pem in cert_pems or ():  # pragma: no cover — exercised only where signxml is installed
        try:
            results = XMLVerifier().verify(bytes(xml_bytes), x509_cert=pem, expect_references=None)
            for r in (results if isinstance(results, (list, tuple)) else [results]):
                el = getattr(r, "signed_xml", None)
                rid = el.get("ID") if el is not None else None
                if rid:
                    verified_ids.add(str(rid))
        except Exception:  # noqa: BLE001 — a cert that does not verify this doc contributes nothing
            continue
    return frozenset(verified_ids)


# ---------------------------------------------------------------------------------------------------
# The verifier (the red-pen keystone).
# ---------------------------------------------------------------------------------------------------

def _text(el: Optional[ET.Element]) -> str:
    return (el.text or "").strip() if el is not None else ""


def _groups_attribute_names() -> frozenset:
    """The SAML attribute Names we read group membership from (the common IdP conventions). Case-sensitive match
    on the `Name` / `FriendlyName`."""
    return frozenset({"groups", "memberOf", "http://schemas.xmlsoap.org/claims/Group",
                      "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "Group", "Groups"})


def _extract_attributes(assertion: ET.Element) -> "tuple[dict, tuple]":
    """Project the AttributeStatement into {name: [values]} and pull the group names out of the group-bearing
    attributes. Values are plain text (never executed); this is inert projection."""
    attrs: dict = {}
    groups: list = []
    group_names = _groups_attribute_names()
    for stmt in assertion.findall(_A("AttributeStatement")):
        for attr in stmt.findall(_A("Attribute")):
            name = attr.get("Name") or attr.get("FriendlyName") or ""
            values = [_text(v) for v in attr.findall(_A("AttributeValue")) if _text(v)]
            if name:
                attrs[name] = values
            if name in group_names:
                groups.extend(values)
    return attrs, tuple(groups)


def verify_saml_response(xml_bytes: bytes, *, config, now: float, replay_ledger: SamlReplayLedger,
                         sig_verifier: Optional[SigVerifier] = None,
                         expected_in_response_to: Optional[str] = None) -> SamlIdentity:
    """Verify a SAML Response/Assertion against the OWNER-SIGNED `config` (a `governor.sso_config.SsoConfig`,
    protocol=="saml"), returning the verified `SamlIdentity` or raising `SamlError`. Checks run in a
    fail-closed order: harden+parse, structural XSW (single assertion, unique ids), SIGNATURE BINDING, issuer,
    audience, recipient/destination, time windows, the SP-initiated InResponseTo binding (when
    `expected_in_response_to` is given), the bounded assertion lifetime, and single-use replay (in the config org's
    ledger partition). `sig_verifier` defaults to
    `signxml_sig_verifier` (fail-closed without a vetted backend); tests inject a stub that attests signed ids."""
    if config is None or getattr(config, "protocol", None) != "saml":
        raise SamlError("no active SAML config for this org")
    certs = tuple(getattr(config, "idp_certs_pem", ()) or ())
    if not certs:
        raise SamlError("SAML config carries no IdP signing certificate (fail-closed)")
    verifier = sig_verifier or signxml_sig_verifier
    skew = int(getattr(config, "clock_skew_seconds", 60) or 0)
    if skew > _MAX_CLOCK_SKEW_SECONDS:
        raise SamlError(f"the configured clock skew exceeds {_MAX_CLOCK_SKEW_SECONDS} s (fail-closed)")

    root = _parse_hardened(xml_bytes)
    _collect_ids(root)                                                # fail-closed on duplicate ids (XSW defence)
    assertion = _single_assertion(root)                               # fail-closed on != 1 assertion
    assertion_id = assertion.get("ID") or ""
    if not assertion_id:
        raise SamlError("the assertion has no ID (cannot bind a signature or guard replay)")

    # --- SIGNATURE BINDING (XSW): the signature must validly cover the one assertion OR the enveloping root.
    # Because exactly one assertion exists in the whole document, a valid signature over the assertion or over
    # the root Response provably covers the element we read — there is no wrapping gap to exploit.
    signed_ids = verifier(bytes(xml_bytes), certs)
    if not isinstance(signed_ids, (set, frozenset)):
        raise SamlError("signature verifier returned a non-set")
    root_id = root.get("ID") or ""
    root_is_response = root.tag == _P("Response")
    bound = (assertion_id in signed_ids) or (root_is_response and bool(root_id) and root_id in signed_ids)
    if not bound:
        raise SamlError("no valid signature binds the processed assertion (forged / unsigned / wrapped)")

    # --- ISSUER (the assertion's, falling back to the Response's) == the configured IdP entity id.
    issuer_el = assertion.find(_A("Issuer"))
    if issuer_el is None and root_is_response:
        issuer_el = root.find(_A("Issuer"))
    if _text(issuer_el) != str(getattr(config, "idp_entity_id", "")):
        raise SamlError("SAML Issuer does not match the configured IdP entity id")

    # --- AUDIENCE restriction CONTAINS our SP entity id (org-scoping).
    conditions = assertion.find(_A("Conditions"))
    if conditions is None:
        raise SamlError("assertion has no <Conditions> (cannot bound audience/time)")
    audiences = {_text(a) for restr in conditions.findall(_A("AudienceRestriction"))
                 for a in restr.findall(_A("Audience"))}
    if str(getattr(config, "sp_entity_id", "")) not in audiences:
        raise SamlError("assertion audience does not contain our SP entity id (wrong-tenant / replayed)")

    # --- TIME WINDOWS: Conditions NotBefore/NotOnOrAfter within skew (NotOnOrAfter required — bounds replay).
    cond_nooa = _parse_instant(conditions.get("NotOnOrAfter"), "Conditions/NotOnOrAfter")
    if now >= cond_nooa + skew:
        raise SamlError("assertion Conditions NotOnOrAfter has passed")
    cond_nb = conditions.get("NotBefore")
    if cond_nb is not None and now < _parse_instant(cond_nb, "Conditions/NotBefore") - skew:
        raise SamlError("assertion is not yet valid (Conditions NotBefore)")

    # --- SUBJECT CONFIRMATION: Recipient == our ACS url; NotOnOrAfter within skew.
    subject = assertion.find(_A("Subject"))
    if subject is None:
        raise SamlError("assertion has no <Subject>")
    scd = None
    for sc in subject.findall(_A("SubjectConfirmation")):
        d = sc.find(_A("SubjectConfirmationData"))
        if d is not None:
            scd = d
            break
    if scd is None:
        raise SamlError("assertion has no <SubjectConfirmationData> (cannot bind recipient/time)")
    if str(scd.get("Recipient") or "") != str(getattr(config, "acs_url", "")):
        raise SamlError("SubjectConfirmationData Recipient does not match our ACS url")
    scd_nooa = _parse_instant(scd.get("NotOnOrAfter"), "SubjectConfirmationData/NotOnOrAfter")
    if now >= scd_nooa + skew:
        raise SamlError("SubjectConfirmationData NotOnOrAfter has passed")
    # Response Destination, when present, must also be our ACS url.
    if root_is_response:
        dest = root.get("Destination")
        if dest is not None and str(dest) != str(getattr(config, "acs_url", "")):
            raise SamlError("Response Destination does not match our ACS url")

    # --- SP-INITIATED BINDING: the SIGNED SubjectConfirmationData InResponseTo must name OUR AuthnRequest (an
    # unsolicited / IdP-initiated response, or one answering another login, is refused). The Response attribute
    # may sit outside the signature, so it is only cross-checked, never relied on.
    if expected_in_response_to is not None:
        want = str(expected_in_response_to)
        if not want:
            raise SamlError("no AuthnRequest ID to bind this response to (fail-closed)")
        if str(scd.get("InResponseTo") or "") != want:
            raise SamlError("assertion InResponseTo does not name this login's AuthnRequest (unsolicited / "
                            "answers another login)")
        if root_is_response:
            rirt = root.get("InResponseTo")
            if rirt is not None and str(rirt) != want:
                raise SamlError("Response InResponseTo does not name this login's AuthnRequest")

    # --- BOUNDED LIFETIME: the IdP chooses NotOnOrAfter, and the replay marker below must outlive the earliest one.
    # An assertion still deliverable more than `_MAX_ASSERTION_LIFETIME_SECONDS` from now is refused, so no IdP can
    # pin a marker (and a slot of its org's ledger) for longer than that.
    if min(cond_nooa, scd_nooa) - now > _MAX_ASSERTION_LIFETIME_SECONDS:
        raise SamlError("assertion NotOnOrAfter lies beyond the bounded assertion lifetime (too far in the future)")

    # --- REPLAY: spend the assertion ID single-use. The time guards above accept it until the earliest NotOnOrAfter
    # PLUS the skew of the config in force AT THAT presentation, and the owner may re-sign a larger skew (up to the
    # bound) between two presentations — so its marker is kept until the earliest NotOnOrAfter plus the LARGEST
    # skew any config may carry. Reaped any earlier (at NotOnOrAfter + a grace smaller than the skew, or + the skew
    # in force at the FIRST spend), the same assertion would verify a second time inside a window still open.
    # The spend is scoped to the config's org: each org's markers, cap and sweep are its own partition.
    accept_until = min(cond_nooa, scd_nooa) + _MAX_CLOCK_SKEW_SECONDS
    if not replay_ledger.try_spend(assertion_id, accept_until, now=now,
                                   scope=str(getattr(config, "org_id", "") or "")):
        raise SamlError("SAML assertion replay refused (ID already spent)")

    # --- IDENTITY (never a role): the NameID, plus attributes and the IdP-asserted groups (for role SELECTION).
    name_id = _text(subject.find(_A("NameID")))
    if not name_id:
        raise SamlError("assertion Subject has no NameID (no usable identity)")
    attrs, groups = _extract_attributes(assertion)
    authn = assertion.find(_A("AuthnStatement"))
    session_index = (authn.get("SessionIndex") if authn is not None else "") or ""
    return SamlIdentity(name_id=name_id, assertion_id=assertion_id, attributes=attrs, groups=groups,
                        session_index=str(session_index))


# ---------------------------------------------------------------------------------------------------
# SP-initiated login — the AuthnRequest (HTTP-Redirect binding). Keyless: the request is UNSIGNED (the IdP
# authenticates the person; what binds the answer to this login is the signed InResponseTo checked above).
# ---------------------------------------------------------------------------------------------------

_BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


def new_request_id() -> str:
    """A fresh AuthnRequest ID: an xsd:ID (an NCName, so it must not start with a digit — hence the leading
    underscore) carrying 160 random bits. Single-use: the edge binds it to one login and spends it at the ACS."""
    return "_" + secrets.token_hex(20)


def _instant(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_authn_request(request_id: str, *, sp_entity_id: str, acs_url: str, idp_sso_url: str,
                        issue_instant: float) -> bytes:
    """The SAML 2.0 `<samlp:AuthnRequest>` for one SP-initiated login: our SP entity id as Issuer, our ACS as the
    response target (HTTP-POST binding), the IdP endpoint as Destination. Every value is attribute-QUOTED /
    text-escaped, so a config value can never break out of the XML. Fail-closed on a blank field."""
    for what, v in (("request_id", request_id), ("sp_entity_id", sp_entity_id), ("acs_url", acs_url),
                    ("idp_sso_url", idp_sso_url)):
        if not isinstance(v, str) or not v.strip():
            raise SamlError(f"cannot build an AuthnRequest without {what}")
    issuer = escape(sp_entity_id)
    xml = (f'<samlp:AuthnRequest xmlns:samlp="{_NS_PROTO}" xmlns:saml="{_NS_ASSERT}" '
           f'ID={quoteattr(request_id)} Version="2.0" IssueInstant={quoteattr(_instant(issue_instant))} '
           f'Destination={quoteattr(idp_sso_url)} AssertionConsumerServiceURL={quoteattr(acs_url)} '
           f'ProtocolBinding="{_BINDING_POST}">'
           f'<saml:Issuer>{issuer}</saml:Issuer>'
           f'<samlp:NameIDPolicy AllowCreate="true"/>'
           f'</samlp:AuthnRequest>')
    return xml.encode("utf-8")


def authn_request_redirect_url(idp_sso_url: str, authn_request_xml: bytes, relay_state: str) -> str:
    """The HTTP-Redirect binding URL (SAML Bindings §3.4): `SAMLRequest` = base64(raw DEFLATE(request)) and the
    opaque `RelayState`, appended to the IdP's sign-in URL. Refuses a non-https IdP URL (the owner-signed config
    is https-only; this is the keyless edge's own last check before redirecting a browser)."""
    parts = urllib.parse.urlparse(str(idp_sso_url or ""))
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise SamlError("the IdP sign-in URL must be an absolute https URL")
    if not isinstance(relay_state, str) or not relay_state:
        raise SamlError("a RelayState is required")
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)          # raw DEFLATE (no zlib header / adler32), per §3.4.4.1
    deflated = comp.compress(bytes(authn_request_xml)) + comp.flush()
    query = urllib.parse.urlencode({"SAMLRequest": base64.b64encode(deflated).decode("ascii"),
                                    "RelayState": relay_state})
    return idp_sso_url + ("&" if parts.query else "?") + query
