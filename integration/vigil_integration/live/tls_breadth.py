"""tls_breadth — HexStrike Wave 3: widen the TLS_WEAKNESS family from one narrow claim to the set of TLS
properties VIGIL can prove with ITS OWN gated handshake.

THE DOCTRINE THIS MODULE EXISTS TO HOLD. ``sslscan``'s output bytes are never evidence. The tool is a
PROPOSER: it says "there is a TLS service at host:port". Everything after that is VIGIL's own work — VIGIL
negotiates the handshake itself, through the SAME audited gate ``verify.reachability._authorize`` guards
(kill-switch -> single-host -> ACTIVE_RECON entitlement -> charter scope, engagement slug required,
fail-closed), retains the JSON-safe result, and a deterministic oracle judges THAT. Nothing here parses tool
stdout. Every capture in this module goes through ``verify.tls.capture_tls_handshake`` with an INJECTED
connector, so the gate, the single bounded attempt and the retained-evidence shape are byte-for-byte the
ones the existing TLS re-drive already uses — this adds no new egress path.

THE FOUR CLAIMS, and what each one honestly is:

  1. DEPRECATED PROTOCOL ACCEPTED (FACT). VIGIL offers ONLY TLS1.0 (then only TLS1.1) and the endpoint
     completes the handshake. The negotiated version is then, by construction, the deprecated one, and the
     EXISTING ``tls_weakness_oracle`` fires on it (``_DEPRECATED_TLS_VERSIONS``). Existential: the server
     really agreed, and the retained evidence re-verifies offline.

  2. DEPRECATED PROTOCOL REFUSED (CLEAN — a CHANNEL-CONFIRMED NEGATIVE). VIGIL offers ONLY TLS1.0 and the
     PEER answers on the established TCP channel with a ``protocol_version(70)`` alert. This is one of the
     very few genuinely CLEAN-capable cases in the product: the negative is something the peer SAID, not an
     absence of signal. :func:`is_conclusive_protocol_refusal` is the CLOSED, deterministic predicate that
     decides it, and it is deliberately narrow — see its docstring. A timeout, a TCP reset, a DNS failure,
     a refused connect, a locally-unsupported protocol, or ANY other alert (including the ambiguous
     ``handshake_failure(40)``) is INCONCLUSIVE. Never CLEAN.

  3. WEAK CIPHER NEGOTIATED (FACT). VIGIL offers ONLY suites drawn from :data:`WEAK_CIPHER_OFFER` — a
     CLOSED, explicit vocabulary of named suites, never a pattern over suite names — and the endpoint
     SELECTS one. The selection is then checked for membership in the exact set VIGIL offered before any
     context is built, and the existing ``tls_weakness_oracle`` independently classifies the negotiated
     name. A refusal is NOT clean here (see the branch's ``blocking_work``): the local OpenSSL build limits
     which legacy suites can be offered at all, so "refused" may mean "never tested".

  4. CERTIFICATE DEFECTS over the retained chain (LEAD-only TODAY). :func:`classify_certificate_defects`
     re-derives expiry / not-yet-valid / hostname mismatch / self-signed from the RETAINED leaf DER, so the
     derivation is pure and re-runnable offline. It is LEAD-only because NO ``OracleKind`` in
     ``verify/models.py`` adjudicates certificate VALIDITY — ``tls_weakness_oracle`` judges the negotiated
     protocol/cipher and ``weak_crypto_artifact_oracle`` judges the signature hash and key size; neither
     reads a validity window, a SAN, or an issuer. The gap is named in the branch's ``blocking_work``.

DETERMINISTIC EXPIRY. A validity comparison needs an instant. Taking it from a wall clock at verify time
would make offline re-verification non-deterministic (the same retained evidence would flip verdict as the
clock moves past ``notAfter``). So the instant is RETAINED IN THE EVIDENCE at capture
(``captured_at_epoch``, stamped by the runner when it performed the handshake) and the classifier reads it
from there and nowhere else. The claim it supports is therefore scoped: "at the instant VIGIL captured this
handshake, the presented leaf was outside its validity window" — bound into the certificate context digest,
so a tamper that moves the instant breaks verification rather than silently re-deciding.

HANDSHAKE BUDGET. :data:`TLS_HANDSHAKE_BUDGET_PER_ENDPOINT` handshakes per (host, port), enforced
structurally: ``run_external_tool`` memoises one capture per DISTINCT capture callable per proposed service
(``id(rd.capture)``), and ``external_tool._TLS_REDRIVES`` carries exactly that many distinct callables. No
retries, no per-suite enumeration loop, no UA/version rotation (Constitution VI.4 — VIGIL stays
correlatable).

FATAL-2: every ``framework`` import is FUNCTION-LOCAL; module import pulls in stdlib only.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# Budget + closed vocabularies. Each of these is a DATA declaration a reviewer can read in one screen;
# none of them is a pattern match over a name.
# ---------------------------------------------------------------------------

#: TLS handshakes VIGIL performs per (host, port) endpoint in one ``tls_scan`` run. Structurally enforced by
#: the count of DISTINCT capture callables on ``external_tool._TLS_REDRIVES`` (the runner memoises per
#: ``id(rd.capture)``), and pinned by ``test_tls_breadth.py::test_the_handshake_budget_is_structural``.
TLS_HANDSHAKE_BUDGET_PER_ENDPOINT = 4

#: The deprecated protocol versions VIGIL offers ONE AT A TIME, each in its own single bounded handshake.
#: Spelled as ``ssl.TLSVersion`` attribute NAMES so the module imports without touching ``ssl`` at load.
#: SSLv2/SSLv3 are deliberately absent: modern OpenSSL cannot offer them at all, so probing for them would
#: produce a ``local_unsupported`` non-result every time and imply a test that never ran.
DEPRECATED_VERSION_PROBES: "tuple[tuple[str, str], ...]" = (
    ("TLSv1", "TLSv1"),
    ("TLSv1_1", "TLSv1.1"),
)

#: THE CLOSED WEAK-CIPHER VOCABULARY. An explicit list of OpenSSL suite NAMES, each one a construction with
#: a published practical break (no encryption / export-grade / RC4 keystream / 56- or 64-bit block /
#: unauthenticated key exchange). VIGIL offers exactly these and nothing else; a suite absent from this
#: tuple is not offered and therefore never tested. This is a membership test on a fixed list — deciding
#: "is this suite weak?" by pattern-matching its name is precisely the hand-approximation this program
#: forbids, because ``TLS_AES_128_GCM_SHA256`` and ``ADH-AES128-SHA`` differ by a prefix.
WEAK_CIPHER_OFFER: "tuple[str, ...]" = (
    # no encryption at all
    "NULL-MD5", "NULL-SHA", "NULL-SHA256",
    "ECDHE-RSA-NULL-SHA", "ECDHE-ECDSA-NULL-SHA",
    # export-grade (deliberately weakened)
    "EXP-RC4-MD5", "EXP-RC2-CBC-MD5", "EXP-DES-CBC-SHA", "EXP-EDH-RSA-DES-CBC-SHA",
    # RC4 keystream biases
    "RC4-MD5", "RC4-SHA", "ECDHE-RSA-RC4-SHA", "ECDHE-ECDSA-RC4-SHA", "ADH-RC4-MD5",
    # single-DES (56-bit key) and 3DES (64-bit block / Sweet32)
    "DES-CBC-SHA", "EDH-RSA-DES-CBC-SHA",
    "DES-CBC3-SHA", "EDH-RSA-DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA", "ECDHE-ECDSA-DES-CBC3-SHA", "ADH-DES-CBC3-SHA",
    # anonymous key exchange — no server authentication, trivially MITM-able
    "ADH-AES128-SHA", "ADH-AES256-SHA", "ADH-AES128-SHA256", "ADH-AES256-SHA256",
    "AECDH-AES128-SHA", "AECDH-AES256-SHA", "AECDH-DES-CBC3-SHA", "AECDH-RC4-SHA",
)

#: The OpenSSL error reason that means THE PEER SENT ``alert(70) protocol_version`` on an established
#: channel. A CLOSED SINGLETON, and the single most load-bearing declaration in this module.
#:
#: Why exactly one entry. OpenSSL's ``TLSV1_ALERT_*`` reason family is reserved for alerts RECEIVED FROM THE
#: PEER; locally-generated version failures surface as ``UNSUPPORTED_PROTOCOL`` / ``VERSION_TOO_LOW`` /
#: ``NO_PROTOCOLS_AVAILABLE`` (see :data:`LOCAL_VERSION_UNSUPPORTED_REASONS`). So this reason — and only
#: this reason — is a statement the ENDPOINT made about the version VIGIL offered, which is what makes the
#: negative channel-confirmed rather than an absence of signal. It is also what RFC 8446 §4.1.1 and RFC 5246
#: §7.2.2 REQUIRE a server to send when it will not speak the offered version.
#:
#: Deliberately EXCLUDED, with the reason:
#:   * ``SSLV3_ALERT_HANDSHAKE_FAILURE`` (alert 40) — ambiguous. A server sends it for no shared cipher, no
#:     shared version, a client-certificate problem, or a policy refusal. Treating it as a version refusal
#:     would let "we could not agree on a cipher" launder into "TLS1.0 is disabled".
#:   * ``TLSV1_ALERT_INSUFFICIENT_SECURITY`` (alert 71) — closer, but it speaks about parameters in
#:     general, not the protocol version specifically.
#:   * ``WRONG_VERSION_NUMBER`` / ``UNSUPPORTED_PROTOCOL`` — these fire when the port is not speaking TLS at
#:     all (plain HTTP answering on 443 produces ``WRONG_VERSION_NUMBER``). Admitting them would report
#:     "this endpoint refuses TLS1.0" for an endpoint that refuses TLS entirely.
#: The cost of this narrowness is UNDER-claiming CLEAN against non-conforming servers. That is the correct
#: direction to be wrong in.
VERSION_REJECTION_REASONS: "frozenset[str]" = frozenset({"TLSV1_ALERT_PROTOCOL_VERSION"})

#: Reasons that mean the LOCAL OpenSSL build would not or could not offer the requested protocol. A
#: capability gap on VIGIL's side is never a statement about the endpoint — always INCONCLUSIVE.
LOCAL_VERSION_UNSUPPORTED_REASONS: "frozenset[str]" = frozenset({
    "NO_PROTOCOLS_AVAILABLE", "UNSUPPORTED_PROTOCOL", "VERSION_TOO_LOW", "VERSION_TOO_HIGH",
    "WRONG_SSL_VERSION", "UNSUPPORTED_SSL_VERSION",
})

# --- the CLOSED failure-class vocabulary a capture may report ------------------------------------------
FAILURE_GATE_REFUSED = "gate_refused"              # the audited gate refused; no packet left      -> INCONCLUSIVE
FAILURE_LOCAL_UNSUPPORTED = "local_unsupported"    # our own stack could not make the offer        -> INCONCLUSIVE
FAILURE_TRANSPORT = "transport_error"              # DNS / connect / reset / timeout / EOF         -> INCONCLUSIVE
FAILURE_VERSION_REJECTED = "protocol_version_rejected"   # peer alert(70) on an open channel       -> CLEAN
FAILURE_TLS_OTHER = "tls_error_other"              # some other TLS alert or SSL error             -> INCONCLUSIVE

#: Every failure class except :data:`FAILURE_VERSION_REJECTED` is inconclusive. Spelled out as a set rather
#: than ``!= FAILURE_VERSION_REJECTED`` so adding a class cannot accidentally inherit CLEAN authority.
INCONCLUSIVE_FAILURE_CLASSES: "frozenset[str]" = frozenset({
    FAILURE_GATE_REFUSED, FAILURE_LOCAL_UNSUPPORTED, FAILURE_TRANSPORT, FAILURE_TLS_OTHER,
})

_DEFAULT_TIMEOUT = 5.0
#: Appended to every cipher string so the local policy layer does not veto the legacy suites VIGIL wants to
#: OFFER. It relaxes what VIGIL is willing to propose; it grants the endpoint nothing and weakens no claim —
#: the FACT is still "the endpoint SELECTED this suite".
_SECLEVEL0 = ":@SECLEVEL=0"


# ---------------------------------------------------------------------------
# Local offerability — a pure, offline capability probe (no network, no target).
# ---------------------------------------------------------------------------
def offerable_weak_ciphers(offer: "tuple[str, ...]" = WEAK_CIPHER_OFFER) -> "tuple[str, ...]":
    """The subset of the closed weak-cipher vocabulary THIS OpenSSL build can actually put in a ClientHello.

    Modern OpenSSL (3.x) has removed RC4, single-DES, 3DES and the export suites from the default provider,
    so most of :data:`WEAK_CIPHER_OFFER` cannot be offered here at all. A suite VIGIL could not offer was
    never tested, and reporting a refusal over it would be a claim about the endpoint drawn from a gap in
    VIGIL. This function is what keeps that distinction explicit: the capture records exactly which suites
    went into the ClientHello, and an EMPTY result makes the weak-cipher probe a no-op (SKIPPED), never a
    negative finding. Pure and offline — it builds throwaway contexts and sends nothing."""
    import ssl

    out: list[str] = []
    for suite in offer:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers(suite + _SECLEVEL0)
        except Exception:  # noqa: BLE001 — an unusable suite is simply not offerable here
            continue
        out.append(suite)
    return tuple(out)


# ---------------------------------------------------------------------------
# The connector — the ONLY place a socket is opened, and it is opened INSIDE
# verify.tls.capture_tls_handshake's gate (the connector is injected into it).
# ---------------------------------------------------------------------------
def _classify_ssl_error(exc: Exception) -> "tuple[str, str]":
    """(failure_class, ssl_reason) for a handshake exception. Deterministic and CLOSED — the reason string
    is matched against the frozensets above, never pattern-matched."""
    import ssl

    if isinstance(exc, ssl.SSLError):
        reason = str(getattr(exc, "reason", "") or "")
        if reason in VERSION_REJECTION_REASONS:
            return FAILURE_VERSION_REJECTED, reason
        if reason in LOCAL_VERSION_UNSUPPORTED_REASONS:
            return FAILURE_LOCAL_UNSUPPORTED, reason
        if isinstance(exc, ssl.SSLEOFError):
            # the peer closed without an alert — it said nothing, so we conclude nothing
            return FAILURE_TRANSPORT, reason
        return FAILURE_TLS_OTHER, reason
    return FAILURE_TRANSPORT, ""


def _restricted_connect(
    host: str,
    port: int,
    timeout: float,
    *,
    min_version_name: "str | None",
    max_version_name: "str | None",
    ciphers: "str | None",
    box: dict,
) -> "tuple[str, str, int | None, bytes | None]":
    """ONE bounded TLS handshake with a RESTRICTED offer, shaped exactly like ``verify.tls._tls_connect``
    (same create_connection -> wrap_socket -> read the negotiated params and the presented leaf DER; cert
    validation off, because this is a posture probe and must work against self-signed endpoints).

    The only difference is that the client context is narrowed to the protocol version and/or cipher list
    the caller wants to OFFER. Failures are CLASSIFIED into ``box`` and then re-raised, so
    ``capture_tls_handshake`` still returns its standard ``connected: False`` evidence and the structured
    classification travels beside it — the caller never has to parse an error string."""
    import socket
    import ssl

    box["connector_invoked"] = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if ciphers is not None:
            ctx.set_ciphers(ciphers + _SECLEVEL0)
        if min_version_name is not None:
            ctx.minimum_version = getattr(ssl.TLSVersion, min_version_name)
        if max_version_name is not None:
            ctx.maximum_version = getattr(ssl.TLSVersion, max_version_name)
    except Exception as e:  # noqa: BLE001 — our stack refused to make the offer; that is OUR gap
        box["failure_class"] = FAILURE_LOCAL_UNSUPPORTED
        box["failure_detail"] = f"{type(e).__name__}: {e}"[:200]
        raise

    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        raw = socket.create_connection((bare, int(port)), timeout=timeout)
    except Exception as e:  # noqa: BLE001 — DNS / refused / unreachable / connect timeout
        box["failure_class"] = FAILURE_TRANSPORT
        box["failure_detail"] = f"{type(e).__name__}: {e}"[:200]
        raise
    box["tcp_established"] = True
    try:
        raw.settimeout(timeout)
        try:
            tls = ctx.wrap_socket(raw, server_hostname=bare)
        except Exception as e:  # noqa: BLE001 — the handshake itself failed; classify WHY
            klass, reason = _classify_ssl_error(e)
            box["failure_class"] = klass
            box["ssl_reason"] = reason
            box["failure_detail"] = f"{type(e).__name__}: {e}"[:200]
            raise
        with tls:
            version = tls.version() or ""
            cipher = tls.cipher()
            try:
                cert_der = tls.getpeercert(binary_form=True)
            except Exception:  # noqa: BLE001
                cert_der = None
    finally:
        try:
            raw.close()
        except OSError:
            pass
    name = cipher[0] if cipher else ""
    bits = cipher[2] if cipher and len(cipher) > 2 else None
    return version, name, (int(bits) if isinstance(bits, int) else None), cert_der


def _capture(
    host: str,
    port: int,
    *,
    slug: str,
    timeout: float,
    min_version_name: "str | None",
    max_version_name: "str | None",
    ciphers: "str | None",
    offered: dict,
    now: "Callable[[], int] | None" = None,
) -> dict:
    """Run one restricted handshake through ``verify.tls.capture_tls_handshake`` (THE gate) and return its
    JSON-safe evidence enriched with (a) what VIGIL OFFERED, (b) the structured failure classification, and
    (c) the retained capture instant. Never raises: a gate refusal, a local gap and a peer refusal all come
    back as ``connected: False`` evidence carrying a ``failure_class``."""
    from framework.v2.verify import capture_tls_handshake  # noqa: PLC0415 (FATAL-2: function-local)

    box: dict = {}

    def connector(h: str, p: int, t: float):
        return _restricted_connect(h, p, t, min_version_name=min_version_name,
                                   max_version_name=max_version_name, ciphers=ciphers, box=box)

    base = capture_tls_handshake(str(host), int(port), slug=slug, timeout=timeout, connect=connector)
    stamp = int((now or (lambda: int(time.time())))())
    out = dict(base)
    out.update(offered)
    out["captured_at_epoch"] = stamp
    out["capture_time_source"] = "runner_clock"
    out["gate_authorized"] = bool(box.get("connector_invoked", False))
    out["tcp_established"] = bool(box.get("tcp_established", False))
    if out.get("connected") is True:
        out["failure_class"] = ""
    else:
        out["failure_class"] = str(box.get("failure_class") or FAILURE_GATE_REFUSED)
        if box.get("ssl_reason"):
            out["ssl_reason"] = str(box["ssl_reason"])
        if box.get("failure_detail"):
            out["failure_detail"] = str(box["failure_detail"])
    return out


def capture_version_restricted_handshake(
    host: str,
    port: int = 443,
    *,
    slug: str = "",
    version_attr: str = "TLSv1",
    version_label: str = "TLSv1",
    timeout: float = _DEFAULT_TIMEOUT,
    now: "Callable[[], int] | None" = None,
) -> dict:
    """Offer ONLY ``version_label`` and capture what happened (claims 1 and 2).

    A completed handshake means the endpoint agreed to the deprecated version — the FACT. A
    ``protocol_version`` alert means it refused — the CLEAN, subject to
    :func:`is_conclusive_protocol_refusal`. Anything else is inconclusive."""
    return _capture(host, port, slug=slug, timeout=timeout,
                    min_version_name=version_attr, max_version_name=version_attr, ciphers=None,
                    offered={"probe": "deprecated_protocol_offer",
                             "offered_only_version": version_label,
                             "offered_ciphers": []},
                    now=now)


def capture_weak_cipher_handshake(
    host: str,
    port: int = 443,
    *,
    slug: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
    offer: "tuple[str, ...]" = WEAK_CIPHER_OFFER,
    now: "Callable[[], int] | None" = None,
) -> dict:
    """Offer ONLY the locally-offerable subset of the closed weak-cipher vocabulary and capture what the
    endpoint SELECTED (claim 3).

    When the local build can offer none of them the capture returns ``connected: False`` with
    ``failure_class = local_unsupported`` and an EMPTY ``offered_ciphers`` — nothing was tested, so the
    re-drive is skipped rather than scored."""
    offerable = offerable_weak_ciphers(offer)
    if not offerable:
        return {"connected": False, "host": str(host), "port": int(port),
                "probe": "weak_cipher_offer", "offered_only_version": "",
                "offered_ciphers": [], "captured_at_epoch": int((now or (lambda: int(time.time())))()),
                "capture_time_source": "runner_clock", "gate_authorized": False,
                "tcp_established": False, "failure_class": FAILURE_LOCAL_UNSUPPORTED,
                "failure_detail": "this OpenSSL build can offer none of the closed weak-cipher vocabulary"}
    # Cap the offer at TLS1.2. ``set_ciphers`` governs the TLS<=1.2 suite list ONLY — TLS1.3's five suites are
    # negotiated through a separate list an OpenSSL client always offers — so without this cap a TLS1.3-
    # preferring server would negotiate an AEAD suite outside the recorded offer, the membership check would
    # (correctly) decline to score it, and the weak-suite question would silently go untested. Capping makes
    # the restricted offer actually govern the negotiation. Nothing is lost: every suite in the closed
    # vocabulary is a TLS<=1.2 construction, and TLS1.3's suite set contains none of them.
    return _capture(host, port, slug=slug, timeout=timeout,
                    min_version_name=None, max_version_name="TLSv1_2", ciphers=":".join(offerable),
                    offered={"probe": "weak_cipher_offer", "offered_only_version": "",
                             "offered_max_version": "TLSv1.2",
                             "offered_ciphers": list(offerable)},
                    now=now)


# ---------------------------------------------------------------------------
# The deterministic predicates. Pure functions over RETAINED evidence: an offline verifier re-runs them and
# gets the same answer, because they read nothing but the dict they are handed.
# ---------------------------------------------------------------------------
def is_conclusive_protocol_refusal(evidence: Any) -> bool:
    """THE CLEAN PREDICATE for claim 2, and the single most attackable decision in this slice.

    True iff ALL of the following hold over the RETAINED capture:

      * the audited gate authorised the probe (``gate_authorized``) — otherwise nothing was sent;
      * the TCP channel was ESTABLISHED (``tcp_established``) — a negative the peer never had a chance to
        state is not a negative;
      * the handshake did NOT complete (``connected`` is not True) — a completed handshake is claim 1;
      * VIGIL had actually restricted the offer to a DEPRECATED version (``offered_only_version`` names one
        of :data:`DEPRECATED_VERSION_PROBES`) — a refusal of something we did not narrow to proves nothing
        about that version;
      * the failure class is EXACTLY :data:`FAILURE_VERSION_REJECTED`, i.e. the peer sent
        ``alert(70) protocol_version``;
      * and the recorded ``ssl_reason`` is itself in the closed :data:`VERSION_REJECTION_REASONS`, so a
        hand-edited ``failure_class`` alone cannot manufacture a CLEAN.

    Every other shape — a timeout, a reset, a refused connect, a DNS failure, an EOF, a locally-unsupported
    protocol, an ambiguous ``handshake_failure(40)``, or a gate refusal — returns False and the branch is
    admitted INCONCLUSIVE. That is the laundering this predicate exists to prevent: an absence of signal
    must never be sold as a clean bill of health."""
    if not isinstance(evidence, dict):
        return False
    if evidence.get("connected") is True:
        return False
    if not bool(evidence.get("gate_authorized")):
        return False
    if not bool(evidence.get("tcp_established")):
        return False
    if str(evidence.get("offered_only_version") or "") not in {lbl for _, lbl in DEPRECATED_VERSION_PROBES}:
        return False
    if str(evidence.get("failure_class") or "") != FAILURE_VERSION_REJECTED:
        return False
    return str(evidence.get("ssl_reason") or "") in VERSION_REJECTION_REASONS


def negotiated_weak_cipher(evidence: Any) -> str:
    """The suite the endpoint SELECTED, but ONLY when it is a member of the exact closed set VIGIL offered
    in this very capture. Returns ``""`` otherwise.

    The membership test is against ``evidence["offered_ciphers"]`` — the list recorded at capture — not
    against the global vocabulary and never against a pattern. If a stack ever negotiated something outside
    the offer, that is an anomaly VIGIL declines to score rather than a weak-cipher finding."""
    if not isinstance(evidence, dict) or evidence.get("connected") is not True:
        return ""
    offered = evidence.get("offered_ciphers") or []
    if not isinstance(offered, (list, tuple)) or not offered:
        return ""
    name = str(evidence.get("cipher") or "")
    return name if name in {str(s) for s in offered} else ""


# ---------------------------------------------------------------------------
# Claim 4 — certificate defects re-derived from the RETAINED DER at the RETAINED instant.
# ---------------------------------------------------------------------------
#: The closed defect vocabulary. A defect absent from this tuple is not reported.
CERTIFICATE_DEFECTS: "tuple[str, ...]" = ("expired", "not_yet_valid", "hostname_mismatch", "self_signed")


def _cert_epochs(cert) -> "tuple[int, int]":
    """(not_before, not_after) as UTC epochs, preferring the timezone-aware accessors so the comparison is
    unambiguous on every ``cryptography`` version."""
    import datetime

    def _epoch(aware_attr: str, naive_attr: str) -> int:
        dt = getattr(cert, aware_attr, None)
        if dt is None:
            dt = getattr(cert, naive_attr)
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())

    return (_epoch("not_valid_before_utc", "not_valid_before"),
            _epoch("not_valid_after_utc", "not_valid_after"))


def _identity_matches(cert, host: str) -> "tuple[bool, list[str]]":
    """(matched, presented_identities) for ``host`` against the leaf's SAN dNSName / iPAddress entries,
    falling back to the subject CN only when the cert presents no SAN at all (RFC 6125 §6.4.4). Wildcards
    match ONE left-most label, as a browser does. Deterministic: no DNS, no clock, no network."""
    import ipaddress

    from cryptography import x509

    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.extend(str(n) for n in san.get_values_for_type(x509.DNSName))
        names.extend(str(n) for n in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass
    if not names:
        try:
            from cryptography.x509.oid import NameOID
            names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
        except Exception:  # noqa: BLE001
            names = []
    target = (host or "").strip().strip("[]").lower()
    try:
        target_ip: "ipaddress._BaseAddress | None" = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None
    for raw in names:
        cand = str(raw).strip().lower()
        if target_ip is not None:
            try:
                if ipaddress.ip_address(cand) == target_ip:
                    return True, [str(n) for n in names]
            except ValueError:
                continue
            continue
        if cand == target:
            return True, [str(n) for n in names]
        if cand.startswith("*.") and "." in target and target.split(".", 1)[1] == cand[2:]:
            return True, [str(n) for n in names]
    return False, [str(n) for n in names]


def classify_certificate_defects(evidence: Any) -> "Optional[dict]":
    """Re-derive the presented leaf's validity defects from the RETAINED DER, at the RETAINED instant.

    Returns ``None`` when there is nothing to judge (no capture, no retained certificate, no retained
    instant, or unparseable DER) — an absent input is never a clean certificate. Otherwise returns a
    JSON-safe record carrying the comparison instant, the validity window, the presented identities and the
    ``defects`` list drawn from the closed :data:`CERTIFICATE_DEFECTS` vocabulary.

    DETERMINISM. ``at_epoch`` comes from ``evidence["captured_at_epoch"]`` — the instant the runner recorded
    when it performed the handshake — and NEVER from a clock read here. Re-running this function over the
    same retained evidence therefore yields the same verdict in a year's time, which is what makes an
    offline re-verification meaningful. The corresponding honesty cost is stated on the branch: the instant
    is the RUNNER's clock, not a trusted timestamp, so the claim is scoped to "at the instant of capture".

    ``self_signed`` is derived structurally (issuer == subject AND the leaf verifies under its own public
    key), not from trust-store lookup: VIGIL's capture deliberately runs with validation off, so it retains
    only the leaf and has no chain to anchor."""
    if not isinstance(evidence, dict):
        return None
    b64 = evidence.get("cert_der_b64")
    if not b64:
        return None
    at = evidence.get("captured_at_epoch")
    if not isinstance(at, int):
        return None
    import base64

    try:
        der = base64.b64decode(str(b64))
    except Exception:  # noqa: BLE001
        return None
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        not_before, not_after = _cert_epochs(cert)
    except Exception:  # noqa: BLE001 — unparseable DER judges nothing
        return None

    host = str(evidence.get("host") or "")
    defects: list[str] = []
    if at > not_after:
        defects.append("expired")
    if at < not_before:
        defects.append("not_yet_valid")
    matched, presented = _identity_matches(cert, host)
    if not matched:
        defects.append("hostname_mismatch")
    if _is_self_signed(cert):
        defects.append("self_signed")

    return {
        "host": host,
        "at_epoch": at,
        "at_epoch_source": str(evidence.get("capture_time_source") or "runner_clock"),
        "not_before_epoch": not_before,
        "not_after_epoch": not_after,
        "presented_identities": presented,
        "issuer": cert.issuer.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "defects": [d for d in CERTIFICATE_DEFECTS if d in defects],
    }


def _is_self_signed(cert) -> bool:
    """True iff issuer == subject AND the certificate's signature verifies under its OWN public key. The
    second half matters: a name collision alone is not self-issuance. Fail-closed — any verification error
    returns False rather than asserting self-signature."""
    try:
        if cert.issuer != cert.subject:
            return False
    except Exception:  # noqa: BLE001
        return False
    try:
        cert.verify_directly_issued_by(cert)
        return True
    except Exception:  # noqa: BLE001
        return False
