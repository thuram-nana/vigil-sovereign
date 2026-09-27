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

  2. DEPRECATED PROTOCOL REFUSED — **INCONCLUSIVE, ALWAYS. NOT A CLEAN.** VIGIL offers ONLY TLS1.0 and the
     PEER answers on the established TCP channel with a ``protocol_version(70)`` alert. That is a real
     statement by a real peer, and it is still not enough to clear the ENDPOINT, because **the refusal and
     any corroborating handshake are on two DIFFERENT TCP CONNECTIONS, and nothing in the evidence binds
     them to the same peer.** An L4 fan-out — a Kubernetes Service with several pods, an haproxy/nginx TCP
     pool, an L4 VIP, a DNS A-record pool mid-rollout — answers one connection from a backend whose
     minimum is TLS1.1 and the next from a backend that speaks TLS1.0; VIGIL would then hold a genuine
     ``alert(70)`` beside a genuine completed session while the endpoint as a whole accepts TLS1.0. It
     does not even look wrong: ``minimum_version=TLSv1.1`` is a legal configuration, so "refused at 1.0,
     completed at 1.1" is internally consistent and undetectable as self-contradiction. The limit is
     IRREDUCIBLE with what TLS hands the refused leg: the completed leg retains ``spki_sha256``, but a
     refusing peer sends the alert IN PLACE OF the ServerHello and presents no certificate, no server
     random and no session id — there is nothing on that side to bind against. Re-probing k times would
     only make the claim probabilistic, which the oracle doctrine forbids. So the registry declares this
     branch ``clean_capable: false``, a refusal is admitted INCONCLUSIVE, and the row's ``blocking_work``
     names what a sound CLEAN would actually require.
     THE GUARDS BELOW ARE KEPT AND STILL RUN. :func:`is_conclusive_protocol_refusal` remains the CLOSED,
     deterministic predicate and :func:`peer_tls_session_witness` still stamps the peer-session witness
     that closed the bare-``alert(70)``-emitter hole. Every sub-condition is mutation-defended, and they
     are the right guards if this class is ever revived at a stronger capability; they simply no longer
     reach CLEAN. A timeout, a TCP reset, a DNS failure, a refused connect, a locally-unsupported
     protocol, ANY other alert (including the ambiguous ``handshake_failure(40)``), and a peer VIGIL never
     completed a single TLS session with were already INCONCLUSIVE and remain so.

  3. WEAK CIPHER NEGOTIATED (FACT). VIGIL offers ONLY suites drawn from :data:`WEAK_CIPHER_OFFER` — a
     CLOSED, explicit vocabulary of named suites, never a pattern over suite names — and the endpoint
     SELECTS one. The selection is then checked for membership in the exact set VIGIL offered before any
     context is built, and the existing ``tls_weakness_oracle`` independently classifies the negotiated
     name. A refusal is NOT clean here (see the branch's ``blocking_work``): the local OpenSSL build limits
     which legacy suites can be offered at all, so "refused" may mean "never tested".

  4. CERTIFICATE DEFECTS over the retained leaf — BUILT, TESTED, **NOT WIRED**.
     :func:`classify_certificate_defects` re-derives expiry / not-yet-valid / hostname mismatch /
     self-signed from a RETAINED leaf DER at a RETAINED instant, so the derivation is pure and re-runnable
     offline. NOTHING IN THE PRODUCT DRIVES IT TODAY: no re-drive on ``external_tool._TLS_REDRIVES`` admits
     to ``tls_weakness.certificate_validity``, and no live capture in this module retains the
     ``captured_at_epoch`` the classifier requires, so against live evidence it returns ``None``.
     The reason is that no ``OracleKind`` adjudicates certificate VALIDITY — ``tls_weakness_oracle`` judges
     the negotiated protocol/cipher, ``weak_crypto_artifact_oracle`` judges the signature hash and key
     size; neither reads a validity window, a SAN or an issuer. A re-drive wired to that branch could
     therefore never emit anything but INCONCLUSIVE, so it was REMOVED rather than left to report a verdict
     with an untrue reason. The registry row keeps ``wired: false`` and names the work in
     ``blocking_work``; :func:`classify_certificate_defects` stays as the reviewed, tested derivation that
     wiring will use. See ``test_tls_breadth.py`` §5.

DETERMINISTIC EXPIRY (the property the unwired claim-4 derivation preserves). A validity comparison needs
an instant. Taking it from a wall clock at verify time would make offline re-verification
non-deterministic — the same retained evidence would flip verdict as the clock moves past ``notAfter``. So
:func:`classify_certificate_defects` reads ``evidence["captured_at_epoch"]`` and NEVER a clock, and returns
``None`` when the evidence carries no instant. Deliberately, no capture path here stamps that field: a
runner wallclock is an untrusted, non-reproducible value, and putting one inside signed evidence NO CLAIM
CONSUMES would be nondeterminism for nothing. Wiring claim 4 means re-introducing the retention at the
capture that feeds it, and saying so as a certificate-invalidating change for that branch.

HANDSHAKE BUDGET. :data:`TLS_HANDSHAKE_BUDGET_PER_ENDPOINT` handshakes per (host, port), enforced
structurally: ``run_external_tool`` memoises one capture per DISTINCT capture callable per proposed service
(``id(rd.capture)``), and ``external_tool._TLS_REDRIVES`` carries exactly that many distinct callables. No
retries, no per-suite enumeration loop, no UA/version rotation (Constitution VI.4 — VIGIL stays
correlatable). COST: the budget is also the worst-case STALL. Against an unresponsive in-scope host each of
the four handshakes burns its own full ``_DEFAULT_TIMEOUT``, so one endpoint can hold a ``tls_scan`` run for
~4x the single-probe timeout (~20s at the default 5s) where the pre-WAVE-3 spec held it for ~5s. That is a
throughput cost on a wide sweep, not a correctness one; shrink ``timeout`` rather than the budget if it
bites.

FATAL-2: every ``framework`` import is FUNCTION-LOCAL; module import pulls in stdlib only.
"""

from __future__ import annotations

from typing import Any, Optional

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

#: THE CLOSED WEAK-CIPHER VOCABULARY — **29** named suites (pinned by
#: ``test_tls_breadth.py::test_the_weak_cipher_vocabulary_size_is_pinned``; on the OpenSSL this repo builds
#: against, 11 of them are actually offerable — see :func:`offerable_weak_ciphers`). Each is a construction
#: with a published practical break (no encryption / export-grade / RC4 keystream / 56- or 64-bit block /
#: unauthenticated key exchange). VIGIL offers exactly these and nothing else; a suite absent from this
#: tuple is not offered and therefore never tested. This is a membership test on a fixed list — deciding
#: "is this suite weak?" by pattern-matching its name is precisely the hand-approximation this program
#: forbids, because weak and strong suite names share long substrings: ``AECDH-AES128-SHA`` (anonymous, so
#: weak) contains ``ECDH`` and ``AES128-SHA``, both of which also occur in authenticated suites, and
#: ``ECDHE-ECDSA-RC4-SHA`` (weak) and ``ECDHE-ECDSA-AES128-GCM-SHA256`` (strong) differ only after the
#: shared key-exchange prefix.
#:
#: THAT ARGUMENT IS NOW DEFENDED BY A TEST, not only by this comment. A review found that replacing the
#: exact set membership in :func:`negotiated_weak_cipher` with a bidirectional substring rule left the
#: whole suite green — the collisions were asserted as string facts but never fed through the function.
#: ``test_tls_breadth.py::test_a_substring_rule_would_score_a_suite_the_endpoint_was_never_offered`` is
#: the kill fixture: an endpoint that selects ``AES128-SHA`` from an offer of ``AECDH-AES128-SHA`` scores
#: ``""`` under membership and ``"AES128-SHA"`` under a substring rule.
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
#: The cost of this narrowness is UNDER-claiming the refusal against non-conforming servers. That is the
#: correct direction to be wrong in. (Since the branch is no longer CLEAN-capable the practical cost is
#: nil today: both a matched and an unmatched reason reach the operator as INCONCLUSIVE.)
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
FAILURE_VERSION_REJECTED = "protocol_version_rejected"   # peer alert(70) on an open channel  -> INCONCLUSIVE
FAILURE_TLS_OTHER = "tls_error_other"              # some other TLS alert or SSL error             -> INCONCLUSIVE

#: Every failure class except :data:`FAILURE_VERSION_REJECTED` is inconclusive AT THE PREDICATE. (The
#: BRANCH is ``clean_capable: false``, so today FAILURE_VERSION_REJECTED is admitted INCONCLUSIVE too —
#: this set is the predicate-level distinction, kept because it is the one the guard exists to draw.)
#: Spelled out as a set rather than ``!= FAILURE_VERSION_REJECTED`` so adding a class cannot accidentally
#: inherit whatever authority this predicate carries.
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
        # ``@SECLEVEL=0`` relaxes what WE OFFER and grants the target nothing (see the module docstring). It
        # is applied on BOTH probe paths: the weak-cipher probe passes an explicit ``ciphers`` string, and
        # the version probes pass ``ciphers is None`` and so offer the WIDEST legal set (``ALL``) at the
        # relaxed level. WHY THE VERSION PATH NEEDS IT: OpenSSL screens every candidate version through
        # ``ssl_security(SSL_SECOP_VERSION)`` while it builds the ClientHello version table, and on a stock
        # build that screen removes TLS1.0 AND TLS1.1 at the default security level (>=1, e.g. the Debian/
        # Ubuntu ``CipherString = DEFAULT:@SECLEVEL=2``). Without this relaxation the deprecated-version
        # probe aborts with ``NO_PROTOCOLS_AVAILABLE`` (classified ``local_unsupported``) AFTER the TCP
        # channel is up and BEFORE a byte is sent, so the capability was inert on every stock-OpenSSL host —
        # it could put a deprecated ClientHello on the wire only on a permissively-configured box. Offering
        # ``ALL`` here isolates the VERSION as the single variable the probe measures.
        ctx.set_ciphers((ciphers if ciphers is not None else "ALL") + _SECLEVEL0)
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
            # py/insecure-protocol (CodeQL, HIGH) fires here and the alert is DISMISSED as
            # "won't fix" with this rationale, NOT suppressed inline -- an inline
            # `# codeql[...]` comment was tried and does NOT work for this analysis, so do not
            # add one back believing it does anything.
            # DELIBERATE: offering the deprecated version IS the
            # measurement. This probe exists to find out whether a TARGET still accepts TLS1.0/1.1,
            # which cannot be determined without offering them. The weakness is asserted about the
            # peer, never accepted by us: the context is built fresh per call and used for exactly
            # one handshake; check_hostname=False / verify_mode=CERT_NONE because we are measuring
            # the peer, not trusting it; @SECLEVEL=0 relaxes what WE OFFER and grants the target
            # nothing; and no request, credential or payload is ever sent -- the socket is read for
            # version/cipher/peercert and closed in the finally below. Suppressed narrowly, on this
            # sink only, for this rule only: the rule is correct in general and this is the one
            # place in the product where a weak offer is the point.
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


class _NothingOfferable(Exception):
    """Raised by the no-op connector on the zero-offerable path, INSIDE the gate, so that path produces the
    same ``connected: False`` evidence shape as every other capture without opening a socket."""


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
    no_offer_reason: str = "",
) -> dict:
    """Run one restricted handshake through ``verify.tls.capture_tls_handshake`` (THE gate) and return its
    JSON-safe evidence enriched with (a) what VIGIL OFFERED and (b) the structured failure classification.
    Never raises: a gate refusal, a local gap and a peer refusal all come back as ``connected: False``
    evidence carrying a ``failure_class``.

    ``no_offer_reason`` is the ZERO-OFFERABLE path: VIGIL has nothing it can legally put in the
    ClientHello. It still goes through ``capture_tls_handshake``, because the gate's answer is itself the
    thing that must not be assumed — the injected connector records that the gate LET IT RUN and then
    raises without touching a socket, so the evidence distinguishes "the gate refused" (``gate_refused``,
    ``gate_authorized: False``) from "we were authorised and had nothing to offer"
    (``local_unsupported``, ``gate_authorized: True``). No packet is sent on either path.

    NO CAPTURE INSTANT IS STAMPED. See the module docstring: the only consumer of a retained instant is the
    UNWIRED claim-4 derivation, and an untrusted runner wallclock inside signed evidence that no claim reads
    is nondeterminism bought for nothing."""
    from framework.v2.verify import capture_tls_handshake  # noqa: PLC0415 (FATAL-2: function-local)

    box: dict = {}

    def connector(h: str, p: int, t: float):
        if no_offer_reason:
            box["connector_invoked"] = True
            box["failure_class"] = FAILURE_LOCAL_UNSUPPORTED
            box["failure_detail"] = no_offer_reason[:200]
            raise _NothingOfferable(no_offer_reason)
        return _restricted_connect(h, p, t, min_version_name=min_version_name,
                                   max_version_name=max_version_name, ciphers=ciphers, box=box)

    base = capture_tls_handshake(str(host), int(port), slug=slug, timeout=timeout, connect=connector)
    out = dict(base)
    out.update(offered)
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
) -> dict:
    """Offer ONLY ``version_label`` and capture what happened (claims 1 and 2).

    A completed handshake means the endpoint agreed to the deprecated version — the FACT. A
    ``protocol_version`` alert means the peer that answered THIS connection refused, which is
    INCONCLUSIVE, not a CLEAN: see :func:`is_conclusive_protocol_refusal` and the module docstring,
    claim 2. Anything else is inconclusive too."""
    return _capture(host, port, slug=slug, timeout=timeout,
                    min_version_name=version_attr, max_version_name=version_attr, ciphers=None,
                    offered={"probe": "deprecated_protocol_offer",
                             "offered_only_version": version_label,
                             "offered_ciphers": []})


#: The ONE protocol version the weak-cipher probe negotiates at, pinned top AND bottom. See
#: :func:`capture_weak_cipher_handshake` for why both ends matter.
WEAK_CIPHER_PROBE_VERSION_ATTR = "TLSv1_2"
WEAK_CIPHER_PROBE_VERSION_LABEL = "TLSv1.2"


def capture_weak_cipher_handshake(
    host: str,
    port: int = 443,
    *,
    slug: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
    offer: "tuple[str, ...]" = WEAK_CIPHER_OFFER,
) -> dict:
    """Offer ONLY the locally-offerable subset of the closed weak-cipher vocabulary, at EXACTLY TLS1.2, and
    capture what the endpoint SELECTED (claim 3).

    When the local build can offer none of them the capture still goes THROUGH THE GATE (with a connector
    that opens no socket) and returns ``connected: False`` with ``failure_class = local_unsupported`` and
    an EMPTY ``offered_ciphers`` — nothing was tested, so the re-drive is skipped rather than scored.

    THE VERSION IS PINNED AT BOTH ENDS, and the two ends are pinned for different reasons.

    * MAXIMUM TLS1.2, so the restricted offer actually governs. ``set_ciphers`` controls the TLS<=1.2 suite
      list ONLY — TLS1.3's five suites travel in a separate list an OpenSSL client always offers — so
      without the cap a TLS1.3-preferring server would negotiate an AEAD suite outside the recorded offer,
      the membership check would (correctly) decline to score it, and the weak-suite question would
      silently go untested.
    * MINIMUM TLS1.2, so the ORACLE'S FIRE IS ATTRIBUTABLE TO THE CIPHER. ``tls_weakness_oracle`` fires on
      a deprecated VERSION before it ever looks at the suite, so against a TLS1.0/TLS1.1-max endpoint this
      branch's FACT would have been adjudicated by the version predicate while being reported as a
      weak-CIPHER finding — a true statement about the endpoint filed under the wrong claim. Pinning the
      floor at TLS1.2 (a version the oracle does not treat as deprecated) means any fire here is the
      cipher. The cost is honest and bounded: a <=TLS1.1-max endpoint is now NOT weak-cipher tested by this
      branch (the probe gets a version refusal and the re-drive is SKIPPED, never CLEAN — the branch is not
      clean-capable), and that endpoint's real problem is already the FACT claim 1 mints over it.

    Nothing else is lost by capping: every suite in the closed vocabulary is a TLS<=1.2 construction, and
    TLS1.3's suite set contains none of them."""
    offerable = offerable_weak_ciphers(offer)
    common = {"probe": "weak_cipher_offer", "offered_only_version": WEAK_CIPHER_PROBE_VERSION_LABEL,
              "offered_min_version": WEAK_CIPHER_PROBE_VERSION_LABEL,
              "offered_max_version": WEAK_CIPHER_PROBE_VERSION_LABEL}
    if not offerable:
        return _capture(host, port, slug=slug, timeout=timeout,
                        min_version_name=None, max_version_name=None, ciphers=None,
                        offered={**common, "offered_ciphers": []},
                        no_offer_reason=("this OpenSSL build can offer none of the closed weak-cipher "
                                         "vocabulary"))
    return _capture(host, port, slug=slug, timeout=timeout,
                    min_version_name=WEAK_CIPHER_PROBE_VERSION_ATTR,
                    max_version_name=WEAK_CIPHER_PROBE_VERSION_ATTR,
                    ciphers=":".join(offerable),
                    offered={**common, "offered_ciphers": list(offerable)})


# ---------------------------------------------------------------------------
# The deterministic predicates. Pure functions over RETAINED evidence: an offline verifier re-runs them and
# gets the same answer, because they read nothing but the dict they are handed.
# ---------------------------------------------------------------------------
#: The key under which a version probe's retained evidence carries its PEER-TLS-SESSION WITNESS: proof,
#: drawn from ANOTHER capture of the SAME endpoint in the SAME run, that VIGIL completed a full TLS
#: handshake with this (host, port) at some other version — ON ANOTHER CONNECTION, which is exactly why
#: it does not make the branch CLEAN-capable (see :func:`is_conclusive_protocol_refusal`). Retained IN the
#: evidence (not consulted at decision time) so the predicate stays a pure function of one dict and
#: re-derives offline from the retained capture alone.
PEER_SESSION_KEY = "peer_tls_session"

#: The shape stamped when no capture in the run completed a session with the peer.
_NO_PEER_SESSION: "dict[str, Any]" = {"completed": False, "tls_version": "", "cipher": "", "probe": ""}


def peer_tls_session_witness(own: Any, siblings: "tuple[dict, ...]" = ()) -> dict:
    """Return ``own`` with a :data:`PEER_SESSION_KEY` witness stamped from ``siblings`` — the other
    captures this run made against the SAME (host, port).

    WHY THIS EXISTS. ``alert(70) protocol_version`` is seven bytes. A thing that emits nothing else is not
    a TLS service, and treating its alert as conclusive would say "this endpoint does not accept TLS1.0"
    about a host VIGIL never completed a single TLS session with — precisely the laundering
    ``channel_established`` is supposed to prevent but cannot, since a bare TCP accept satisfies it. The
    witness is that missing half: something at this (host, port) must have COMPLETED a handshake, at a
    different version, in the same run.

    WHAT IT IS NOT. It does not, and cannot, show that the SAME PEER answered both connections, so it is
    not enough to support a CLEAN — the branch is ``clean_capable: false`` for exactly that reason. It is
    retained and enforced as the narrower guard it really is.

    Pure and deterministic: it reads only the dicts handed to it (no clock, no network), scans ``siblings``
    in the order the runner captured them and takes the FIRST completed session whose host and port match
    ``own``. Skips ``own`` itself — a probe cannot witness for itself."""
    base = dict(own) if isinstance(own, dict) else {}
    found = None
    for sib in siblings:
        if not isinstance(sib, dict) or sib is own:
            continue
        if sib.get("connected") is not True:
            continue
        version = str(sib.get("tls_version") or "")
        if not version:
            continue
        if str(sib.get("host") or "") != str(base.get("host") or ""):
            continue
        try:
            same_port = int(sib.get("port")) == int(base.get("port"))
        except (TypeError, ValueError):
            same_port = False
        if not same_port:
            continue
        found = {"completed": True, "tls_version": version, "cipher": str(sib.get("cipher") or ""),
                 "probe": str(sib.get("probe") or "baseline_handshake")}
        break
    base[PEER_SESSION_KEY] = found or dict(_NO_PEER_SESSION)
    return base


def is_conclusive_protocol_refusal(evidence: Any) -> bool:
    """The CONCLUSIVENESS predicate for claim 2 — the single most attackable decision in this slice, and
    NO LONGER A CLEAN PREDICATE.

    **A True here does NOT produce a CLEAN.** ``tls_weakness.deprecated_protocol_offer`` is declared
    ``clean_capable: false``, so ``verdict.admit`` maps a conclusive non-fire on this branch to
    INCONCLUSIVE. The reason is stated at length in the module docstring (claim 2) and in the registry
    row: this predicate reads ONE capture, but the peer-session witness it requires was obtained on a
    DIFFERENT TCP connection, and no retained material binds the two connections to one peer — an L4 pool
    that refuses TLS1.0 on one connection and accepts it on the next satisfies every condition below
    while the endpoint does accept TLS1.0. The predicate is kept, exercised and mutation-defended because
    it is the correct guard for this class and would be needed again if a sound CLEAN ever became
    reachable; it is not, today, an absence-authority.

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
      * the recorded ``ssl_reason`` is itself in the closed :data:`VERSION_REJECTION_REASONS`, so a
        hand-edited ``failure_class`` alone cannot manufacture a conclusive refusal;
      * AND the retained :data:`PEER_SESSION_KEY` witness shows VIGIL COMPLETED a TLS handshake with this
        (host, port), in this same run, at a DIFFERENT version. Without it the thing answering need not be
        a TLS service at all: a socket that answers every ClientHello with the same seven-byte
        ``alert(70)`` record satisfies every other condition here. The witness also may not name the
        version being refused — a session at the very version we claim was refused would be a
        contradiction, not a corroboration. NOTE WHAT THE WITNESS DOES AND DOES NOT ESTABLISH: it shows
        that SOMETHING at this (host, port) spoke TLS, on ANOTHER connection. It does not show that the
        same peer answered both, and cannot — see this function's opening paragraph.

    Every other shape — a timeout, a reset, a refused connect, a DNS failure, an EOF, a locally-unsupported
    protocol, an ambiguous ``handshake_failure(40)``, a gate refusal, or a peer VIGIL never completed a TLS
    session with — returns False. Both a False and a True reach the operator as INCONCLUSIVE today; the
    distinction is kept because it is the one the guard exists to draw."""
    if not isinstance(evidence, dict):
        return False
    if evidence.get("connected") is True:
        return False
    if not bool(evidence.get("gate_authorized")):
        return False
    if not bool(evidence.get("tcp_established")):
        return False
    offered_version = str(evidence.get("offered_only_version") or "")
    if offered_version not in {lbl for _, lbl in DEPRECATED_VERSION_PROBES}:
        return False
    if str(evidence.get("failure_class") or "") != FAILURE_VERSION_REJECTED:
        return False
    if str(evidence.get("ssl_reason") or "") not in VERSION_REJECTION_REASONS:
        return False
    witness = evidence.get(PEER_SESSION_KEY)
    if not isinstance(witness, dict) or witness.get("completed") is not True:
        return False
    witnessed_version = str(witness.get("tls_version") or "")
    return bool(witnessed_version) and witnessed_version != offered_version


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
# Claim 4 — certificate defects re-derived from a RETAINED DER at a RETAINED instant.
# BUILT AND TESTED, **NOT WIRED**: no re-drive admits to ``tls_weakness.certificate_validity`` and no
# capture above retains ``captured_at_epoch``, so over live evidence classify_certificate_defects()
# returns None. See the module docstring, claim 4, and the registry row's ``wired: false``.
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

    **NOT WIRED.** Nothing in the product calls this on live evidence: the cert-validity re-drive was
    removed (it could only ever emit INCONCLUSIVE, because no ``OracleKind`` adjudicates certificate
    validity), and no capture in this module stamps ``captured_at_epoch``, so a live capture handed here
    returns ``None``. It is kept as the reviewed, tested derivation a future wiring uses; the work that
    wiring needs is named in the registry row's ``blocking_work``.

    Returns ``None`` when there is nothing to judge (no capture, no retained certificate, no retained
    instant, or unparseable DER) — an absent input is never a clean certificate. Otherwise returns a
    JSON-safe record carrying the comparison instant, the validity window, the presented identities and the
    ``defects`` list drawn from the closed :data:`CERTIFICATE_DEFECTS` vocabulary.

    DETERMINISM. ``at_epoch`` comes from ``evidence["captured_at_epoch"]`` and NEVER from a clock read
    here. Re-running this function over the same retained evidence therefore yields the same verdict in a
    year's time, which is what makes an offline re-verification meaningful. The corresponding honesty cost
    a wiring must state: such an instant would be the RUNNER's clock, not a trusted timestamp, so the
    claim would be scoped to "at the instant of capture" — and adding the field to a capture that already
    ships changes that branch's signed context digest, which is a deliberate certificate-invalidating
    change, never a silent one.

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
