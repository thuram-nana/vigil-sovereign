"""transport_redrive — route a Strix-reported host:port into VIGIL's OWN gated transport captures (S2).

A Strix agent may REPORT "port 8080 is open" or "this endpoint negotiates TLS 1.0". Those reports are
producer narrative: the ``strix.service_reachability`` / ``strix.tls_negotiation`` evidence branches are
``fact_capable: false`` BY DESIGN and stay that way. What this module adds is the missing ROUTING the
capability matrix names as the ``blocking_work`` for both branches — "the oracle and capture exist; the
missing piece is the LEAD-to-re-drive binding":

  * the Strix report supplies ONLY a host, a port and (optionally) a protocol — never evidence;
  * VIGIL re-authorises that host through the charter/scope gate BEFORE any byte leaves the box;
  * VIGIL performs its OWN bounded handshake with the EXISTING captures
    (``verify/reachability.py:capture_handshake`` / ``verify/tls.py:capture_tls_handshake``);
  * the deterministic oracle judges VIGIL'S OWN retained capture and the verdict is ADMITTED to the
    already-FACT-capable VIGIL-owned branch (``service_reachability.tcp_handshake`` /
    ``tls_weakness.tls_handshake`` / ``weak_crypto.cert_signature_algorithm``) — never to the producer
    branch. No new OracleKind; no new oracle; no payload and no write of any kind.

GATE ORDER (each step fail-closed, and NOTHING is sent until all of them pass):

    1. protocol must be ``tcp`` (see UDP SOUNDNESS below) — refused before any gate and any socket;
    2. protected-domain floor + signed charter + scope + posture (``agents.scope_gate.validate_action``);
    3. kill-switch -> single-host -> ACTIVE_RECON entitlement -> charter scope
       (``verify.reachability._authorize``, the SAME audited active-connect gate the capture re-runs
       internally, called here FIRST so a refusal is an unambiguous ``refused`` with no traffic);
    4. THE NEVER-LIFTABLE EGRESS FLOOR + CONNECT-PIN (``live.egress_floor.pin_egress``). Steps 2 and 3 are
       BOTH pure string matching — ``ethics.host_matches_scope`` resolves nothing and classifies no
       address — so on their own they authorise a name, or a charter-LISTED literal, that is the cloud
       instance-metadata address. Step 4 resolves the target and runs
       ``vigil_gateway.denylist.is_egress_denied`` over EVERY resolved address (metadata/link-local/
       reserved never liftable by any charter; loopback and RFC1918 liftable only for an exactly
       charter-authorized IP), then PINS the capture's connector to the validated literal so the address
       checked is the address dialled;
    5. the capture's own bounded connect, to that pinned address.

WHAT THIS CHAIN DOES NOT ENFORCE — stated so the list above is not read as a complete security story.
It authorises a DESTINATION, not a payload: nothing here bounds what is sent beyond the captures' own
construction (a TCP connect plus a bounded banner read; a TLS ClientHello). There is NO WARDEN in this
path — the proof sink installs this runner directly (``proof/bootstrap.py``) and no WARDEN wrapper exists
between them. It does not rate-limit, and it does not re-check the destination DURING a capture: the pin
closes the resolve-then-connect window, but a kill-switch tripped mid-capture is caught only by the
capture's own internal re-check. Certificate validation is deliberately OFF in the TLS capture (a posture
probe, not a trust check), so the evidence binds the pinned ADDRESS, not a verified peer identity.

A refusal means VIGIL never observed the target: no capture, no admission, no FACT, and — critically —
never a CLEAN either (a refusal is not a negative observation).

UDP SOUNDNESS (a prior wave's invariant, re-asserted here). ``capture_handshake`` is TCP-only and refuses a
non-tcp protocol before any socket; this module refuses it EARLIER still, so a Strix ``udp``-open row can
never drive a TCP connect whose reachability FACT would be mislabelled as udp. A non-tcp row mints nothing.

FATAL-2: every ``framework``-touching import is FUNCTION-LOCAL — importing this module co-loads no offense
engine into the sovereign env.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The three classes this runner re-drives, each mapped to the VIGIL-OWNED, already-FACT-capable evidence
# branch it admits to (kept in lockstep with docs/capability-matrix/evidence-branches.json). The producer
# twins (strix.service_reachability / strix.tls_negotiation) are NOT in this map: a Strix report is the
# "where to look", never the proof, and those branches stay fact_capable:false.
TRANSPORT_FACT_CLASSES = ("service_reachable", "weak_tls", "weak_crypto_artifact")

_REACHABILITY_BRANCH = "service_reachability.tcp_handshake"
_WEAK_TLS_BRANCH = "tls_weakness.tls_handshake"
_WEAK_CRYPTO_BRANCH = "weak_crypto.cert_signature_algorithm"

# class -> the branch(es) ONE VIGIL-owned capture is judged on. The two TLS classes share a SINGLE
# handshake (mirroring external_tool._TLS_REDRIVES): one negotiation, judged for a weak protocol/cipher AND
# for a broken-hash leaf certificate.
_BRANCHES_FOR = {
    "service_reachable": (("service_reachable", _REACHABILITY_BRANCH),),
    "weak_tls": (("weak_tls", _WEAK_TLS_BRANCH), ("weak_crypto_artifact", _WEAK_CRYPTO_BRANCH)),
    "weak_crypto_artifact": (("weak_tls", _WEAK_TLS_BRANCH), ("weak_crypto_artifact", _WEAK_CRYPTO_BRANCH)),
}

_TLS_CLASSES = frozenset({"weak_tls", "weak_crypto_artifact"})

_DEFAULT_PORT_FOR_SCHEME = {"http": 80, "https": 443, "ws": 80, "wss": 443}


@dataclass
class TransportRedriveResult:
    """What ONE transport re-drive observed. Shaped like ``SmugglingRedriveResult`` /
    ``RuntimeRedriveResult`` so the proof-sink rail's ``_finish_runtime_arm`` persists it unchanged."""

    url: str = ""
    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    bug_class: str = ""
    facts: list = field(default_factory=list)          # AdapterResult (is_fact), signed
    leads: list = field(default_factory=list)          # AdapterResult (non-fact: LEAD / CLEAN / INCONCLUSIVE)
    inconclusive: list = field(default_factory=list)   # (class, reason) — no judgeable capture
    admissions: list = field(default_factory=list)     # (branch, verdict, reason) — the audit trail
    contexts: dict = field(default_factory=dict)       # finding_ref -> oracle_context (offline re-verify)
    refused: bool = False                              # a gate refused BEFORE any traffic
    notes: list = field(default_factory=list)
    # The POSITIVE audit trail for the never-liftable egress floor (``live.egress_floor``): one
    # ``(address, denied, reason)`` row per resolved address the floor adjudicated, and the validated
    # literal the capture was pinned to. A caller/test proves the guard RAN from these, rather than
    # inferring it from the absence of a connection.
    egress_checked: list = field(default_factory=list)
    pinned_address: str = ""

    @property
    def n_facts(self) -> int:
        return len(self.facts)


def _coerce_port(value: Any) -> "int | None":
    """A port from a producer report is free text. Accept only a clean integer in 1..65535; anything else
    is ``None`` (the caller then has no port and drives nothing)."""
    if isinstance(value, bool):
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _host_port(endpoint: str, host: str, port: Any, *, default_port: "int | None") -> "tuple[str, int | None]":
    """Derive (host, port) from whatever the producer supplied — an explicit host/port, or a URL-ish
    ``endpoint``. PURE and total: no DNS, no network, no exception. An unparseable input yields
    ``("", None)`` and the caller drives nothing."""
    from urllib.parse import urlsplit  # noqa: PLC0415 — stdlib

    h = (host or "").strip()
    p = _coerce_port(port)
    ep = (endpoint or "").strip()
    if (not h or p is None) and ep:
        candidate = ep if "://" in ep else f"//{ep}"
        try:
            sp = urlsplit(candidate)
            h = h or (sp.hostname or "")
            if p is None:
                try:
                    p = _coerce_port(sp.port)
                except ValueError:      # urlsplit raises on a non-numeric port
                    p = None
                if p is None:
                    p = _DEFAULT_PORT_FOR_SCHEME.get((sp.scheme or "").lower())
        except ValueError:
            pass
    if p is None:
        p = default_port
    return (h or "").strip(), p


def _gate_refusal(host: str, port: int, *, slug: str, protocol: str, scheme: str,
                  posture: str) -> "tuple[str | None, Any]":
    """Re-authorise this exact host:port BEFORE any byte leaves the box. Returns
    ``(refusal_reason_or_None, EgressPin_or_None)``; the pin carries the validated address the capture
    must dial and the per-address audit trail proving the floor ran.

      0. protocol must be ``tcp`` — the captures reproduce a TCP (and, above it, a TLS) handshake and
         nothing else. A ``udp`` row is refused HERE, before the gate chain and before any socket.
      1. ``agents.scope_gate.validate_action`` — protected-domain categorical floor, charter present AND
         signed, URL parseable, host in the signed scope, posture.
      2. ``verify.reachability._authorize`` — the SAME audited active-connect gate the capture re-runs
         internally (kill-switch -> single-host -> ACTIVE_RECON entitlement -> charter scope). Calling it
         here FIRST makes a refusal an unambiguous pre-traffic ``refused`` rather than a ``connected: False``
         that would otherwise be indistinguishable from a closed port (and so from a CLEAN).
      3. ``live.egress_floor.pin_egress`` — the NEVER-LIFTABLE egress floor. Steps 1 and 2 both bottom out
         in ``ethics.host_matches_scope``, which is pure string matching: no DNS, no IP classification, no
         denylist. Without this step an in-scope NAME that resolves to ``169.254.169.254`` — and, worse, a
         charter that directly LISTS that literal, the exact case the gateway denylist declares impossible
         — would connect. This resolves the target, adjudicates EVERY resolved address against
         ``vigil_gateway.denylist.is_egress_denied``, and pins the connect to the validated literal.

    Fail-closed: any error in a gate is itself a refusal. FATAL-2: imports are function-local."""
    if str(protocol or "").strip().lower() != "tcp":
        return ((f"transport re-drive is TCP-only; refusing protocol {protocol!r} — a non-tcp row never "
                 "drives a TCP handshake (and so never mints a reachability/TLS FACT)"), None)
    target_url = f"{scheme}://{host}:{int(port)}/"
    try:
        from framework.v2.agents.scope_gate import validate_action  # noqa: PLC0415
        decision = validate_action(slug=slug, method="GET", target_url=target_url,
                                   posture=posture)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 — a gate error fails closed
        return f"scope-gate error (fail-closed): {type(exc).__name__}: {exc}", None
    if not decision.allowed:
        return f"validate_action refused ({decision.refusal_kind}): {decision.reason}", None
    try:
        from framework.v2.verify.reachability import _authorize as _reach_authorize  # noqa: PLC0415
        refusal = _reach_authorize(host, int(port), slug)
    except Exception as exc:  # noqa: BLE001 — fail closed
        return f"active-connect gate error (fail-closed): {type(exc).__name__}: {exc}", None
    if refusal is not None:
        return f"active-connect gate refused: {refusal}", None
    try:
        from .egress_floor import pin_egress  # noqa: PLC0415 — stdlib + the gateway denylist (no framework)
        pin = pin_egress(host, int(port), slug=slug)
    except Exception as exc:  # noqa: BLE001 — a floor we could not RUN is a refusal, never a free pass
        return f"egress-floor error (fail-closed): {type(exc).__name__}: {exc}", None
    if not pin.allowed:
        return pin.refused_reason, pin
    return None, pin


# A ``connected: False`` capture is a CHANNEL-CONFIRMED NEGATIVE (a closed port / a failed handshake) ONLY
# when the gate let the probe through. These markers name the refusals the capture itself can still emit
# (a kill-switch tripped between our pre-gate and the capture's own re-check, an entitlement revoked
# mid-run, the capture's TCP-only guard): seeing one means VIGIL never observed the target, so the result is
# INCONCLUSIVE and must never be adjudicated as clean.
_CAPTURE_REFUSAL_MARKERS = (
    "kill-switch", "not entitled", "out of charter scope", "must be a single host",
    "port must be an integer", "requires an engagement slug", "TCP-only",
)


def _capture_was_refused(capture: dict) -> bool:
    err = str((capture or {}).get("error") or "")
    return any(marker in err for marker in _CAPTURE_REFUSAL_MARKERS)


def _oracle_signal(finding: dict) -> "tuple[bool, bool]":
    """Run the deterministic oracle over the finding's retained ``oracle_context`` and return
    ``(fired, conclusive)`` WITHOUT minting, so admission sees the oracle's answer BEFORE any certificate
    exists (identical to ``external_tool._oracle_signal`` / ``live.web_redrive._oracle_signal``).
    FATAL-2: every framework import is function-local."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    oracle_context = finding.get("oracle_context") or {}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    return fired, (fired or verdict == "clean")


def _reachability_context(capture: dict) -> "dict | None":
    """The verifier context for VIGIL's OWN TCP handshake. A connected:False capture is still judgeable —
    it is the channel-confirmed negative the ``service_reachability.tcp_handshake`` branch declares itself
    clean-capable for — but a GATE-REFUSED capture is not an observation at all and yields ``None``."""
    if _capture_was_refused(capture):
        return None
    from framework.v2.verify import reachable_context  # noqa: PLC0415 — offense-side only
    return reachable_context(capture)


def _weak_tls_context(capture: dict) -> "dict | None":
    """The verifier context for VIGIL's OWN TLS negotiation; ``None`` when no handshake completed (no
    negotiated protocol/cipher to judge — INCONCLUSIVE, never a clean)."""
    if not (capture or {}).get("connected"):
        return None
    from framework.v2.verify import weak_tls_context  # noqa: PLC0415 — offense-side only
    return weak_tls_context(capture)


def _weak_crypto_context(capture: dict) -> "dict | None":
    """The verifier context for the LEAF CERTIFICATE VIGIL itself retrieved in that same handshake; ``None``
    when no certificate was presented/parseable (mirrors ``external_tool._weak_crypto_context``)."""
    import base64  # noqa: PLC0415 — stdlib

    from framework.v2.verify import weak_crypto_context  # noqa: PLC0415 — offense-side only
    b64 = (capture or {}).get("cert_der_b64")
    if not b64:
        return None
    try:
        der = base64.b64decode(b64)
    except Exception:  # noqa: BLE001 — an unparseable cert is not evidence
        return None
    fc = weak_crypto_context(der)
    return fc.to_verifier_context() if fc is not None else None


_CONTEXT_FOR = {
    "service_reachable": _reachability_context,
    "weak_tls": _weak_tls_context,
    "weak_crypto_artifact": _weak_crypto_context,
}


def transport_redrive(endpoint: str = "", *, claimed_class: str, slug: str, engagement_slug: str,
                      signers: "list[tuple[str, str]]", host: str = "", port: Any = None,
                      protocol: str = "tcp", posture: str = "AUDIT",
                      timeout: "float | None" = None) -> TransportRedriveResult:
    """Re-drive a producer-reported ``host:port`` through VIGIL's OWN gated transport capture and mint a
    signed, offline-re-verifiable FACT ONLY when the deterministic oracle fires over THAT capture.

    ``claimed_class`` is the "where to look" (``service_reachable`` / ``weak_tls`` /
    ``weak_crypto_artifact``); it never decides anything — the oracle does, and a mis-routed class simply
    fails to fire. Never raises: a gate refusal, an unparseable target, an unregistered branch or a probe
    error all return a result whose ``n_facts`` is 0."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids  # noqa: PLC0415 — pure stdlib

    cls = str(claimed_class or "").strip().lower()
    res = TransportRedriveResult(bug_class=cls, protocol=str(protocol or "tcp").strip().lower() or "tcp")
    pairs = _BRANCHES_FOR.get(cls)
    if pairs is None:
        res.notes.append(f"{cls!r} is not a transport re-drive class (nothing driven)")
        return res

    is_tls = cls in _TLS_CLASSES
    scheme = "https" if is_tls else "http"
    target_host, target_port = _host_port(endpoint, host, port, default_port=443 if is_tls else None)
    res.host, res.port = target_host, int(target_port or 0)
    res.url = f"{scheme}://{target_host}:{target_port}/" if target_host and target_port else (endpoint or "")
    if not target_host or not target_port:
        res.notes.append("no host:port could be derived from the report (nothing driven)")
        return res

    registered = branch_ids()
    drivable = [(c, b) for (c, b) in pairs if b in registered]
    for c, b in pairs:
        if b not in registered:
            res.notes.append(f"branch {b!r} is not registered — cannot admit {c!r} (fail-closed)")
    if not drivable:
        return res

    # --- the gate chain: NOTHING is sent until every check passes ------------------------------------
    refusal, pin = _gate_refusal(target_host, int(target_port), slug=slug, protocol=res.protocol,
                                 scheme=scheme, posture=posture)
    if pin is not None:
        res.egress_checked = list(pin.checked)
        res.pinned_address = pin.pinned
    if refusal is not None:
        res.refused = True
        res.notes.append(f"refused before any traffic: {refusal}")
        res.inconclusive.append((cls, refusal))
        return res

    # --- ONE VIGIL-owned capture, judged for every branch this class covers ---------------------------
    # The connector is PINNED to the address the floor validated, so the capture dials the literal that was
    # checked rather than re-resolving the name (the rebinding / short-TTL / multi-A window).
    from .egress_floor import pinned_tcp_connector, pinned_tls_connector  # noqa: PLC0415 — no framework
    try:
        if is_tls:
            from framework.v2.verify import capture_tls_handshake  # noqa: PLC0415 — offense-side only
            kwargs = {"slug": slug, "connect": pinned_tls_connector(pin.pinned)}
            if timeout is not None:
                kwargs["timeout"] = timeout
            capture = capture_tls_handshake(target_host, int(target_port), **kwargs)
        else:
            from framework.v2.verify import capture_handshake  # noqa: PLC0415 — offense-side only
            kwargs = {"slug": slug, "protocol": res.protocol,
                      "connect": pinned_tcp_connector(pin.pinned)}
            if timeout is not None:
                kwargs["timeout"] = timeout
            capture = capture_handshake(target_host, int(target_port), **kwargs)
    except Exception as exc:  # noqa: BLE001 — a capture we could not RUN is INCONCLUSIVE, never a CLEAN
        res.inconclusive.append((cls, f"capture error: {type(exc).__name__}: {exc}"))
        res.notes.append(f"capture errored: {type(exc).__name__}: {exc}")
        return res

    if _capture_was_refused(capture):
        # The capture's own gate re-check refused (e.g. a kill-switch tripped between our pre-gate and it).
        res.refused = True
        res.notes.append(f"capture refused by its own gate: {capture.get('error')}")
        res.inconclusive.append((cls, str(capture.get("error") or "gate refusal")))
        return res

    connected = bool(capture.get("connected"))
    if not connected and capture.get("error"):
        res.notes.append(f"no handshake: {capture.get('error')}")
    observed = {"gate_authorized": True, "channel_established": connected}

    for branch_class, branch in drivable:
        ctx = _CONTEXT_FOR[branch_class](capture)
        if ctx is None:
            # VIGIL's own capture yielded nothing this branch can judge (no handshake / no certificate).
            # NOT a clean negative and never a fabricated FACT.
            res.inconclusive.append((branch_class, "VIGIL's capture yielded no evidence this branch judges"))
            continue
        finding = {"check_id": f"transport:{branch_class}:{target_host}:{target_port}#{branch}",
                   "bug_class": branch_class,
                   "insertion_point": f"{target_host}:{target_port}/{res.protocol}",
                   "oracle_context": ctx}
        try:
            fired, conclusive = _oracle_signal(finding)
        except Exception as exc:  # noqa: BLE001 — an oracle we could not RUN mints nothing
            res.inconclusive.append((branch_class, f"oracle error: {type(exc).__name__}: {exc}"))
            continue
        admitted = admit(branch, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="live_redrive")
        res.contexts[r.finding_ref] = ctx
        if r.is_fact:
            res.facts.append(r)
        elif admitted.verdict is Verdict.INCONCLUSIVE:
            res.inconclusive.append((branch_class, admitted.reason))
            res.leads.append(r)
        else:
            res.leads.append(r)
    return res


def reachability_redrive(endpoint: str = "", **kwargs: Any) -> TransportRedriveResult:
    """``transport_redrive`` pinned to ``service_reachable`` (VIGIL's OWN bounded TCP handshake)."""
    kwargs.pop("claimed_class", None)
    return transport_redrive(endpoint, claimed_class="service_reachable", **kwargs)


def tls_redrive(endpoint: str = "", **kwargs: Any) -> TransportRedriveResult:
    """``transport_redrive`` pinned to the TLS pair (VIGIL's OWN bounded TLS negotiation, judged for a weak
    protocol/cipher AND a broken-hash leaf certificate)."""
    kwargs.pop("claimed_class", None)
    return transport_redrive(endpoint, claimed_class="weak_tls", **kwargs)


__all__ = ["TRANSPORT_FACT_CLASSES", "TransportRedriveResult", "reachability_redrive", "tls_redrive",
           "transport_redrive"]
