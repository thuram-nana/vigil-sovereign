"""proof_capture — build the executor-captured exchange bundle a VIGIL proof is minted from (Proof Studio).

This module is IMPORT-CLEAN: it imports only stdlib and (lazily, inside the async orchestrator) strix's own
``tools.proxy.caido_api``. It NEVER imports ``vigil_integration`` or ``framework`` — the mint happens later,
in the (offense-env) ``proof_sink`` hook. All this does is turn the raw request/response bytes Caido already
captured into the plain-dict ``_vigil_capture`` structure the sink understands::

    {"exchanges": [{"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                    "status": 500, "bug_class": "sqli"}, ...],
     "blobs": {"resp": b"...response body..."}}

The bytes are what the TARGET returned (response-side) — the channel a FACT may soundly rest on. The model
never supplies these bytes; it can at most point at a Caido request id, and the oracle still judges the real
captured bytes (a benign/wrong exchange simply fails to fire → an honest LEAD, never a false FACT).

The key MUST match ``vigil_integration.proof.sink.CAPTURE_KEY`` (the sink reads this exact key). It is a bare
literal here (not an import) so strix stays import-clean of the integration package.
"""

from __future__ import annotations

from typing import Any, Optional

# Must equal vigil_integration.proof.sink.CAPTURE_KEY. Kept as a literal (not an import) to preserve
# strix's import-cleanliness of the integration package.
CAPTURE_KEY = "_vigil_capture"

# The response-side channel a single captured exploit exchange proves (a datastore/parser error the payload
# provoked). Response bytes are target-produced, so this is a sound standalone proof channel. Must match
# framework.v2.verify.poc_translate.ERROR_SIGNATURE.
_ERROR_SIGNATURE = "error_signature"


def build_error_signature_capture(
    *,
    bug_class: str,
    exploit_body: "bytes | str | None",
    exploit_status: Optional[int] = None,
    control_body: "bytes | str | None" = None,
    exploit_request: "bytes | str | None" = None,
) -> Optional[dict]:
    """Build the plain-dict ``_vigil_capture`` for an error-signature proof from already-fetched bytes.

    Pure + synchronous (trivially unit-testable). Returns ``None`` when there is no usable exploit body or no
    bug_class — an honest "nothing to prove", never a guessed capture.

    ``exploit_request`` are the raw REQUEST bytes the agent actually sent (inv 8): when present they are
    bound as ``request_bytes_ref`` on the mutated exchange so the certificate records WHAT produced the
    response, not only the response. Without them the mint declines a FACT (see ``proof.run``): a response
    alone, with no record of the request, is not something VIGIL can attribute — it stays a LEAD."""
    if not str(bug_class or "").strip():
        return None
    ex_bytes = _as_bytes(exploit_body)
    if not ex_bytes:
        return None
    mutated: dict = {
        "channel": _ERROR_SIGNATURE, "role": "mutated",
        "response_bytes_ref": "resp", "status": exploit_status, "bug_class": bug_class,
    }
    blobs: dict[str, bytes] = {"resp": ex_bytes}
    req_bytes = _as_bytes(exploit_request)
    if req_bytes:
        mutated["request_bytes_ref"] = "req"     # bind the exploit REQUEST (inv 8)
        blobs["req"] = req_bytes
    exchanges: list[dict] = [mutated]
    ctrl_bytes = _as_bytes(control_body)
    if ctrl_bytes:
        exchanges.append({"channel": _ERROR_SIGNATURE, "role": "control",
                          "response_bytes_ref": "ctrl", "status": None, "bug_class": bug_class})
        blobs["ctrl"] = ctrl_bytes
    return {"exchanges": exchanges, "blobs": blobs}


def _as_bytes(v: "bytes | str | None") -> "bytes | None":
    if isinstance(v, (bytes, bytearray)):
        return bytes(v) or None
    if isinstance(v, str):
        return v.encode("utf-8") or None
    return None


def _request_bytes(fetched: Any) -> "bytes | None":
    """The raw exploit REQUEST bytes from a Caido ``view_request`` result — what the agent actually SENT
    (``result.request.raw``; ``get_request_with_client`` fetches request_raw + response_raw together, and
    ``repeat_request`` reads the same ``result.request.raw``). Returns ``None`` when absent, so a capture
    that could not recover the request simply carries no request binding (⇒ the mint declines a FACT)."""
    req = getattr(fetched, "request", None)
    raw = getattr(req, "raw", None) if req is not None else None
    # Accept ONLY real request bytes/text — never ``str()``-coerce an arbitrary object (a duck-typed ``.raw``
    # with a custom ``__str__`` would otherwise fabricate "request" bytes). A non-primitive raw ⇒ no binding
    # ⇒ the mint declines a FACT (a missing binding is safe; a fabricated one is not).
    if not isinstance(raw, (bytes, bytearray, str)):
        return None
    return _as_bytes(raw)


def _response_body(fetched: Any, parse: Any) -> tuple["bytes | None", Optional[int]]:
    """Extract (body_bytes, status) from a Caido ``view_request`` result, tolerating the SDK model shape.
    Returns (None, None) when no response is present."""
    resp = getattr(fetched, "response", None)
    raw = getattr(resp, "raw", None) if resp is not None else None
    if raw is None:
        return None, None
    parsed = None
    try:
        parsed = parse(raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8"))
    except Exception:  # noqa: BLE001 — a parse failure falls back to the raw bytes, never raises
        parsed = None
    if isinstance(parsed, dict):
        body = parsed.get("body")
        status = parsed.get("status")
        if body is not None:
            return _as_bytes(body), (int(status) if isinstance(status, int) else None)
    # fall back to the raw response bytes (still target-produced; the error signature is in the body)
    return _as_bytes(raw if isinstance(raw, (bytes, bytearray)) else str(raw)), None


async def capture_for_report(
    report: dict,
    *,
    caido: Any = None,
    explicit_ids: "list[str] | None" = None,
) -> Optional[dict]:
    """Best-effort: build the ``_vigil_capture`` for a finding from Caido-captured traffic. NEVER raises.

    The exploit exchange is the one the agent CAUSALLY cited: ``explicit_ids[0]`` (a second id is a
    benign control). There is no retrospective substring correlation — without a cited id the capture is
    refused so the finding stays a LEAD (see :func:`_resolve_ids`). Returns ``None`` (⇒ the finding stays
    a plain report / LEAD) when no id is cited, Caido is unavailable, or no response was captured."""
    bug_class = str(report.get("finding_class") or report.get("bug_class") or "").strip()
    if not bug_class:
        return None
    try:
        if caido is None:
            from strix.tools.proxy import caido_api as caido  # lazy — strix's own module, import-clean
        exploit_id, control_id = await _resolve_ids(report, caido, explicit_ids)
        if not exploit_id:
            return None
        # One fetch returns BOTH raw halves (``get_request_with_client`` sets request_raw+response_raw), so
        # the exploit REQUEST bytes come from the SAME object as the response — no extra round-trip.
        exploit = await caido.view_request(exploit_id, part="response")
        body, status = _response_body(exploit, caido.parse_raw_response)
        if not body:
            return None
        request_bytes = _request_bytes(exploit)
        control_body = None
        if control_id:
            control = await caido.view_request(control_id, part="response")
            control_body, _ = _response_body(control, caido.parse_raw_response)
        return build_error_signature_capture(
            bug_class=bug_class, exploit_body=body, exploit_status=status, control_body=control_body,
            exploit_request=request_bytes)
    except Exception:  # noqa: BLE001 — capture is best-effort; a failure just means no proof (an honest LEAD)
        return None


async def _resolve_ids(report: dict, caido: Any, explicit_ids: "list[str] | None") -> tuple[Optional[str], Optional[str]]:
    """Resolve (exploit_id, control_id) from the request ids the agent CAUSALLY cited — not retrospectively.

    A proof exchange must be the exchange the agent actually sent (``repeat_request`` / ``replay_send_raw``
    both hand the exact request + session id back to their caller), NOT "whatever request Caido most
    recently recorded whose path happens to contain this endpoint substring". That old auto-correlation — a
    path-substring HTTPQL filter, newest-first, limit one — selected an exchange with no payload match, no
    parameter match, no time window and no link to the agent's own action: a target that merely returns a
    datastore stack trace on any malformed ``?id=`` could be attributed a signed FACT off an unrelated
    request, and a Caido "seed" row (created with no response) could even be adjudicated. It is removed.
    Without an explicitly cited id the capture is refused (returns ``(None, None)``) so the finding stays a
    LEAD — VIGIL earns the FACT only by independently re-driving the cited exchange (S7). ``report`` /
    ``caido`` are kept in the signature for the S7 re-drive wiring and API stability."""
    if not explicit_ids:
        return None, None
    ids = [str(x) for x in explicit_ids if str(x).strip()]
    return (ids[0] if ids else None), (ids[1] if len(ids) > 1 else None)
