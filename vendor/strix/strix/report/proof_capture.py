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
) -> Optional[dict]:
    """Build the plain-dict ``_vigil_capture`` for an error-signature proof from already-fetched bytes.

    Pure + synchronous (trivially unit-testable). Returns ``None`` when there is no usable exploit body or no
    bug_class — an honest "nothing to prove", never a guessed capture."""
    if not str(bug_class or "").strip():
        return None
    ex_bytes = _as_bytes(exploit_body)
    if not ex_bytes:
        return None
    exchanges: list[dict] = [{
        "channel": _ERROR_SIGNATURE, "role": "mutated",
        "response_bytes_ref": "resp", "status": exploit_status, "bug_class": bug_class,
    }]
    blobs: dict[str, bytes] = {"resp": ex_bytes}
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

    Preference order for the exploit exchange: an explicitly-cited Caido request id (``explicit_ids[0]``),
    else the most recent request whose endpoint/method matches the report. A second explicit id is used as a
    benign control. Returns ``None`` (⇒ the finding stays a plain report / LEAD) when Caido is unavailable,
    nothing matches, or no response was captured."""
    bug_class = str(report.get("finding_class") or report.get("bug_class") or "").strip()
    if not bug_class:
        return None
    try:
        if caido is None:
            from strix.tools.proxy import caido_api as caido  # lazy — strix's own module, import-clean
        exploit_id, control_id = await _resolve_ids(report, caido, explicit_ids)
        if not exploit_id:
            return None
        exploit = await caido.view_request(exploit_id, part="response")
        body, status = _response_body(exploit, caido.parse_raw_response)
        if not body:
            return None
        control_body = None
        if control_id:
            control = await caido.view_request(control_id, part="response")
            control_body, _ = _response_body(control, caido.parse_raw_response)
        return build_error_signature_capture(
            bug_class=bug_class, exploit_body=body, exploit_status=status, control_body=control_body)
    except Exception:  # noqa: BLE001 — capture is best-effort; a failure just means no proof (an honest LEAD)
        return None


async def _resolve_ids(report: dict, caido: Any, explicit_ids: "list[str] | None") -> tuple[Optional[str], Optional[str]]:
    if explicit_ids:
        ids = [str(x) for x in explicit_ids if str(x).strip()]
        return (ids[0] if ids else None), (ids[1] if len(ids) > 1 else None)
    # auto-correlate: the most recent captured request matching this finding's endpoint (+ method).
    endpoint = str(report.get("endpoint") or "").strip()
    method = str(report.get("method") or "").strip().upper()
    if not endpoint:
        return None, None
    hql = f'req.path.cont:"{_hql_escape(endpoint)}"'
    if method:
        hql = f'{hql} and req.method.eq:"{method}"'
    listing = await caido.list_requests(httpql_filter=hql, first=1, sort_by="timestamp", sort_order="desc")
    rid = _first_request_id(listing)
    return rid, None


def _hql_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')[:512]


def _first_request_id(listing: Any) -> Optional[str]:
    """Pull the first request id out of a Caido list result, tolerating dict / model / edge shapes."""
    try:
        items = listing
        for attr in ("edges", "nodes", "items", "requests"):
            got = getattr(items, attr, None) if not isinstance(items, dict) else items.get(attr)
            if got:
                items = got
                break
        if isinstance(items, (list, tuple)) and items:
            first = items[0]
            node = getattr(first, "node", None) or (first.get("node") if isinstance(first, dict) else None) or first
            rid = getattr(node, "id", None) or (node.get("id") if isinstance(node, dict) else None)
            return str(rid) if rid else None
    except Exception:  # noqa: BLE001
        return None
    return None
