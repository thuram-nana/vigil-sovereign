"""VIGIL Proof Studio (B5) — the import-clean Caido→_vigil_capture builder (strix.report.proof_capture).

Loaded DIRECTLY from the file (like the other tests_vigil modules) so it runs without Strix's heavy runtime
deps — ``proof_capture`` imports only stdlib (its one strix import, ``tools.proxy.caido_api``, is lazy and
never fires here because the tests inject a fake caido). Async orchestrator paths are driven with
``asyncio.run`` so no pytest-asyncio plugin is required.

Doctrine: the capture bytes are TARGET-produced (response-side) — the channel a FACT may soundly rest on; the
model supplies at most a request id / an endpoint, never the bytes.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib

_MOD = pathlib.Path(__file__).resolve().parents[1] / "strix" / "report" / "proof_capture.py"
_spec = importlib.util.spec_from_file_location("vigil_proof_capture", _MOD)
pc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pc)


def test_capture_key_matches_the_sink_contract():
    assert pc.CAPTURE_KEY == "_vigil_capture"


def test_build_error_signature_capture_is_pure_and_honest():
    cap = pc.build_error_signature_capture(bug_class="error_based_sqli",
                                           exploit_body=b"SQL syntax error near ''", exploit_status=500)
    assert cap["exchanges"][0]["channel"] == "error_signature"
    assert cap["exchanges"][0]["role"] == "mutated"
    assert cap["blobs"]["resp"] == b"SQL syntax error near ''"
    # no bug_class or no body → nothing to prove (None, never a guessed capture)
    assert pc.build_error_signature_capture(bug_class="", exploit_body=b"x") is None
    assert pc.build_error_signature_capture(bug_class="sqli", exploit_body=None) is None


def test_build_capture_includes_a_control_when_present():
    cap = pc.build_error_signature_capture(bug_class="error_based_sqli", exploit_body="err", control_body="ok")
    roles = [e["role"] for e in cap["exchanges"]]
    assert roles == ["mutated", "control"] and cap["blobs"]["ctrl"] == b"ok"


class _Resp:
    def __init__(self, raw):
        self.raw = raw


class _Fetched:
    def __init__(self, raw, request_raw=None):
        self.response = _Resp(raw)
        # ``get_request_with_client`` fetches request_raw + response_raw together, so a real fetched object
        # carries BOTH halves; the capture binds the request bytes (inv 8).
        self.request = _Resp(request_raw) if request_raw is not None else None


class _FakeCaido:
    """A stand-in for strix.tools.proxy.caido_api with the two async accessors + the sync parser."""

    def __init__(self, by_id=None, listing=None):
        self._by_id = by_id or {}
        self._listing = listing

    async def view_request(self, rid, *, part="request"):
        return self._by_id.get(rid)

    async def list_requests(self, **kw):
        return self._listing

    @staticmethod
    def parse_raw_response(raw):
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
        status = 500 if "500" in text else 200
        body = text.split("\r\n\r\n", 1)[-1]
        return {"status": status, "body": body}


def test_capture_for_report_uses_an_explicit_request_id_and_binds_the_request():
    raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\nYou have an error in your SQL syntax"
    req = b"POST /login HTTP/1.1\r\nHost: t\r\n\r\nid=1' OR '1'='1"
    caido = _FakeCaido(by_id={"req-7": _Fetched(raw, request_raw=req)})
    cap = asyncio.run(pc.capture_for_report(
        {"finding_class": "sql injection", "endpoint": "/login", "method": "POST"},
        caido=caido, explicit_ids=["req-7"]))
    assert cap is not None
    assert cap["exchanges"][0]["channel"] == "error_signature"
    assert b"SQL syntax" in cap["blobs"]["resp"]
    assert cap["exchanges"][0]["status"] == 500
    # inv 8: the exploit REQUEST bytes are bound, not just the response
    assert cap["exchanges"][0]["request_bytes_ref"] == "req"
    assert cap["blobs"]["req"] == req


def test_capture_without_recoverable_request_bytes_binds_no_request():
    """When the fetched exchange carries no request half, the capture is still built (best-effort) but binds
    NO request — so the mint declines a FACT (proof.run's inv-6/8 gate) and the finding stays a LEAD."""
    raw = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    caido = _FakeCaido(by_id={"req-7": _Fetched(raw)})  # request_raw=None → no .request
    cap = asyncio.run(pc.capture_for_report(
        {"finding_class": "sqli", "endpoint": "/x"}, caido=caido, explicit_ids=["req-7"]))
    assert cap is not None
    assert "request_bytes_ref" not in cap["exchanges"][0]
    assert "req" not in cap["blobs"]


def test_capture_for_report_refuses_without_a_cited_request_id():
    """The retrospective substring auto-correlation is GONE (S6/inv 6): without an explicitly cited id the
    capture is refused, so the finding stays a LEAD even though a matching error-bearing request exists in
    Caido. VIGIL earns the FACT only by re-driving the exchange the agent actually sent (S7)."""
    raw = b"HTTP/1.1 500\r\n\r\nORA-00933: SQL command not properly ended"
    # a request Caido recorded that the OLD code would have substring-matched and minted a signed FACT from:
    caido = _FakeCaido(by_id={"r1": _Fetched(raw)}, listing={"edges": [{"node": {"id": "r1"}}]})
    cap = asyncio.run(pc.capture_for_report(
        {"finding_class": "sqli", "endpoint": "/search", "method": "GET"}, caido=caido))
    assert cap is None, "a finding with no cited request id must NOT auto-correlate into a proof"


def test_capture_for_report_never_queries_list_requests_for_correlation():
    """Negative control: the capture must not fall back to a listing query at all — if it does, a
    substring / most-recent correlation has crept back in."""
    class _NoListing(_FakeCaido):
        async def list_requests(self, **kw):  # noqa: ANN001
            raise AssertionError("capture_for_report performed a retrospective list_requests correlation")

    caido = _NoListing(by_id={"r1": _Fetched(b"HTTP/1.1 500\r\n\r\nORA-00933")},
                       listing={"edges": [{"node": {"id": "r1"}}]})
    assert asyncio.run(pc.capture_for_report(
        {"finding_class": "sqli", "endpoint": "/search"}, caido=caido)) is None


def test_capture_for_report_is_none_without_a_class_or_on_error():
    caido = _FakeCaido(by_id={"r1": _Fetched(b"HTTP/1.1 200\r\n\r\nok")})
    assert asyncio.run(pc.capture_for_report(
        {"endpoint": "/x"}, caido=caido, explicit_ids=["r1"])) is None       # no class

    class _Boom:
        async def view_request(self, *a, **k):
            raise RuntimeError("caido down")

        async def list_requests(self, **k):
            raise RuntimeError("caido down")

        def parse_raw_response(self, raw):
            return None

    # a Caido failure is swallowed → an honest None (no proof), never an exception into the reporting path
    assert asyncio.run(pc.capture_for_report(
        {"finding_class": "sqli", "endpoint": "/x"}, caido=_Boom(), explicit_ids=["r1"])) is None
