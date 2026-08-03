"""
verify.confirmation — the oracle as the confirmation authority, end to end.

This is the module that discharges the audit's single most important finding:
"no real target has ever driven a real confirmed finding." Until now the
`confirmed` stamp came from an LLM's opinion over fixture text. Here a finding
becomes `confirmed` for exactly one reason — a deterministic oracle *fired* at
or above threshold over data a real (local) target actually produced.

Two pieces:

  `confirm_finding(finding, context, verifier=None) -> ConfirmedFinding | None`
      Runs the oracle layer over a `FindingContext` (or a raw context mapping)
      and promotes the finding to `ConfirmedFinding` ONLY when an oracle fired
      at/above the verifier threshold. No fired signal → `None`. The returned
      object carries the firing `OracleSignal`s and a calibrated confidence
      (the strength of the strongest confirming signal), so the confirmation
      is reconstructable from evidence, never from assertion.

  `confirm_against_local_target(app=DifferentialDemoHandler) -> ConfirmedFinding | None`
      The reproducible proof. It stands up a deliberately-vulnerable stdlib
      HTTP app on 127.0.0.1:0, sends a benign baseline request and a boolean
      probe request, feeds the two REAL responses through the differential
      oracle via the adapter, and returns a genuinely oracle-confirmed
      finding. Point it at `SafeDemoHandler` (a parameterised, non-injectable
      twin) and it returns `None` — the negative control that proves the
      authority does not rubber-stamp.

Everything is localhost-only and deterministic: the oracle verdict rests on
response *content* (status/length/lexical), never on wallclock timing.
"""

from __future__ import annotations

import contextlib
import re
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator, Mapping

from pydantic import BaseModel, ConfigDict, Field

from .adapter import FindingContext
from .models import OracleKind, OracleSignal, VerificationResult
from .verifier import OracleVerifier


# ---------------------------------------------------------------------------
# ConfirmedFinding — a finding that survived the oracle gate
# ---------------------------------------------------------------------------


class ConfirmedFinding(BaseModel):
    """A finding promoted to `confirmed` by a fired oracle signal.

    An instance only ever exists when at least one oracle fired at or above the
    verifier threshold; `confirm_finding` returns `None` otherwise. It retains
    the original finding fields plus the machine evidence: which oracle carried
    the confirmation, the calibrated confidence, and every signal that ran."""

    model_config = ConfigDict(extra="forbid")

    confirmed: bool = Field(default=True, description="Always True; the type is the proof.")
    bug_class: str = ""
    title: str = ""
    severity: str = ""
    surface: str = ""
    summary: str = ""
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Calibrated confidence — the strength of the strongest "
        "confirming signal.",
    )
    confirmed_by: OracleKind = Field(description="The oracle kind that carried the confirmation.")
    signals: list[OracleSignal] = Field(
        default_factory=list, description="Every oracle signal that ran, for audit."
    )
    rationale: str = ""
    finding: dict[str, Any] = Field(
        default_factory=dict, description="The original finding payload, retained verbatim."
    )


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    """Reduce whatever a caller calls a 'finding' (a pydantic FindingPayload,
    a mapping, or a plain object) to a dict, without importing agents.models."""
    if finding is None:
        return {}
    if hasattr(finding, "model_dump"):
        return dict(finding.model_dump())
    if isinstance(finding, Mapping):
        return dict(finding)
    return {
        k: getattr(finding, k)
        for k in ("title", "bug_class", "severity", "surface", "summary")
        if hasattr(finding, k)
    }


def _build_verifier_ctx(
    finding: Any, context: "FindingContext | Mapping[str, Any]"
) -> "tuple[dict[str, Any], dict[str, Any]]":
    """Reduce a `finding` + `context` to the (verifier_ctx, finding_dict) pair the
    oracle layer reads — shared by `confirm_finding` and `adjudicate_finding` so the
    positive and the retained-negative paths adjudicate over byte-identical inputs."""
    if isinstance(context, FindingContext):
        ctx = context.to_verifier_context()
    elif isinstance(context, Mapping):
        ctx = dict(context)
    else:  # pragma: no cover - defensive
        raise TypeError(
            f"context must be FindingContext or Mapping, got {type(context).__name__}"
        )
    fd = _finding_to_dict(finding)
    if not ctx.get("bug_class"):
        ctx["bug_class"] = str(fd.get("bug_class", ""))
    return ctx, fd


def adjudicate_finding(
    finding: Any,
    context: "FindingContext | Mapping[str, Any]",
    verifier: OracleVerifier | None = None,
) -> VerificationResult:
    """Run the oracle layer and return the FULL `VerificationResult` — BOTH branches.

    Unlike `confirm_finding` (which returns `None` on the negative branch and so
    discards the fact that an oracle actually RAN and rendered a clean verdict),
    this retains that negative-adjudication evidence: `result.signals` are the
    applicable oracle kinds that ran over the observed data, `result.confirmed` is
    whether any fired at/above threshold. It promotes NOTHING — `confirm_finding`
    remains the sole confirmation authority; this is the coverage/completeness lens
    over the same single `verifier.confirm(ctx)` call."""
    verifier = verifier or OracleVerifier()
    ctx, _fd = _build_verifier_ctx(finding, context)
    return verifier.confirm(ctx)


def confirmed_from_result(
    result: VerificationResult,
    finding: Any,
    verifier: OracleVerifier | None = None,
) -> ConfirmedFinding | None:
    """Build the `ConfirmedFinding` from an already-computed `VerificationResult`
    (or `None` when it did not confirm). Factored out so a caller that already ran
    `adjudicate_finding` derives the positive without a second oracle pass — the
    ConfirmedFinding it returns is byte-identical to `confirm_finding`'s."""
    verifier = verifier or OracleVerifier()
    if not result.confirmed:
        return None
    fd = _finding_to_dict(finding)
    confirming = [
        s for s in result.signals
        if s.fired and s.confidence >= verifier.high_confidence
    ]
    top = max(confirming, key=lambda s: s.confidence)
    return ConfirmedFinding(
        bug_class=result.bug_class or str(fd.get("bug_class", "")),
        title=str(fd.get("title", "")),
        severity=str(fd.get("severity", "")),
        surface=str(fd.get("surface", "")),
        summary=str(fd.get("summary", "")),
        confidence=top.confidence,
        confirmed_by=top.kind,
        signals=result.signals,
        rationale=result.rationale,
        finding=fd,
    )


def confirm_finding(
    finding: Any,
    context: "FindingContext | Mapping[str, Any]",
    verifier: OracleVerifier | None = None,
) -> ConfirmedFinding | None:
    """Promote `finding` to `ConfirmedFinding` iff the oracle layer fires.

    `context` is a `FindingContext` (preferred) or a raw context mapping in the
    shape `OracleVerifier.confirm` reads. The finding's `bug_class` fills in
    when the context did not set one. Returns `None` when no oracle fired at or
    above the verifier's high-confidence threshold — there is no assertion-only
    path to a `ConfirmedFinding`.

    (Return contract UNCHANGED — this now delegates to `adjudicate_finding` +
    `confirmed_from_result`, which is exactly this function's old body split so the
    negative branch's evidence can be retained by other callers.)"""
    verifier = verifier or OracleVerifier()
    result = adjudicate_finding(finding, context, verifier)
    return confirmed_from_result(result, finding, verifier)


# ---------------------------------------------------------------------------
# A local, deliberately-vulnerable target — and its safe twin
# ---------------------------------------------------------------------------
#
# These exist ONLY to prove the confirmation authority against real traffic.
# They are self-contained demo handlers bound to loopback, not a probe or an
# exploit aimed at anything external. The vulnerable one models a classic
# boolean-based blind SQLi: user input is string-built into a WHERE clause, so
# a tautology returns every row while a benign term returns none — a real,
# observable differential in the HTTP response.


_ROWS: tuple[dict[str, Any], ...] = (
    {"id": 1, "name": "alice", "role": "user"},
    {"id": 2, "name": "bob", "role": "admin"},
    {"id": 3, "name": "carol", "role": "user"},
)

_BENIGN_QUERY = "obsidian-no-such-name"
_TAUTOLOGY_QUERY = "x' OR '1'='1"

_USER_AGENT = "CRUCIBLE-verify/1.0 (localhost oracle self-check)"

_CLAUSE_NAME = re.compile(r"name = '(.*)'")
_CLAUSE_TAUTOLOGY = re.compile(r"'(.*)'\s*=\s*'(.*)'")


def _query_param(path: str, key: str) -> str:
    qs = urllib.parse.urlsplit(path).query
    values = urllib.parse.parse_qs(qs).get(key, [""])
    return values[0]


def _clause_true(clause: str, name: str) -> bool:
    m = _CLAUSE_NAME.fullmatch(clause)
    if m:
        return name == m.group(1)
    m = _CLAUSE_TAUTOLOGY.fullmatch(clause)
    if m:
        return m.group(1) == m.group(2)
    return False


def _vulnerable_match(q: str) -> list[dict[str, Any]]:
    """Deliberately flawed: builds `name = '<q>'` by string concatenation, so an
    `' OR '1'='1` breaks out and the OR-tautology selects every row."""
    stmt = "name = '" + q + "'"
    clauses = [c.strip() for c in stmt.split(" OR ")]
    return [row for row in _ROWS if any(_clause_true(c, row["name"]) for c in clauses)]


def _safe_match(q: str) -> list[dict[str, Any]]:
    """The parameterised twin: `q` is a literal value, never structure. No
    input can change which rows are selected beyond an exact name match."""
    return [row for row in _ROWS if row["name"] == q]


def _render(rows: list[dict[str, Any]]) -> bytes:
    if not rows:
        return b"No results found."
    lines = "\n".join(
        f"id={r['id']} name={r['name']} role={r['role']}" for r in rows
    )
    return lines.encode("utf-8")


class _DemoHandler(BaseHTTPRequestHandler):
    matcher = staticmethod(_vulnerable_match)

    def log_message(self, *args: object) -> None:  # keep the demo quiet
        return

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        rows = type(self).matcher(_query_param(self.path, "q"))
        body = _render(rows)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DifferentialDemoHandler(_DemoHandler):
    """Boolean-based blind SQLi demo: a tautology returns every row."""

    matcher = staticmethod(_vulnerable_match)


class SafeDemoHandler(_DemoHandler):
    """The non-injectable negative control: input is always a literal value."""

    matcher = staticmethod(_safe_match)


@contextlib.contextmanager
def _local_server(handler_cls: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    """Run `handler_cls` on 127.0.0.1:<ephemeral> for the duration of the
    block, yielding its base URL and shutting it down cleanly on exit."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, name="verify-demo-target", daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _http_get(base_url: str, query: str) -> dict[str, Any]:
    url = f"{base_url}/search?" + urllib.parse.urlencode({"q": query})
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback only)
        body = resp.read().decode("utf-8", errors="replace")
        return {"status": resp.status, "body": body}


def confirm_against_local_target(
    app: type[BaseHTTPRequestHandler] = DifferentialDemoHandler,
    *,
    baseline_query: str = _BENIGN_QUERY,
    probe_query: str = _TAUTOLOGY_QUERY,
    verifier: OracleVerifier | None = None,
) -> ConfirmedFinding | None:
    """Drive a REAL local target through the confirmation authority.

    Stands up `app` on loopback, sends a benign baseline and a boolean probe,
    feeds the two real responses through the differential oracle, and returns
    the oracle-confirmed finding (or `None` if nothing fired — e.g. against
    `SafeDemoHandler`). This is the reproducible artifact proving a real target
    drives a real confirmed finding via a fired signal, not an LLM opinion.

    The comparison uses only content dimensions (status/length/lexical), so the
    verdict is deterministic and independent of machine timing."""
    with _local_server(app) as base_url:
        baseline = _http_get(base_url, baseline_query)
        mutated = _http_get(base_url, probe_query)

    context = FindingContext.from_http_responses(
        baseline,
        mutated,
        bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]},
    )
    finding = {
        "title": "Boolean-based blind SQL injection in /search",
        "bug_class": "boolean_sqli",
        "severity": "High",
        "surface": "GET /search?q=",
        "summary": (
            "User input is string-built into a WHERE clause; a boolean "
            "tautology returns every row while a benign term returns none, "
            "yielding an observable response differential."
        ),
    }
    return confirm_finding(finding, context, verifier=verifier)
