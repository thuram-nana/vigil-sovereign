"""
scanner.benchmark — a repeatable, ground-truth benchmark for the scanner.

The project has never had an honest "is it any good" number: what fraction of
real bugs does the autonomous scanner actually confirm (recall), and how often
does it flag something that isn't there (false-positive rate)? This module
answers both, deterministically, on loopback.

It ships a small **deliberately-vulnerable benchmark app** — a localhost
``http.server`` handler exposing a handful of endpoints, each labelled in the
:data:`GROUND_TRUTH` manifest as either vulnerable to a specific ``bug_class``
on a specific parameter, or SAFE (a parameter that takes input but must NEVER be
flagged). The classes covered are the oracle-confirmable ones the existing check
library handles end-to-end: a boolean-SQLi differential, a reflected-XSS
side-effect, and an IDOR/BOLA cross-tenant read — plus safe controls that a
precise scanner must leave alone.

:func:`run_benchmark` stands the app up on ``127.0.0.1:0``, runs a real
:class:`~framework.v2.scanner.campaign.WebScanCampaign` against it (a caller may
inject a ``campaign_factory`` that builds the campaign from a ``send``), matches
each oracle-confirmed finding against the manifest by ``(bug_class, param)``, and
returns a scored :class:`BenchmarkReport` (true/false positives, false
negatives, precision, recall, F1, and a per-class breakdown).

This is a local WAVSEP-style harness. It is deterministic (the app has no clock
or randomness in its decision logic; the only nondeterminism is the OS-assigned
loopback port, which is not part of any scoring input) and loopback-only. Every
byte of traffic still flows through the campaign's injected ``send``. Nothing
here touches a non-loopback host.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterator

from pydantic import BaseModel, ConfigDict, Field

from .campaign import WebScanCampaign
from .checks import BOOLEAN_SQLI, REFLECTED_XSS, IdorCheck, Send
from .engine import AuditFinding
from .insertion import HttpRequest, InsertionKind

# A factory turns the (authenticated) campaign ``send`` into a ready campaign, so
# a caller can substitute their own check set / budget while the harness owns the
# app lifecycle and the scoring. When None, the harness builds the default
# campaign covering every seeded class.
CampaignFactory = Callable[[Send], WebScanCampaign]


# ---------------------------------------------------------------------------
# Ground-truth manifest — the single source of what SHOULD and SHOULD NOT fire.
# The benchmark app below is built to match it exactly; keep the two in step.
# ---------------------------------------------------------------------------


class VulnLabel(BaseModel):
    """One planted bug: the endpoint path, the vulnerable parameter, and the
    ``bug_class`` a correct scanner must confirm on it."""

    model_config = ConfigDict(extra="forbid")

    path: str
    param: str
    bug_class: str


class SafeLabel(BaseModel):
    """A control: a parameter that takes input but is not vulnerable. Any
    confirmed finding landing on it is a false positive by construction."""

    model_config = ConfigDict(extra="forbid")

    path: str
    param: str


class GroundTruth(BaseModel):
    """The labelled manifest the app implements and the report is scored against."""

    model_config = ConfigDict(extra="forbid")

    vulns: list[VulnLabel]
    safe: list[SafeLabel]

    @property
    def expected_pairs(self) -> set[tuple[str, str]]:
        """The ``(bug_class, param)`` set a perfect scanner confirms exactly."""
        return {(v.bug_class, v.param) for v in self.vulns}

    @property
    def safe_params(self) -> set[str]:
        return {s.param for s in self.safe}


GROUND_TRUTH = GroundTruth(
    vulns=[
        # boolean-blind SQLi: a tautology payload flips the result set.
        VulnLabel(path="/search", param="term", bug_class="boolean_sqli"),
        # reflected XSS: the parameter is echoed into HTML unescaped.
        VulnLabel(path="/profile", param="bio", bug_class="xss"),
        # IDOR / BOLA: object reference honoured across tenants (no owner check).
        VulnLabel(path="/document", param="docid", bug_class="idor"),
    ],
    safe=[
        # constant response, input ignored — nothing to confirm.
        SafeLabel(path="/status", param="check"),
        # input consumed server-side but never reflected and not injectable.
        SafeLabel(path="/feedback", param="rating"),
    ],
)


# ---------------------------------------------------------------------------
# The deliberately-vulnerable benchmark app (loopback only)
# ---------------------------------------------------------------------------

# Two tenants keyed by an opaque session cookie. No login flow is needed — the
# cookie *is* the identity — which keeps the harness deterministic. The IDOR
# endpoint deliberately omits the owner check.
_SESSIONS = {"crucible-alice": "alice", "crucible-bob": "bob"}
_DOCS = {
    "1": ("alice", "alice-private-tax-return-A1B2C3"),
    "2": ("bob", "bob-confidential-medical-record-X9Y8Z7"),
}

# The index links every endpoint with a seed value so the crawler discovers each
# request (and thus each parameter) as a query-value insertion point.
_INDEX = (
    "<html><body>"
    '<a href="/search?term=hello">search</a>'
    '<a href="/profile?bio=hi">profile</a>'
    '<a href="/document?docid=1">document</a>'
    '<a href="/status?check=1">status</a>'
    '<a href="/feedback?rating=5">feedback</a>'
    "</body></html>"
).encode()


def _looks_sqli(value: str) -> bool:
    """The benchmark's stand-in for a query that a boolean-blind injection would
    turn always-true. Deliberately narrow so the scanner's benign baseline value
    never trips it — only an actual tautology payload does."""
    low = value.lower()
    return "'='" in value or " or " in low


class _BenchmarkApp(BaseHTTPRequestHandler):
    """Serves the endpoints labelled in :data:`GROUND_TRUTH`. Each endpoint
    reacts to exactly one payload class and is inert to the others, so a
    finding's ``(bug_class, param)`` maps unambiguously back to the manifest."""

    def log_message(self, *args: object) -> None:  # silence stderr access log
        return

    def _user(self) -> str | None:
        cookie = self.headers.get("Cookie", "") or ""
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return _SESSIONS.get(value)
        return None

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        sp = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(sp.query, keep_blank_values=True)

        if sp.path == "/search":
            # VULN boolean_sqli: a tautology flips a small result set into a
            # large one. Input is NOT reflected, so the reflected-XSS check
            # cannot fire here and only the differential oracle sees a signal.
            term = params.get("term", [""])[0]
            if _looks_sqli(term):
                rows = "\n".join(f"row {i}: user account #{i}" for i in range(1, 25))
                self._reply(200, f"results:\n{rows}".encode())
            else:
                self._reply(200, b"results:\nno matching records")
            return

        if sp.path == "/profile":
            # VULN xss: bio is echoed UNESCAPED, but only when it carries markup
            # (a '<'). Payloads without markup (the SQLi baseline/probe, IDOR
            # refs) hit the constant branch, so only the XSS canary reflects.
            bio = params.get("bio", [""])[0]
            if "<" in bio:
                self._reply(200, f"<html><body><div>bio: {bio}</div></body></html>".encode())
            else:
                self._reply(200, b"<html><body>profile page</body></html>")
            return

        if sp.path == "/document":
            # VULN idor: returns the requested object with NO owner check, so a
            # logged-in tenant can read another tenant's document. Unknown ids
            # return a constant, so the SQLi/XSS probes see no differential.
            user = self._user()
            if user is None:
                self._reply(401, b"authentication required")
                return
            doc = _DOCS.get(params.get("docid", [""])[0])
            if doc is None:
                self._reply(404, b"no such document")
                return
            owner, secret = doc
            self._reply(200, f"document owner={owner} body={secret}".encode())
            return

        if sp.path == "/status":
            # SAFE: constant health string, input ignored entirely.
            self._reply(200, b"status: service ok")
            return

        if sp.path == "/feedback":
            # SAFE: input consumed server-side (a rating) but never reflected
            # and not used in any sink — a genuine non-vulnerable parameter.
            _ = params.get("rating", [""])[0]
            self._reply(200, b"feedback recorded, thank you")
            return

        self._reply(200, _INDEX)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextlib.contextmanager
def _serve() -> Iterator[str]:
    """Stand the benchmark app up on an ephemeral loopback port; tear it down on
    exit. Yields the base URL."""
    srv = _Server(("127.0.0.1", 0), _BenchmarkApp)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _raw_send(request: HttpRequest) -> dict:
    """Loopback HTTP send. Returns error responses as dicts (401/403/404 are
    normal signals here) rather than raising, so a check sees them as data."""
    req = urllib.request.Request(request.url, method=request.method, headers=dict(request.headers))
    if request.body is not None:
        req.data = request.body.encode("utf-8")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (loopback only)
            return {"status": resp.status, "headers": list(resp.headers.items()),
                    "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "headers": list(exc.headers.items()),
                "body": exc.read().decode("utf-8", "replace")}


def _with_cookie(send: Send, cookie: str) -> Send:
    """Wrap ``send`` so every request carries a fixed session cookie — the
    campaign runs as one authenticated identity throughout."""

    def _send(request: HttpRequest) -> dict:
        headers = [(k, v) for k, v in request.headers if k.lower() != "cookie"]
        headers.append(("Cookie", cookie))
        return send(request.model_copy(update={"headers": headers}))

    return _send


# ---------------------------------------------------------------------------
# Scored report
# ---------------------------------------------------------------------------


class ClassScore(BaseModel):
    """Per-``bug_class`` confusion counts and derived precision/recall."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0


class MatchPair(BaseModel):
    """A ``(bug_class, param)`` identity — the unit the harness matches on."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    param: str


class BenchmarkReport(BaseModel):
    """The honest detection-quality number: how much of the planted ground truth
    the scanner confirmed, and whether it flagged anything it shouldn't have."""

    model_config = ConfigDict(extra="forbid")

    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    per_class: dict[str, ClassScore] = Field(default_factory=dict)
    confirmed: list[MatchPair] = Field(default_factory=list)
    expected: list[MatchPair] = Field(default_factory=list)
    false_positive_pairs: list[MatchPair] = Field(default_factory=list)
    safe_param_hits: list[MatchPair] = Field(
        default_factory=list,
        description="Confirmed findings landing on a manifest-SAFE parameter — "
        "the strict precision violation the oracle anchor is meant to preclude.",
    )


def _score(findings: list[AuditFinding], truth: GroundTruth) -> BenchmarkReport:
    """Match oracle-confirmed findings against the manifest by (bug_class, param)
    and compute the confusion matrix, overall and per class."""
    expected = truth.expected_pairs
    # De-duplicate confirmed findings to their (bug_class, param) identity: the
    # manifest labels a parameter, not each insertion point that reaches it.
    confirmed = {(f.bug_class, f.param) for f in findings}

    tp_pairs = confirmed & expected
    fp_pairs = confirmed - expected
    fn_pairs = expected - confirmed

    tp, fp, fn = len(tp_pairs), len(fp_pairs), len(fn_pairs)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    per_class: dict[str, ClassScore] = {}
    classes = {bc for bc, _ in expected} | {bc for bc, _ in confirmed}
    for bc in sorted(classes):
        exp_c = {p for c, p in expected if c == bc}
        conf_c = {p for c, p in confirmed if c == bc}
        per_class[bc] = ClassScore(
            bug_class=bc,
            true_positives=len(conf_c & exp_c),
            false_positives=len(conf_c - exp_c),
            false_negatives=len(exp_c - conf_c),
        )

    safe = truth.safe_params
    return BenchmarkReport(
        true_positives=tp, false_positives=fp, false_negatives=fn,
        precision=precision, recall=recall, f1=f1,
        per_class=per_class,
        confirmed=[MatchPair(bug_class=b, param=p) for b, p in sorted(confirmed)],
        expected=[MatchPair(bug_class=b, param=p) for b, p in sorted(expected)],
        false_positive_pairs=[MatchPair(bug_class=b, param=p) for b, p in sorted(fp_pairs)],
        safe_param_hits=[MatchPair(bug_class=b, param=p) for b, p in sorted(confirmed) if p in safe],
    )


def _default_campaign(send: Send, *, insertion_kinds: tuple[InsertionKind, ...]) -> WebScanCampaign:
    """Build the campaign that covers every seeded class. The IDOR check needs a
    second identity (the victim's send) which the default check set cannot carry
    on its own, so the harness supplies it here."""
    victim_send = _with_cookie(_raw_send, "session=crucible-bob")
    checks = (
        BOOLEAN_SQLI,
        REFLECTED_XSS,
        IdorCheck(id="idor-doc", ref_param="docid", victim_ref="2", victim_send=victim_send),
    )
    return WebScanCampaign(
        send, checks=checks, insertion_kinds=insertion_kinds, enable_oob=False,
    )


def run_benchmark(
    campaign_factory: CampaignFactory | None = None,
    *,
    insertion_kinds: tuple[InsertionKind, ...] = (InsertionKind.QUERY_VALUE,),
) -> BenchmarkReport:
    """Run the scanner against the ground-truth benchmark app and score it.

    Stands the deliberately-vulnerable app up on loopback, runs a
    :class:`WebScanCampaign` (the default covers every seeded class; pass
    ``campaign_factory(send) -> WebScanCampaign`` to substitute your own check
    set / budget), matches confirmed findings against :data:`GROUND_TRUTH` by
    ``(bug_class, param)``, and returns the scored :class:`BenchmarkReport`.

    Deterministic and loopback-only: the app makes no time- or randomness-based
    decisions, and the campaign's authenticated ``send`` is the sole traffic
    path."""
    with _serve() as base:
        attacker_send = _with_cookie(_raw_send, "session=crucible-alice")
        if campaign_factory is None:
            campaign = _default_campaign(attacker_send, insertion_kinds=insertion_kinds)
        else:
            campaign = campaign_factory(attacker_send)
        report = campaign.run(base + "/")
    return _score(report.active_findings, GROUND_TRUTH)
