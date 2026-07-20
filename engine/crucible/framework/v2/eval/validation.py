"""
eval.validation — the comparative validation / benchmark spine.

Where `eval.harness` scores CRUCIBLE's own produced findings against a corpus
(the self-improvement loop), this module is the *comparative* spine that lets a
coverage gain be PROVEN against the incumbents. It defines one normalized finding
shape every tool speaks, a precision/recall Scoreboard, a greedy produced-vs-truth
matcher over (bug_class, path+param) locations, an in-process CRUCIBLE runner over
a loopback target, and a comparative report that runs every available adapter
(CRUCIBLE + the Burp/Nuclei/ZAP/sqlmap adapters in `eval.adapters`) against the
same labelled target — so "does it find what they miss, with fewer false
positives" becomes a number, not an anecdote.

Deterministic where the tools allow; no third-party deps in the core (stdlib +
pydantic). Incumbent adapters shell out (see `eval.adapters`).
"""

from __future__ import annotations

import json
import resource
import time
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..common.errors import EvalError
from ..scanner.campaign import ScanReport, WebScanCampaign
from ..scanner.cli import loopback_send
from ..scanner.engine import AuditFinding
from ..scanner.insertion import InsertionKind
from .models import _normalize_class


class HarnessError(EvalError):
    """A benchmark-harness failure: an unloadable corpus target, a CRUCIBLE run
    pointed at a non-loopback host, or a malformed scoreboard input. A recoverable
    measurement error (a CrucibleError), never an authorization decision."""


# The loopback hosts CRUCIBLE's thin in-process runner is allowed to hit. The
# comparative CRUCIBLE adapter is a measurement tool, not the gated executor, so
# — exactly like scanner.cli — it refuses any non-loopback target rather than
# send ungated traffic. Remote authorized targets go through `engage`.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _is_loopback(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in _LOOPBACK_HOSTS


# ---------------------------------------------------------------------------
# location canonicalisation — the surface half of a finding's identity.
#
# A location is a URL, a path+query, or a bare parameter name (CRUCIBLE's
# AuditFinding retains the fuzzed parameter but not the endpoint URL, so its
# findings are param-level). `_split_location` reduces any of these to a
# comparable (path, {param names}) pair, and `_locations_correspond` is the
# matcher's "same path+param" relation over two such pairs.
# ---------------------------------------------------------------------------


def _split_location(loc: str) -> tuple[str, frozenset[str]]:
    """Reduce a location string to ``(normalized_path, param_names)``.

    Accepts a full URL (``http://h/p?a=1``), a path+query (``/p?a``), or a bare
    parameter token (``a``). A bare token has an empty path and itself as the
    sole param, so it can still line up with a path+param label on the param."""
    s = (loc or "").strip().lower()
    if not s:
        return ("", frozenset())
    # a bare parameter token carries no URL structure
    if not any(ch in s for ch in "/?=&"):
        return ("", frozenset({s}))
    if "://" in s:  # drop scheme://authority, keep the path onward
        rest = s.split("://", 1)[1]
        slash = rest.find("/")
        s = rest[slash:] if slash != -1 else "/"
    s = s.split("#", 1)[0]  # drop fragment
    path, _, query = s.partition("?")
    path = path.rstrip("/") or "/"
    params = {
        chunk.split("=", 1)[0].strip()
        for chunk in query.split("&")
        if chunk.split("=", 1)[0].strip()
    }
    return (path, frozenset(params))


def _canon_location(loc: str) -> str:
    """A stable canonical string for a location — the surface half of a
    finding's dedup key. ``/p?a=1&b=2`` and ``/p/?b=2&a=1`` collapse alike."""
    path, params = _split_location(loc)
    return f"{path}?{','.join(sorted(params))}" if params else path


def _paths_agree(a: str, b: str) -> bool:
    """Two non-empty paths line up if they are equal or one is the other's
    tail (a full-URL path vs a relative one, e.g. ``/app/search`` ⊇ ``/search``)."""
    return a == b or a.endswith(b) or b.endswith(a)


def _locations_correspond(produced: str, expected: str) -> bool:
    """The "same path+param" relation: two locations correspond iff their named
    parameters share one AND their paths agree — with a fallback to param-only
    when a side has no path (CRUCIBLE's param-level findings) and to path-only
    when a side names no param (a tool that reports only an endpoint)."""
    pp, sp = _split_location(produced)
    pe, se = _split_location(expected)
    if sp and se:  # both name params -> require a shared param
        if not (sp & se):
            return False
        return _paths_agree(pp, pe) if (pp and pe) else True
    if pp and pe:  # neither/only-one names a param -> fall back to path
        return _paths_agree(pp, pe)
    return _canon_location(produced) == _canon_location(expected)


# ---------------------------------------------------------------------------
# schemas
# ---------------------------------------------------------------------------


class NormalizedFinding(BaseModel):
    """One finding in the tool-agnostic shape the comparative harness scores.

    Every adapter — CRUCIBLE and each incumbent — maps its native output to this,
    so a scoreboard compares like with like. ``confirmed`` is True only for a
    CRUCIBLE oracle-confirmed finding (the precision anchor the incumbents'
    heuristic detections lack); it is metadata, not a match input."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    bug_class: str = Field(description="Normalized, lowercased bug class.")
    location: str = Field(description="URL, path+param, or bare param the finding sits on.")
    severity: str = ""
    confirmed: bool = False
    evidence: str = ""

    @field_validator("bug_class")
    @classmethod
    def _normalize_bug_class(cls, v: str) -> str:
        return v.strip().lower()

    def key(self) -> tuple[str, str]:
        """The canonical identity — ``(normalized bug_class, canonical location)``
        — used to de-duplicate a tool's output before scoring."""
        return (_normalize_class(self.bug_class), _canon_location(self.location))


class ExpectedFinding(BaseModel):
    """One ground-truth label: the bug class planted on a location."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    location: str


class CorpusTarget(BaseModel):
    """A labelled benchmark target: where to point every tool, and the complete
    manifest of what is actually there. Complete ground truth is what makes a
    false-positive count meaningful — anything a tool reports off-manifest is a
    false positive by construction."""

    model_config = ConfigDict(extra="forbid")

    name: str
    base_url: str
    expected: list[ExpectedFinding] = Field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_json(cls, path: str | Path) -> "CorpusTarget":
        """Load one target manifest from a JSON file."""
        p = Path(path).expanduser()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except OSError as e:
            raise HarnessError(f"cannot read corpus target {p}: {e}") from e
        except json.JSONDecodeError as e:
            raise HarnessError(f"corpus target {p} is not valid JSON: {e}") from e
        try:
            return cls.model_validate(data)
        except ValidationError as e:
            raise HarnessError(f"corpus target {p} is not a valid CorpusTarget: {e}") from e

    @classmethod
    def load_corpus(cls, directory: str | Path) -> list["CorpusTarget"]:
        """Load every ``*.json`` target manifest in a directory (sorted for a
        deterministic order)."""
        d = Path(directory).expanduser()
        if not d.is_dir():
            raise HarnessError(f"corpus directory does not exist: {d}")
        return [cls.from_json(p) for p in sorted(d.glob("*.json"))]


class Scoreboard(BaseModel):
    """One tool's confusion counts on one target, with derived precision/recall.

    Divide-by-zero is guarded to 0.0 throughout: a tool that finds nothing
    (tp+fp == 0) has precision 0.0, and a target with no ground truth (tp+fn == 0)
    yields recall 0.0 — the honest floor for a comparative table."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    target: str
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 6) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 6) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 6) if (p + r) else 0.0


class RunMetrics(BaseModel):
    """The performance/cost side of one tool's run on one target — the axis a
    precision/recall Scoreboard is silent on. Professionals judge a scanner on
    *what it costs to find what it finds*: wall-clock, active-request budget, and
    coverage breadth. Numbers a tool cannot honestly report are ``None``, never a
    fabricated zero — an incumbent that CRUCIBLE shells out to does not expose its
    internal request count, so ``requests_sent`` is None for it, not 0.

    ``peak_rss_kb`` is best-effort (see :func:`_attributable_rss`): for a
    subprocess incumbent it is that child's max resident set; for the in-process
    CRUCIBLE runner it is a coarse process high-water delta and is only meaningful
    on the first in-process run of a fresh process. Treat it as an indicator, not
    a precise measurement — wall-clock and request count are the load-bearing
    performance metrics."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    target: str
    elapsed_s: float = 0.0
    requests_sent: int | None = None
    peak_rss_kb: int | None = None
    pages_discovered: int | None = None
    requests_discovered: int | None = None
    findings_reported: int = 0

    @property
    def peak_rss_mb(self) -> float | None:
        return round(self.peak_rss_kb / 1024, 1) if self.peak_rss_kb is not None else None


class MeasuredBoard(BaseModel):
    """A tool's :class:`Scoreboard` (accuracy) paired with its :class:`RunMetrics`
    (cost) on the same target — the full comparative row."""

    model_config = ConfigDict(extra="forbid")

    scoreboard: Scoreboard
    metrics: RunMetrics


def _attributable_rss(self0: int, self1: int, child0: int, child1: int) -> int | None:
    """Best-effort peak RSS (KB) to attribute to a single adapter run, from
    ``getrusage`` snapshots taken before/after it.

    A subprocess incumbent moves ``RUSAGE_CHILDREN.ru_maxrss`` (the high-water of
    terminated children); its rise over the run is that tool's peak, and we prefer
    it. Failing that (an in-process run spawns no child), we fall back to the rise
    in ``RUSAGE_SELF.ru_maxrss`` — a monotonic process high-water, so only the
    first in-process run of a fresh process yields a non-zero, and even then it is
    coarse. When neither moved we report ``None`` rather than an untrue 0. On
    Linux ``ru_maxrss`` is in kilobytes."""
    child_delta = child1 - child0
    if child_delta > 0:
        return child_delta
    self_delta = self1 - self0
    if self_delta > 0:
        return self_delta
    return None


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def score(
    produced: list[NormalizedFinding],
    expected: list[ExpectedFinding],
    *,
    tool: str,
    target: str,
    class_key: Callable[[str], str] = _normalize_class,
) -> Scoreboard:
    """Score ``produced`` against ``expected`` and return a Scoreboard.

    A produced finding matches an expected one iff their bug classes are equal
    under ``class_key`` AND their locations correspond (same path+param — see
    :func:`_locations_correspond`). This is a greedy one-to-one match: each
    expected finding is claimed by at most one produced finding.

    ``class_key`` canonicalises a bug-class label for the equality test; it
    defaults to :func:`eval.models._normalize_class` (format-only). A corpus whose
    ground-truth vocabulary is coarser than CRUCIBLE's — e.g. OWASP Benchmark's
    single ``sqli`` category vs CRUCIBLE's ``boolean_sqli``/``error_based_sqli`` —
    passes a family-collapsing key so a subclass detection still matches the family
    label. Both sides go through the same key, so it can never inflate a match.

    Matcher provenance: this reuses the greedy-1-1 *shape* of
    :func:`eval.scoring.score_target` (and its bug-class normalization,
    :func:`eval.models._normalize_class`), but with a location-aware predicate
    rather than that module's surface-containment/detection-key predicate —
    NormalizedFinding's location is a URL/path+param, a different surface
    vocabulary than a GroundTruthFinding's free-text ``surface``.

    Produced findings are de-duplicated by canonical key first, so a bug reported
    twice is one TP or one FP, never double-counted. TP = matched expected,
    FP = deduped produced that matched nothing, FN = expected left unmatched."""
    seen: set[tuple[str, str]] = set()
    unique: list[NormalizedFinding] = []
    for f in produced:
        k = f.key()
        if k in seen:
            continue
        seen.add(k)
        unique.append(f)

    claimed = [False] * len(expected)
    true_positives = 0
    for f in unique:
        fc = class_key(f.bug_class)
        for i, exp in enumerate(expected):
            if claimed[i]:
                continue
            if fc == class_key(exp.bug_class) and _locations_correspond(f.location, exp.location):
                claimed[i] = True
                true_positives += 1
                break

    return Scoreboard(
        tool=tool,
        target=target,
        true_positives=true_positives,
        false_positives=len(unique) - true_positives,
        false_negatives=len(expected) - true_positives,
    )


# ---------------------------------------------------------------------------
# adapters — CRUCIBLE lives here; the incumbents live in eval.adapters
# ---------------------------------------------------------------------------


@runtime_checkable
class Adapter(Protocol):
    """A pluggable tool the comparative harness can run against a target.

    ``available()`` decides whether the tool can run at all (binary on PATH, REST
    endpoint configured, in-process); the harness silently skips an unavailable
    adapter. ``run()`` executes it and returns normalized findings."""

    name: str

    def available(self) -> bool: ...

    def run(self, target: "CorpusTarget") -> "list[NormalizedFinding]": ...


class CrucibleAdapter:
    """Runs CRUCIBLE's own :class:`WebScanCampaign` against a target and maps its
    oracle-confirmed :class:`ScanReport.active_findings` to NormalizedFindings.

    Loopback-only: like ``scanner.cli``, this in-process runner issues traffic
    through the plain :func:`loopback_send` client, so it refuses any non-loopback
    host rather than send ungated traffic (a remote authorized target goes through
    ``engage``). Every mapped finding carries ``confirmed=True`` — CRUCIBLE only
    reports what an oracle proved.

    ``AuditFinding`` retains the fuzzed *parameter* but not the endpoint URL, so a
    mapped finding's ``location`` is param-level; the scorer's path+param fallback
    still lines it up with a path+param ground-truth label."""

    name: str = "crucible"

    def __init__(
        self,
        *,
        max_pages: int = 100,
        max_depth: int = 6,
        max_audit_requests: int = 0,
        enable_oob: bool = True,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
        authorized_hosts: frozenset[str] = frozenset(),
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_audit_requests = max_audit_requests
        self.enable_oob = enable_oob
        self.insertion_kinds = insertion_kinds
        # Non-loopback hosts an operator has explicitly authorized for the eval
        # corpus (e.g. a dockerized app bound to a container-network IP, or an
        # operator-run remote target). Empty by default, so out of the box this
        # runner stays loopback-only — exactly like `scan`. The corpus runner is
        # the only caller that populates this, and only for a host the operator
        # named. Local containers on 127.0.0.1:PORT don't need it: they are
        # already loopback.
        self.authorized_hosts = authorized_hosts
        # Tool-specific metrics the harness reads back after run(); CRUCIBLE knows
        # its exact request budget and crawl breadth, which shell-out incumbents do
        # not expose. Reset per run so a skipped/failed run never reports stale data.
        self.last_metrics: dict[str, int] | None = None

    def available(self) -> bool:
        """Always available — the scanner is in-process, no external tool."""
        return True

    def _authorized(self, base_url: str) -> bool:
        """A target is scannable by this in-process runner if it is loopback OR its
        host was explicitly authorized by the operator for the eval corpus."""
        host = (urlsplit(base_url).hostname or "").lower()
        return _is_loopback(base_url) or host in self.authorized_hosts

    def run(self, target: "CorpusTarget") -> list[NormalizedFinding]:
        if not self._authorized(target.base_url):
            raise HarnessError(
                f"CrucibleAdapter refuses {target.base_url!r}: not loopback and not in "
                "authorized_hosts. Pass the operator-authorized host explicitly for the "
                "eval corpus, or scan a remote target through the gated `engage` runner."
            )
        report: ScanReport = WebScanCampaign(
            loopback_send,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            max_audit_requests=self.max_audit_requests,
            enable_oob=self.enable_oob,
            insertion_kinds=self.insertion_kinds,
        ).run(target.base_url)
        return self._record(report)

    def _record(self, report: ScanReport) -> list[NormalizedFinding]:
        """Capture the run's request/discovery counts into ``last_metrics`` and
        return the normalized oracle-confirmed findings. Shared by every
        CrucibleAdapter variant so each records the same tool-specific metrics the
        measured harness reads back — no matter which ``run()`` built the report."""
        self.last_metrics = {
            "requests_sent": report.audit_requests_sent,
            "pages_discovered": report.pages_crawled,
            "requests_discovered": report.requests_discovered,
        }
        return [self._normalize(f) for f in report.active_findings]

    @staticmethod
    def _normalize(finding: AuditFinding) -> NormalizedFinding:
        # Build the richest location the finding supports. When the endpoint URL is
        # known (the common case now), emit ``path?param`` so the finding is locatable
        # to a specific page — essential on a multi-endpoint app where the same param
        # name recurs across many endpoints. Fall back to the bare param (then the
        # insertion-point id for request-level findings) when no endpoint was retained.
        param = finding.param
        param_token = param if param and param != "(request)" else finding.insertion_point
        if finding.endpoint:
            path = urlsplit(finding.endpoint).path.rstrip("/") or "/"
            location = f"{path}?{param_token}" if param and param != "(request)" else path
        else:
            location = param_token
        return NormalizedFinding(
            tool="crucible",
            bug_class=finding.bug_class,
            location=location,
            severity="high",  # active findings are oracle-confirmed exploitable
            confirmed=True,
            evidence=f"{finding.confirmed_by}: {finding.rationale}".strip(": "),
        )


# ---------------------------------------------------------------------------
# comparative report
# ---------------------------------------------------------------------------


def comparative_report_measured(
    target: CorpusTarget,
    adapters: list[Adapter],
    *,
    class_key: Callable[[str], str] = _normalize_class,
) -> list[MeasuredBoard]:
    """Run every *available* adapter against ``target``, and for each return both
    its accuracy Scoreboard and its :class:`RunMetrics` (wall-clock, request
    budget, coverage, best-effort peak RSS).

    Timing and RSS are measured generically by wrapping ``run()`` — they work for
    any adapter, in-process or shell-out. Tool-specific counts (exact requests
    sent, pages/requests discovered) are read back from an adapter's optional
    ``last_metrics`` dict, which the CRUCIBLE adapter populates and incumbents
    leave unset (reported as ``None``, never a fake 0). Unavailable adapters are
    skipped, not failed — we compare whatever is present on this host, honestly."""
    boards: list[MeasuredBoard] = []
    for adapter in adapters:
        try:
            usable = adapter.available()
        except Exception:  # a broken availability probe just skips the tool
            usable = False
        if not usable:
            continue
        # Clear any stale per-run metrics so a run that sets none reports None.
        if hasattr(adapter, "last_metrics"):
            adapter.last_metrics = None  # type: ignore[attr-defined]
        self0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        child0 = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        t0 = time.monotonic()
        produced = adapter.run(target)
        elapsed = time.monotonic() - t0
        self1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        child1 = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

        board = score(produced, target.expected, tool=adapter.name,
                      target=target.name, class_key=class_key)
        partial = getattr(adapter, "last_metrics", None) or {}
        metrics = RunMetrics(
            tool=adapter.name,
            target=target.name,
            elapsed_s=round(elapsed, 3),
            peak_rss_kb=_attributable_rss(self0, self1, child0, child1),
            findings_reported=len(produced),
            requests_sent=partial.get("requests_sent"),
            pages_discovered=partial.get("pages_discovered"),
            requests_discovered=partial.get("requests_discovered"),
        )
        boards.append(MeasuredBoard(scoreboard=board, metrics=metrics))
    return boards


def comparative_report(
    target: CorpusTarget,
    adapters: list[Adapter],
    *,
    class_key: Callable[[str], str] = _normalize_class,
) -> list[Scoreboard]:
    """Accuracy-only view of :func:`comparative_report_measured`: run every
    available adapter against ``target`` and return just the scoreboards. Kept as
    the stable, backward-compatible entry point for callers that do not need the
    performance metrics."""
    return [
        mb.scoreboard
        for mb in comparative_report_measured(target, adapters, class_key=class_key)
    ]


def render_table(scoreboards: list[Scoreboard]) -> str:
    """Render a comparative scoreboard as a fixed-width text table:
    ``tool | tp | fp | fn | precision | recall | f1``."""
    header = ("tool", "tp", "fp", "fn", "precision", "recall", "f1")
    rows: list[tuple[str, ...]] = [header]
    for s in scoreboards:
        rows.append((
            s.tool,
            str(s.true_positives),
            str(s.false_positives),
            str(s.false_negatives),
            f"{s.precision:.3f}",
            f"{s.recall:.3f}",
            f"{s.f1:.3f}",
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines: list[str] = []
    for j, row in enumerate(rows):
        lines.append(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if j == 0:
            lines.append("-+-".join("-" * w for w in widths))
    return "\n".join(lines)


def render_measured_table(measured: list[MeasuredBoard]) -> str:
    """Render the full accuracy+cost comparative table:
    ``tool | tp | fp | fn | precision | recall | f1 | time_s | reqs | rss_mb | found``.

    Cost columns a tool does not report show ``-`` (an honest gap), never 0."""
    def _opt(v: object) -> str:
        return "-" if v is None else str(v)

    header = ("tool", "tp", "fp", "fn", "precision", "recall", "f1",
              "time_s", "reqs", "rss_mb", "found")
    rows: list[tuple[str, ...]] = [header]
    for mb in measured:
        s, m = mb.scoreboard, mb.metrics
        rows.append((
            s.tool,
            str(s.true_positives),
            str(s.false_positives),
            str(s.false_negatives),
            f"{s.precision:.3f}",
            f"{s.recall:.3f}",
            f"{s.f1:.3f}",
            f"{m.elapsed_s:.2f}",
            _opt(m.requests_sent),
            _opt(m.peak_rss_mb),
            str(m.findings_reported),
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    lines: list[str] = []
    for j, row in enumerate(rows):
        lines.append(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if j == 0:
            lines.append("-+-".join("-" * w for w in widths))
    return "\n".join(lines)
