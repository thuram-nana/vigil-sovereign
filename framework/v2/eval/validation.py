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
from pathlib import Path
from typing import Protocol, runtime_checkable
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


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def score(
    produced: list[NormalizedFinding],
    expected: list[ExpectedFinding],
    *,
    tool: str,
    target: str,
) -> Scoreboard:
    """Score ``produced`` against ``expected`` and return a Scoreboard.

    A produced finding matches an expected one iff their normalized bug classes
    are equal AND their locations correspond (same path+param — see
    :func:`_locations_correspond`). This is a greedy one-to-one match: each
    expected finding is claimed by at most one produced finding.

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
        fc = _normalize_class(f.bug_class)
        for i, exp in enumerate(expected):
            if claimed[i]:
                continue
            if fc == _normalize_class(exp.bug_class) and _locations_correspond(f.location, exp.location):
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
    ) -> None:
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_audit_requests = max_audit_requests
        self.enable_oob = enable_oob
        self.insertion_kinds = insertion_kinds

    def available(self) -> bool:
        """Always available — the scanner is in-process, no external tool."""
        return True

    def run(self, target: "CorpusTarget") -> list[NormalizedFinding]:
        if not _is_loopback(target.base_url):
            raise HarnessError(
                f"CrucibleAdapter is loopback-only; refusing {target.base_url!r}. "
                "Scan an authorized remote target through the gated `engage` runner."
            )
        report: ScanReport = WebScanCampaign(
            loopback_send,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            max_audit_requests=self.max_audit_requests,
            enable_oob=self.enable_oob,
            insertion_kinds=self.insertion_kinds,
        ).run(target.base_url)
        return [self._normalize(f) for f in report.active_findings]

    @staticmethod
    def _normalize(finding: AuditFinding) -> NormalizedFinding:
        # Prefer the human parameter name as the location; request-level findings
        # (param == "(request)") fall back to the insertion-point id.
        param = finding.param
        location = param if param and param != "(request)" else finding.insertion_point
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


def comparative_report(target: CorpusTarget, adapters: list[Adapter]) -> list[Scoreboard]:
    """Run every *available* adapter against ``target``, score each against the
    target's ground truth, and return the scoreboards. Unavailable adapters
    (tool not installed / not configured) are skipped, not failed — the point is
    to compare whatever is present on this host, honestly."""
    boards: list[Scoreboard] = []
    for adapter in adapters:
        try:
            usable = adapter.available()
        except Exception:  # a broken availability probe just skips the tool
            usable = False
        if not usable:
            continue
        produced = adapter.run(target)
        boards.append(score(produced, target.expected, tool=adapter.name, target=target.name))
    return boards


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
