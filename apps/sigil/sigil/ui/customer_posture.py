"""APEX consumer PR-B — the customer FIX-FIRST read and the posture TREND (Area 1, the UI half).

What the customer app's Fix-first screen (and the Overview's Posture card) shows, computed SOVEREIGN-side from the
org's OWN oracle-confirmed findings, over PR-A's presentation spine (``finding_presentation``) — never re-derived:

  * the POSTURE SCORE 0-100: PR-A's ``posture_score`` over the findings that are still OPEN. A finding whose newest
    C1b retest verdict says the proof no longer works ("fixed") stops counting against it — the verdict the
    Assessments screen badges — and a verdict counts only while the retest UI is on (the switch under which the
    Assessments screen shows verdicts at all). This read is the stricter of the two in exactly one case: a verdict
    covers only the proofs recorded BEFORE it (see below), so a finding proven again after its fix is open here;
  * the worst-first FIX-FIRST list: PR-A's per-finding triage entry (severity, the impact×effort priority and its
    tier, the standards chips, and — only when the certificate SIGNED them — the plain-language impact and the exact
    remediation), in PR-A's order, plus what the screen needs to act on each one: its host, its retest status, and
    its full finding identity for the Retest button (``assessments.finding_identity``);
  * the posture TREND: the very same arithmetic re-applied at a small fixed series of points (weekly, oldest first,
    the last point being now), so "72, up from 65" is one function of what was on record at each point. A pure
    projection of the append-only spine — no new storage, no wall clock or randomness inside (``now`` is passed in),
    so a read is reproducible.

TENANT ISOLATION (the IDOR class) is STRUCTURAL, exactly as ``assessments`` has it: the engagement-slug set is
derived SERVER-SIDE from the org's OWN current ownership proofs (``_customer_slug`` is a one-way hash of
``org_id\\x00host``), every record — finding, retest verdict, assessment outcome — is kept ONLY when its own slug is
in that set, and nothing here is ever taken from the client. Another tenant's finding, its signed presentation and
its retest verdicts are therefore unreachable: they can neither be shown nor move this org's score or trend.

PROVEN ONLY, READ ONLY. Only ``kind="finding"`` records that carry a certificate (oracle-confirmed FACTs admitted by
the finding receiver) are scored, and only the provisioner's own ``finding_retest`` records (source ``provision``,
the one writer the C1b overlay accepts) can mark one fixed. This module writes nothing, decides no verdict, mints
nothing and makes no model call. The score is PR-A's honest heuristic for prioritising, not a certified rating; the
read returns its basis so a reader can see exactly how it was computed.

A FIX NEVER OUTLIVES A NEWER PROOF. A verdict applies only to finding records that landed BEFORE it (by spine seq):
a finding proven again after its "fixed" verdict is open again — and only open: its earlier record, the one the
verdict covered, is then neither listed nor counted as fixed (the finding is open once, never fixed and open at once).

THE TRIAL PREVIEW HOLDS HERE TOO. For an org whose report is locked (``finding_preview.preview_locked``), only the
ONE revealed finding (``finding_preview.reveal_seq``, pinned over the ever-proven slug set exactly as the findings
read pins it) carries its signed plain-language impact, its remediation and its identity; every other entry is
cut to an allowlist of what the locked findings read already reveals (title, rated severity, class, where) plus
class-level priority, standards chips and guidance — never its signed fix. The score and the trend are aggregates
of severity, which the preview already shows (``assessment_summary``'s per-host severity counts).

TIME. The trend places each record at its spine time (the store's append timestamp — informational, outside the
record digest, so it orders nothing here: which verdict is newest, and which finding a verdict covers, are decided by
the hash-chained seq). A time that cannot be read, or that lies ahead of ``now``, is placed where it can only make
the trend's improvement look SMALLER, never larger: a finding, a still-vulnerable verdict or a completed assessment
at the latest point, a fix at the earliest — so a bad time can never manufacture an "up from". The last point is
always the headline score. Points before the org's first measurement (its first finding or first completed
assessment on a verified host) carry no score: "not measured yet" is never shown as a perfect 100.

COST. Each read is ONE pass over the spine, as the C1b retest overlay's is: the record times the trend needs, and the
retest verdicts, are kept by no fold index, so they are read per request (the score and list need that same pass).

FATAL-2: sovereign-side, stdlib + ui-local only; ``assert_no_offense`` at import.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.asset_ownership import AssetOwnershipRegistry  # noqa: E402
from . import assessments as _assess  # noqa: E402
from . import finding_presentation as _fpres  # noqa: E402
from . import finding_preview as _fp  # noqa: E402

# The trend: a small FIXED series — TREND_POINTS points TREND_STEP_S apart, the last one at ``now`` (twelve weeks).
TREND_POINTS = 12
TREND_STEP_S = 7 * 24 * 3600
# The most entries one read returns per list; the *_total fields always carry the true counts.
LIST_CAP = 500

_FIXED = "fixed"
_STILL = "still_vulnerable"
_OPEN = "open"
_VERDICTS = (_FIXED, _STILL)
# An assessment outcome that MEASURED the host (a completed run with zero findings is still a measurement).
_MEASURED_OUTCOME = "completed"
_EARLIEST = float("-inf")

# What a LOCKED (trial-preview) entry may carry — an allowlist, so no field PR-A's triage entry gains later can ride
# past the lock. Every value here is what the locked findings read reveals, or class-level data derived from it.
_LOCKED_ENTRY_KEYS = ("finding_ref", "engagement_slug", "bug_class", "surface", "title", "severity", "severity_basis",
                      "priority_score", "effort", "tier", "tier_label", "standards_chips", "host", "status",
                      "status_at", "class_guidance", "locked")


def _record_time(ts: object) -> Optional[float]:
    """A spine record's ``ts`` (an ISO-8601 string; naive means UTC) as epoch seconds, or None when unreadable."""
    if not isinstance(ts, str) or not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None


def _placed(t: Optional[float], *, now: float, good_news: bool) -> float:
    """Where a record sits on the trend's time axis: its own time when readable and not ahead of ``now``; else the
    point that can only make the trend look worse — a fix (good news) at the earliest, anything else at ``now``."""
    if t is not None and t <= now:
        return t
    return _EARLIEST if good_news else now


class _Scan:
    """One pass over the spine, kept to the org's own slugs (see :func:`_scan`)."""

    __slots__ = ("findings", "verdicts", "outcomes", "ever")

    def __init__(self) -> None:
        self.findings: "list[tuple[int, Optional[float], dict]]" = []        # (seq, record time, projected row)
        self.verdicts: "dict[tuple, list[tuple[int, Optional[float], str]]]" = {}   # identity -> [(seq, t, status)]
        self.outcomes: "list[Optional[float]]" = []                          # completed assessments' record times
        self.ever: "list[tuple[int, dict]]" = []                             # (seq, {slug}) over the ever-proven set


def _scan(store, slugs: "set[str]", ever: "set[str]") -> _Scan:
    """ONE pass over the spine collecting the org's findings (``slugs`` — its CURRENT proven hosts, the set every
    customer read scores and shows), its provisioner-written retest verdicts and its completed assessments; and, for
    a locked trial org only (``ever`` non-empty), each finding's seq over its EVER-proven slugs, to pin the preview's
    one reveal. A record is kept only when its own engagement slug is a ``str`` in the set (an unhashable or missing
    slug is skipped, never compared). The finding filter and projection are exactly ``assessments``' own
    (``_finding_json``)."""
    out = _Scan()
    for r in store.iter_records():
        kind = getattr(r, "kind", None)
        p = getattr(r, "payload", None)
        if not isinstance(p, dict):
            continue
        if kind == _assess._FINDING_KIND:
            cert = p.get("certificate")
            if not isinstance(cert, dict):
                continue
            slug = cert.get("engagement_slug")
            if not isinstance(slug, str):
                continue
            seq = int(getattr(r, "seq", 0))
            if slug in ever:
                out.ever.append((seq, {"engagement_slug": slug}))
            if slug in slugs:
                out.findings.append((seq, _record_time(getattr(r, "ts", None)), _assess._finding_json(p, cert)))
        elif kind == _assess.RETEST_KIND:
            # the second, independent refusal the C1b overlay has: only the provisioner's retest action writes verdicts
            if getattr(r, "source", None) != _assess.RETEST_SOURCE:
                continue
            slug, status = p.get("engagement_slug"), p.get("status")
            if not isinstance(slug, str) or slug not in slugs:
                continue
            if not isinstance(p.get("finding_ref"), str) or status not in _VERDICTS:
                continue
            out.verdicts.setdefault(_assess.finding_identity(p), []).append(
                (int(getattr(r, "seq", 0)), _record_time(getattr(r, "ts", None)), status))
        elif kind == _assess._OUTCOME_KIND:
            slug = p.get("engagement_slug")
            if isinstance(slug, str) and slug in slugs and p.get("outcome") == _MEASURED_OUTCOME:
                out.outcomes.append(_record_time(getattr(r, "ts", None)))
    return out


class _Timeline:
    """The org's scored history, with every record already placed on the time axis (:func:`_placed`)."""

    __slots__ = ("findings", "verdicts", "first_measured")

    def __init__(self, scan: _Scan, *, now: float, use_verdicts: bool) -> None:
        # (seq, placed time, real time, row, identity)
        self.findings = [(seq, _placed(t, now=now, good_news=False), t, row, _assess.finding_identity(row))
                         for seq, t, row in scan.findings]
        # identity -> [(seq, placed time, real time, status)]; empty while the retest UI is off
        self.verdicts: "dict[tuple, list[tuple[int, float, Optional[float], str]]]" = {}
        if use_verdicts:
            for ident, rows in scan.verdicts.items():
                self.verdicts[ident] = [(seq, _placed(t, now=now, good_news=(st == _FIXED)), t, st)
                                        for seq, t, st in rows]
        firsts = [f[1] for f in self.findings]
        firsts += [_placed(t, now=now, good_news=False) for t in scan.outcomes]
        self.first_measured: Optional[float] = min(firsts) if firsts else None

    def verdict(self, ident: tuple, finding_seq: int, at: float) -> "Optional[tuple[int, float, Optional[float], str]]":
        """The newest verdict (by seq) for ``ident`` that is on record by ``at`` AND newer than the finding record
        (a verdict never covers a finding proven after it), or None — the finding has not been retested since."""
        best = None
        for v in self.verdicts.get(ident, ()):
            if v[0] > finding_seq and v[1] <= at and (best is None or v[0] > best[0]):
                best = v
        return best

    def state(self, at: float) -> "tuple[bool, list, list]":
        """(measured, open, fixed) as on record at ``at``; open/fixed are [(seq, row, verdict-or-None)]. A fixed record
        whose finding (its full identity) also has an OPEN record — necessarily a newer proof, since a verdict covers
        every older record of its finding — is superseded: the finding is open, and is not also listed as fixed."""
        measured = self.first_measured is not None and self.first_measured <= at
        open_rows: list = []
        fixed_rows: list = []
        still_open: set = set()
        for seq, placed, _t, row, ident in self.findings:
            if placed > at:
                continue
            v = self.verdict(ident, seq, at)
            if v is not None and v[3] == _FIXED:
                fixed_rows.append((seq, row, v, ident))
            else:
                open_rows.append((seq, row, v))
                still_open.add(ident)
        return measured, open_rows, [(s, r, v) for s, r, v, ident in fixed_rows if ident not in still_open]


def _timeline(store, org_id: str, *, now: float, use_verdicts: bool,
              locked: bool = False) -> "tuple[_Timeline, dict[str, str], Optional[int]]":
    """(timeline, host-by-slug for the org's CURRENT proven hosts, the preview's revealed seq when ``locked``)."""
    from .target_authorization import _customer_slug
    own = AssetOwnershipRegistry(store, owner_key=None)
    host_of = {_customer_slug(org_id, h): h for h in own.proven_hosts(org_id, now=now)}
    if not host_of:                                    # no proven host -> no slug -> nothing to read (fail-closed)
        return _Timeline(_Scan(), now=now, use_verdicts=False), host_of, None
    ever = {_customer_slug(org_id, h) for h in own.ever_proven_hosts(org_id)} if locked else set()
    scan = _scan(store, set(host_of), ever)
    revealed = _fp.reveal_seq(scan.ever, ever) if locked else None
    return _Timeline(scan, now=now, use_verdicts=use_verdicts), host_of, revealed


def _status_of(v) -> str:
    return _OPEN if v is None else v[3]


def _entry(row: dict, *, seq: int, verdict, host: Optional[str], shown_in_full: bool) -> "dict[str, Any]":
    """ONE list entry: PR-A's triage entry for the finding (never re-derived here) plus its host, its retest status
    and — when it is shown in full — its identity digest for the Retest button. A locked entry is built WITHOUT the
    signed presentation block and then cut to ``_LOCKED_ENTRY_KEYS``."""
    status = _status_of(verdict)
    if shown_in_full:
        e = _fpres._triage_row(row)
        e["oracle_context_digest"] = str(row.get("oracle_context_digest") or "")
    else:
        e = _fpres._triage_row({k: v for k, v in row.items() if k != "presentation"})
        guidance = _fp.lock_row(row, host).get("class_guidance")
        if guidance:
            e["class_guidance"] = guidance
        e["locked"] = True
    e["host"] = host
    e["status"] = status
    if verdict is not None and verdict[2] is not None:
        e["status_at"] = verdict[2]                       # when the verdict was recorded (its spine time)
    if not shown_in_full:
        e = {k: e[k] for k in _LOCKED_ENTRY_KEYS if k in e}
    return e


def _worst_first(entry: dict, seq: int) -> tuple:
    """PR-A's triage order (``finding_presentation._triage``: severity, then the impact×effort priority — a quick win
    first — then the finding ref), extended by the digest and the newest record so the order is total."""
    return (_fpres._severity_rank(entry["severity"]), -float(entry["priority_score"]), entry["finding_ref"],
            str(entry.get("oracle_context_digest") or ""), -seq)


def _trend(tl: _Timeline, *, now: float) -> "dict[str, Any]":
    points: "list[dict[str, Any]]" = []
    scored: "list[tuple[int, int]]" = []                  # (at, score) of every measured point, oldest first
    current: Optional[int] = None
    for k in range(TREND_POINTS):
        at = now - (TREND_POINTS - 1 - k) * TREND_STEP_S
        measured, open_rows, fixed_rows = tl.state(at)
        current = _fpres.posture_score([r for _s, r, _v in open_rows]) if measured else None
        if current is not None:
            scored.append((int(at), current))
        points.append({"at": int(at), "posture_score": current, "open": len(open_rows), "fixed": len(fixed_rows)})
    # the change is the latest score against the window's FIRST measured point; one measured point is no change yet
    first = scored[0] if len(scored) >= 2 else None
    return {"points": points, "step_seconds": TREND_STEP_S, "current": current,
            "since": first[0] if first is not None else None,
            "change": current - first[1] if first is not None and current is not None else None}


def _basis(*, use_verdicts: bool) -> "dict[str, Any]":
    """How the score was computed — PR-A's weights, never a copy — and whether retest verdicts counted."""
    return {
        "method": "100 × 100 // (100 + Σ severity penalties) over the org's OPEN oracle-confirmed findings",
        "weights": dict(_fpres._PENALTY),
        "counts_fixes": bool(use_verdicts),
        "note": "an honest heuristic for prioritising, not a measured or certified rating",
    }


def posture_trend(store, org_id: str, *, now: float, retest_verdicts: bool) -> "dict[str, Any]":
    """ONE org's posture over the last ``TREND_POINTS`` weeks (oldest first; the last point is ``now`` and equals
    the headline score of :func:`customer_posture`). Each point: the score (None before the org's first
    measurement), and how many proven findings were open / fixed then. ``change`` is the latest score minus the
    first scored point's (``since``), or None with fewer than two scored points. Tenant-scoped and read-only (see the
    module docstring); assumes the caller already authorized ``org_id`` for ``view_assessments``."""
    tl, _host_of, _rev = _timeline(store, org_id, now=now, use_verdicts=retest_verdicts)
    out = _trend(tl, now=now)
    out["org_id"] = org_id
    return out


def customer_posture(store, org_id: str, *, now: float, retest_verdicts: bool, locked: bool = False,
                     can_buy: bool = False) -> "dict[str, Any]":
    """ONE org's Fix-first view from its OWN oracle-confirmed findings: the posture score (None until the org's
    first measurement), the worst-first list of OPEN findings (each PR-A's triage entry + host + retest status +
    identity), the findings a retest proved fixed (newest verdict first), the open severity counts and standards
    summary, the trend (:func:`posture_trend`, from the SAME pass, so the tile and its last point always agree) and
    the score's basis. ``retest_verdicts``: count the C1b verdicts (the caller passes the retest UI switch).
    ``locked``: the org's report is the trial preview (``finding_preview.preview_locked``) — only the revealed
    finding is shown in full and a ``preview`` block says so (``can_buy``: the requester may buy the unlock).
    Assumes the caller already authorized ``org_id`` for ``view_assessments``."""
    tl, host_of, revealed = _timeline(store, org_id, now=now, use_verdicts=retest_verdicts, locked=locked)
    measured, open_rows, fixed_rows = tl.state(now)

    def entry(seq: int, row: dict, v) -> "dict[str, Any]":
        full = (not locked) or (revealed is not None and seq == revealed)
        return _entry(row, seq=seq, verdict=v, host=host_of.get(str(row.get("engagement_slug"))), shown_in_full=full)

    # open: worst first (PR-A's order); fixed: the newest verdict first, then worst first among one verdict's records.
    # Every sort key ends in the record's own seq, so both orders are total (and never compare two entries).
    keyed_open = []
    for s, r, v in open_rows:
        e = entry(s, r, v)
        keyed_open.append((_worst_first(e, s), e))
    keyed_fixed = []
    for s, r, v in fixed_rows:
        e = entry(s, r, v)
        keyed_fixed.append(((-v[0],) + _worst_first(e, s), e))
    opened = [e for _k, e in sorted(keyed_open, key=lambda ke: ke[0])]
    fixed = [e for _k, e in sorted(keyed_fixed, key=lambda ke: ke[0])]
    out: "dict[str, Any]" = {
        "org_id": org_id,
        "measured": measured,
        "posture_score": _fpres.posture_score([r for _s, r, _v in open_rows]) if measured else None,
        "hosts_total": len(host_of),
        "findings_total": len(open_rows) + len(fixed_rows),
        "open_total": len(open_rows),
        "fixed_total": len(fixed_rows),
        "severity_counts": _fp.severity_counts(r for _s, r, _v in open_rows),
        "fix_first": opened[:LIST_CAP],
        "fixed": fixed[:LIST_CAP],
        "standards_summary": _fpres._standards_summary(opened),
        "trend": _trend(tl, now=now),
        "basis": _basis(use_verdicts=retest_verdicts),
        "generated_from": "proven_findings",
    }
    if locked:
        out["preview"] = _fp.preview_block(can_buy=can_buy)
    return out
