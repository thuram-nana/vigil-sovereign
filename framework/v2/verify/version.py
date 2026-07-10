"""
verify.version — a PURE, deterministic version comparator + range-membership evaluator, and the
confirmation seam for the version-range oracle (Wave 5b).

The supply-chain half of prove-don't-guess. A scanner (grype / osv-scanner / trivy) reports "package X
version V is affected by CVE-Y". That is a THIRD-PARTY LEAD — a `fact` only when a deterministic oracle
proves that V actually falls inside the advisory's affected version range. This module is that proof:
it parses versions across ecosystems (PEP 440 via ``packaging`` first, then a loose numeric-segment
fallback) and evaluates membership over OSV-style ``{introduced, fixed, last_affected}`` ranges and
simple comparator strings (``>=1.0.0,<2.0.0``). It is FAIL-CLOSED: an unparseable version or range does
NOT confirm (the finding stays a lead), so a scanner's say-so can never be laundered into a fact and a
mangled range can never fabricate one.

Everything here is pure and deterministic (no I/O, no wallclock, no rng) and the evidence it judges is
JSON-safe, so a confirmed vulnerable-dependency re-verifies offline from its certificate (verify.reverify).
"""

from __future__ import annotations

import re
from typing import Any

from packaging.version import InvalidVersion
from packaging.version import parse as _pep440_parse

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier

# One comparable component: an int sorts below a str of the same position is handled by the tuple of
# (is_int, value) so numeric and alphanumeric segments never compare across types.
_SEG_RE = re.compile(r"[.\-+_~]")


def _loose_key(version: str) -> tuple | None:
    """A comparable key for a version ``packaging`` cannot parse (loose semver / vendor strings).
    Splits on ``. - + _ ~`` into numeric-aware segments; a release with a pre-release tag sorts BELOW
    the same release without one (``1.2.0-rc1`` < ``1.2.0``). Returns None if there is no digit at all
    (not a version)."""
    v = version.strip().lstrip("vV=").strip()
    if not v or not any(c.isdigit() for c in v):
        return None
    segs = [s for s in _SEG_RE.split(v) if s != ""]
    key: list[tuple[int, int, str]] = []
    saw_prerelease = False
    for s in segs:
        if s.isdigit():
            key.append((0, int(s), ""))
        else:
            saw_prerelease = True
            # split a mixed segment like 'rc1' into ('rc', 1) so 'rc2' > 'rc1'
            m = re.match(r"^([A-Za-z]*)(\d*)$", s)
            alpha = (m.group(1) if m else s).lower()
            num = int(m.group(2)) if (m and m.group(2)) else -1
            key.append((1, num, alpha))
    # a trailing pre-release tag makes the whole version sort just BELOW its release counterpart
    return (tuple(key), 0 if saw_prerelease else 1)


class _Ver:
    """A comparable version — PEP 440 when possible, else the loose key. Unparseable -> ``.ok`` False,
    and every comparison returns False so it never lands 'inside' a range (fail-closed)."""

    __slots__ = ("raw", "_pep", "_loose", "ok")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self._pep = None
        self._loose = None
        try:
            self._pep = _pep440_parse(str(raw).strip().lstrip("vV=").strip())
        except (InvalidVersion, TypeError, ValueError):
            self._loose = _loose_key(str(raw))
        self.ok = self._pep is not None or self._loose is not None

    def _cmp(self, other: "_Ver") -> int | None:
        if self._pep is not None and other._pep is not None:
            return (self._pep > other._pep) - (self._pep < other._pep)
        a, b = _Ver(self.raw)._loose or _loose_key(self.raw), other._loose or _loose_key(other.raw)
        # if one is PEP-parseable and the other only loose, fall back to loose on BOTH for a stable order
        if a is None:
            a = _loose_key(self.raw)
        if b is None:
            b = _loose_key(other.raw)
        if a is None or b is None:
            return None
        return (a > b) - (a < b)

    def lt(self, o: "_Ver") -> bool:
        c = self._cmp(o); return c is not None and c < 0

    def le(self, o: "_Ver") -> bool:
        c = self._cmp(o); return c is not None and c <= 0

    def ge(self, o: "_Ver") -> bool:
        c = self._cmp(o); return c is not None and c >= 0

    def gt(self, o: "_Ver") -> bool:
        c = self._cmp(o); return c is not None and c > 0


def _in_osv_range(ver: _Ver, rng: dict) -> bool:
    """Membership in one OSV-style range: affected iff ver >= introduced AND (ver < fixed OR
    ver <= last_affected). A missing ``introduced`` means from 0 (``introduced: "0"`` in OSV). Requires
    an explicit upper bound (fixed / last_affected) — an open-ended range does NOT confirm (fail-closed)."""
    intro = str(rng.get("introduced", "0") or "0")
    fixed = rng.get("fixed")
    last = rng.get("last_affected")
    lo = _Ver(intro)
    if not lo.ok or not ver.ge(lo):
        return False
    if fixed is not None:
        hi = _Ver(str(fixed))
        return hi.ok and ver.lt(hi)
    if last is not None:
        hi = _Ver(str(last))
        return hi.ok and ver.le(hi)
    return False


_CMP_RE = re.compile(r"^\s*(>=|<=|==|=|>|<|~=)?\s*(.+?)\s*$")


def _in_comparator_string(ver: _Ver, spec: str) -> bool:
    """Membership in a comma/space-separated comparator string like ``>=1.0.0,<2.0.0`` (all clauses
    must hold). An unparseable clause makes the whole spec fail (fail-closed). ``~=`` is treated as
    ``>=`` on the same string (conservative)."""
    clauses = [c for c in re.split(r"[,\s]+", spec.strip()) if c]
    if not clauses:
        return False
    for c in clauses:
        m = _CMP_RE.match(c)
        if not m:
            return False
        op = m.group(1) or "=="
        bound = _Ver(m.group(2))
        if not bound.ok:
            return False
        ok = {
            ">=": ver.ge, ">": ver.gt, "<=": ver.le, "<": ver.lt,
            "==": lambda b: ver.ge(b) and ver.le(b), "=": lambda b: ver.ge(b) and ver.le(b),
            "~=": ver.ge,
        }[op](bound)
        if not ok:
            return False
    return True


def version_in_affected(version: str, affected: Any) -> bool:
    """True iff ``version`` PROVABLY falls in the ``affected`` set — a list of OSV range dicts
    (``{introduced, fixed|last_affected}``) and/or comparator strings (``>=1.0,<2.0``). Pure and
    fail-closed: an unparseable version or every-range-unparseable input returns False."""
    ver = _Ver(str(version))
    if not ver.ok:
        return False
    items = affected if isinstance(affected, (list, tuple)) else [affected]
    for item in items:
        if isinstance(item, dict):
            if _in_osv_range(ver, item):
                return True
        elif isinstance(item, str):
            if _in_comparator_string(ver, item):
                return True
    return False


def vulnerable_dependency_context(advisory: dict) -> dict:
    """The verifier context for a captured advisory match — routes to the version-range oracle."""
    return FindingContext.from_version_advisory(advisory).to_verifier_context()


def confirm_vulnerable_dependency(advisory: dict, *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a scanner's advisory match: ``confirmed`` iff the package's concrete version provably
    falls in the advisory's affected range. The retained ``advisory`` is JSON-safe, so the same verdict
    re-verifies offline from the finding's certificate via ``verify.reverify``."""
    return (verifier or OracleVerifier()).confirm(vulnerable_dependency_context(advisory))
