"""
authority.charter — derive an engagement authority from the charter.

The charter is already the binding authorization document (signed,
scoped). This builds an EngagementAuthority from it so an engagement
carries a scoped, time-boxed authority by default rather than the
operator hand-writing one. `authority_from_scope` is the pure core;
`authority_from_charter` reads the charter's in-scope host table via the
existing ethics parser.

Defaults are conservative: destructive actions OFF, a bounded validity
window, and a finite action budget. The operator widens these
deliberately (and, at high assurance, threshold-signs the result).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..common import ethics
from ..common.errors import OutOfScope
from .models import EngagementAuthority, TargetEnvironment


def authority_from_scope(
    slug: str,
    scope: list[str],
    *,
    environment: TargetEnvironment = TargetEnvironment.TWIN,
    duration_hours: float = 8.0,
    allow_destructive: bool = False,
    max_actions: int = 1000,
    issued_by: str = "",
    now: datetime | None = None,
) -> EngagementAuthority:
    """Build an authority from an explicit scope list. Fail closed on an
    empty scope — an authority that authorises nothing is not useful, and
    an empty scope usually means a parse problem upstream."""
    if not scope:
        raise OutOfScope(
            f"cannot build an engagement authority for {slug!r}: empty scope"
        )
    ts = now or datetime.now(timezone.utc)
    return EngagementAuthority(
        engagement_slug=slug,
        environment=environment,
        scope=scope,
        not_before=ts,
        not_after=ts + timedelta(hours=duration_hours),
        allow_destructive=allow_destructive,
        max_actions=max_actions,
        issued_by=issued_by,
    )


def authority_from_charter(
    slug: str,
    *,
    environment: TargetEnvironment = TargetEnvironment.TWIN,
    duration_hours: float = 8.0,
    allow_destructive: bool = False,
    max_actions: int = 1000,
    issued_by: str = "",
    now: datetime | None = None,
) -> EngagementAuthority:
    """Build an authority from the charter's in-scope host table. Raises
    OutOfScope if the charter declares no in-scope hosts."""
    scope = ethics.parse_scope(slug)
    return authority_from_scope(
        slug, scope,
        environment=environment, duration_hours=duration_hours,
        allow_destructive=allow_destructive, max_actions=max_actions,
        issued_by=issued_by, now=now,
    )
