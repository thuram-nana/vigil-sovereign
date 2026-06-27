"""Tests for charter-derived authorities."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ...common.errors import OutOfScope
from ..charter import authority_from_scope
from ..models import TargetEnvironment

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def test_authority_from_scope_defaults_conservative() -> None:
    a = authority_from_scope("eng", ["*.example.com"], now=_NOW)
    assert a.scope == ["*.example.com"]
    assert a.environment is TargetEnvironment.TWIN     # twin-first default
    assert a.allow_destructive is False                # destructive off by default
    assert a.not_after > a.not_before


def test_empty_scope_fails_closed() -> None:
    with pytest.raises(OutOfScope):
        authority_from_scope("eng", [], now=_NOW)


def test_duration_window() -> None:
    a = authority_from_scope("eng", ["x.test"], duration_hours=2, now=_NOW)
    assert (a.not_after - a.not_before).total_seconds() == 2 * 3600
