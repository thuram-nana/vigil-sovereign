"""Tests for authority persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ..models import EngagementAuthority, TargetEnvironment
from ..store import AuthorityError, load_authority, save_authority

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _authority() -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug="eng",
        environment=TargetEnvironment.TWIN,
        scope=["*.example.com"],
        not_before=_NOW,
        not_after=_NOW + timedelta(days=1),
        issued_by="operator",
    )


def test_save_load_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "eng.authority.json"
    save_authority(_authority(), p)
    loaded = load_authority("eng", p)
    assert loaded.engagement_slug == "eng"
    assert loaded.environment is TargetEnvironment.TWIN
    assert loaded.scope == ["*.example.com"]


def test_load_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(AuthorityError):
        load_authority("eng", tmp_path / "absent.json")


def test_load_malformed_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuthorityError):
        load_authority("eng", p)
