"""Tests for the gate's first-class authority load selector.

``load_authority_for_gate`` picks between the legacy unsigned load path
and the verified (threshold-signed) load path; passing a trust root
selects the verified path, which must fail closed on a missing/invalid
signature.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ...entitlement import provision
from ...entitlement.models import AuthorizerKey, TrustRoot
from ..gate import load_authority_for_gate
from ..models import EngagementAuthority, TargetEnvironment
from ..signing import sign_authority
from ..store import AuthorityError, AuthorityUnsigned, save_authority, save_signed_authority

_NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _authority(scope: list[str] | None = None) -> EngagementAuthority:
    return EngagementAuthority(
        engagement_slug="eng",
        environment=TargetEnvironment.TWIN,
        scope=scope or ["*.example.com"],
        not_before=_NOW - timedelta(hours=1),
        not_after=_NOW + timedelta(hours=1),
    )


def _authority_set(n: int, threshold: int) -> tuple[TrustRoot, dict[str, str]]:
    authorizers: list[AuthorizerKey] = []
    privs: dict[str, str] = {}
    for i in range(n):
        ak, priv = provision.new_authorizer(f"a{i}", f"Authoriser {i}")
        authorizers.append(ak)
        privs[f"a{i}"] = priv
    return provision.build_trust_root(authorizers, threshold), privs


def test_verified_path_selected_by_trust_root(tmp_path: Path) -> None:
    tr, privs = _authority_set(2, 2)
    signed = sign_authority(_authority(), {"a0": privs["a0"], "a1": privs["a1"]})
    p = tmp_path / "eng.authority.json"
    save_signed_authority(signed, p)

    loaded = load_authority_for_gate("eng", trust_root=tr, path=p)
    assert loaded.engagement_slug == "eng"
    assert loaded.scope == ["*.example.com"]


def test_verified_path_fails_closed_on_missing_signature(tmp_path: Path) -> None:
    # A plain unsigned document must NOT arm the gate when a trust root is
    # supplied (verified path selected).
    tr, _ = _authority_set(1, 1)
    p = tmp_path / "eng.authority.json"
    save_authority(_authority(), p)

    with pytest.raises(AuthorityUnsigned):
        load_authority_for_gate("eng", trust_root=tr, path=p)


def test_verified_path_fails_closed_on_below_threshold(tmp_path: Path) -> None:
    tr, privs = _authority_set(3, 2)
    signed = sign_authority(_authority(), {"a0": privs["a0"]})  # 1 of 2
    p = tmp_path / "eng.authority.json"
    save_signed_authority(signed, p)

    with pytest.raises(AuthorityUnsigned):
        load_authority_for_gate("eng", trust_root=tr, path=p)


def test_verified_path_fails_closed_on_tampered_document(tmp_path: Path) -> None:
    tr, privs = _authority_set(1, 1)
    signed = sign_authority(_authority(), {"a0": privs["a0"]})
    p = tmp_path / "eng.authority.json"
    save_signed_authority(signed, p)
    blob = json.loads(p.read_text(encoding="utf-8"))
    blob["document"]["scope"] = ["*.evil.test"]
    p.write_text(json.dumps(blob), encoding="utf-8")

    with pytest.raises(AuthorityUnsigned):
        load_authority_for_gate("eng", trust_root=tr, path=p)


def test_unsigned_path_when_no_trust_root(tmp_path: Path) -> None:
    # Compat: without a trust root the legacy unsigned load path is used.
    p = tmp_path / "eng.authority.json"
    save_authority(_authority(), p)

    loaded = load_authority_for_gate("eng", path=p)
    assert loaded.engagement_slug == "eng"


def test_unsigned_path_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AuthorityError):
        load_authority_for_gate("eng", path=tmp_path / "nope.json")
