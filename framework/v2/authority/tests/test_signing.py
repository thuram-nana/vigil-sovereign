"""Tests for authority signing/verification and verified loading."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ...entitlement import provision
from ...entitlement.models import AuthorizerKey, TrustRoot
from ..models import EngagementAuthority, TargetEnvironment
from ..signing import sign_authority, verify_authority
from ..store import (
    AuthorityUnsigned,
    load_verified_authority,
    save_signed_authority,
)

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


def test_sign_and_verify_roundtrip() -> None:
    tr, privs = _authority_set(3, 2)
    signed = sign_authority(_authority(), {"a0": privs["a0"], "a1": privs["a1"]})
    ok, _ = verify_authority(signed, tr)
    assert ok is True


def test_below_threshold_fails() -> None:
    tr, privs = _authority_set(3, 2)
    signed = sign_authority(_authority(), {"a0": privs["a0"]})  # 1 of 2
    ok, _ = verify_authority(signed, tr)
    assert ok is False


def test_tampered_scope_detected() -> None:
    tr, privs = _authority_set(1, 1)
    signed = sign_authority(_authority(scope=["*.example.com"]), {"a0": privs["a0"]})
    # Mutate the scope after signing.
    tampered = signed.model_copy(
        update={"document": signed.document.model_copy(update={"scope": ["*.evil.test"]})}
    )
    ok, _ = verify_authority(tampered, tr)
    assert ok is False


def test_load_verified_authority(tmp_path: Path) -> None:
    tr, privs = _authority_set(1, 1)
    signed = sign_authority(_authority(), {"a0": privs["a0"]})
    p = tmp_path / "eng.authority.json"
    save_signed_authority(signed, p)
    loaded = load_verified_authority("eng", tr, p)
    assert loaded.engagement_slug == "eng"
    assert loaded.scope == ["*.example.com"]


def test_load_verified_rejects_tampered_file(tmp_path: Path) -> None:
    tr, privs = _authority_set(1, 1)
    signed = sign_authority(_authority(), {"a0": privs["a0"]})
    p = tmp_path / "eng.authority.json"
    save_signed_authority(signed, p)
    # Tamper the scope on disk after signing.
    blob = json.loads(p.read_text(encoding="utf-8"))
    blob["document"]["scope"] = ["*.evil.test"]
    p.write_text(json.dumps(blob), encoding="utf-8")
    with pytest.raises(AuthorityUnsigned):
        load_verified_authority("eng", tr, p)


def test_load_verified_rejects_unsigned_document(tmp_path: Path) -> None:
    # A plain (unsigned) authority document must not load as verified.
    tr, _ = _authority_set(1, 1)
    p = tmp_path / "eng.authority.json"
    p.write_text(json.dumps(_authority().model_dump(mode="json")), encoding="utf-8")
    with pytest.raises(AuthorityUnsigned):
        load_verified_authority("eng", tr, p)
