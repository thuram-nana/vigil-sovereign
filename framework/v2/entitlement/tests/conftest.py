"""
Fixtures for entitlement tests.

Every test runs against an isolated, empty entitlement directory
(CRUCIBLE_ENTITLEMENT_DIR -> a per-test tmp dir), with enforcement and
attestation env vars cleared, and the cached policy reset before and
after. The `mint` fixture provisions trust roots and signed
entitlements into that directory.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from .. import policy, provision
from ..models import (
    Capability,
    CapabilityTier,
    EntitlementDocument,
    EntitlementSubject,
    HardwareBinding,
    RevocationDocument,
    SignedEntitlement,
    SignedRevocation,
    TrustRoot,
)


@pytest.fixture(autouse=True)
def _isolated_entitlement_dir(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(tmp_path))
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    monkeypatch.delenv("CRUCIBLE_ATTESTED_IDENTITY", raising=False)
    policy.reset_policy()
    yield
    policy.reset_policy()


@dataclass
class Authority:
    """A provisioned trust root plus the authoriser private keys, so a
    test can sign with any subset."""

    trust_root: TrustRoot
    private_keys: dict[str, str]  # key_id -> private_key_b64

    def all_signers(self) -> dict[str, str]:
        return dict(self.private_keys)

    def signers(self, *key_ids: str) -> dict[str, str]:
        return {k: self.private_keys[k] for k in key_ids}


class Mint:
    """Provisioning helper exposed to tests."""

    def authority(self, n: int = 1, threshold: int = 1) -> Authority:
        authorizers = []
        privs: dict[str, str] = {}
        for i in range(n):
            key_id = f"auth-{i}"
            ak, priv = provision.new_authorizer(key_id, f"Authoriser {i}")
            authorizers.append(ak)
            privs[key_id] = priv
        tr = provision.build_trust_root(authorizers, threshold)
        provision.write_trust_root(tr)
        return Authority(trust_root=tr, private_keys=privs)

    def document(
        self,
        *,
        tier: CapabilityTier = CapabilityTier.OFFENSIVE,
        granted: list[Capability] | None = None,
        binding: HardwareBinding | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        entitlement_id: str = "ent-0001",
    ) -> EntitlementDocument:
        now = datetime.now(timezone.utc)
        return EntitlementDocument(
            entitlement_id=entitlement_id,
            issuer="ANTIC Governance Panel",
            subject=EntitlementSubject(
                institution_id="inst-0001",
                institution_name="Authorised Red Team Alpha",
            ),
            capability_tier=tier,
            granted_capabilities=granted or [],
            binding=binding or HardwareBinding(),
            issued_at=now,
            not_before=not_before or (now - timedelta(hours=1)),
            not_after=not_after or (now + timedelta(hours=1)),
        )

    def entitle(
        self,
        authority: Authority,
        signers: dict[str, str],
        *,
        document: EntitlementDocument | None = None,
        write: bool = True,
        **doc_kwargs: object,
    ) -> SignedEntitlement:
        doc = document if document is not None else self.document(**doc_kwargs)  # type: ignore[arg-type]
        signed = provision.sign_entitlement(doc, signers)
        if write:
            provision.write_entitlement(signed)
        return signed

    def revoke(
        self,
        authority: Authority,
        signers: dict[str, str],
        revoked_ids: list[str],
        *,
        serial: int = 1,
        write: bool = True,
    ) -> SignedRevocation:
        doc = RevocationDocument(
            serial=serial,
            issued_at=datetime.now(timezone.utc),
            revoked_entitlement_ids=revoked_ids,
        )
        signed = provision.sign_revocation(doc, signers)
        if write:
            provision.write_revocation(signed)
        return signed


@pytest.fixture
def mint() -> Mint:
    return Mint()


@pytest.fixture
def enforced(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    def _set() -> None:
        monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_ENFORCED", "1")
        policy.reset_policy()

    return _set
