"""
Fixtures for SIL tests.

Isolate entitlement state (so capability checks in the merge gate are
deterministic) and reset the cached policy before/after each test.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest

from ...entitlement import policy as ent_policy


@pytest.fixture(autouse=True)
def _isolated_entitlement(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    monkeypatch.setenv("CRUCIBLE_ENTITLEMENT_DIR", str(tmp_path) + "/ent")
    monkeypatch.delenv("CRUCIBLE_ENTITLEMENT_ENFORCED", raising=False)
    monkeypatch.delenv("CRUCIBLE_ATTESTED_IDENTITY", raising=False)
    ent_policy.reset_policy()
    yield
    ent_policy.reset_policy()
