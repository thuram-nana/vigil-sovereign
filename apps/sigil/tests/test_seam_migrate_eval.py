"""`sigil seam migrate --apply` — owner-sealed eval publications are REBUILT from the spine on the seam, never copied.

The keyless offense plane honours what the seam publishes (an owner-sealed record list per engagement). The spine is
the truth: the migration republishes every engagement the former directory published from the spine, under the
owner key, into the seam — so a grant or attestation the spine shows revoked is revoked on the seam, whatever the
former directory still published. The seal verifies under the owner key and sits at or above the seam's floor.

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets:
  * publications copied instead of re-derived              -> test_a_grant_the_spine_revoked_stays_revoked_on_the_seam
  * the publisher's base_dir ignored (resolver always used) -> test_a_live_grant_is_republished_on_the_seam
"""
from __future__ import annotations

import tempfile

import pytest

from sigil import seam_migrate
from vigil_integration import seam_migration as sm

from tests.test_eval_publish_fail_closed import NOW, SLUG, TGT, _Rig  # type: ignore


@pytest.fixture
def trees(monkeypatch, tmp_path):
    legacy, seam = tmp_path / "legacy", tmp_path / "seam"
    legacy.mkdir()
    seam.mkdir()
    monkeypatch.setenv("VIGIL_BASE_DIR", str(legacy))
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    for k in ("VIGIL_EVAL_GRANT_HIGHWATER_DIR", "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR", "VIGIL_SEAM_MIGRATION_GUARD"):
        monkeypatch.delenv(k, raising=False)
    return legacy, seam


def _offense_ok(rig, base, target=TGT) -> bool:
    live = rig.live_module()
    pinned = [rig.owner.public_key_b64]
    if rig.kind == "grant":
        return live.verify_eval_capability_grant(str(base), engagement_slug=SLUG, target=target,
                                                 trusted_owner_pubkeys=pinned).granted
    return live.verify_live_offense_attested(str(base), engagement_slug=SLUG, trusted_owner_pubkeys=pinned,
                                             now=NOW)[0]


def _migrate(rig, legacy, seam):
    code, rep = seam_migrate.run(rig.store, rig.owner, seam=seam, sources=[str(legacy)], apply=True, now=NOW)
    assert code == 0, rep
    assert rep["sources"][0]["status"] == "migrated"
    return rep


@pytest.mark.parametrize("kind", ["grant", "attestation"])
def test_a_grant_the_spine_revoked_stays_revoked_on_the_seam(trees, monkeypatch, kind):
    legacy, seam = trees
    rig = _Rig(kind)
    assert _offense_ok(rig, legacy)                                        # published in the former tree
    _revoke_elsewhere(rig, legacy.parent / "elsewhere")                    # on the spine, never in the former tree
    assert _offense_ok(rig, legacy)                                        # the former tree never heard of it
    _migrate(rig, legacy, seam)
    monkeypatch.setenv("VIGIL_BASE_DIR", str(seam))
    assert not _offense_ok(rig, seam)                                      # the seam says what the spine says
    cls = "eval_grants" if kind == "grant" else "eval_attestations"
    assert seam_migrate._publication_verifies(cls, str(seam), SLUG, rig.owner.public_key_b64)


@pytest.mark.parametrize("kind", ["grant", "attestation"])
def test_a_live_grant_is_republished_on_the_seam(trees, monkeypatch, kind):
    legacy, seam = trees
    rig = _Rig(kind)
    _migrate(rig, legacy, seam)
    assert _offense_ok(rig, seam)
    j = sm.read_journal(seam)["sources"][str(legacy)]
    assert j["state"] == "complete"


def _revoke_elsewhere(rig, elsewhere) -> None:
    """Revoke on the spine while publishing to a third tree (the former tree keeps its stale publication)."""
    elsewhere.mkdir(exist_ok=True)
    cls = rig._grant_cls if rig.kind == "grant" else rig._att_cls
    cls(rig.store, owner_key=rig.owner, base_dir=str(elsewhere)).revoke(engagement_slug=SLUG, reason="closed")


def test_a_publication_that_cannot_be_written_is_not_committed(trees, monkeypatch):
    """The publisher withdraws and absorbs a write failure (fail-closed for the reader); the migration's VERIFY
    then refuses to commit a seam that does not hold a verified publication."""
    from vigil_integration.live import eval_capability_grant as live
    legacy, seam = trees
    rig = _Rig("grant")

    def _disk_full(*a, **k):
        raise OSError("no space left on device")
    monkeypatch.setattr(live, "write_eval_capability_grants", _disk_full)
    code, rep = seam_migrate.run(rig.store, rig.owner, seam=seam, sources=[str(legacy)], apply=True, now=NOW)
    assert code == 1 and rep["sources"][0]["status"] == "aborted" and "does not verify" in rep["sources"][0]["error"]
    assert sm.read_journal(seam)["sources"][str(legacy)]["state"] == "applying"
