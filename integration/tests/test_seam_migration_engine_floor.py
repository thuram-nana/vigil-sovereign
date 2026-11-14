"""Seam migration — a lease armed from the former seam directory stays consumed on the seam.

The offense engine arms a customer lease once (``framework.v2.launch_lease``: the single-use floor
``<seam>/.credit-lease-highwater/<slug>.json``). A lease armed while the engine read the former directory, then
carried into the seam by ``sigil seam migrate --apply``, is refused as a replay on the seam: the floor is carried as a
max, never lowered. A genuine re-lease (a newer issued_at) still arms.

Offense leg (framework importorskip). The migration runs in a SOVEREIGN child process
(fixtures/seam_migrate_sovereign_side.py), since ``sigil`` and ``framework`` never co-load (FATAL-2).

Mutation-verify target: the lease-floor class dropped from the migration -> test_a_lease_armed_before_the_move_*.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.launch_lease", reason="framework (offense) not importable in the sovereign leg")

from vigil_core import AuthorizerKey, TrustRoot  # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
_SIDE = Path(__file__).resolve().parent / "fixtures" / "seam_migrate_sovereign_side.py"
SLUG, HOST, ORG = "cust_abc123", "apme.cm", "org_a"


class _Sovereign:
    def __init__(self, tmp: Path):
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("VIGIL_", "SIGIL_"))}
        self.env.update({
            "PYTHONPATH": os.pathsep.join(str(_REPO / p) for p in ("apps/sigil", "integration",
                                                                   "packages/core/vigil_core")),
            "SIGIL_HOME": str(tmp / "sigil_home"), "SIGIL_SPINE_DIR": str(tmp / "spine"),
            "SEAM_TEST_STORE": str(tmp / "spine.jsonl")})

    def __call__(self, *argv: str) -> dict:
        r = subprocess.run([sys.executable, str(_SIDE), *argv], env=self.env, capture_output=True, text=True,
                           timeout=120)
        assert r.returncode == 0, r.stderr[-3000:]
        return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture()
def rig(tmp_path, monkeypatch):
    sov = _Sovereign(tmp_path)
    try:
        subprocess.run([sys.executable, "-c", "import sigil.seam_migrate"], env=sov.env, check=True,
                       capture_output=True, timeout=120)
    except subprocess.CalledProcessError as e:      # pragma: no cover — named, never silent (-rs)
        pytest.skip(f"sovereign plane not importable in a child process: {e.stderr[-300:]!r}")
    legacy, seam = tmp_path / "legacy", tmp_path / "seam"
    legacy.mkdir()
    seam.mkdir()
    return sov, legacy, seam


def _pin_owner(monkeypatch, owner_pub: str) -> None:
    from framework.v2.authority import store as authz_store
    from framework.v2.authority.models import EngagementAuthority
    root = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner_pub)])
    t = _dt.datetime.fromtimestamp(1000.0, tz=_dt.timezone.utc)
    auth = EngagementAuthority(engagement_slug=SLUG, environment="twin", scope=[HOST], issued_by=f"customer:{ORG}",
                               not_before=t - _dt.timedelta(hours=1), not_after=t + _dt.timedelta(hours=8))
    monkeypatch.setattr(authz_store, "load_authority_root", lambda path=None: root)
    monkeypatch.setattr(authz_store, "load_verified_authority", lambda slug, root, path=None: auth)


def _arm(base: Path, now: float = 1000.0):
    from framework.v2.launch_lease import verify_customer_launch_lease
    return verify_customer_launch_lease(SLUG, HOST, ORG, base_dir=str(base), now=now, consume=True)


def test_a_lease_armed_before_the_move_is_a_replay_on_the_seam(rig, monkeypatch):
    sov, legacy, seam = rig
    owner = sov("lease", str(legacy), SLUG, HOST, ORG, "n1", "1000")["owner_public_key_b64"]
    _pin_owner(monkeypatch, owner)
    assert _arm(legacy) == (True, "ok")                                    # armed from the former tree
    out = sov("migrate", str(legacy), str(seam))
    assert out["report"]["sources"][0]["status"] == "migrated", out
    ok, why = _arm(seam)
    assert not ok and "replay" in why                                      # still consumed on the seam


def test_a_genuine_re_lease_still_arms_on_the_seam(rig, monkeypatch):
    sov, legacy, seam = rig
    owner = sov("lease", str(legacy), SLUG, HOST, ORG, "n1", "1000")["owner_public_key_b64"]
    _pin_owner(monkeypatch, owner)
    assert _arm(legacy)[0]
    sov("migrate", str(legacy), str(seam))
    sov("lease", str(seam), SLUG, HOST, ORG, "n2", "1001")                 # a newer lease of the same target
    assert _arm(seam, now=1001.0) == (True, "ok")
