"""Red-Pen R2 — the sovereign ConnectedRepoRegistry (owner-signed connected-repo records, the authorization of record).

Invariants pinned here:
  * connect is the DANGEROUS direction (owner-signed, fresh), carrying the per-repo threshold + monthly limit inside
    the signed bytes; disconnect is the SAFE direction (honored unsigned);
  * a record signed by a NON-owner is inert (refused), a tampered setting is refused;
  * cross-tenant isolation: one org can never read / overwrite / authorize another's repository;
  * a captured active record cannot resurrect a disconnected repo (anti-replay high-water); a fresh owner connect re-activates;
  * HARD-PRUNE durability: the prune tripwire refuses a prune that would strand a connection's active record, and
    allows one re-asserted live.
"""
from __future__ import annotations

import itertools
import tempfile

import pytest

from sigil.governor.connected_repos import ConnectedRepoRegistry
from sigil.reuse import generate_keypair
from sigil.spine import prune
from sigil.spine.manifest import read_manifest
from sigil.spine.store import SpineStore
from vigil_core import BlockThreshold

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()
_c = itertools.count(1)
REPO = "github.com/acme/widgets"


def _t() -> float:
    return float(next(_c))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, key=OWNER, pub=OP):
    return ConnectedRepoRegistry(store, owner_key=key, trusted_pubkey=pub)


def test_connect_records_an_owner_signed_connection_with_its_settings():
    s = _store()
    _reg(s).connect("acme", 42, REPO, block_threshold=BlockThreshold.MEDIUM_UP, monthly_limit_credits=250,
                    issued_at=_t())
    rec = _reg(s).active("acme", REPO)
    assert rec is not None and rec.repo == REPO and rec.installation_id == 42
    assert rec.block_threshold == BlockThreshold.MEDIUM_UP and rec.monthly_limit_credits == 250


def test_connect_requires_the_owner_signing_key():
    with pytest.raises(ValueError, match="owner signing key"):
        ConnectedRepoRegistry(_store(), owner_key=None, trusted_pubkey=OP).connect("acme", 1, REPO, issued_at=_t())


def test_a_record_signed_by_a_non_owner_is_refused():
    s = _store()
    ConnectedRepoRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP).connect("acme", 1, REPO, issued_at=_t())
    assert _reg(s).active("acme", REPO) is None               # forged under the attacker key -> inert


def test_settings_change_is_owner_signed_and_refused_for_an_unconnected_repo():
    s = _store()
    with pytest.raises(ValueError, match="not connected"):
        _reg(s).set_settings("acme", REPO, monthly_limit_credits=10, issued_at=_t())
    _reg(s).connect("acme", 42, REPO, monthly_limit_credits=100, issued_at=_t())
    _reg(s).set_settings("acme", REPO, monthly_limit_credits=500, block_threshold=BlockThreshold.NONE, issued_at=_t())
    rec = _reg(s).active("acme", REPO)
    assert rec.monthly_limit_credits == 500 and rec.block_threshold == BlockThreshold.NONE and rec.installation_id == 42


def test_disconnect_is_the_safe_direction_honored_even_unsigned():
    s = _store()
    _reg(s).connect("acme", 42, REPO, issued_at=_t())
    # a keyless registry (no owner key) can still disconnect (the safe direction never fails open)
    ConnectedRepoRegistry(s, owner_key=None, trusted_pubkey=OP).disconnect("acme", REPO)
    assert _reg(s).active("acme", REPO) is None


def test_cross_tenant_isolation():
    s = _store()
    _reg(s).connect("acme", 1, REPO, issued_at=_t())
    assert _reg(s).active("evil", REPO) is None               # another org cannot read acme's connection
    assert _reg(s).repos_of_org("evil") == []
    assert [d.repo for d in _reg(s).repos_of_org("acme")] == [REPO]


def test_a_captured_active_record_cannot_resurrect_a_disconnected_repo():
    s = _store()
    r = _reg(s)
    r.connect("acme", 42, REPO, issued_at=10.0)
    r.disconnect("acme", REPO)
    r.connect("acme", 42, REPO, issued_at=10.0)               # replayed at the SAME issued_at -> not fresh -> ignored
    assert r.active("acme", REPO) is None
    r.connect("acme", 42, REPO, issued_at=20.0)               # a FRESH owner connect re-activates (intended)
    assert r.active("acme", REPO) is not None


def test_repos_of_org_is_ordered_and_only_active():
    s = _store()
    r = _reg(s)
    r.connect("acme", 1, "github.com/acme/b", issued_at=_t())
    r.connect("acme", 1, "github.com/acme/a", issued_at=_t())
    r.connect("acme", 1, "github.com/acme/z", issued_at=_t())
    r.disconnect("acme", "github.com/acme/z")
    assert [d.repo for d in r.repos_of_org("acme")] == ["github.com/acme/a", "github.com/acme/b"]


def test_a_malformed_repo_reference_is_refused():
    s = _store()
    for bad in ("https://github.com/a/b", "github.com/a/b/c", "gitlab.com/a/b", "github.com/a"):
        with pytest.raises(ValueError):
            _reg(s).connect("acme", 1, bad, issued_at=_t())


# ---- hard-prune durability (the tripwire; real sealed segments, mirrors the monitoring prune tests) -----------
def _segmented(tmp_path):
    """A rotated spine with the connect record (seq 0) inside the FIRST sealed segment [0..4], then two more sealed
    segments — so a prune to K=5 archives the connect record. Mirrors ``_segmented`` in the monitoring test."""
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _reg(s).connect("acme", 42, REPO, issued_at=2.0)                     # seq 0
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})   # seq 1..4
    s.rotate()                                                           # seal [0..4]
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})  # seq 5..9
    s.rotate()                                                           # seal [5..9]
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "tail"})  # seq 10..12
    return s


def _archived_below(store, K):
    return [seg for seg in read_manifest(store._layout).sealed_in_order()
            if seg.last_seq is not None and seg.last_seq < K]


def test_the_prune_tripwire_refuses_stranding_an_active_connection(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    # the connect record sits below K=5 and is not re-asserted live -> stranded, and check_prune_safe refuses
    assert prune.stranded_active_connected_repos(s, _archived_below(s, 5), 5) == [f"{REPO}@acme"]
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert f"{REPO}@acme" in str(e.value) and "connected repositor" in str(e.value)


def test_the_prune_tripwire_allows_a_connection_re_asserted_live(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    _reg(s).connect("acme", 42, REPO, issued_at=99.0)                    # re-assert LIVE (seq >= 5) at a higher hw
    assert prune.stranded_active_connected_repos(s, _archived_below(s, 5), 5) == []


def test_a_below_k_active_record_blocks_the_prune_even_after_a_revoke(tmp_path, monkeypatch):
    # Soundness: a connect+revoke BOTH below K would reset the high-water to -inf, so a CAPTURED copy of the
    # below-K active record could be replayed above K to RESURRECT the disconnected repo. The tripwire is
    # fail-closed and blocks it (the owner re-signs the revoke above K, or the snapshot-seed follow-on carries it).
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    _reg(s).connect("acme", 42, REPO, issued_at=2.0)                     # seq 0
    _reg(s).disconnect("acme", REPO)                                     # seq 1 (tombstone)
    for _ in range(3):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})   # seq 2..4
    s.rotate()
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    assert prune.stranded_active_connected_repos(s, _archived_below(s, 5), 5) == [f"{REPO}@acme"]


def test_a_repo_with_no_active_record_below_k_is_not_stranded(tmp_path, monkeypatch):
    # A spine with connected repos whose active records ALL sit >= K (or none at all) prunes cleanly — the common
    # case, so a prune is not gratuitously blocked.
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    for _ in range(5):
        s.append(kind="event", source="t", actor="u", payload={"i": "pad"})   # seq 0..4 (no connect below K)
    s.rotate()
    _reg(s).connect("acme", 42, REPO, issued_at=2.0)                     # seq 5 (>= K)
    for _ in range(4):
        s.append(kind="event", source="t", actor="u", payload={"i": "seg1"})
    s.rotate()
    assert prune.stranded_active_connected_repos(s, _archived_below(s, 5), 5) == []


def test_check_prune_safe_wires_the_connected_repo_tripwire(tmp_path, monkeypatch):
    monkeypatch.setattr("sigil.governor.identity.owner_pubkey", lambda: OP)
    s = _segmented(tmp_path)
    monkeypatch.setattr(prune, "stranded_active_connected_repos", lambda st, a, K: ["ghost@org"])
    with pytest.raises(prune.PruneUnsafe) as e:
        prune.check_prune_safe(s, 5)
    assert "ghost@org" in str(e.value)
