"""Publishing an eval-capability grant / eval-offense attestation to the seam fails CLOSED.

The keyless offense plane cannot fold the sovereign spine; it trusts the owner-sealed record list the
sovereign publishes to the seam. Two ways a publish could fail used to leave the PREVIOUS seam file in place,
so a sovereign REVOKE never reached the offense plane and it kept honouring the revoked grant/attestation:

* a record that cannot be canonicalised (a lone surrogate, only possible through a raw spine-file write)
  made sealing raise, and the publish swallowed the error;
* any other seam write failure (unwritable seam, full disk) was swallowed the same way.

Now an unencodable record is published as an UNSIGNED REVOKE placeholder in its place (the safe direction is
never droppable, and the offense plane honours a revoke whoever signs it), and on any publish failure the seam
file is removed, so the offense plane falls back to default-ungranted / default-unattested.
"""
from __future__ import annotations

import itertools
import logging
import os
import tempfile
from pathlib import Path

import pytest

SLUG, TGT, CID, CHASH = "eng-x", "https://staging.x.example", "charter-x", "a" * 64
NOW, FUTURE = 1e9, 2e9
OVR = ["witness_quorum", "blast_veto", "containment_preview"]


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    for var in ("VIGIL_BASE_DIR", "SIGIL_SPINE_DIR", "SIGIL_HOME", "VIGIL_EVAL_GRANT_HIGHWATER_DIR",
                "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR"):
        monkeypatch.setenv(var, tempfile.mkdtemp())


class _Rig:
    """A real spine with an enrolled evaluator, a covering attestation and (for kind == "grant") a grant."""

    def __init__(self, kind: str):
        from sigil.governor.accounts import AccountsRegistry
        from sigil.governor.eval_capability_grant import EvalCapabilityGrant
        from sigil.governor.eval_capability_grant import SIGNAL as GRANT_SIGNAL
        from sigil.governor.eval_offense_attestation import SIGNAL as ATT_SIGNAL
        from sigil.governor.eval_offense_attestation import EvalOffenseAttestation
        from sigil.governor.identity import ensure_owner_keypair
        from sigil.reuse import generate_keypair
        from sigil.spine.store import SpineStore
        self.kind = kind
        self._iss = itertools.count(1)
        self.path = os.path.join(tempfile.mkdtemp(), "spine.jsonl")
        self.store = SpineStore(self.path)
        self.owner = ensure_owner_keypair()
        self.user = generate_keypair()
        reg = AccountsRegistry(self.store, owner_key=self.owner)
        reg.create("eval-bob", "operator", bearer_token="B" * 40, issued_at=self.iss())
        reg.enroll_pubkey("eval-bob", self.user.public_key_b64, issued_at=self.iss())
        self.signal = GRANT_SIGNAL if kind == "grant" else ATT_SIGNAL
        self._grant_cls, self._att_cls = EvalCapabilityGrant, EvalOffenseAttestation
        self.reload()
        self.arm()

    def iss(self) -> float:
        return float(next(self._iss))

    def reload(self):
        from sigil.spine.store import SpineStore
        self.store = SpineStore(self.path)
        self.att = self._att_cls(self.store, owner_key=self.owner)
        self.grant = self._grant_cls(self.store, owner_key=self.owner)

    def arm(self):
        from sigil.governor.eval_capability_grant import build_core, sign_evaluator_pop
        from sigil.governor.eval_offense_attestation import build_core as abuild
        from sigil.governor.eval_offense_attestation import sign_evaluator_pop as apop
        iat = self.iss()
        c = abuild(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                   evaluator_pubkey=self.user.public_key_b64, not_after=FUTURE, issued_at=iat)
        self.att.attest(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH, evaluator="eval-bob",
                        evaluator_pubkey=self.user.public_key_b64, evaluator_pop=apop(c, self.user.private_key_b64),
                        not_after=FUTURE, issued_at=iat)
        if self.kind == "grant":
            anchor = self.iss()
            core = build_core(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=OVR, issued_anchor=anchor,
                              max_covered_actions=100, evaluator_pubkey=self.user.public_key_b64)
            self.grant.attest(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=OVR, evaluator="eval-bob",
                              evaluator_pubkey=self.user.public_key_b64,
                              evaluator_pop=sign_evaluator_pop(core, self.user.private_key_b64),
                              max_covered_actions=100, issued_anchor=anchor, charter_hash=CHASH, now=NOW)

    def grant_target(self, target: str):
        from sigil.governor.eval_capability_grant import build_core, sign_evaluator_pop
        anchor = self.iss()
        core = build_core(engagement_slug=SLUG, target=target, allowed_gate_overrides=OVR, issued_anchor=anchor,
                          max_covered_actions=100, evaluator_pubkey=self.user.public_key_b64)
        self.grant.attest(engagement_slug=SLUG, target=target, allowed_gate_overrides=OVR, evaluator="eval-bob",
                          evaluator_pubkey=self.user.public_key_b64,
                          evaluator_pop=sign_evaluator_pop(core, self.user.private_key_b64),
                          max_covered_actions=100, issued_anchor=anchor, charter_hash=CHASH, now=NOW)

    def revoke(self, **kw):
        (self.grant if self.kind == "grant" else self.att).revoke(engagement_slug=SLUG, **kw)

    def live_module(self):
        from vigil_integration.live import eval_attestation, eval_capability_grant
        return eval_capability_grant if self.kind == "grant" else eval_attestation

    def seam_path(self):
        live = self.live_module()
        base = os.environ["VIGIL_BASE_DIR"]
        return (live.eval_capability_grant_path(base, SLUG) if self.kind == "grant"
                else live.eval_attestation_path(base, SLUG))

    def offense_ok(self, target: str = TGT) -> bool:
        live = self.live_module()
        base, pinned = os.environ["VIGIL_BASE_DIR"], [self.owner.public_key_b64]
        if self.kind == "grant":
            return live.verify_eval_capability_grant(base, engagement_slug=SLUG, target=target,
                                                     trusted_owner_pubkeys=pinned).granted
        ok, _reason = live.verify_live_offense_attested(base, engagement_slug=SLUG, trusted_owner_pubkeys=pinned,
                                                        now=NOW)
        return ok

    def write_unencodable_record(self):
        """Append a record, then raw-edit the spine file so one of its strings is a lone surrogate."""
        self.store.append(kind="event", source="governor", actor="X",
                          payload={"signal": self.signal, "engagement_slug": SLUG, "state": "noise",
                                   "note": "XJUNKX"})
        self.raw_edit('"note": "XJUNKX"', '"note": "\\ud800"')

    def raw_edit(self, old: str, new: str):
        with open(self.path, encoding="utf-8") as fh:
            raw = fh.read()
        assert old in raw
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(raw.replace(old, new, 1))
        self.reload()


@pytest.fixture(params=["grant", "attestation"])
def rig(request):
    return _Rig(request.param)


def test_a_revoke_reaches_the_offense_plane_despite_an_unencodable_record(rig):
    assert rig.offense_ok() is True
    rig.write_unencodable_record()
    rig.revoke()
    assert rig.offense_ok() is False


def test_an_unencodable_record_is_published_as_an_unsigned_revoke_in_its_place(rig, caplog):
    rig.write_unencodable_record()
    with caplog.at_level(logging.ERROR, logger="sigil.governor.seam_publish"):
        rig.revoke()
    assert any(r.levelno == logging.ERROR and SLUG in r.getMessage() for r in caplog.records)
    records = rig.live_module()._read_published(os.environ["VIGIL_BASE_DIR"], SLUG)["records"]
    placeholders = [r for r in records if r.get("state") == "revoked" and "sig" not in r]
    assert len(placeholders) == 1 and placeholders[0]["signal"] == rig.signal
    assert placeholders[0]["engagement_slug"] == SLUG          # the offense folds skip any other slug
    assert all("\ud800" not in str(r) for r in records)


def test_a_fresh_grant_after_the_unencodable_record_still_arms(rig):
    """The placeholder sits at the junk record's position: it never un-grants what the owner grants later, and
    the later grant is actually PUBLISHED (not a stale seam that happened to be granted already)."""
    rig.revoke()
    assert rig.offense_ok() is False
    rig.write_unencodable_record()
    rig.arm()
    assert rig.offense_ok() is True


@pytest.mark.parametrize("error", [OSError("seam unwritable"), ValueError("unsafe seam")])
def test_a_failed_seam_write_removes_the_stale_published_grant(rig, monkeypatch, caplog, error):
    assert rig.offense_ok() is True and rig.seam_path().is_file()
    live = rig.live_module()
    name = "write_eval_capability_grants" if rig.kind == "grant" else "write_eval_attestations"

    def _fail(*_a, **_kw):
        raise error

    monkeypatch.setattr(live, name, _fail)
    with caplog.at_level(logging.ERROR, logger="sigil.governor.seam_publish"):
        rig.revoke()                               # the spine records the revoke; the publish fails
    assert not rig.seam_path().exists()
    assert rig.offense_ok() is False               # default-ungranted, never the stale grant
    assert any("previous publication was withdrawn" in r.getMessage() and SLUG in r.getMessage()
               and r.exc_info and r.exc_info[1] is error for r in caplog.records)   # cause logged for the operator


def test_an_unexpected_publish_error_also_removes_the_seam_and_still_raises(rig, monkeypatch):
    live = rig.live_module()
    name = "write_eval_capability_grants" if rig.kind == "grant" else "write_eval_attestations"

    def _boom(*_a, **_kw):
        raise RuntimeError("programming error")

    monkeypatch.setattr(live, name, _boom)
    with pytest.raises(RuntimeError, match="programming error"):
        rig.revoke()
    assert not rig.seam_path().exists()
    assert rig.offense_ok() is False


def test_a_corrupted_owner_revoke_still_revokes_on_the_offense_plane():
    """The never-drop guard: the unencodable record IS the owner's revoke. A later publish for another target
    must still carry a revoke at its position, so the earlier grant stays revoked offense-side."""
    rig = _Rig("grant")
    rig.revoke(reason="XJUNKX")
    rig.raw_edit('"reason": "XJUNKX"', '"reason": "\\ud800"')
    rig.grant_target("https://other.x.example")              # a publish that does not itself revoke
    assert rig.offense_ok("https://other.x.example") is True
    assert rig.offense_ok(TGT) is False


@pytest.mark.parametrize("error,raises", [(OSError("EMFILE"), False), (RuntimeError("segment missing"), True)])
def test_a_failure_reading_the_spine_during_publish_also_withdraws(rig, monkeypatch, error, raises):
    def _boom(*_a, **_kw):
        raise error

    monkeypatch.setattr(rig.store, "iter_records", _boom)
    if raises:
        with pytest.raises(type(error)):
            rig.revoke()
    else:
        rig.revoke()
    assert not rig.seam_path().exists()
    assert rig.offense_ok() is False


@pytest.mark.parametrize("error", [OSError("EIO"), RuntimeError("segment missing")])
def test_an_attestation_revoke_withdraws_the_grant_even_when_the_spine_cannot_be_read(monkeypatch, error):
    """The attestation revoke cascades to the grant. When the cascade cannot run, the grant's publication is
    withdrawn rather than left honoured on the offense plane - also when the attestation's own publish raised."""
    rig = _Rig("grant")                                       # arms the covering attestation AND a grant
    assert rig.offense_ok() is True

    def _boom(*_a, **_kw):
        raise error

    monkeypatch.setattr(rig.store, "iter_records", _boom)
    if isinstance(error, OSError):
        rig.att.revoke(engagement_slug=SLUG)
    else:
        with pytest.raises(RuntimeError):
            rig.att.revoke(engagement_slug=SLUG)
    assert not rig.seam_path().exists()
    assert rig.offense_ok() is False


def _unlink_denied(*_a, **_kw):
    raise PermissionError("directory not writable")


def test_an_unwritable_seam_directory_empties_the_stale_publication_in_place(rig, monkeypatch, caplog):
    live = rig.live_module()
    name = "write_eval_capability_grants" if rig.kind == "grant" else "write_eval_attestations"
    monkeypatch.setattr(live, name, _unlink_denied)
    monkeypatch.setattr(Path, "unlink", _unlink_denied)
    with caplog.at_level(logging.ERROR, logger="sigil.governor.seam_publish"):
        rig.revoke()                                          # absorbed: the publication was withdrawn
    assert rig.seam_path().exists() and rig.seam_path().stat().st_size == 0
    assert rig.offense_ok() is False
    assert any("emptied in place" in r.getMessage() for r in caplog.records)


def test_a_publication_that_cannot_be_withdrawn_fails_the_revoke_loudly(rig, monkeypatch, caplog):
    from sigil.governor import seam_publish
    live = rig.live_module()
    name = "write_eval_capability_grants" if rig.kind == "grant" else "write_eval_attestations"
    monkeypatch.setattr(live, name, _unlink_denied)
    monkeypatch.setattr(Path, "unlink", _unlink_denied)

    class _ReadOnlyOs:
        O_WRONLY, O_TRUNC, O_NOFOLLOW = os.O_WRONLY, os.O_TRUNC, getattr(os, "O_NOFOLLOW", 0)
        open = staticmethod(_unlink_denied)
        close = staticmethod(os.close)

    monkeypatch.setattr(seam_publish, "os", _ReadOnlyOs)
    with caplog.at_level(logging.ERROR, logger="sigil.governor.seam_publish"):
        with pytest.raises(PermissionError):
            rig.revoke()                                      # never reported as a successful revoke
    assert any(r.levelno == logging.CRITICAL for r in caplog.records)
