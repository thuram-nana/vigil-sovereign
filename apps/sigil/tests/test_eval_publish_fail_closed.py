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
    assert any(SLUG in r.getMessage() and r.exc_info and r.exc_info[1] is error
               for r in caplog.records)                                             # cause logged for the operator


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
    # An attestation revoke also cascades to the grant; when the spine cannot be read, whether a grant is still live
    # cannot be known, so the cascade withdraws it, names it in the alarm and fails the revoke loudly.
    if raises or rig.kind == "attestation":
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
    with pytest.raises(type(error)):                          # never reported as a clean engagement close
        rig.att.revoke(engagement_slug=SLUG)
    assert not rig.seam_path().exists()
    assert rig.offense_ok() is False
    assert f"grant:{SLUG}" in _alarm()["failed"]               # named until a reconcile confirms it


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
        """The real os module, except that emptying a file in place is refused too."""
        def __getattr__(self, name):
            return getattr(os, name)

        def open(self, path, flags, *a):
            if flags & os.O_TRUNC:
                _unlink_denied()
            return os.open(path, flags, *a)

    monkeypatch.setattr(seam_publish, "os", _ReadOnlyOs())
    with caplog.at_level(logging.ERROR, logger="sigil.governor.seam_publish"):
        with pytest.raises(PermissionError):
            rig.revoke()                                      # never reported as a successful revoke
    assert any(r.levelno == logging.CRITICAL for r in caplog.records)


# ==== revocation fail-closed: anti-rollback after a withdrawal, publish atomicity, offense close ==============
def _fail_writes(rig, monkeypatch):
    live = rig.live_module()
    name = "write_eval_capability_grants" if rig.kind == "grant" else "write_eval_attestations"

    def _fail(*_a, **_kw):
        raise OSError("ENOSPC")

    monkeypatch.setattr(live, name, _fail)


def test_a_withdrawn_publication_cannot_be_replayed_onto_the_seam(rig, monkeypatch):
    assert rig.offense_ok() is True                 # the offense plane read it: its floor is at that seq
    saved = rig.seam_path().read_bytes()
    _fail_writes(rig, monkeypatch)
    rig.revoke()                                    # publish fails -> withdrawn + rollback floor raised
    assert not rig.seam_path().exists()
    rig.seam_path().write_bytes(saved)              # someone puts the withdrawn file back
    assert rig.offense_ok() is False                # refused as a rollback, never re-armed


def test_a_later_publication_after_a_withdrawal_still_arms(rig, monkeypatch):
    """The raised floor never blocks the owner's NEXT legitimate publication."""
    with monkeypatch.context() as m:
        _fail_writes(rig, m)
        rig.revoke()
    rig.arm()
    assert rig.offense_ok() is True


def test_a_withdrawal_whose_rollback_floor_cannot_be_raised_fails_loudly(rig, monkeypatch):
    _fail_writes(rig, monkeypatch)

    def _no_floor(*_a, **_kw):
        raise PermissionError("floor not writable")

    monkeypatch.setattr(rig.live_module(), "advance_publication_floor", _no_floor)
    with pytest.raises(OSError, match="ENOSPC"):
        rig.revoke()
    assert not rig.seam_path().exists()


def test_publishes_are_serialized_so_a_stale_list_never_overwrites_a_revoke(rig, monkeypatch):
    """Forced interleaving: publish A snapshots the record list (no revoke yet) and stalls; meanwhile a revoke
    appends and publishes B. B must not complete before A, so the LAST write carries the revoke."""
    import threading

    from sigil.governor import eval_capability_grant as g_mod
    from sigil.governor import eval_offense_attestation as a_mod
    mod = g_mod if rig.kind == "grant" else a_mod
    real = mod.encodable_or_revoke
    stalled, go = threading.Event(), threading.Event()

    def _stall_first(records, **kw):
        out = real(records, **kw)
        if threading.current_thread().name == "publisher-A":
            stalled.set()
            go.wait(5)
        return out

    monkeypatch.setattr(mod, "encodable_or_revoke", _stall_first)
    pub = rig.grant if rig.kind == "grant" else rig.att
    a = threading.Thread(target=pub._publish, args=(SLUG,), name="publisher-A")
    a.start()
    assert stalled.wait(5)
    b = threading.Thread(target=rig.revoke, name="revoker-B")
    b.start()
    b.join(0.5)                                     # without serialization B finishes here, then A overwrites
    go.set()
    a.join(5)
    b.join(5)
    assert not a.is_alive() and not b.is_alive()
    assert rig.offense_ok() is False                # the final publication carries the revoke


def test_the_publish_lock_holds_across_processes(rig):
    """A second process holding the publish lock blocks a publish until it lets go."""
    import subprocess
    import sys
    import time
    lock = str(rig.store.path) + ".seam-publish.lock"
    child = subprocess.Popen([sys.executable, "-c",
                              "import fcntl,os,sys,time\n"
                              "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600)\n"
                              "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('held',flush=True)\ntime.sleep(1.5)\n", lock],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "held"
        t0 = time.monotonic()
        rig.revoke()
        waited = time.monotonic() - t0
    finally:
        child.wait(10)
    assert waited >= 1.0, waited                    # it waited for the other process instead of racing it
    assert rig.offense_ok() is False


def _close_offense(rig):
    from sigil.governor.offense_gate import OffenseGate
    return OffenseGate(rig.store, owner_key=rig.owner).close_gate(reason="test")


def test_an_offense_close_that_cannot_read_the_spine_still_ungrants_and_raises_the_alarm(monkeypatch, caplog):
    from sigil.governor.seam_publish import close_alarm_path
    rig = _Rig("grant")
    assert rig.offense_ok() is True

    def _unreadable(*_a, **_kw):
        raise RecursionError("spine line too deeply nested")

    monkeypatch.setattr(rig.store, "iter_records", _unreadable)       # a PERSISTENT read fault
    with caplog.at_level(logging.ERROR):
        _close_offense(rig)                                            # the fail-safe close still completes
    assert not rig.seam_path().exists()
    assert rig.offense_ok() is False                                   # ungranted, never the stale grant
    assert close_alarm_path().is_file()                                # doctor will name it
    assert any(r.name == "sigil.governor.offense_gate" and r.levelno >= logging.ERROR and r.exc_info
               for r in caplog.records)                                # close_gate never swallows it silently


def test_a_later_close_from_a_readable_spine_clears_the_alarm(monkeypatch):
    from sigil.governor.seam_publish import close_alarm_path
    rig = _Rig("grant")
    with monkeypatch.context() as m:
        m.setattr(rig.store, "iter_records", lambda *a, **k: (_ for _ in ()).throw(RecursionError("x")))
        _close_offense(rig)
    assert close_alarm_path().is_file()
    _close_offense(rig)
    assert not close_alarm_path().exists()


def test_doctor_reports_the_offense_close_alarm_as_a_hard_issue(tmp_path, monkeypatch):
    from pathlib import Path as _P

    from sigil.governor.seam_publish import raise_close_alarm
    from vigil_integration import doctor as _doc
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    repo = _P(_doc.__file__).resolve().parents[2]
    clean = _doc.collect(repo)
    raise_close_alarm("RecursionError")
    report = _doc.collect(repo)
    new = [i for i in report["issues"] if i not in clean["issues"]]
    assert len(new) == 1 and "offense close could not revoke" in new[0] and "RecursionError" in new[0]


def test_a_grant_withdrawn_by_the_attestation_cascade_cannot_be_replayed(monkeypatch):
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    saved = rig.seam_path().read_bytes()
    with monkeypatch.context() as m:
        m.setattr(rig.store, "iter_records", lambda *a, **k: (_ for _ in ()).throw(OSError("EIO")))
        with pytest.raises(OSError):
            rig.att.revoke(engagement_slug=SLUG)      # the cascade cannot run -> the grant is withdrawn, loudly
    assert not rig.seam_path().exists()
    rig.seam_path().write_bytes(saved)
    assert rig.offense_ok() is False


# ==== review fold: the seam is reconciled before the alarm clears; floor first; per-target fold; pre-lock retract ====
TGT2 = "https://staging2.x.example"


class _NoTruncOs:
    """The real os module, except that emptying a file in place is refused."""
    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *a):
        if flags & os.O_TRUNC:
            _unlink_denied()
        return os.open(path, flags, *a)


def _dead_seam(m, rig, *, floor: bool = True):
    """Nothing on the seam can be written or removed (EROFS-like); with ``floor`` the floor cannot be raised either."""
    from sigil.governor import seam_publish
    live = rig.live_module()
    m.setattr(live, "write_eval_capability_grants" if rig.kind == "grant" else "write_eval_attestations",
              _unlink_denied)
    m.setattr(Path, "unlink", _unlink_denied)
    m.setattr(seam_publish, "os", _NoTruncOs())
    if floor:
        m.setattr(live, "advance_publication_floor", _unlink_denied)


def _alarm():
    import json as _json

    from sigil.governor.seam_publish import close_alarm_path
    p = close_alarm_path()
    return _json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def test_a_later_close_keeps_the_alarm_until_the_seam_is_reconciled(caplog):
    """HIGH: close #1 cannot touch the seam; close #2 (seam still broken) must NOT clear the alarm; close #3 with a
    working seam re-publishes the revoked list and only then clears it."""
    rig = _Rig("grant")
    assert rig.offense_ok() is True                 # the offense plane has read the granted file
    saved = rig.seam_path().read_bytes()
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig)
        with caplog.at_level(logging.CRITICAL):
            _close_offense(rig)
    assert _alarm() and _alarm()["failed"] == [f"grant:{SLUG}"] and _alarm()["cause"] == "seam_unreconciled"
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig)
        _close_offense(rig)                         # the spine already shows the grant revoked
    assert _alarm() and _alarm()["failed"] == [f"grant:{SLUG}"]   # never cleared while the stale grant may still authorize
    _close_offense(rig)
    assert _alarm() is None
    rig.seam_path().write_bytes(saved)              # before the offense plane reads the re-publication
    assert rig.offense_ok() is False                # the re-publish raised the floor: the old file is refused


def test_a_floor_raised_first_refuses_a_stale_file_that_cannot_be_removed(rig):
    """Floor first: even when the stale publication can be neither removed nor emptied, the offense plane refuses
    it (its seal seq is below the floor), and the revoke still fails loudly."""
    assert rig.offense_ok() is True
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig, floor=False)
        with pytest.raises(PermissionError):
            rig.revoke()
    assert rig.seam_path().is_file() and rig.seam_path().stat().st_size > 0
    assert rig.offense_ok() is False


def test_withdraw_publication_raises_the_floor_before_touching_the_file(tmp_path):
    from sigil.governor.seam_publish import withdraw_publication
    order = []
    f = tmp_path / "pub.json"
    f.write_text("{}")

    def _path():
        order.append("file")
        return f
    assert withdraw_publication(_path, what="x", floor_fn=lambda: order.append("floor")) is True
    assert order == ["floor", "file"] and not f.exists()
    f.write_text("{}")
    assert withdraw_publication(lambda: f, what="x", floor_fn=_unlink_denied) is False   # floor failed
    assert not f.exists()                                                                  # file still withdrawn


def test_an_attestation_revoke_that_cannot_withdraw_its_grant_fails_and_a_retry_repairs_it():
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig)
        with pytest.raises(OSError):
            rig.att.revoke(engagement_slug=SLUG)    # never reported as a clean engagement close
    assert _alarm() and _alarm()["failed"] == [f"grant:{SLUG}"]
    rig.att.revoke(engagement_slug=SLUG)            # retry: the spine already shows the grant revoked
    assert rig.offense_ok() is False                # the grant publication was re-published from the spine


@pytest.mark.parametrize("sovereign_floor_dir", ["unset", "elsewhere"])
def test_the_sovereign_floor_binds_an_offense_reader_with_a_private_floor_dir(rig, monkeypatch, sovereign_floor_dir):
    """The reader keeps its floor in an offense-private directory; the sovereign process either does not carry that
    setting or names a different directory. A withdrawn file replayed onto the seam must still be refused."""
    env = "VIGIL_EVAL_GRANT_HIGHWATER_DIR" if rig.kind == "grant" else "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR"
    private = os.environ[env]
    assert rig.offense_ok() is True                 # the reader's private floor is at the published seq
    saved = rig.seam_path().read_bytes()
    with monkeypatch.context() as m:
        if sovereign_floor_dir == "unset":
            m.delenv(env)                           # the sovereign process does not carry the offense setting
        else:
            m.setenv(env, tempfile.mkdtemp())       # or it names a directory the offense plane never reads
        _fail_writes(rig, m)
        rig.revoke()                                # withdrawn; the floor is raised where both planes look
    assert os.environ[env] == private
    rig.seam_path().write_bytes(saved)
    assert rig.offense_ok() is False


def test_a_successful_revoke_refuses_the_superseded_file_at_once(rig):
    """A revoke whose publish succeeds raises the floor to its own seal seq, so the pre-revoke file is refused even
    before the offense plane has read the revoke."""
    assert rig.offense_ok() is True
    saved = rig.seam_path().read_bytes()
    rig.revoke()
    rig.seam_path().write_bytes(saved)              # put the pre-revoke file back before the offense plane reads
    assert rig.offense_ok() is False


def _grant_with_anchor(rig, target, anchor):
    from sigil.governor.eval_capability_grant import build_core, sign_evaluator_pop
    core = build_core(engagement_slug=SLUG, target=target, allowed_gate_overrides=OVR, issued_anchor=anchor,
                      max_covered_actions=100, evaluator_pubkey=rig.user.public_key_b64)
    rig.grant.attest(engagement_slug=SLUG, target=target, allowed_gate_overrides=OVR, evaluator="eval-bob",
                     evaluator_pubkey=rig.user.public_key_b64,
                     evaluator_pop=sign_evaluator_pop(core, rig.user.private_key_b64),
                     max_covered_actions=100, issued_anchor=anchor, charter_hash=CHASH, now=NOW)


def _rearmed_on_a_second_target_with_a_lower_anchor():
    rig = _Rig("grant")
    _grant_with_anchor(rig, TGT, 1000.0)
    rig.grant.revoke(engagement_slug=SLUG)
    _grant_with_anchor(rig, TGT2, 50.0)             # below the first target's anchor
    assert rig.grant.state(engagement_slug=SLUG, now=NOW).granted is False      # the shared fold misses it
    assert rig.offense_ok(TGT2) is True                                          # the offense plane honours it
    return rig


def test_an_offense_close_revokes_a_grant_live_on_any_target():
    rig = _rearmed_on_a_second_target_with_a_lower_anchor()
    assert rig.grant.granted_targets(engagement_slug=SLUG) == [TGT2]
    _close_offense(rig)
    assert rig.offense_ok(TGT2) is False and _alarm() is None


def test_an_attestation_revoke_cascades_to_a_grant_live_on_any_target():
    rig = _rearmed_on_a_second_target_with_a_lower_anchor()
    rig.att.revoke(engagement_slug=SLUG)
    assert rig.offense_ok(TGT2) is False


def test_status_reports_a_grant_live_on_any_target(monkeypatch, capsys):
    import json as _json
    from types import SimpleNamespace

    from sigil import cli
    rig = _rearmed_on_a_second_target_with_a_lower_anchor()
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
    cli.cmd_eval_grant(SimpleNamespace(action="status", engagement=SLUG, target=""))
    out = _json.loads(capsys.readouterr().out)
    assert out["armed"] is True and out["target"] == TGT2


def test_a_revoke_blocked_on_the_publish_lock_has_already_ungranted_the_offense_plane(rig):
    """The cockpit kills a ceremony CLI after 60 s; a revoke stuck waiting for the publish lock must already have
    raised the floor and removed the stale publication."""
    import subprocess
    import sys
    import threading
    import time
    lock = str(rig.store.path) + ".seam-publish.lock"
    child = subprocess.Popen([sys.executable, "-c",
                              "import fcntl,os,sys,time\n"
                              "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600)\n"
                              "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('held',flush=True)\ntime.sleep(2)\n", lock],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "held"
        t = threading.Thread(target=rig.revoke)
        t.start()
        time.sleep(0.5)
        assert t.is_alive()                         # still waiting for the lock
        assert not rig.seam_path().exists()
        assert rig.offense_ok() is False
        t.join(10)
    finally:
        child.wait(10)
    assert rig.offense_ok() is False


def test_an_offense_backup_never_carries_the_eval_publications(tmp_path):
    from vigil_integration import backup as ob
    base = tmp_path / "base"
    for rel in ("eval-capability-grants/eng-x.json", "eval-offense-attestations/eng-x.json",
                ".eval-grant-highwater/eng-x.json", ".eval-offense-highwater/eng-x.json", "other/keep.json"):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text("{}")
    rels = {rel for _p, rel in ob._iter_base_files(base)}
    assert rels == {".eval-grant-highwater/eng-x.json", ".eval-offense-highwater/eng-x.json", "other/keep.json"}


def test_doctor_names_a_grant_that_may_still_authorize(tmp_path, monkeypatch):
    from pathlib import Path as _P

    from sigil.governor.seam_publish import raise_close_alarm
    from vigil_integration import doctor as _doc
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "base"))
    repo = _P(_doc.__file__).resolve().parents[2]
    clean = _doc.collect(repo)
    raise_close_alarm("PermissionError", cause="seam_unreconciled", failed=["grant:eng-y"])
    new = [i for i in _doc.collect(repo)["issues"] if i not in clean["issues"]]
    assert len(new) == 1 and "eng-y" in new[0] and "may STILL AUTHORIZE" in new[0]


# ==== second review fold: every finding pinned ======================================================================
def _floor_paths(rig):
    live = rig.live_module()
    base = os.environ["VIGIL_BASE_DIR"]
    return live._highwater_path(base, SLUG), live._shared_floor_path(base, SLUG)


def test_a_deleted_seam_floor_beside_an_offense_floor_is_refused(rig):
    """F1: after a withdrawal, deleting the seam-directory floor must not re-open a replay of the withdrawn file."""
    assert rig.offense_ok() is True                 # the offense-private floor now exists
    saved = rig.seam_path().read_bytes()
    with pytest.MonkeyPatch.context() as m:
        _fail_writes(rig, m)
        rig.revoke()                                # withdrawn, seam floor raised
    private, shared = _floor_paths(rig)
    assert private != shared and shared.is_file()
    shared.unlink()                                 # the seam-directory floor is deleted
    rig.seam_path().write_bytes(saved)              # and the withdrawn file is put back
    assert rig.offense_ok() is False


def test_a_forged_seam_floor_is_enforced_but_never_copied_into_the_offense_floor(rig):
    """F7: a planted huge seam floor blocks only while it is there; the offense-private floor never takes it."""
    import json as _json
    assert rig.offense_ok() is True
    private, shared = _floor_paths(rig)
    shared.write_text(_json.dumps({"entry_count": 10 ** 9, "last_seq": 10 ** 9}))
    assert rig.offense_ok() is False
    assert _json.loads(private.read_text())["last_seq"] < 10 ** 9
    shared.unlink()
    rig.revoke() if rig.kind == "grant" else None
    rig.arm()                                       # the sovereign's next publish restores the seam floor
    assert rig.offense_ok() is True


def test_a_revoke_killed_after_its_append_has_already_ungranted(rig):
    """F3: the retract runs BEFORE the spine append, so a kill right after the append leaves nothing honoured."""
    real = rig.store.append

    def _append_then_die(*a, **kw):
        real(*a, **kw)
        raise KeyboardInterrupt("killed right after the append")
    with pytest.MonkeyPatch.context() as m:
        m.setattr(rig.store, "append", _append_then_die)
        with pytest.raises(KeyboardInterrupt):
            rig.revoke()
    assert rig.offense_ok() is False


def test_a_reconcile_that_cannot_start_raises_the_alarm_and_the_close_still_completes(monkeypatch):
    """F4: a failure building the grant registry takes the alarm path; close_gate stays a completed close."""
    from sigil.governor import eval_capability_grant as g_mod
    rig = _Rig("grant")

    def _boom(*_a, **_kw):
        raise RuntimeError("registry unavailable")
    monkeypatch.setattr(g_mod.EvalCapabilityGrant, "__init__", _boom)
    _close_offense(rig)
    assert "(reconcile did not run)" in _alarm()["failed"]


def test_a_direct_revoke_that_cannot_be_confirmed_names_it_and_status_says_so(rig, monkeypatch, capsys):
    """F5 / F12: an owner revoke whose publication can be neither replaced nor withdrawn raises AND leaves the alarm
    (grant and attestation alike); `eval-grant status` then says the seam is unconfirmed."""
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig)
        with pytest.raises(OSError):
            rig.revoke()
    kind = "grant" if rig.kind == "grant" else "attestation"
    assert f"{kind}:{SLUG}" in _alarm()["failed"]
    if rig.kind == "grant":
        import json as _json
        from types import SimpleNamespace

        from sigil import cli
        monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
        cli.cmd_eval_grant(SimpleNamespace(action="status", engagement=SLUG, target=""))
        out = _json.loads(capsys.readouterr().out)
        assert out["armed"] is False and out["seam_unconfirmed"] is True and out["notes"]


def _fail_revoke_appends(m, rig, signal_state="revoked"):
    real = rig.store.append

    def _append(*a, **kw):
        pl = kw.get("payload") or {}
        if pl.get("signal") == "governor.eval_capability_grant" and pl.get("state") == signal_state:
            raise OSError("ENOSPC")
        return real(*a, **kw)
    m.setattr(rig.store, "append", _append)


def test_an_offense_close_whose_revoke_cannot_be_recorded_still_withdraws_the_grant():
    """F6: the grant revoke never reaches the spine; the close must still withdraw the publication (floor first) and
    name it, instead of leaving it honoured."""
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    with pytest.MonkeyPatch.context() as m:
        _fail_revoke_appends(m, rig)
        _close_offense(rig)                         # the close event itself appends
    assert rig.offense_ok() is False
    assert f"grant:{SLUG}" in _alarm()["failed"]


def test_an_attestation_revoke_whose_grant_revoke_cannot_be_recorded_fails_and_stays_named():
    """F2: the cascade withdrew the grant but its revoke never reached the spine, so it is NOT a clean close; a later
    reconcile (which revokes nothing) must not re-arm it either."""
    from sigil.governor.eval_capability_grant import EvalGrantSeamUnreconciled, reconcile_eval_seam
    rig = _Rig("grant")
    with pytest.MonkeyPatch.context() as m:
        _fail_revoke_appends(m, rig)
        with pytest.raises(OSError):
            rig.att.revoke(engagement_slug=SLUG)
    assert rig.offense_ok() is False and f"grant:{SLUG}" in _alarm()["failed"]
    with pytest.raises(EvalGrantSeamUnreconciled):
        reconcile_eval_seam(rig.store, owner_key=rig.owner, revoke_live_grants=False)
    assert rig.offense_ok() is False and f"grant:{SLUG}" in _alarm()["failed"]
    _close_offense(rig)                             # an offense close revokes it on the spine and confirms it
    assert rig.offense_ok() is False and _alarm() is None


def test_retract_leaves_a_publication_sealed_at_or_above_the_floor(tmp_path):
    """F8: a newer publication (sealed at or above the revoke's floor) is never removed by the pre-lock retract."""
    import json as _json

    from sigil.governor.seam_publish import retract_for_revoke
    f = tmp_path / "pub.json"
    for seal_seq, floor, kept in ((10, 5, True), (10, 10, True), (4, 5, False)):
        f.write_text(_json.dumps({"seal": {"seq": seal_seq}}))
        retract_for_revoke(lambda: f, what="x", floor_fn=lambda floor=floor: floor)
        assert f.exists() is kept, (seal_seq, floor)
    f.write_text("not json")
    retract_for_revoke(lambda: f, what="x", floor_fn=lambda: 5)
    assert not f.exists()                           # an unparseable publication is removed


def test_a_slug_whose_floor_raise_failed_is_floored_by_the_next_close(monkeypatch):
    """F10: close #1 removes the file but cannot raise the floor; close #2 (healthy) must raise it, so a replay of
    the revoked grant is refused, before it clears the alarm."""
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    saved = rig.seam_path().read_bytes()
    with pytest.MonkeyPatch.context() as m:
        m.setattr(rig.live_module(), "advance_publication_floor", _unlink_denied)
        _close_offense(rig)
    assert not rig.seam_path().exists() and f"grant:{SLUG}" in _alarm()["failed"]
    _close_offense(rig)
    assert _alarm() is None
    rig.seam_path().write_bytes(saved)
    assert rig.offense_ok() is False


def test_an_unlistable_seam_directory_keeps_the_alarm(monkeypatch):
    """F11: a grants directory that cannot be listed is never read as an empty one."""
    from sigil.governor import seam_publish
    rig = _Rig("grant")
    real = os.scandir

    def _scandir(path):
        if str(path).endswith("eval-capability-grants"):
            raise PermissionError("EACCES")
        return real(path)
    monkeypatch.setattr(seam_publish.os, "scandir", _scandir)
    _close_offense(rig)
    assert "(grant seam directory unreadable)" in _alarm()["failed"]


def test_a_revoke_alarm_merges_with_what_an_earlier_one_named():
    """F13: a cascade or direct revoke adds to the alarm; it never drops what an earlier failure named."""
    from sigil.governor.seam_publish import raise_close_alarm
    raise_close_alarm("first", cause="seam_unreconciled", failed=["grant:a"])
    raise_close_alarm("second", cause="seam_unreconciled", failed=["grant:b"])
    assert _alarm()["failed"] == ["grant:a", "grant:b"]


def test_a_stray_or_unsafe_file_on_the_seam_is_no_false_alarm():
    """F14: a stray file the offense plane cannot read is skipped, never a permanent red."""
    rig = _Rig("grant")
    root = rig.seam_path().parent
    (root / "not a slug!.json").write_text("{}")
    (root / "eng-x.json.tmp").write_text("{}")
    _close_offense(rig)
    assert _alarm() is None and rig.offense_ok() is False


def test_eval_grant_reconcile_confirms_the_seam_and_clears_the_alarm(monkeypatch, capsys):
    """F15: the doctor's remedy exists: `sigil eval-grant reconcile` re-publishes from the spine and clears the alarm
    once everything is confirmed (it revokes nothing)."""
    import json as _json
    from types import SimpleNamespace

    from sigil import cli
    rig = _Rig("grant")
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig)
        with pytest.raises(OSError):
            rig.revoke()
    assert _alarm()
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
    monkeypatch.setattr(cli, "owner_keypair", lambda: rig.owner, raising=False)
    cli.cmd_eval_grant(SimpleNamespace(action="reconcile", engagement=None, target=None, reason=None))
    assert _json.loads(capsys.readouterr().out)["ok"] is True
    assert _alarm() is None and rig.offense_ok() is False


def test_a_close_whose_alarm_cannot_be_written_raises(monkeypatch):
    """F16: with no durable signal left, the failure reaches the caller instead of a silent success."""
    from sigil.governor import seam_publish
    rig = _Rig("grant")
    monkeypatch.setattr(seam_publish, "close_alarm_path", lambda: Path("/proc/forbidden/alarm.json"))
    with pytest.MonkeyPatch.context() as m:
        _dead_seam(m, rig)
        with pytest.raises(Exception):
            _close_offense(rig)


def test_a_close_revokes_a_grant_whose_signature_the_sovereign_cannot_verify(monkeypatch):
    """Critic: liveness is structural, so a key resolver that rejects every signature cannot make a live grant look
    revoked to the close."""
    from sigil.governor import eval_capability_grant as g_mod
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    monkeypatch.setattr(g_mod, "verify_signed", lambda *a, **k: False)
    assert rig.grant.state(engagement_slug=SLUG, now=NOW).granted is False
    _close_offense(rig)
    assert rig.offense_ok() is False and _alarm() is None


def test_an_attestation_revoke_retracts_its_grant_before_any_lock_wait():
    """Critic: both the attestation and its covered grant are un-armed before either publish waits for the lock."""
    import subprocess
    import sys
    import threading
    import time
    rig = _Rig("grant")
    att_path = rig.live_module().__name__ and __import__(
        "vigil_integration.live.eval_attestation", fromlist=["x"]).eval_attestation_path(os.environ["VIGIL_BASE_DIR"],
                                                                                        SLUG)
    assert rig.offense_ok() is True and att_path.is_file()
    lock = str(rig.store.path) + ".seam-publish.lock"
    child = subprocess.Popen([sys.executable, "-c",
                              "import fcntl,os,sys,time\n"
                              "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600)\n"
                              "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('held',flush=True)\ntime.sleep(2)\n", lock],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "held"
        t = threading.Thread(target=lambda: rig.att.revoke(engagement_slug=SLUG))
        t.start()
        time.sleep(0.5)
        assert t.is_alive()
        assert not rig.seam_path().exists() and not att_path.exists()
        assert rig.offense_ok() is False
        t.join(10)
    finally:
        child.wait(10)


def test_a_close_floors_every_revoked_grant_on_the_spine_even_with_no_alarm():
    """F10 (second layer): even when the first close could not record its alarm, the next close raises the floor of
    every grant on the spine that is not live, so the replay is still refused."""
    from sigil.governor.seam_publish import close_alarm_path
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    saved = rig.seam_path().read_bytes()
    with pytest.MonkeyPatch.context() as m:
        m.setattr(rig.live_module(), "advance_publication_floor", _unlink_denied)
        _close_offense(rig)
    close_alarm_path().unlink()                     # as if the alarm could not be written
    _close_offense(rig)
    rig.seam_path().write_bytes(saved)
    assert rig.offense_ok() is False


def test_an_unrecorded_close_revoke_empties_the_grant_when_nothing_else_works():
    """F6 (narrow path): the revoke cannot be recorded, the floor cannot be raised and the file cannot be removed,
    but it can be emptied in place: the close's withdrawal empties it, so it no longer authorizes."""
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    with pytest.MonkeyPatch.context() as m:
        _fail_revoke_appends(m, rig)
        m.setattr(rig.live_module(), "advance_publication_floor", _unlink_denied)
        m.setattr(Path, "unlink", _unlink_denied)
        _close_offense(rig)
    assert rig.seam_path().stat().st_size == 0
    assert rig.offense_ok() is False and f"grant:{SLUG}" in _alarm()["failed"]


def test_an_attestation_revoke_killed_after_the_grant_revoke_append_has_ungranted():
    """Critic / F3 for the cascade: the covered grant is retracted before its revoke is appended, so a kill right
    after that append leaves the grant un-honoured."""
    rig = _Rig("grant")
    assert rig.offense_ok() is True
    real = rig.store.append

    def _append(*a, **kw):
        seq = real(*a, **kw)
        pl = kw.get("payload") or {}
        if pl.get("signal") == "governor.eval_capability_grant" and pl.get("state") == "revoked":
            raise KeyboardInterrupt("killed right after the grant revoke append")
        return seq
    with pytest.MonkeyPatch.context() as m:
        m.setattr(rig.store, "append", _append)
        with pytest.raises(KeyboardInterrupt):
            rig.att.revoke(engagement_slug=SLUG)
    assert rig.offense_ok() is False
