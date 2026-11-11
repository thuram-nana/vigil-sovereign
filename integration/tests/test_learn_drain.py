"""A2c — the OFFENSE learn-grant consumer (`vigil_integration.learn_drain`).

Doctrine under test:
  * a grant is learned ONLY if it verifies under the OWNER public key (single-signer Ed25519 over the
    canonical core) — a forged / wrong-key / tampered / non-object grant is quarantined, never learned;
  * FATAL-2: `verify_grant` uses vigil_core only; `deep_learn` is reached lazily (monkeypatched here so the
    drain logic is exercised without importing the offense engine);
  * a hostile spool file (symlink/FIFO/oversize/non-UTF-8) is quarantined, never followed or hung on;
  * the offense per-slug kill-switch DEFERS (un-claims for retry), 'no_lead' is TERMINAL, dedup is by bytes;
  * NO POISON FILE: a body that cannot be parsed or verified for ANY reason (deep nesting → RecursionError, a lone
    surrogate → UnicodeEncodeError) is quarantined, never raised out of ``drain()`` — the files after it are still
    processed in the SAME pass;
  * NO STRANDED FILE: every pass first reclaims ``working/`` (a claim a crashed pass never finished), like the
    sibling drains — and a reclaim never destroys a grant it cannot move.
"""

import hashlib
import json

from vigil_core import canonical_json, generate_keypair, sign
from vigil_integration.learn_drain import LearnGrantWatcher, verify_grant

OWNER = generate_keypair()


def _grant(owner=OWNER, slug="loopback", vuln="CVE-2024-0001", approval_seq=5, **override):
    core = {"schema": 1, "kind": "learn_grant", "slug": slug, "vuln_id": vuln, "approval_seq": approval_seq}
    m = canonical_json(core)
    m = m if isinstance(m, bytes) else m.encode("utf-8")
    env = {**core, "sig": sign(owner.private_key_b64, m), "pubkey": owner.public_key_b64}
    env.update(override)
    return env


def _write_incoming(spool, env):
    inc = spool / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(env, sort_keys=True)
    p = inc / (hashlib.sha256(raw.encode()).hexdigest()[:32] + ".json")
    p.write_text(raw, encoding="utf-8")
    return p


class _RecordingWatcher(LearnGrantWatcher):
    """Overrides the lazy `_deep_learn` so the drain logic is tested without the offense engine."""

    def __init__(self, *, status="learned", **kw):
        super().__init__(**kw)
        self._status = status
        self.calls = []

    def _deep_learn(self, slug, vuln_id):
        self.calls.append((slug, vuln_id))
        return self._status


def _watcher(tmp_path, **kw):
    return _RecordingWatcher(spool_dir=tmp_path / "spool", owner_pubkey=OWNER.public_key_b64,
                             skills_dir=tmp_path / "skills", **kw)


# ---- verify_grant: owner-signature, fail-closed ----------------------------

def test_verify_accepts_a_valid_owner_grant():
    core = verify_grant(_grant(), OWNER.public_key_b64)
    assert core and core["vuln_id"] == "CVE-2024-0001" and core["slug"] == "loopback"


def test_verify_is_fail_closed():
    assert verify_grant(_grant(), generate_keypair().public_key_b64) is None      # wrong owner key
    g = _grant(); g.pop("sig"); assert verify_grant(g, OWNER.public_key_b64) is None        # no signature
    g = _grant(); g["slug"] = "evil-scope"; assert verify_grant(g, OWNER.public_key_b64) is None  # tampered
    g = _grant(); g["kind"] = "other"; assert verify_grant(g, OWNER.public_key_b64) is None       # wrong kind
    g = _grant(); g["sig"] = 12345; assert verify_grant(g, OWNER.public_key_b64) is None          # non-str sig


# ---- drain: verify → deep-learn, fail-closed, idempotent -------------------

def test_drain_learns_a_valid_grant_and_is_idempotent(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["learned"] == 1 and w.calls == [("loopback", "CVE-2024-0001")]
    assert not list((spool / "incoming").glob("*.json"))          # consumed out of incoming
    _write_incoming(spool, _grant())                              # re-spool the identical grant
    r2 = w.drain()
    assert r2["deduped"] == 1 and len(w.calls) == 1               # not re-learned


def test_drain_rejects_a_forged_grant(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant(owner=generate_keypair()))      # signed by a NON-owner key
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["rejected"] == 1 and w.calls == []                   # never reached deep_learn
    assert list((spool / "rejected").glob("*.json"))


def test_drain_defers_on_killswitch(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path, status="halted")
    r = w.drain()
    assert r["halted"] == 1
    assert list((spool / "incoming").glob("*.json"))              # un-claimed back to incoming for retry


def test_drain_no_lead_is_terminal(tmp_path):
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path, status="no_lead")
    r = w.drain()
    assert r["no_lead"] == 1
    assert not list((spool / "incoming").glob("*.json"))          # archived, not retried forever


def test_drain_rejects_a_hostile_symlink(tmp_path):
    spool = tmp_path / "spool"
    inc = spool / "incoming"
    inc.mkdir(parents=True)
    (inc / "evil.json").symlink_to("/etc/passwd")                # a planted symlink must never be followed
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["rejected"] == 1 and w.calls == []


# --- poison files: quarantined on ANY parse / verify failure, the rest of the pass still runs ----------------

def _names(d):
    return sorted(p.name for p in d.iterdir())


def _spool_named(spool, name, raw):
    inc = spool / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / name).write_text(raw, encoding="utf-8")


_DEEP = "[" * 200_000                         # under the 256 KiB cap; json.loads raises RecursionError, not ValueError
_SURROGATE = ('{"schema": 1, "kind": "learn_grant", "slug": "\\ud800", "vuln_id": "CVE-2024-0001", '
              '"approval_seq": 5, "sig": "AAAA", "pubkey": "%s"}' % OWNER.public_key_b64)


def test_a_deeply_nested_poison_file_is_quarantined_and_the_next_file_still_learns(tmp_path):
    """`except ValueError` let the RecursionError out of drain(): the pass stopped, the good grant behind the
    poison file waited, and the poison file sat in working/ forever (never quarantined)."""
    spool = tmp_path / "spool"
    _spool_named(spool, "a_poison.json", _DEEP)
    _spool_named(spool, "b_good.json", json.dumps(_grant(), sort_keys=True))
    w = _watcher(tmp_path)
    r = w.drain()                                                   # never raises on one bad file
    assert r == {"learned": 1, "rejected": 1, "deduped": 0, "no_lead": 0, "halted": 0}
    assert w.calls == [("loopback", "CVE-2024-0001")]              # the good grant, in the SAME pass
    assert _names(spool / "working") == [] and _names(spool / "incoming") == []
    assert _names(spool / "rejected") == ["a_poison.json", "a_poison.json.reason"]
    assert "RecursionError" in (spool / "rejected" / "a_poison.json.reason").read_text()
    assert w.drain() == {"learned": 0, "rejected": 0, "deduped": 0, "no_lead": 0, "halted": 0}   # and it is final


def test_a_grant_that_cannot_be_canonicalised_is_not_authentic_and_never_raises(tmp_path):
    """A lone surrogate parses as JSON but cannot be UTF-8 encoded for the signature check: a UnicodeEncodeError
    (not TypeError / IntegrityError) used to escape verify_grant and drain() the same way."""
    assert verify_grant(json.loads(_SURROGATE), OWNER.public_key_b64) is None      # fail-closed, no raise
    spool = tmp_path / "spool"
    _spool_named(spool, "a_poison.json", _SURROGATE)
    _spool_named(spool, "b_good.json", json.dumps(_grant(), sort_keys=True))
    w = _watcher(tmp_path)
    r = w.drain()
    assert r["rejected"] == 1 and r["learned"] == 1 and w.calls == [("loopback", "CVE-2024-0001")]
    assert _names(spool / "working") == []
    assert "failed owner-signature verification" in (spool / "rejected" / "a_poison.json.reason").read_text()


# --- working/ crash-reclaim (sibling-drain parity) -------------------------------------------------------------

def test_a_grant_stranded_in_working_is_reclaimed_and_learned(tmp_path):
    spool = tmp_path / "spool"
    w = _watcher(tmp_path)
    (spool / "working" / "stranded.json").write_text(json.dumps(_grant(), sort_keys=True), encoding="utf-8")
    r = w.drain()
    assert r["learned"] == 1 and w.calls == [("loopback", "CVE-2024-0001")]
    assert _names(spool / "working") == [] and len(_names(spool / "processed")) == 1


def test_a_pass_killed_mid_learn_strands_nothing(tmp_path):
    """The real crash: the daemon dies after the claim, inside deep-learn. The next pass reclaims and finishes."""
    import pytest
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path)
    real, killed = w._deep_learn, {"n": 0}

    def die_once(slug, vuln_id):
        killed["n"] += 1
        if killed["n"] == 1:
            raise KeyboardInterrupt("daemon killed mid-learn")
        return real(slug, vuln_id)

    w._deep_learn = die_once  # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt):
        w.drain()
    assert len(_names(spool / "working")) == 1 and _names(spool / "incoming") == []    # stranded by the crash
    r = w.drain()
    assert r["learned"] == 1 and _names(spool / "working") == [] and _names(spool / "rejected") == []


def test_a_poison_file_stranded_by_an_earlier_crash_is_quarantined_on_the_next_pass(tmp_path):
    """The audit's end state — a poison file left in working/ by the pre-fix drain — heals itself: it is reclaimed
    and quarantined (with its reason), and it never becomes a crash loop that blocks the grants behind it."""
    spool = tmp_path / "spool"
    w = _watcher(tmp_path)
    (spool / "working" / "a_poison.json").write_text(_DEEP, encoding="utf-8")
    _spool_named(spool, "b_good.json", json.dumps(_grant(), sort_keys=True))
    for _ in range(2):                                              # two passes: no loop, nothing re-processed
        w.drain()
    assert w.calls == [("loopback", "CVE-2024-0001")]
    assert _names(spool / "working") == []
    assert _names(spool / "rejected") == ["a_poison.json", "a_poison.json.reason"]


def test_reclaim_never_destroys_a_grant_it_cannot_move(tmp_path, monkeypatch):
    import os

    from vigil_integration import learn_drain as ld
    spool = tmp_path / "spool"
    w = _watcher(tmp_path)
    raw = json.dumps(_grant(), sort_keys=True)
    (spool / "working" / "stuck.json").write_text(raw, encoding="utf-8")
    real_replace = os.replace

    def unmovable(src, dst):
        if os.path.basename(str(src)) == "stuck.json" and os.path.basename(os.path.dirname(str(dst))) == "incoming":
            raise OSError("EXDEV")
        return real_replace(src, dst)

    monkeypatch.setattr(ld.os, "replace", unmovable)
    assert w.drain()["learned"] == 0
    assert (spool / "working" / "stuck.json").read_text(encoding="utf-8") == raw      # still there, untouched
    monkeypatch.setattr(ld.os, "replace", real_replace)
    assert w.drain()["learned"] == 1 and _names(spool / "working") == []               # the next sweep gets it


def test_reclaim_leaves_a_killswitch_deferral_retryable(tmp_path):
    """A halted grant is un-claimed back to incoming/ (unchanged); the reclaim sweep does not disturb that."""
    spool = tmp_path / "spool"
    _write_incoming(spool, _grant())
    w = _watcher(tmp_path, status="halted")
    assert w.drain()["halted"] == 1 and w.drain()["halted"] == 1    # still deferred, pass after pass
    assert len(_names(spool / "incoming")) == 1 and _names(spool / "working") == []
    w._status = "learned"                                           # the operator releases STOP
    assert w.drain()["learned"] == 1


# --- #73 NET hardening: the watch loop survives a single-drain failure (sibling-drain parity) -------------

class _StopLoop(BaseException):
    """Raised from the injected sleep to end the (otherwise infinite) watch loop in a test."""


def _stop_after(n):
    state = {"sleeps": 0}

    def sleep(_interval):
        state["sleeps"] += 1
        if state["sleeps"] >= n:
            raise _StopLoop
    return sleep, state


def test_watch_survives_a_drain_error_and_keeps_draining(tmp_path, capsys):
    import pytest
    w = _watcher(tmp_path)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("transient spool-dir fault outside the per-file loop")
        return {"learned": 0, "rejected": 0, "deduped": 0, "no_lead": 0, "halted": 0}

    w.drain = flaky  # type: ignore[method-assign]
    sleep, state = _stop_after(3)
    with pytest.raises(_StopLoop):
        w.watch(interval=0.0, sleep=sleep)
    assert calls["n"] == 3                         # the failing round did NOT kill the loop; it kept draining
    err = capsys.readouterr().err
    assert "learn-drain: WARNING drain error (continuing): OSError" in err


def test_watch_still_stops_on_keyboard_interrupt(tmp_path):
    import pytest
    w = _watcher(tmp_path)

    def interrupted():
        raise KeyboardInterrupt

    w.drain = interrupted  # type: ignore[method-assign]
    sleep, _state = _stop_after(2)                 # bounded: a loop that swallowed Ctrl-C ends in _StopLoop, not a hang
    with pytest.raises(KeyboardInterrupt):         # only Exception is swallowed — Ctrl-C / SIGTERM still stop it
        w.watch(interval=0.0, sleep=sleep)
