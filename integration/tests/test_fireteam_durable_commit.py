"""
DEFECT 2 — a signed fireteam approval must not become ACTIONABLE before it is DURABLY committed.

The operator-reported durability-ordering bug (NOT a forgery — the signature is VALID): register an
escalation, make its :class:`EscalationLedger` UNWRITABLE, submit a VALID signed approval. The live resolver
returned APPROVED, yet a FRESH resolver over the same ledger saw NO durable terminal — because
``ConfirmationRegistry._emit`` appended the APPROVED terminal best-effort and SWALLOWED the write failure,
while ``_finish`` had ALREADY recorded ``self._resolved[key]=APPROVED`` and returned it. A restart / failover
would then disagree around a dangerous action.

The fix, exercised here against the real ledger + registry (no framework, no network — the sovereign leg):
an APPROVED-with-ledger terminal MUST be durably committed BEFORE it is recorded / returned as actionable.
On a durable-append FAILURE it FAILS CLOSED — non-actionable (``approved=False``), the escalation stays
PENDING, and the atomic CAS marker is RELEASED so a retry (once the ledger is writable) durably commits.

  (1) REPRODUCE-then-RETRY — unwritable ledger -> the live ``resolve()`` returns ``approved=False`` AND a
      fresh reader over the same ledger sees NO APPROVED terminal (agreement); make it writable + RETRY ->
      the SAME envelope durably commits APPROVED and a fresh reader AGREES;
  (2) MUTATION-CHECK — reverting to swallow-and-return-APPROVED (ignore the durable-append result) FLIPS
      (1)'s "not actionable when non-durable" property from pass -> fail: the live resolver returns APPROVED
      while a fresh reader disagrees — the exact operator-reported divergence;
  (3) CAS RELEASE — the atomic single-terminal marker is released on the fail-closed path so the retry can
      re-claim and durably commit;
  (4) UNCHANGED — the writable-ledger happy path (durable APPROVED) and the pure in-memory (no-ledger) path
      still return APPROVED.

Root-safe unwritability: the ledger path is swapped to a SYMLINK. ``EscalationLedger.append`` opens the
final component with ``O_NOFOLLOW`` (ELOOP even as root, so the append truly fails), while ``replay()``
uses a plain ``open`` that FOLLOWS the symlink to the real file — so the durable register line is still
read back (the escalation stays visibly PENDING, with no approved terminal). Restoring the real file makes
the path writable again for the retry.
"""

from __future__ import annotations

import errno
import json
import os

import pytest

from vigil_core import generate_keypair

from vigil_integration.fireteam import (
    ConfirmationOutcome,
    ConfirmationRegistry,
    EscalationLedger,
    EscalationRequest,
    sign_escalation_approval,
)
from vigil_integration.fireteam.confirmation import _key_digest


# --- helpers ------------------------------------------------------------------------------------------


class _Appr:
    """A verdict object whose ``.approved`` the registry reads (Path-A in-memory approver seam)."""

    def __init__(self, approved: bool, reason: str = "") -> None:
        self.approved = approved
        self.reason = reason


def _identity(key_id: str = "owner"):
    kp = generate_keypair()
    return key_id, kp.public_key_b64, kp.private_key_b64


def _esc(wave="w1", member="m1", seq=1, *, tool="sqlmap", tier="A3", target="", reason=""):
    return EscalationRequest(wave_id=wave, member_id=member, seq=seq, tool_name=tool,
                             requested_tier=tier, target=target, reason=reason)


def _make_unwritable(led_path: str) -> str:
    """Swap the real ledger file for a SYMLINK so ``append`` (O_NOFOLLOW -> ELOOP) truly fails even as root,
    while ``replay`` follows the link to the real file. Returns the real backing path."""
    real = led_path + ".real"
    os.rename(led_path, real)          # move the real file aside
    os.symlink(real, led_path)         # the ledger path is now a symlink -> O_NOFOLLOW refuses the append
    assert os.path.islink(led_path)
    return real


def _make_writable(led_path: str, real: str) -> None:
    """Undo :func:`_make_unwritable`: drop the symlink (not its target) and restore the real file."""
    os.unlink(led_path)                # remove the symlink itself
    os.rename(real, led_path)          # the real regular file is back at the ledger path


def _approved_terminal_lines(led_path: str) -> list:
    """The physically-present ``approved`` records in the ledger file (follows a symlink, like replay)."""
    out = []
    try:
        with open(led_path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(obj, dict) and obj.get("event") == "approved":
                    out.append(obj)
    except OSError:
        return []
    return out


# --- (1) the operator's exact scenario: reproduce, then retry -----------------------------------------


def test_unwritable_ledger_approval_is_not_actionable_then_retry_commits(tmp_path):
    """THE reproduction. A VALID signed approval over an UNWRITABLE ledger is NOT actionable
    (``approved=False``), and a fresh reader agrees (no durable APPROVED terminal). Once the ledger is
    writable again, the SAME envelope durably commits APPROVED and a fresh reader agrees."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}

    # register durably (writable), producing the durable register line
    reg = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    key = reg.register(_esc(seq=1))
    assert os.path.exists(led_path) and reg.pending_keys() == [key]

    # a GENUINE signed approval envelope over THIS exact terminal
    env = sign_escalation_approval(priv, key_id=kid, key=key)

    # --- make the ledger UNWRITABLE, then resolve with the valid approval ---
    real = _make_unwritable(led_path)
    live = reg.resolve(key, env)

    # DEFECT-2 GUARANTEE: the verified approval is NOT actionable while it is not durable
    assert live.approved is False
    assert live.outcome != ConfirmationOutcome.APPROVED           # non-terminal, not a durable allow
    assert "durably committed" in live.reason

    # AGREEMENT: a FRESH resolver over the same ledger sees NO durable terminal — the register is still
    # durable (so it stays PENDING and resolvable), but there is NO approved terminal at rest
    fresh = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    assert fresh.resolution(key) is None
    assert fresh.pending_keys() == [key]
    assert _approved_terminal_lines(led_path) == []

    # --- RETRY once the ledger is writable again: the SAME envelope now durably commits APPROVED ---
    _make_writable(led_path, real)
    retry = reg.resolve(key, env)
    assert retry.outcome == ConfirmationOutcome.APPROVED and retry.approved is True

    # and a FRESH resolver now AGREES (durable + re-verifiable), with exactly one approved terminal at rest
    fresh2 = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    assert fresh2.resolution(key).outcome == ConfirmationOutcome.APPROVED
    assert fresh2.resolution(key).approved is True
    assert len(_approved_terminal_lines(led_path)) == 1


# --- (2) mutation check: swallowing the append failure reintroduces the defect ------------------------


def test_mutation_swallowing_the_durable_append_failure_reintroduces_the_defect(tmp_path, monkeypatch):
    """MUTATION CHECK. Revert to swallow-and-return-APPROVED (attempt the durable append but IGNORE its
    result) and the "not actionable when non-durable" property FLIPS pass -> fail: the live resolver returns
    APPROVED while a fresh reader sees NO durable terminal — the exact operator-reported divergence. This
    proves the fix's durable-commit CHECK is load-bearing (removing it re-breaks the test)."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}
    reg = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    key = reg.register(_esc(seq=1))
    env = sign_escalation_approval(priv, key_id=kid, key=key)

    real = _make_unwritable(led_path)

    # the mutation == the ORIGINAL bug: still attempt the (failing) append, but swallow its result and
    # report success, so _finish records + returns APPROVED regardless of durability.
    orig_append = ConfirmationRegistry._append_ledger

    def _swallow(self, record, *, fsync=False):
        orig_append(self, record, fsync=fsync)   # attempt the real append (fails, writes nothing at rest)
        return True                              # ...and swallow the failure, exactly as the old _emit did

    monkeypatch.setattr(ConfirmationRegistry, "_append_ledger", _swallow)

    live = reg.resolve(key, env)
    # bug reintroduced -> the live resolver hands back an ACTIONABLE allow
    assert live.outcome == ConfirmationOutcome.APPROVED and live.approved is True

    # ...but nothing durable was written -> a FRESH reader DISAGREES (the divergence the defect describes)
    fresh = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    assert fresh.resolution(key) is None or fresh.resolution(key).outcome != ConfirmationOutcome.APPROVED
    assert _approved_terminal_lines(led_path) == []
    _ = real  # symlink swap intentionally left in place; tmp_path is discarded by pytest


# --- (3) the atomic CAS marker is released on fail-closed so a retry can re-claim ----------------------


def test_cas_marker_released_on_fail_closed_lets_the_retry_reclaim(tmp_path):
    """On the fail-closed durable-commit path the atomic single-terminal marker is RELEASED (unlinked), so
    the escalation is not left permanently claimed — a later retry can re-claim it and durably commit."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}
    reg = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    key = reg.register(_esc(seq=1))
    env = sign_escalation_approval(priv, key_id=kid, key=key)

    real = _make_unwritable(led_path)
    live = reg.resolve(key, env)
    assert live.approved is False

    # the CAS marker for this key must NOT be left behind (it was released), so a retry can re-claim it
    cas_marker = os.path.join(led_path + ".cas", _key_digest(key))
    assert not os.path.exists(cas_marker)

    # retry once writable: re-claims the released marker and durably commits APPROVED
    _make_writable(led_path, real)
    retry = reg.resolve(key, env)
    assert retry.outcome == ConfirmationOutcome.APPROVED and retry.approved is True
    assert os.path.exists(cas_marker)         # the winning terminal now holds the claim


# --- (4) unchanged: writable-ledger happy path + pure in-memory (no-ledger) path ----------------------


def test_writable_ledger_happy_path_still_approves_durably(tmp_path):
    """A valid signed approval WITH a writable ledger still returns APPROVED and is durable (unchanged)."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}
    reg = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    key = reg.register(_esc(seq=1))
    env = sign_escalation_approval(priv, key_id=kid, key=key)

    res = reg.resolve(key, env)
    assert res.outcome == ConfirmationOutcome.APPROVED and res.approved is True

    fresh = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    assert fresh.resolution(key).approved is True
    assert len(_approved_terminal_lines(led_path)) == 1


def test_in_memory_no_ledger_path_is_unchanged(tmp_path):
    """A pure in-memory registry (``self._ledger is None``) skips the durable-first branch entirely: both a
    Path-A injected approver and a Path-V signed envelope still yield an in-memory APPROVED."""
    # Path A — injected approver, no ledger
    reg = ConfirmationRegistry()
    key = reg.register(_esc(seq=1))
    res = reg.resolve(key, "sig", approver=lambda s, e: _Appr(True))
    assert res.outcome == ConfirmationOutcome.APPROVED and res.approved is True

    # Path V — signed envelope, no ledger
    kid, pub, priv = _identity()
    reg2 = ConfirmationRegistry(trusted_approvers={kid: pub})
    key2 = reg2.register(_esc(seq=2))
    env = sign_escalation_approval(priv, key_id=kid, key=key2)
    res2 = reg2.resolve(key2, env)
    assert res2.outcome == ConfirmationOutcome.APPROVED and res2.approved is True


# --- ADVISORY-1: correlated-failure (ENOSPC) liveness — a mid-write claim failure self-cleans ----------


def test_correlated_failure_leaves_no_stale_marker_and_a_restart_retry_recovers(tmp_path, monkeypatch):
    """ADVISORY-1 (correlated failure / disk-full). The CAS marker's O_EXCL create SUCCEEDS (0-byte) but the
    subsequent write FAILS with ENOSPC — the same correlated condition (disk-full / read-only mount) that
    fails the ledger append. ``claim()`` self-cleans the marker IT created, so NO stale marker survives to
    block future claims: the escalation is NOT permanently un-approvable. After recovery a FRESH registry
    (restart / failover) re-claims the key and durably commits APPROVED.

    Mutation sensitivity: the pre-advisory ``claim()`` (which returned False WITHOUT unlinking) would leave a
    stale marker here -> the ``not os.path.exists(marker)`` assertion, and the restart-retry APPROVED, both
    flip to failing."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}
    reg = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    key = reg.register(_esc(seq=1))              # durable register, BEFORE the failure is injected
    env = sign_escalation_approval(priv, key_id=kid, key=key)

    marker = os.path.join(led_path + ".cas", _key_digest(key))
    target_digest = _key_digest(key).encode("ascii")
    real_write = os.write

    def _enospc_on_marker(fd, data):
        # ONLY the marker write for THIS key fails (its O_EXCL create already succeeded) — the correlated
        # ENOSPC that in reality also fails the ledger append.
        try:
            payload = bytes(data)
        except TypeError:
            payload = data
        if payload == target_digest:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", _enospc_on_marker)
    live = reg.resolve(key, env)
    assert live.approved is False                                 # not actionable (fail-closed)
    assert not os.path.exists(marker)                            # SELF-CLEAN: no stale marker left behind
    assert _approved_terminal_lines(led_path) == []              # nothing durable was written as an allow

    # --- recovery: storage healthy again, a FRESH registry (restart) re-claims and durably commits ---
    monkeypatch.setattr(os, "write", real_write)
    fresh = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    assert fresh.pending_keys() == [key]                          # recovered — NOT permanently un-approvable
    recovered = fresh.resolve(key, env)
    assert recovered.outcome == ConfirmationOutcome.APPROVED and recovered.approved is True
    again = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    assert again.resolution(key).approved is True
    assert len(_approved_terminal_lines(led_path)) == 1          # exactly one durable terminal


def test_loser_cleanup_never_unlinks_a_concurrent_winners_marker(tmp_path):
    """ADVISORY-1 safety: self-clean removes ONLY a marker THIS call created via O_EXCL. A LOSER hits
    ``FileExistsError`` (before any create) and returns without unlinking, so a concurrent legitimate
    winner's marker is never removed — the loser adopts the coordinated winner, exactly one terminal."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}
    key = ConfirmationRegistry(ledger=EscalationLedger(led_path),
                               trusted_approvers=trusted).register(_esc(seq=1))

    reg_win = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    reg_lose = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)

    env = sign_escalation_approval(priv, key_id=kid, key=key)
    assert reg_win.resolve(key, env).outcome == ConfirmationOutcome.APPROVED   # winner claims + commits
    marker = os.path.join(led_path + ".cas", _key_digest(key))
    assert os.path.exists(marker)                                             # winner holds its marker

    lose_res = reg_lose.reject(key, "member declined")           # loser: FileExistsError -> adopt winner
    assert lose_res.outcome == ConfirmationOutcome.APPROVED and lose_res.approved is True
    assert os.path.exists(marker)                                             # winner's marker UNTOUCHED
    assert len(_approved_terminal_lines(led_path)) == 1                       # exactly one terminal


# --- ADVISORY-2: the authoritative APPROVED terminal is power-loss durable (fsync) --------------------


def test_authoritative_approved_terminal_is_fsynced_non_approval_is_not(tmp_path, monkeypatch):
    """ADVISORY-2: the AUTHORITATIVE APPROVED terminal (the record that authorizes the dangerous action) is
    appended with ``fsync=True`` (power-loss durable); a non-approval (register / reject) stays best-effort
    (``fsync=False`` — a lost non-approval merely reappears pending, fail-safe)."""
    kid, pub, priv = _identity()
    led_path = str(tmp_path / "eng.escalations.jsonl")
    trusted = {kid: pub}

    calls: list = []
    real_append = EscalationLedger.append

    def _spy(self, record, *, fsync=False):
        calls.append((str(record.get("event")), fsync))
        return real_append(self, record, fsync=fsync)

    monkeypatch.setattr(EscalationLedger, "append", _spy)

    reg = ConfirmationRegistry(ledger=EscalationLedger(led_path), trusted_approvers=trusted)
    key = reg.register(_esc(seq=1))
    env = sign_escalation_approval(priv, key_id=kid, key=key)
    assert reg.resolve(key, env).outcome == ConfirmationOutcome.APPROVED

    assert ("approved", True) in calls          # the actionable terminal is fsync'd (power-loss durable)
    assert ("register", False) in calls          # a non-approval stays cheap best-effort
    assert ("approved", False) not in calls      # the approved terminal is NEVER appended without fsync


def test_fsync_failure_on_the_authoritative_append_reports_not_durable(tmp_path, monkeypatch):
    """ADVISORY-2 contract: an ``fsync`` that itself fails means the record is NOT durable, so ``append``
    returns False -> the caller fails closed rather than call a non-durable terminal committed. The
    best-effort (``fsync=False``) path never calls fsync and is unaffected."""
    led = EscalationLedger(str(tmp_path / "x.escalations.jsonl"))
    rec = {"event": "approved", "wave_id": "w", "member_id": "m", "seq": 1, "approved": True}

    assert led.append(rec, fsync=True) is True                   # fsync works -> durable

    def _boom(_fd):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "fsync", _boom)
    assert led.append(rec, fsync=True) is False                  # fsync failed -> reported NOT durable
    # a best-effort (non-approval) append never calls fsync, so the fsync failure does not affect it
    assert led.append({"event": "rejected", "wave_id": "w", "member_id": "m", "seq": 2}, fsync=False) is True
