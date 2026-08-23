"""W11-7 (#488) — the CHAOS AND FAILOVER suite.

Before this suite only the failover guard's DECISION CORE was unit-tested (test_ha_failover_guard.py).
This module is the cohesive, explicitly-labelled chaos/failover suite the issue asks for: one test for
each of the four chaos classes the single-writer sovereign spine is built to survive, each asserting the
system's DOCUMENTED behaviour (docs/architecture/HA-PROFILE.md, the store's invariant-15 fail-closed
doctrine, and the transparency-log quorum-intersection rule), each with a negative control in the SAME run
so the gate can never be a green no-op:

  1. NETWORK PARTITION  — a partition that defeats advisory fencing brings up a second writer; its
     divergent same-height owner-signed head is a DETECTABLE FORK (HA-PROFILE §2/§4, W8-2 SLA) and the
     failover guard REFUSES to promote it. Negative control: a healthy single-writer extension is NOT
     flagged and DOES promote.
  2. CLOCK SKEW         — a future-dated / stale off-box anchor is REFUSED fail-closed (HA-PROFILE §3.1,
     W7-5 freshness gate). Negative control (same run): a FRESH anchor of the same head ACTIVATES.
  3. BYZANTINE WITNESS  — an honest stateful witness in a STRICT-MAJORITY quorum refuses to equivocate on
     a second same-height fork (transparency.py). THE REQUIRED negative control: a witness set that meets a
     signing quorum but VIOLATES the quorum-intersection (strict-majority-of-distinct-keys) rule — one that
     would otherwise be trusted by ``verify_witnessed`` — is REJECTED by ``verify_split_view_resistant`` /
     ``is_split_view_resistant``, while a genuinely strict-majority set is accepted.
  4. TORN-PAGE INJECTION — a torn TAIL from an interrupted write is REPAIRED (reads skip it, the prefix
     verifies, an append after it is not lost — store.py BLOCK-1). Negative control: a torn MIDDLE line is
     a chain break that verify() FAILS on (invariant 15: a state-scanner never fails open / silently
     short-reads).

The suite runs in the REQUIRED ``SIGIL governor gates (P7 — offense gate + authn)`` CI job (which executes
the whole apps/sigil/tests/ directory) AND, on a cadence with failure-alerting, in the scheduled
``.github/workflows/scheduled-chaos-failover.yml`` workflow (#467) — both wirings are asserted below so the
"runs on a schedule and alerts" criterion is itself falsifiable. Heavier full-partition/crash chaos
(subprocess concurrent writers, SIGKILL crash-fuzz) is honestly labelled and lives off the PR runner: the
existing test_spine_crashfuzz.py + the scheduled workflow's ``chaos-heavy`` leg.

FAILS WITHOUT THE CHANGE: this module, the alert-decision helper, and the scheduled workflow do not exist
on a pre-W11-7 tree, so the wiring/alert tests below cannot pass there; and each chaos assertion is tied to
a real enforcing symbol (flipping that symbol — e.g. ``is_split_view_resistant`` to ``return True`` — turns
the matching negative control red, see RED-PEN-BRIEF.md).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from vigil_core import AuthorizerKey, TrustRoot
from vigil_core import generate_keypair as core_keypair
from vigil_integration.transparency import (
    Checkpoint,
    ConsistencyError,
    Witness,
    WitnessedCheckpoint,
    checkpoint_hash,
    checkpoint_of,
    consistent,
    is_split,
    is_split_view_resistant,
    verify_split_view_resistant,
    verify_witnessed,
)

from sigil.reuse import build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine import witness as W
from sigil.spine.store import SpineStore

# The failover guard + fork-detection SLA live at tools/ha/ (not installed packages); load them by path —
# exactly as test_ha_failover_guard.py / test_ha_fork_detection_sla.py do.
_REPO = Path(__file__).resolve().parents[3]
_GUARD_DIR = _REPO / "tools" / "ha"
if str(_GUARD_DIR) not in sys.path:
    sys.path.insert(0, str(_GUARD_DIR))
import fork_detection_sla as sla  # noqa: E402
import spine_failover_guard as guard  # noqa: E402

OWNER = generate_keypair()
SCOPE = "sigil"


# ─────────────────────────────────────────────────────────────────────────── shared fixtures ──────────
def _chain(n, salt=""):
    """A signed spine head at record count ``n``. ``salt`` produces a DIFFERENT (forked) history at the
    same height — the split-brain second writer."""
    entries = build_chain([digest_payload({"i": i, "s": salt}) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("owner", OWNER.private_key_b64)])
    return entries, head


def _solo_tr():
    """The default owner-only, threshold-1 witness set (retention-based DETECTION, not independence)."""
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _witnessed_env(head, tmp_path):
    wc = W.emit_checkpoint(head, [W_Witness("owner", OWNER.private_key_b64)],
                           tip_path=tmp_path / "tip", scope=SCOPE)
    return W.dump_witnessed(wc, scope=SCOPE)


def _witnessed_env_at(head, tmp_path, *, now):
    """A witnessed envelope stamped with an emission timestamp (the W7-5 scheduled-emitter behaviour)."""
    wc = W.emit_checkpoint(head, [W_Witness("owner", OWNER.private_key_b64)],
                           tip_path=tmp_path / "tip", scope=SCOPE, now=now)
    return W.dump_witnessed(wc, scope=SCOPE, emitted_at=int(now))


# The sovereign witness.emit_checkpoint takes its own Witness type; transparency.Witness is the co-signer
# used for the quorum tests. Alias to keep the two straight.
W_Witness = Witness


def _fresh_spine(n=5, salt="clean"):
    """A clean, migrated-agnostic single-file spine with records seq 0..n-1. Hermetic (own tmp path)."""
    p = tempfile.mktemp(suffix=".jsonl")
    s = SpineStore(p)
    for i in range(n):
        s.append(kind="event", source="chaos", actor="u", payload={"i": i, "s": salt})
    return p, s


# ═══════════════════════════════════════════════════ CHAOS 1 — NETWORK PARTITION (split-brain fork) ════

def test_partition_split_brain_fork_is_detected_and_refused(tmp_path):
    """A network partition that defeats the ADVISORY passive fencing brings up a SECOND writer. Two writers
    sharing the owner key produce two owner-signed heads at the SAME height with DIFFERENT ``head_hash`` —
    the documented DETECTABLE FORK (HA-PROFILE §2/§4). Assert:
      * the audited detector flags it (``is_split`` / ``detect_fork`` True), and
      * the failover guard REFUSES to promote the second writer's head against the true active's off-box
        witnessed anchor (SAME-HEIGHT FORK, exit 2) — a fork is never silently PROMOTED.
    Negative control in the SAME run: a HEALTHY single-writer extension (count 2 → 3) is NOT flagged and
    DOES promote — so detection is not a no-op that flags everything."""
    _ea, ha = _chain(2, salt="TRUE")                     # writer A — the true active
    env = _witnessed_env(ha, tmp_path)                    # off-box witnessed anchor from A
    eb, hb = _chain(2, salt="PARTITION-SECOND-WRITER")    # writer B — brought up during the partition
    assert hb.entry_count == ha.entry_count and hb.last_seq == ha.last_seq   # same height ...
    assert hb.head_hash != ha.head_hash                                      # ... divergent head (the fork)

    cp_a, cp_b = checkpoint_of(ha), checkpoint_of(hb)
    assert is_split(cp_a, cp_b) is True and sla.detect_fork(cp_a, cp_b) is True  # DETECTED

    v = guard.evaluate_promotion(hb, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_solo_tr(), entries=eb)
    assert not v.activate and v.exit_code == 2 and "SAME-HEIGHT FORK" in v.reason  # never PROMOTED

    # ── negative control: a legitimate single-writer extension is NOT a fork and DOES promote ──
    e3, h3 = _chain(3, salt="TRUE")                       # A grew by one record on the SAME history
    cp3 = checkpoint_of(h3, prev_checkpoint_hash=checkpoint_hash(cp_a))
    assert is_split(cp_a, cp3) is False and sla.detect_fork(cp_a, cp3) is False
    assert consistent(cp_a, cp3)[0] is True
    good = guard.evaluate_promotion(h3, env, scope=SCOPE, trust_root=_solo_tr(),
                                    owner_trust_root=_solo_tr(), entries=e3)
    assert good.activate and good.exit_code == 0


def test_partition_stale_passive_mirror_is_refused(tmp_path):
    """The other partition-failover hazard: a passive whose synced mirror was PARTITIONED and is now BELOW
    the off-box witnessed checkpoint (a rolled-back / stale head). Promoting it would roll the durable floor
    backwards. Documented behaviour (HA-PROFILE §3.2, guard step 3/4): REFUSE (ROLLBACK, exit 2)."""
    _e3, h3 = _chain(3, salt="TRUE")
    env = _witnessed_env(h3, tmp_path)                    # witnessed at count 3
    e2, h2 = _chain(2, salt="TRUE")                       # stale mirror: same history, only count 2
    v = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_solo_tr(), entries=e2)
    assert not v.activate and v.exit_code == 2 and "ROLLBACK" in v.reason


# ── the HEAVY leg: a real MULTI-PROCESS partition split-brain. Gated OFF the required PR runner (it forks
#    two real writer subprocesses) and run only by the scheduled workflow, which sets VIGIL_CHAOS_HEAVY=1.
_CHAOS_HEAVY = os.environ.get("VIGIL_CHAOS_HEAVY") == "1"

_HEAVY_CHILD = r"""
import json, sys
from pathlib import Path
from sigil.spine.store import SpineStore
from sigil.reuse.chain import sign_head
d, salt, owner_priv = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
s = SpineStore(d / "spine.jsonl")
for i in range(3):
    s.append(kind="event", source="w", actor="u", payload={"i": i, "s": salt})
entries = s.entries()
head = sign_head(entries, engagement_slug="sigil", signers=[("owner", owner_priv)])
(d / "head.json").write_text(head.model_dump_json(), encoding="utf-8")
(d / "entries.json").write_text(json.dumps(
    [{"seq": e.seq, "prev_hash": e.prev_hash, "cert_digest": e.cert_digest, "entry_hash": e.entry_hash}
     for e in entries]), encoding="utf-8")
"""


@pytest.mark.skipif(not _CHAOS_HEAVY,
                    reason="heavy multi-process partition chaos: scheduled-only (set VIGIL_CHAOS_HEAVY=1)")
def test_partition_multiprocess_split_brain_heavy(tmp_path):
    """HEAVY, scheduled-only: two REAL writer subprocesses each append to their own spine and sign a head
    with the SHARED owner key (a genuine split-brain from a partition where fencing failed). Prove the
    fork is DETECTED (``is_split``) and the guard REFUSES to promote the second writer against the true
    active's off-box witnessed anchor. Multi-process (subprocess + real fsync appends), so it is deselected
    on the required PR runner and run only when the scheduled workflow sets VIGIL_CHAOS_HEAVY=1."""
    from sigil.reuse import ChainEntry, SignedChainHead

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(_REPO / "apps" / "sigil"), str(_REPO / "integration"),
                                         env.get("PYTHONPATH", "")])
    da, db = tmp_path / "A", tmp_path / "B"
    da.mkdir(); db.mkdir()
    for d, salt in ((da, "TRUE"), (db, "PARTITION-FORK")):
        env["SIGIL_HOME"] = str(d)
        r = subprocess.run([sys.executable, "-c", _HEAVY_CHILD, str(d), salt, OWNER.private_key_b64],
                           env=env, capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, f"writer child failed: {r.stderr}"

    ha = SignedChainHead.model_validate_json((da / "head.json").read_text(encoding="utf-8"))
    hb = SignedChainHead.model_validate_json((db / "head.json").read_text(encoding="utf-8"))
    eb = [ChainEntry(**e) for e in json.loads((db / "entries.json").read_text(encoding="utf-8"))]
    assert ha.entry_count == hb.entry_count and ha.head_hash != hb.head_hash, "two writers → same-height fork"
    assert is_split(checkpoint_of(ha), checkpoint_of(hb)) is True

    env_a = _witnessed_env(ha, tmp_path)
    v = guard.evaluate_promotion(hb, env_a, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_solo_tr(), entries=eb)
    assert not v.activate and v.exit_code == 2 and "SAME-HEIGHT FORK" in v.reason


# ═══════════════════════════════════════════════════════════════════ CHAOS 2 — CLOCK SKEW ═════════════

_WARN = 100
_REFUSE = 200


def test_clock_skew_future_dated_anchor_refused(tmp_path):
    """A skewed clock: the off-box anchor is stamped in the FUTURE beyond the skew tolerance. A skewed clock
    corrupts every freshness bound, so the guard REFUSES it fail-closed (HA-PROFILE §3.1 — "or one dated in
    the future past the skew tolerance"). freshness == 'future-skew'."""
    _e2, h2 = _chain(2)
    env = _witnessed_env_at(h2, tmp_path, now=10_000)     # anchor emitted "at t=10000"
    v = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                 owner_trust_root=_solo_tr(), entries=_chain(2)[0],
                                 now=100, warn_after_s=_WARN, refuse_after_s=_REFUSE)  # ... but "now" is t=100
    assert not v.activate and v.exit_code == 2 and v.freshness == "future-skew"


def test_clock_skew_stale_anchor_refused_fresh_accepted(tmp_path):
    """The W7-5 freshness gate under clock skew, with its negative control in ONE run: the SAME
    owner-authenticated head at the witnessed height is REFUSED when the clock has advanced past the refusal
    bound (the scheduled off-box emitter has stopped and the rollback window widened → STALE ANCHOR), and
    ACTIVATES when the clock is fresh. So the refusal is freshness, and freshness is not a no-op."""
    e2, h2 = _chain(2)
    env = _witnessed_env_at(h2, tmp_path, now=1_000)

    fresh = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                     owner_trust_root=_solo_tr(), entries=e2,
                                     now=1_000 + _WARN - 1, warn_after_s=_WARN, refuse_after_s=_REFUSE)
    assert fresh.activate and fresh.exit_code == 0 and fresh.freshness == "fresh"

    stale = guard.evaluate_promotion(h2, env, scope=SCOPE, trust_root=_solo_tr(),
                                     owner_trust_root=_solo_tr(), entries=e2,
                                     now=1_000 + _REFUSE + 1, warn_after_s=_WARN, refuse_after_s=_REFUSE)
    assert not stale.activate and stale.exit_code == 2 and "STALE ANCHOR" in stale.reason
    assert stale.freshness == "stale-refuse"


# ══════════════════════════════════════════════════════════ CHAOS 3 — BYZANTINE WITNESS ═══════════════

def _witnesses(n):
    """n independent, distinctly-keyed witnesses + a factory for a threshold-m TrustRoot over them —
    mirrors integration/tests/test_transparency.py."""
    kps = [core_keypair() for _ in range(n)]
    ws = [Witness(f"w{i}", kps[i].private_key_b64) for i in range(n)]

    def root(threshold):
        return TrustRoot(threshold=threshold, authorizers=[
            AuthorizerKey(key_id=f"w{i}", name=f"w{i}", public_key_b64=kps[i].public_key_b64)
            for i in range(n)])

    return ws, root


def _cp(entry_count, head_hash, prev=""):
    return Checkpoint(last_seq=entry_count, entry_count=entry_count, head_hash=head_hash,
                      merkle_root=f"m{entry_count}", prev_checkpoint_hash=prev)


def test_byzantine_witness_equivocation_is_refused_by_an_honest_witness():
    """A byzantine OPERATOR tries to get a second witness quorum for a competing same-height fork. At a
    STRICT MAJORITY (2-of-3) any two quorums must share ≥1 witness; that shared HONEST, stateful witness has
    already tracked fork A and REFUSES to co-sign fork B (ConsistencyError) — so the operator cannot form a
    second valid quorum. Documented in transparency.py (the honest-witness non-equivocation contract)."""
    ws, root = _witnesses(3)
    tr = root(2)                                          # 2*2 == 4 > 3 → strict majority
    assert is_split_view_resistant(tr) is True
    old = _cp(10, "h-old")
    for w in ws:
        w.cosign(old)                                    # shared honest history
    fa = _cp(20, "head-A", prev=checkpoint_hash(old))
    qa = WitnessedCheckpoint(fa, (ws[0].cosign(fa), ws[1].cosign(fa)))
    assert verify_split_view_resistant(qa, witness_trust_root=tr) is True

    fb = _cp(20, "head-B", prev=checkpoint_hash(old))    # the competing fork at the same height
    for w in (ws[0], ws[1]):                             # both already tracked fork A ...
        with pytest.raises(ConsistencyError):
            w.cosign(fb)                                 # ... and refuse to equivocate
    best_fb = WitnessedCheckpoint(fb, (ws[2].cosign(fb),))   # the best the operator can assemble: w2 alone
    assert verify_witnessed(best_fb, witness_trust_root=tr) is False   # below threshold — no valid quorum


def test_byzantine_witness_violating_quorum_intersection_is_rejected():
    """THE required negative control: a byzantine witness set that WOULD OTHERWISE BE TRUSTED (a valid
    signing quorum signed the checkpoint, so ``verify_witnessed`` returns True) is REJECTED by the
    quorum-intersection rule (``verify_split_view_resistant`` / ``is_split_view_resistant`` return False),
    because the set is NOT a strict majority of DISTINCT keys — two disjoint quorums could each sign a
    different fork with NO witness equivocating. And a genuinely strict-majority set IS accepted, so the
    rule is not reject-everything."""
    # (a) SUB-MAJORITY: 2-of-4 (2*2 == 4 is NOT > 4). A valid quorum signs, so verify_witnessed is fooled,
    #     but the set is not strict-majority — two DISJOINT quorums ({w0,w1} and {w2,w3}) could each sign a
    #     different fork with no witness equivocating — so the full split-view guarantee is fail-closed False.
    ws, root = _witnesses(4)
    tr = root(2)
    assert is_split_view_resistant(tr) is False
    fa = _cp(20, "head-A")
    q = WitnessedCheckpoint(fa, (ws[0].cosign(fa), ws[1].cosign(fa)))
    assert verify_witnessed(q, witness_trust_root=tr) is True                 # a quorum DID sign ...
    assert verify_split_view_resistant(q, witness_trust_root=tr) is False     # ... but it is REJECTED

    # (b) DUPLICATE KEY: one operator key registered under two key_ids fakes an arithmetic "strict majority"
    #     (2-of-3). The rule dedups over the DECODED key and fails closed.
    shared, other = core_keypair(), core_keypair()
    dup_tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=shared.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=shared.public_key_b64),   # SAME key
        AuthorizerKey(key_id="w2", name="w2", public_key_b64=other.public_key_b64)])
    assert is_split_view_resistant(dup_tr) is False
    wa, wb = Witness("w0", shared.private_key_b64), Witness("w1", shared.private_key_b64)
    dq = WitnessedCheckpoint(fa, (wa.cosign(fa), wb.cosign(fa)))
    assert verify_witnessed(dq, witness_trust_root=dup_tr) is True            # the shared key signs twice ...
    assert verify_split_view_resistant(dq, witness_trust_root=dup_tr) is False  # ... REJECTED

    # (c) POSITIVE control — a genuinely strict-majority set of distinct keys IS resistant (not a no-op).
    ws3, root3 = _witnesses(3)
    good_tr = root3(2)                                    # 2*2 == 4 > 3
    assert is_split_view_resistant(good_tr) is True
    gq = WitnessedCheckpoint(fa, (ws3[0].cosign(fa), ws3[1].cosign(fa)))
    assert verify_split_view_resistant(gq, witness_trust_root=good_tr) is True


def test_byzantine_malformed_or_low_order_witness_key_fails_closed():
    """A byzantine witness key that is unparseable, or a low-order Ed25519 point (which admits a KEYLESS
    signature forgery), cannot be reasoned about — the quorum-intersection rule fails CLOSED rather than
    counting it toward a majority (IntegrityError swallowed → False)."""
    import base64
    bad = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64="!!!not-base64!!!")])
    assert is_split_view_resistant(bad) is False
    identity = base64.b64encode((1).to_bytes(32, "little")).decode()          # low-order point
    real = core_keypair()
    low = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=identity),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=real.public_key_b64)])
    assert is_split_view_resistant(low) is False


# ══════════════════════════════════════════════════════════ CHAOS 4 — TORN-PAGE INJECTION ═════════════

def test_torn_page_tail_is_repaired_and_append_not_lost():
    """Inject a TORN TAIL (a partial last line with no newline — an interrupted write / torn page) into a
    live spine and assert the DOCUMENTED recovery (store.py ``_last_valid_boundary`` / BLOCK-1):
      * a reopen does not crash and the tip is the last VALID record (the torn tail is skipped),
      * reads skip the torn tail and verify() on the valid prefix passes (a torn tail is a crash artifact,
        not tampering), and
      * an append AFTER the torn tail truncates the dead bytes first, so the new record is durable and NOT
        silently merged/lost — the chain stays contiguous and verifies."""
    p, _ = _fresh_spine(5)                                # clean seq 0..4
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"seq": 5, "scope": "sigil", "kind": "eve')   # a torn/partial LAST line, NO newline

    s = SpineStore(p)                                     # reopen must not crash (a daemon restarts here)
    assert s.next_seq == 5, "the tip is the last VALID record; the torn tail is skipped"
    assert [r.seq for r in s.iter_records()] == [0, 1, 2, 3, 4], "reads skip the torn tail, no crash"
    ok, _ = s.verify()
    assert ok, "the valid prefix still verifies — a torn tail is a crash artifact, not tampering"

    seq = SpineStore(p).append(kind="event", source="chaos", actor="u", payload={"real": True})
    got = SpineStore(p).get(seq)
    assert got is not None and got.payload.get("real") is True, \
        "the append AFTER a torn tail is durable + readable — not silently merged/lost (BLOCK-1)"
    assert [r.seq for r in SpineStore(p).iter_records()] == [0, 1, 2, 3, 4, 5], "contiguous after tail repair"
    ok, reason = SpineStore(p).verify()
    assert ok, f"chain intact after the torn tail is truncated + the real record appended: {reason}"


def test_torn_page_middle_is_rejected_not_silently_short_read():
    """Negative control for CHAOS 4: a torn/corrupt MIDDLE line is NOT a benign tail — it is real
    corruption. The documented fail-closed behaviour (invariant 15: a state-scanner never fails open /
    silently short-reads) is that verify() FAILS with a chain break, and the corrupt line surfaces as a
    seq GAP on read — it is REJECTED, never hidden as a shorter-but-green chain."""
    p, _ = _fresh_spine(6)                                # clean seq 0..5
    lines = open(p, encoding="utf-8").read().splitlines()
    lines[2] = '{"seq": 2, "kind": "eve'                 # corrupt a MIDDLE line (real corruption/tamper)
    open(p, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    s = SpineStore(p)
    assert [r.seq for r in s.iter_records()] == [0, 1, 3, 4, 5], "the corrupt middle line surfaces as a gap"
    ok, msg = s.verify()
    assert not ok and "chain break" in msg, f"mid-file corruption must NEVER be hidden — verify() fails: {msg}"


# ══════════════════════════════════════ scheduled run + failure alerting (#467), and it is FALSIFIABLE ══

_WF = _REPO / ".github" / "workflows" / "scheduled-chaos-failover.yml"
_ALERT = _REPO / ".github" / "scripts" / "chaos_alert.py"


def _load_chaos_alert():
    spec = importlib.util.spec_from_file_location("chaos_alert", _ALERT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_chaos_suite_runs_on_a_schedule():
    """The suite must run on a CADENCE, not only on a PR — a regression in chaos behaviour surfaces on its
    own. Assert the scheduled workflow exists, triggers on ``schedule:`` with a cron, and actually runs THIS
    suite (deterministic leg) by name."""
    assert _WF.is_file(), f"scheduled chaos workflow missing: {_WF}"
    text = _WF.read_text(encoding="utf-8")
    assert re.search(r"^\s*schedule:\s*$", text, re.MULTILINE), "workflow does not trigger on a schedule"
    assert re.search(r"-\s*cron:", text), "workflow has no cron entry under schedule"
    assert "test_chaos_failover" in text, "the scheduled workflow does not run this chaos suite"


def test_scheduled_chaos_failure_alerts():
    """Its failures must ALERT (#467). Assert the workflow opens a GitHub issue (the CI-native alert) gated
    on FAILURE and the schedule/dispatch event, and that the alert DECISION is falsifiable in code."""
    text = _WF.read_text(encoding="utf-8")
    assert "gh issue create" in text, "the workflow does not open an issue on failure (no #467 alert)"
    assert "chaos_alert.py" in text, "the workflow does not use the falsifiable alert-decision helper"
    # the alert-decision helper is real, pure-stdlib, and has both a positive and a negative outcome:
    assert _ALERT.is_file(), f"alert-decision helper missing: {_ALERT}"
    m = _load_chaos_alert()
    assert m.should_alert(1) is True, "a FAILED chaos run (nonzero exit) must alert"          # positive
    assert m.should_alert(0) is False, "a PASSING chaos run (zero exit) must NOT alert"        # neg control
    assert m.should_alert(2) is True, "any nonzero exit (error/collection failure) must alert"
    title, body = m.issue(3, run_url="https://example/run/1")
    assert "chaos" in title.lower() and "https://example/run/1" in body


# ═══════════════════════════════════════════════ the docs' HA claims are TRUE of the code ══════════════

def test_ha_profile_non_claim_and_symbols_are_true_of_the_code():
    """Verify the docs' HA claims are actually true of the code (issue AC). Assert (1) the load-bearing
    HA-PROFILE non-claim string is present verbatim, and (2) each symbol the profile cites as the mechanism
    for the four chaos behaviours actually exists and behaves as the doc says (checked by the tests above):
    ``is_split`` (fork detection), ``is_split_view_resistant`` (quorum-intersection), ``evaluate_promotion``
    (failover interlock), ``_last_valid_boundary`` (torn-tail repair)."""
    profile = _REPO / "docs" / "architecture" / "HA-PROFILE.md"
    assert profile.is_file()
    ptext = profile.read_text(encoding="utf-8")
    assert ("VIGIL does not provide, and this profile does not claim, multi-writer high\n"
            "> availability of the sovereign spine.") in ptext, \
        "the load-bearing HA non-claim string drifted from HA-PROFILE.md"

    # each cited mechanism resolves to a real callable with the documented behaviour
    assert callable(is_split) and callable(is_split_view_resistant)
    assert callable(guard.evaluate_promotion)
    from sigil.spine import store as _store
    assert callable(_store._last_valid_boundary), "documented torn-tail repair symbol is missing"
    # the profile references these exact source files as the mechanisms — they must exist
    for rel in ("integration/vigil_integration/transparency.py",
                "tools/ha/spine_failover_guard.py",
                "apps/sigil/sigil/spine/store.py",
                "tools/ha/fork_detection_sla.py"):
        assert (_REPO / rel).is_file(), f"HA-PROFILE cites a mechanism file that is missing: {rel}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
