"""W8-2 (#468) — passive fencing is ADVISORY; the ACCEPTED, TESTED limitation is a fork-DETECTION SLA.

Nothing at the storage/orchestration layer PREVENTS a second concurrent writer (the fencing is a shell
guard + a ``:ro`` bind in one optional compose profile). Per the witnessed-floor doctrine
(``docs/architecture/HA-PROFILE.md`` §2, §4) a prevention lease would contradict the product's core
trade, so W8-2 takes path (b): document the limitation and prove a DETECTION SLA. The decision record is
``docs/decisions/W8-2-passive-fencing-detection-sla.md``.

This suite MEASURES actual fork-detection latency against the stated SLA and proves, as a negative
control, that the detector is not a no-op (a legitimate single-writer extension is NOT flagged). It also
ties detection to the fail-closed promotion backstop: even if detection is delayed, the failover guard
refuses to PROMOTE a fork.

FAILS WITHOUT THE FIX: ``tools/ha/fork_detection_sla`` and the decision record do not exist on a tree
without W8-2, so import + the doc assertions fail there.
"""
from __future__ import annotations

import math
import re
import sys
from pathlib import Path

from sigil.reuse import build_chain, digest_payload, generate_keypair
from sigil.reuse.chain import sign_head
from sigil.spine import witness as W
from vigil_integration.transparency import (
    Witness,
    checkpoint_hash,
    checkpoint_of,
    consistent,
    is_split,
)

_REPO = Path(__file__).resolve().parents[3]
_GUARD_DIR = _REPO / "tools" / "ha"
if str(_GUARD_DIR) not in sys.path:
    sys.path.insert(0, str(_GUARD_DIR))
import fork_detection_sla as sla  # noqa: E402  — the module under test (absent on a pre-W8-2 tree)
import spine_failover_guard as guard  # noqa: E402

OWNER = generate_keypair()
SCOPE = "sigil"


def _chain(n, salt=""):
    entries = build_chain([digest_payload({"i": i, "s": salt}) for i in range(n)])
    head = sign_head(entries, engagement_slug=SCOPE, signers=[("owner", OWNER.private_key_b64)])
    return entries, head


def _tr():
    return W.witness_trust_root(None, owner_pub=OWNER.public_key_b64, owner_key_id="owner")


def _witnessed_env(head, tmp_path):
    wc = W.emit_checkpoint(head, [Witness("owner", OWNER.private_key_b64)],
                           tip_path=tmp_path / "tip", scope=SCOPE)
    return W.dump_witnessed(wc, scope=SCOPE)


def _first_split_time(events):
    """A checkpoint-comparing monitor (what a witness / the transparency reader does): keep the first head
    seen at each height, and flag a split the MOMENT a different head shows up at a seen height. Returns the
    event time at which the fork is first DETECTED via the real ``is_split``, or ``None``."""
    seen = {}
    for t, cp in events:
        prior = seen.get(cp.entry_count)
        if prior is not None and sla.detect_fork(prior, cp):
            return t
        seen.setdefault(cp.entry_count, cp)
    return None


# ---------------------------------------------------------------- the SLA is grounded in shipped values

def test_cadence_matches_the_shipped_checkpoint_timer():
    """The SLA is one witness-checkpoint cadence; that cadence MUST equal the shipped timer's, or the SLA
    number is a fiction. Parse the sovereign timer and assert a 15-minute cadence."""
    timer = _REPO / "apps" / "sigil" / "deploy" / "systemd" / "sigil-checkpoint.timer"
    text = timer.read_text(encoding="utf-8")
    # OnCalendar=*-*-* *:MM/15:00 — the `/15` step is the 15-minute cadence.
    assert re.search(r"OnCalendar=.*:\d+/15:00", text), \
        f"sigil-checkpoint.timer must fire every 15 min to back the SLA; got:\n{text}"
    assert sla.WITNESS_CHECKPOINT_CADENCE_S == 15 * 60
    assert sla.FORK_DETECTION_SLA_S == sla.WITNESS_CHECKPOINT_CADENCE_S
    # The hard fail-closed ceiling is the same 24h freshness-refuse bound the guard enforces (no drift).
    assert sla.FORK_PROMOTION_REFUSE_CEILING_S == 24 * 3600


# ---------------------------------------------------------------- detection fires, and within the SLA

def test_second_writer_fork_is_detected_within_the_sla():
    """A deliberately started SECOND WRITER produces a divergent owner-signed head at the SAME height. Drive
    a checkpoint-comparing monitor over a realistic timeline and MEASURE the detection latency against the
    SLA (not assume it)."""
    _ea, ha = _chain(2)                              # writer A: head at count 2
    _eb, hb = _chain(2, salt="SECOND-WRITER")        # writer B (fencing failed): SAME height, different head
    assert hb.entry_count == ha.entry_count and hb.last_seq == ha.last_seq
    assert hb.head_hash != ha.head_hash              # ... the fork
    cp_a, cp_b = checkpoint_of(ha), checkpoint_of(hb)

    # detection actually fires on the fork (the audited is_split, via detect_fork)
    assert sla.detect_fork(cp_a, cp_b) is True and is_split(cp_a, cp_b) is True

    # Timeline: A's checkpoint at t=0; B comes up just after (t=1s); a witness obtains B's divergent head at
    # the NEXT cadence tick. This is the worst case (B started just after a tick).
    cadence = sla.WITNESS_CHECKPOINT_CADENCE_S
    b_start = 1
    next_tick = int(math.ceil(b_start / cadence)) * cadence      # = one full cadence
    events = [(0, cp_a), (next_tick, cp_b)]

    detect_time = _first_split_time(events)
    assert detect_time is not None, "the monitor must DETECT the second-writer fork"
    measured_latency = detect_time - b_start
    assert sla.detection_within_sla(measured_latency), (
        f"measured detection latency {measured_latency}s exceeds the SLA {sla.FORK_DETECTION_SLA_S}s")
    assert measured_latency <= sla.worst_case_detection_latency_s()


# ---------------------------------------------------------------- NEGATIVE CONTROL: not a no-op detector

def test_legitimate_single_writer_extension_is_not_flagged():
    """The detector must not flag a HEALTHY single writer. Two checkpoints from ONE writer growing its head
    (count 2 -> 3, a valid append-only extension) are NOT a split, and a monitor over that timeline never
    fires. If this failed, the SLA test above would be a no-op that flags everything."""
    _e2, h2 = _chain(2)
    _e3, h3 = _chain(3)                               # same history, one record longer (single-writer growth)
    cp1 = checkpoint_of(h2)
    cp2 = checkpoint_of(h3, prev_checkpoint_hash=checkpoint_hash(cp1))

    assert sla.detect_fork(cp1, cp2) is False and is_split(cp1, cp2) is False
    ok, _why = consistent(cp1, cp2)
    assert ok is True, "a legitimate single-writer append-only extension must verify as consistent"
    assert _first_split_time([(0, cp1), (sla.WITNESS_CHECKPOINT_CADENCE_S, cp2)]) is None


# ---------------------------------------------------------------- fail-closed backstop (composition)

def test_detected_fork_can_never_be_silently_promoted(tmp_path):
    """Detection is the SLA; the BACKSTOP is that a fork is never silently PROMOTED even if detection lags.
    The failover guard refuses (exit 2) to promote writer B's forked head against A's witnessed checkpoint."""
    _ea, ha = _chain(2)
    env = _witnessed_env(ha, tmp_path)                # off-box witnessed checkpoint from the true active A
    eb, hb = _chain(2, salt="SECOND-WRITER")          # the second writer's divergent head at the same height
    v = guard.evaluate_promotion(hb, env, scope=SCOPE, trust_root=_tr(),
                                 owner_trust_root=_tr(), entries=eb)
    assert not v.activate and v.exit_code == 2 and "SAME-HEIGHT FORK" in v.reason


# ---------------------------------------------------------------- the decision record states the SLA

def test_decision_record_states_the_limitation_and_sla():
    doc = _REPO / "docs" / "decisions" / "W8-2-passive-fencing-detection-sla.md"
    assert doc.exists(), f"missing W8-2 decision record at {doc}"
    text = doc.read_text(encoding="utf-8")
    norm = re.sub(r"\s+", " ", text)
    # states the limitation precisely
    assert "advisory" in text.lower() and "second" in text.lower() and "writer" in text.lower()
    # states the DETECTION SLA (one witness-checkpoint cadence, 15 minutes) and the fail-closed ceiling
    assert "15" in text and "detection" in text.lower()
    assert "24h" in norm or "24 h" in norm or "24-hour" in norm.lower()
    # records that no prevention lease is added, and why (witnessed-floor doctrine)
    assert "witnessed-floor" in text.lower() or "witnessed floor" in text.lower()
