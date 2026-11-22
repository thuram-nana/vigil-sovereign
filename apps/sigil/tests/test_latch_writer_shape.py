"""The kill switch and the capability latch honour only records written the way the governor writes them.

A latch record counts only when it is ``kind == "event"`` and ``source == "governor"`` — the shape
``KillSwitch.engage/release`` and ``CapabilityGate.disable/enable`` give it (``authn.governor_written``). A record
appended by any other path never halts, releases, disables or re-enables anything, whatever its payload says. The
live scan, the verified fold cache and the snapshot fold (``spine.snapshot.build``) agree on this, so a hard prune
carries exactly the same verdict. The safe direction keeps working: an unsigned governor-written disable or halt
still takes effect, and the paired phone's halt — written by the bridge in the governor shape, or in the earlier
``source == "mesh"`` device shape — is still a halt.

The guard at the end pins WHO may write a governor-shaped event record: the reviewed governor writers only, so no
customer-facing path can append a record these folds honour.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest apps/sigil/tests/test_latch_writer_shape.py -q
"""
from __future__ import annotations

import ast
import itertools
from pathlib import Path

import pytest

from sigil.bridge.daemon import BridgeDaemon
from sigil.governor.authn import governor_written, signed_payload
from sigil.governor.capability import SIGNAL as CAP_SIGNAL, CapabilityGate
from sigil.governor.killswitch import SIGNAL as KS_SIGNAL, KillSwitch
from sigil.reuse import generate_keypair
from sigil.spine.snapshot import SnapshotState, build
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OWNER_PUB = OWNER.public_key_b64

_issue = itertools.count(1)


def _iss() -> float:
    return float(next(_issue))


# Writer shapes that are NOT the governor's: customer/edge audit, the monitoring and finding inbound, the cockpit's
# own audit, a governor-sourced record of another kind, and the phone bridge (a halt only — see below).
FOREIGN = [("event", "provision", "WARDEN"), ("event", "aegis", "AEGIS"), ("event", "authn", "cockpit"),
           ("finding", "receiver", "oracle"), ("refusal", "governor", "WARDEN"), ("event", "agent", "ENVOY"),
           ("event", "mesh", "DEVICE")]


def _store(tmp_path, name="spine.jsonl"):
    return SpineStore(str(tmp_path / name))


def _caps(store):
    return CapabilityGate(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _kill(store):
    return KillSwitch(store, owner_key=OWNER, trusted_pubkey=OWNER_PUB)


def _cap_record(store, shape, state, *, key=None):
    kind, source, actor = shape
    core = {"signal": CAP_SIGNAL, "capability": "voice", "state": state,
            "issued_at": 0.0 if state == "disabled" else _iss()}
    return store.append(kind=kind, source=source, actor=actor,
                        payload={**signed_payload(core, key), "tier": "A0", "decision": "auto"})


def _ks_record(store, shape, state, *, key=None):
    kind, source, actor = shape
    core = {"signal": KS_SIGNAL, "state": state, "issued_at": 0.0 if state == "engaged" else _iss()}
    return store.append(kind=kind, source=source, actor=actor,
                        payload={**signed_payload(core, key), "tier": "A0", "decision": "auto"})


@pytest.fixture(params=["", "1"], ids=["fold-cache-off", "fold-cache-on"])
def fold_cache(request, monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", request.param)
    return request.param


# ---------------------------------------------------------------------------------------------------------------
# capability latch
# ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("shape", FOREIGN, ids=lambda s: "/".join(s))
def test_a_disable_from_any_other_writer_never_disables_a_capability(tmp_path, fold_cache, shape):
    s = _store(tmp_path)
    caps = _caps(s)
    assert caps.is_enabled("voice")
    _cap_record(s, shape, "disabled", key=OWNER)            # even owner-signed: the writer shape decides
    _cap_record(s, shape, "disabled")                       # and unsigned
    assert caps.is_enabled("voice") is True
    assert caps._scan_enabled("voice") is True


@pytest.mark.parametrize("shape", FOREIGN, ids=lambda s: "/".join(s))
def test_an_owner_signed_enable_from_any_other_writer_never_re_enables(tmp_path, fold_cache, shape):
    s = _store(tmp_path)
    caps = _caps(s)
    caps.disable("voice")
    _cap_record(s, shape, "enabled", key=OWNER)             # a genuine owner signature, foreign writer shape
    assert caps.is_enabled("voice") is False
    caps.enable("voice", issued_at=_iss())                  # the governor's own enable still works
    assert caps.is_enabled("voice") is True


def test_an_unsigned_governor_written_disable_still_disables(tmp_path, fold_cache):
    s = _store(tmp_path)
    caps = _caps(s)
    _cap_record(s, ("event", "governor", "WARDEN"), "disabled")   # the fail-safe direction needs no signature
    assert caps.is_enabled("voice") is False


# ---------------------------------------------------------------------------------------------------------------
# kill switch
# ---------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("shape", [s for s in FOREIGN if s != ("event", "mesh", "DEVICE")], ids=lambda s: "/".join(s))
def test_a_halt_from_any_other_writer_never_halts(tmp_path, fold_cache, shape):
    s = _store(tmp_path)
    ks = _kill(s)
    _ks_record(s, shape, "engaged", key=OWNER)
    _ks_record(s, shape, "engaged")
    assert ks.is_engaged() is False
    assert ks._scan_engaged() is False


@pytest.mark.parametrize("shape", FOREIGN, ids=lambda s: "/".join(s))
def test_an_owner_signed_release_from_any_other_writer_never_releases(tmp_path, fold_cache, shape):
    s = _store(tmp_path)
    ks = _kill(s)
    ks.engage(reason="drill")
    _ks_record(s, shape, "released", key=OWNER)             # the phone's shape included: release is owner-only
    assert ks.is_engaged() is True
    ks.release(issued_at=_iss())
    assert ks.is_engaged() is False


def test_a_phone_halt_in_the_earlier_device_shape_is_still_a_halt(tmp_path, fold_cache):
    s = _store(tmp_path)
    ks = _kill(s)
    s.append(kind="event", source="mesh", actor="DEVICE",   # what the bridge recorded before governor records
             payload={"signal": KS_SIGNAL, "state": "engaged", "by": "phone", "reason": "panic halt from phone",
                      "tier": "A0", "decision": "auto"})
    assert ks.is_engaged() is True
    # the same shape from any other actor on the mesh source is not the phone's halt
    s2 = _store(tmp_path, "other.jsonl")
    s2.append(kind="event", source="mesh", actor="OWNER", payload={"signal": KS_SIGNAL, "state": "engaged"})
    assert _kill(s2).is_engaged() is False


def test_the_phone_panic_is_written_in_the_governor_shape_and_halts(tmp_path, fold_cache):
    s = _store(tmp_path)
    seq = BridgeDaemon(s, trusted_pubkey=OWNER_PUB).panic_engage(by="phone")
    rec = s.get(seq)
    assert (rec.kind, rec.source, rec.actor) == ("event", "governor", "DEVICE")
    assert governor_written(rec)
    assert rec.payload["signal"] == KS_SIGNAL and rec.payload["state"] == "engaged"
    assert rec.payload.get("sig") is None                   # the bridge holds no private key
    assert _kill(s).is_engaged() is True


# ---------------------------------------------------------------------------------------------------------------
# the snapshot fold carries exactly the live verdict across a prune
# ---------------------------------------------------------------------------------------------------------------
def _mixed_store(tmp_path, halted):
    """A spine whose last foreign records would flip both latches if their writer shape were ignored. ``halted``:
    the mesh is halted last by the phone's earlier-shape record (so dropping that shape, or honouring a foreign
    release, flips the verdict); otherwise it is released last by the governor (so honouring a foreign halt
    flips it)."""
    s = _store(tmp_path)
    caps, ks = _caps(s), _kill(s)
    caps.disable("gesture")
    ks.engage(reason="a")
    ks.release(issued_at=_iss())                             # governor release: live
    if halted:
        _ks_record(s, ("event", "mesh", "DEVICE"), "engaged")   # the phone's earlier shape: halted again
    for shape in FOREIGN:
        _cap_record(s, shape, "disabled")                   # would disable voice
        if shape != ("event", "mesh", "DEVICE"):
            _ks_record(s, shape, "engaged")                 # would halt
        _cap_record(s, shape, "enabled", key=OWNER)         # would re-enable gesture
        _ks_record(s, shape, "released", key=OWNER)
    return s


@pytest.mark.parametrize("halted", [True, False], ids=["halted", "released"])
def test_the_snapshot_fold_matches_the_live_scan(tmp_path, halted):
    s = _mixed_store(tmp_path, halted)
    recs = list(s.iter_records())
    st = build(recs, trusted_pubkey=OWNER_PUB, base_seq=len(recs), snapshot_seq=len(recs) - 1)
    assert st.killswitch_engaged is halted and _kill(s)._scan_engaged() is halted
    latch = st.capability_latch_map()
    assert latch.get("voice", True) is True and _caps(s)._scan_enabled("voice") is True
    assert latch.get("gesture", True) is False and _caps(s)._scan_enabled("gesture") is False


@pytest.mark.parametrize("halted", [True, False], ids=["halted", "released"])
def test_every_prefix_seed_composes_to_the_full_scan(tmp_path, monkeypatch, halted):
    s = _mixed_store(tmp_path, halted)
    full_ks = _kill(s)._scan_engaged()
    full_caps = {c: _caps(s)._scan_enabled(c) for c in ("gesture", "voice")}
    recs = list(s.iter_records())
    for k in range(1, len(recs)):
        snap = build([r for r in recs if r.seq < k], trusted_pubkey=OWNER_PUB, base_seq=k, snapshot_seq=k - 1)
        monkeypatch.setattr(SnapshotState, "load", classmethod(lambda cls, store, _s=snap: _s))
        assert _kill(s)._scan_engaged() is full_ks, k
        assert {c: _caps(s)._scan_enabled(c) for c in ("gesture", "voice")} == full_caps, k


# ---------------------------------------------------------------------------------------------------------------
# who may write a governor-shaped event record (the customer-facing write-path audit, pinned)
# ---------------------------------------------------------------------------------------------------------------
_PKG = Path(__file__).resolve().parents[1] / "sigil"

# Every module that appends a `kind="event", source="governor"` record. Each builds its payload from a signed core
# whose `signal` is the module's own constant (never a caller- or customer-supplied key), and none is reachable
# from a customer request with a caller-chosen signal. A new writer must be reviewed and added here.
_GOVERNOR_EVENT_WRITERS = frozenset({
    "agents/approvals.py", "gesture/navmode.py", "ui/settings.py", "ui/target_authorization.py",
    "governor/accounts.py", "governor/asset_ownership.py", "governor/capability.py", "governor/cost_ledger.py",
    "governor/customer_credentials.py", "governor/customers.py", "governor/eval_capability_grant.py",
    "governor/eval_offense_attestation.py", "governor/invoices.py", "governor/killswitch.py",
    "governor/launch_settlement.py", "governor/metering.py", "governor/monitoring_authority.py",
    "governor/offense_gate.py", "governor/orgs.py", "governor/postpaid.py", "governor/promotion.py",
    "governor/report_unlock.py", "governor/subscription.py", "governor/trial_claim.py", "governor/wallet.py",
    "governor/billing_reversal.py",   # W5: owner-signed reversal/arrears ledger (its own literal signal governor.billing_reversal)
    "governor/connected_repos.py",    # Red-Pen R2: owner-signed connected-repo registry (its own literal signal)
    "governor/shard_assignment.py",   # Front C S2a: owner-signed shard-assignment registry (its own literal signal, no latch)
    "governor/redpen_spend.py",       # Red-Pen R2: owner-signed per-(repo,month) spend record (its own literal signal)
    "governor/auto_topup.py",         # A1: owner-signed per-org auto-top-up settings + saved method + charge ledger
    "governor/redpen_schedule.py",    # Red-Pen R4: owner-signed System-review schedule + per-period enqueue markers
    #                                   (its own literal signals governor.redpen_schedule / _run; owner-only, no latch)
    "governor/cloud_connect.py",      # PR-C: owner-signed read-only cloud-grant registry (its own literal signals
    #                                   governor.cloud_connect_challenge / _grant; unsigned only for the fail-safe revoke)
    "governor/assistant_turns.py",    # PR-J2: owner-signed per-turn assistant audit record (its own literal signal
    #                                   governor.assistant_turn; the per-org rate-limit ledger only — no latch reads it)
    "seam_migrate.py",                # the owner-signed seam-migration audit record (its own signal, no latch)
    "governor/sso_config.py",         # PR-H: owner-signed per-org SSO/SCIM config registry (its own literal signal
    #                                   governor.sso_config; mirrors orgs/accounts key custody, re-enforced at mint)
    "governor/scim_directory.py",     # PR-H edge: owner-signed per-org SCIM directory (users/groups/edges; its own
    #                                   literal signal governor.scim_directory; bookkeeping only — no latch, no grant)
})

# Appends whose kind or source is not a literal: each is reviewed — none can write `kind="event"` with
# `source="governor"`.
_REVIEWED_DYNAMIC = frozenset({
    "agents/base.py",                 # source=AGENTS_SOURCE ("agent")
    "consolidate/brief.py",           # source=CONSOLIDATE_SOURCE
    "consolidate/promote.py",         # source=CONSOLIDATE_SOURCE
    "governor/key_history.py",        # kind=KEY_HISTORY_KIND ("owner_key_history")
    "inbound/finding_receiver.py",    # kind=finding/detection, source=FINDING_SOURCE
    "ingest/subagents.py",            # source=_SUBAGENT_SOURCE, kind="session"
    "ingest/transcript.py",           # kind in {message, tool_call, tool_result}
    "spine/store.py",                 # the store itself
    "ui/authn_audit.py",              # source=_AUTHN_SOURCE ("authn")
    "ui/provision.py",                # C1b retest: kind=RETEST_KIND ("finding_retest"), source=RETEST_SOURCE ("provision")
})


def _appends():
    for path in sorted(_PKG.rglob("*.py")):
        rel = path.relative_to(_PKG).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "append"):
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if "kind" not in kw and "source" not in kw:
                continue
            yield rel, kw.get("kind"), kw.get("source")


def _literal(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def test_only_the_reviewed_governor_writers_append_governor_shaped_event_records():
    writers, dynamic = set(), set()
    for rel, kind, source in _appends():
        k, src = _literal(kind), _literal(source)
        if (kind is not None and k is None) or (source is not None and src is None):
            dynamic.add(rel)
            continue
        if k == "event" and src == "governor":
            writers.add(rel)
    assert writers <= _GOVERNOR_EVENT_WRITERS, sorted(writers - _GOVERNOR_EVENT_WRITERS)
    assert dynamic <= _REVIEWED_DYNAMIC, sorted(dynamic - _REVIEWED_DYNAMIC)
    assert {"governor/killswitch.py", "governor/capability.py"} <= writers


def test_the_customer_edge_and_provisioner_write_no_governor_shaped_record():
    """The customer edge, the provisioner and the inbound spools append only in their own shapes."""
    for rel, kind, source in _appends():
        if rel in ("ui/custui.py", "ui/provision.py", "ui/launch_gate.py", "ui/pubui.py") or rel.startswith("inbound/"):
            assert not (_literal(kind) == "event" and _literal(source) == "governor"), rel
