"""A complete, chained spine line whose payload is not a JSON object is a RECORD (test_spine_store_integrity). No
append can write one (append and append_many refuse it before any lock); only a hand edit can. Each consumer that
folds it fails closed — it raises, never answers — with the fold cache on exactly as with it off:

  * `approvals.pending` (and the prune floor that reads it): the approval queue is never served without it;
  * the kill switch: an engaged mesh is never read as released, and the error is never cached;
  * mesh `authorized_devices`: no device set is served without it, so no device approval verifies against one;

and the live tailer shows it (its payload as compact JSON) and keeps advancing. A falsy payload that is not an
object (null, [], "", 0, false) reads as an empty payload, so `verify()` reports the line as tampered.

Run: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration:packages/core/vigil_core \\
     .venv-sovereign/bin/python -m pytest apps/sigil/tests/test_spine_record_payload_consumers.py
"""
from __future__ import annotations

import pytest

from sigil.agents.approvals import pending
from sigil.governor.killswitch import KillSwitch
from sigil.mesh import authorize_device, authorized_devices
from sigil.reuse import generate_keypair
from sigil.spine import fold_cache
from sigil.spine.prune import open_workflow_floor
from sigil.spine.store import SpineStore
from sigil.spine.tail import SpineTailer
from test_spine_store_integrity import write_chained_line

OWNER = generate_keypair()
PUB = OWNER.public_key_b64
NOT_OBJECTS = [["not", "a", "dict"], "text", 5, True]


@pytest.fixture(params=["1", ""], ids=["cache-on", "cache-off"])
def store(request, tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", request.param)
    fold_cache.clear_all()
    yield SpineStore(tmp_path / "spine.jsonl")
    fold_cache.clear_all()


def _queued(store):
    return store.append(kind="draft", source="agents", actor="TESTER",
                        payload={"subject": "s", "decision": "queued", "status": "awaiting-approval", "tier": "A2"})


@pytest.mark.parametrize("payload", NOT_OBJECTS)
def test_the_approval_queue_is_never_served_without_it(store, payload):
    seq = _queued(store)
    assert [r.seq for r in pending(store, PUB)] == [seq]
    write_chained_line(store, payload)
    with pytest.raises(AttributeError):
        pending(store, PUB)
    with pytest.raises(AttributeError):
        open_workflow_floor(store)                          # a prune never computes its floor without the queue


@pytest.mark.parametrize("payload", NOT_OBJECTS)
def test_an_engaged_kill_switch_is_never_read_as_released(store, payload):
    ks = KillSwitch(store, owner_key=OWNER, trusted_pubkey=PUB)
    ks.engage()
    assert ks.is_engaged() is True                          # warm
    write_chained_line(store, payload)
    for _ in range(2):                                      # the error is never cached as an answer
        with pytest.raises(AttributeError):
            ks.is_engaged()
        with pytest.raises(AttributeError):
            KillSwitch(store, owner_key=OWNER, trusted_pubkey=PUB).is_engaged()


@pytest.mark.parametrize("payload", NOT_OBJECTS)
def test_the_authorized_device_set_is_never_served_without_it(store, payload):
    dev = generate_keypair().public_key_b64
    authorize_device(store, "phone-1", dev, OWNER, issued_at=10.0)
    assert authorized_devices(store, PUB) == {dev}
    write_chained_line(store, payload)
    with pytest.raises(AttributeError):
        authorized_devices(store, PUB)


@pytest.mark.parametrize("payload", NOT_OBJECTS)
def test_the_live_tailer_shows_it_and_keeps_advancing(tmp_path, payload):
    import json
    s = SpineStore(tmp_path / "spine.jsonl")
    s.append(kind="message", source="t", actor="u", payload={"text": "first"})
    t = SpineTailer(s, since_seq=0)
    seq = write_chained_line(s, payload)
    ev = t.poll()
    assert [(e["seq"], e["integrity_ok"], e["text"]) for e in ev] == [(seq, True, json.dumps(payload))]
    nxt = s.append(kind="message", source="t", actor="u", payload={"text": "after"})
    assert [(e["seq"], e["text"]) for e in t.poll()] == [(nxt, "after")]


@pytest.mark.parametrize("payload", [None, [], "", 0, False])
def test_a_falsy_payload_reads_as_an_empty_payload_and_verify_reports_the_line(tmp_path, payload):
    s = SpineStore(tmp_path / "spine.jsonl")
    s.append(kind="message", source="t", actor="u", payload={"text": "first"})
    seq = write_chained_line(s, payload)
    fresh = SpineStore(tmp_path / "spine.jsonl")
    assert fresh.get(seq).payload == {} and fresh.count() == 2
    ok, why = fresh.verify()
    assert ok is False and f"binding break at seq {seq}" in why
