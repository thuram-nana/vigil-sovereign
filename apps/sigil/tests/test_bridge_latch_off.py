"""The Companion's OFF-buttons for the owner's customer latches (bridge ``POST /api/latch-off``).

An OFF is the safe direction, so the phone sends it exactly like PANIC: a device-signed envelope (no wire secret)
with the action bound to the endpoint, a freshness window and the strict nonce replay gate + receipt; the latch name
rides INSIDE the signed args. The bridge records the OFF unsigned in the governor's record shape (it holds no private
key), and it takes effect at once. There is no phone route that turns a latch back ON. The webapp offers one button
per latch plus "all", and shows each latch's state from the signed snapshot read.

Run: SIGIL_HOME=$(mktemp -d) python -m pytest apps/sigil/tests/test_bridge_latch_off.py -q
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sigil.governor import customer_latch as cl
from sigil.spine.store import SpineStore

from test_bridge_server import OP, _authorize, _env, _get, _post, _serve, _spine

_WEBAPP = Path(__file__).resolve().parents[1] / "sigil" / "bridge" / "webapp"


@pytest.fixture
def bridge():
    p = _spine()
    srv, port = _serve(p)
    try:
        yield p, port
    finally:
        srv.shutdown()


def _states(p):
    return cl.state_all(SpineStore(p), trusted_pubkey=OP)


@pytest.mark.parametrize("name", cl.LATCHES)
def test_an_authorized_phone_turns_one_latch_off_at_once(bridge, name):
    p, port = bridge
    dev = _authorize(p)
    code, body = _post(port, "/api/latch-off", None, env=_env(dev, "latch_off", {"latch": name}, 1))
    assert code == 200, body
    out = json.loads(body)
    assert out["ok"] is True and out["off"] == [name]
    assert _states(p) == {n: ("off" if n == name else "on") for n in cl.LATCHES}
    rec = SpineStore(p).get(out["seqs"][name])
    assert (rec.kind, rec.source, rec.actor) == ("event", "governor", "DEVICE")
    assert rec.payload["state"] == "disabled" and rec.payload.get("sig") is None and rec.payload["by"] == "phone"


def test_all_turns_every_customer_latch_off(bridge):
    p, port = bridge
    dev = _authorize(p)
    code, body = _post(port, "/api/latch-off", None, env=_env(dev, "latch_off", {"latch": "all"}, 1))
    assert code == 200 and sorted(json.loads(body)["off"]) == sorted(cl.LATCHES)
    assert _states(p) == {n: "off" for n in cl.LATCHES}


def test_a_replayed_off_envelope_is_refused(bridge):
    p, port = bridge
    dev = _authorize(p)
    env1 = _env(dev, "latch_off", {"latch": "checkout"}, 1)
    assert _post(port, "/api/latch-off", None, env=env1)[0] == 200
    n = SpineStore(p).count()
    assert _post(port, "/api/latch-off", None, env=env1)[0] == 409
    assert SpineStore(p).count() == n                              # nothing written for the replay


def test_an_envelope_for_another_action_or_device_never_switches_anything(bridge):
    p, port = bridge
    dev = _authorize(p)
    assert _post(port, "/api/latch-off", None, env=_env(dev, "panic", {"latch": "all"}, 1))[0] == 403
    from sigil.reuse import generate_keypair
    stranger = generate_keypair()
    assert _post(port, "/api/latch-off", None, env=_env(stranger, "latch_off", {"latch": "all"}, 1))[0] == 401
    assert _post(port, "/api/latch-off", None)[0] == 401          # no envelope at all
    assert _post(port, "/api/latch-off", None, env=_env(dev, "latch_off", {"latch": "all"}, 2),
                 headers={"Host": "evil.example"})[0] == 403      # the anti-rebinding gate
    assert _states(p) == {n: "on" for n in cl.LATCHES}


@pytest.mark.parametrize("args", [{"latch": "voice"}, {"latch": "nope"}, {}, ["checkout"], "checkout", 5])
def test_an_unknown_or_malformed_latch_is_refused_cleanly(bridge, args):
    p, port = bridge
    dev = _authorize(p)
    code, _ = _post(port, "/api/latch-off", None, env=_env(dev, "latch_off", args, 1))
    assert code == 400
    assert _states(p) == {n: "on" for n in cl.LATCHES}


def test_there_is_no_phone_route_that_turns_a_latch_on(bridge):
    p, port = bridge
    dev = _authorize(p)
    cl.turn_off(SpineStore(p), "checkout", owner_key=None)
    assert _post(port, "/api/latch-on", None, env=_env(dev, "latch_off", {"latch": "checkout"}, 1))[0] == 404
    assert _post(port, "/api/latch-off", None, env=_env(dev, "latch_on", {"latch": "checkout"}, 2))[0] == 401
    assert _states(p)["checkout"] == "off"


def test_the_signed_snapshot_read_carries_the_latch_states(bridge):
    p, port = bridge
    dev = _authorize(p)
    cl.turn_off(SpineStore(p), "trial", owner_key=None)
    code, body = _get(port, "/api/snapshot", env=_env(dev, "read:snapshot", {}, 1))
    assert code == 200 and json.loads(body)["customer_latches"]["trial"] == "off"


# ---------------------------------------------------------------------------------------------------------------
# the webapp
# ---------------------------------------------------------------------------------------------------------------
def test_the_webapp_offers_one_off_button_per_latch_and_all():
    html = (_WEBAPP / "index.html").read_text(encoding="utf-8")
    offered = re.findall(r'data-act="latch-off" data-latch="([a-z_]+)"', html)
    assert sorted(offered) == sorted([*cl.LATCHES, "all"])
    assert 'id="latch-state"' in html
    assert "latch-on" not in html and "data-act=\"latch-on\"" not in html


def test_the_webapp_sends_the_off_as_a_signed_replay_gated_envelope():
    js = (_WEBAPP / "app.js").read_text(encoding="utf-8")
    m = re.search(r"var LATCHES = (\[[^\]]*\]);", js)
    assert m and sorted(json.loads(m.group(1))) == sorted(cl.LATCHES)
    assert 'effectfulPost("/api/latch-off", "latch_off", { latch: name })' in js
    assert 'if (act === "latch-off") { return onLatchOff(btn.dataset.latch); }' in js
    assert '$("#latch-state").innerHTML = kv(s.customer_latches)' in js
