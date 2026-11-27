"""AEGIS AS-2e — output hygiene: "no seeded secrets or raw IPs in journald or snapshots".

Three leaks closed: (A) --status-out / registry snapshots pseudonymize the actor id (``session:<hmac>``) so no
raw — nor /24-recoverable — client IP reaches a snapshot; (B) the DEFAULT stderr/journald verdict sink is
UI-safe — the certificate's ``oracle_context`` (matched-span PLAINTEXT + sentinel) never streams to journald;
(C) the gateway REFUSES to run under the built-in demo secret (a world-known key makes every actor pseudonym
reversible) or with no secret at all — the demo secret is for ``aegis demo`` only.
"""
from __future__ import annotations

import json
import os
import threading
from types import SimpleNamespace

import pytest

from framework.v2.aegis import cli as C
from framework.v2.aegis import gateway as G
from framework.v2.aegis.actor_graph import ActorGraph
from framework.v2.aegis.cli import _DEMO_SECRET, _gateway_snapshot, _log_verdict
from framework.v2.aegis.models import (ActorRef, AegisConfig, CertRef, LLMInteraction, Surface,
                                       TelemetryEnvelope, Verdict)
from framework.v2.aegis.sensors import LLMInteractionSensor


def _confirmed_verdict() -> Verdict:
    cert = CertRef.mint({"matched_span": "SENTINEL-SECRET-LEAK", "sentinel": "AEGIS-CANARY"},
                        bug_class="prompt_injection", confirmed_by="canary_leak", confidence=1.0)
    return Verdict(decision="confirmed", attack_class="prompt_injection", confidence=1.0,
                   certificate=cert, provenance="grounded:aegis:canary")


# --- Leak B: UI-safe stderr/journald -------------------------------------------------------------------------
def test_log_verdict_is_ui_safe_no_oracle_context_in_journald(capsys):
    _log_verdict(_confirmed_verdict())
    err = capsys.readouterr().err
    assert "SENTINEL-SECRET-LEAK" not in err      # NEGATIVE: the matched-span plaintext never reaches journald
    assert "AEGIS-CANARY" not in err              # nor the sentinel
    assert "oracle_context" not in err
    rec = json.loads(err.strip())                 # POSITIVE: still actionable — valid JSON, decision + cert id
    assert rec["decision"] == "confirmed" and rec["attack_class"] == "prompt_injection"
    assert rec["certificate"].get("cert_id")


# --- Leak A: HMAC-pseudonymized snapshots ---------------------------------------------------------------------
def _settings_with_actor(secret: str, ip: str = "203.0.113.9"):
    cfg = AegisConfig(deployment_secret=secret)
    sensor = LLMInteractionSensor(cfg)
    env = TelemetryEnvelope(surface=Surface.LLM, actor=ActorRef(ip=ip), seq=1,
                            llm=LLMInteraction(user_input="ignore previous instructions", llm_output="x"))
    g = ActorGraph()
    g.observe_all(sensor.observations(env, seq=1))
    return SimpleNamespace(config=cfg, _belief_lock=threading.Lock(), actor_graph=g, enforce=False)


def test_snapshot_pseudonymizes_actor_ip_no_raw_ip():
    snap = _gateway_snapshot(SimpleNamespace(settings=_settings_with_actor("a-real-deployment-secret")))
    blob = json.dumps(snap)
    assert "203.0.113.9" not in blob              # NEGATIVE: no raw client IP in a snapshot
    assert "203.0.113" not in blob                # nor the /24 (pseudonymize_source coarsens then HMACs)
    assert '"session:' in blob                     # POSITIVE: the session: prefix is kept (the UI still correlates)
    row = snap["actors"][0]
    assert snap["actor_count"] == 1 and "mean" in row and "lcb" in row and row["n"] == 2   # belief row still renders


def test_snapshot_pseudonym_is_keyed_and_deterministic():
    id_k = _gateway_snapshot(SimpleNamespace(settings=_settings_with_actor("k")))["actors"][0]["id"]
    id_k2 = _gateway_snapshot(SimpleNamespace(settings=_settings_with_actor("k2")))["actors"][0]["id"]
    id_k_again = _gateway_snapshot(SimpleNamespace(settings=_settings_with_actor("k")))["actors"][0]["id"]
    assert id_k == id_k_again and id_k != id_k2    # deterministic under a key; differs across keys


# --- Leak C: demo secret refused in production ----------------------------------------------------------------
class _Stop(Exception):
    pass


@pytest.fixture
def captured(monkeypatch):
    seen = {}

    def fake(upstream, **kw):
        seen.update(kw, upstream=upstream)
        raise _Stop()

    monkeypatch.setattr(G, "serve_gateway", fake)
    for k in list(os.environ):
        if k.startswith("AEGIS_GW_"):
            monkeypatch.delenv(k)
    return seen


def test_gateway_refuses_no_secret(captured, capsys):
    rc = C.main(["gateway", "--upstream", "http://127.0.0.1:9"])
    assert rc == 2 and "refusing to run" in capsys.readouterr().err.lower()


def test_gateway_refuses_the_demo_secret(captured, capsys):
    rc = C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--secret", _DEMO_SECRET])
    assert rc == 2 and "demo secret" in capsys.readouterr().err.lower()


def test_gateway_refuses_demo_secret_from_env(captured, monkeypatch):
    monkeypatch.setenv("AEGIS_GW_SECRET", _DEMO_SECRET)
    assert C.main(["gateway", "--upstream", "http://127.0.0.1:9"]) == 2


def test_gateway_accepts_a_real_secret(captured):
    with pytest.raises(_Stop):            # a real secret passes the guard -> serve_gateway is reached
        C.main(["gateway", "--upstream", "http://127.0.0.1:9", "--secret", "a-real-deployment-secret-key"])
    assert captured["config"].deployment_secret == "a-real-deployment-secret-key"
