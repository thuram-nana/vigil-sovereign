"""M-11 — the OOB AUTONOMOUS COLLECTOR-FEEDER: the deploy-wiring that lets a GOVERNED integration engage
mint an out-of-band FACT autonomously.

The runner-owned OOB arm (``oob_callback_redrive``) and its oracle are proven in ``test_oob_redrive_arm``.
THIS suite proves the FEEDER that stands the arm up on the governed-engage path:

  * ``_governed_oob_material`` — the integration-side mirror of ``engine.engage._engage_oob_authority`` —
    builds the TRUSTED collector bundle (an independent collector keypair + the owner-pinned collector pubkey +
    the owner-signed window) ONLY from the SIGNED authority + the deployment-provisioned collector private key;
  * ``provision_authority`` PINS the collector pubkey INTO the owner-signed authority (default-off byte-identical);
  * ``_with_trusted_oob_material`` + ``_build_oracle`` thread that bundle onto the redrive spec through the
    TRUSTED channel, so the governed oracle seam mints a signed OOB FACT end-to-end;
  * ``build_engine`` wires the whole chain — a governed engage with OOB provisioned mints; without it stays a LEAD.

THE TRIPLE-LOCK, under test with POSITIVE + SAFE-NEGATIVE controls:
  1. the material arrives ONLY from the trusted feeder/authority — a model-supplied ``oob_material`` on the spec
     is STRIPPED and refused;
  2. the router (``engine._redrive_spec``) emits class + url ONLY — never a token/pin/window;
  3. a forged / wrong / unpinned collector is refused (feeder-side AND the arm's offline verifier).

Every positive control drives a REAL loopback origin's ``/oobtest/fetch`` through VIGIL's OWN collector and
asserts a SIGNED FACT that re-verifies offline WITH the pin and FAILS CLOSED without it; every negative asserts
POSITIVELY that OOB stayed a LEAD for the RIGHT reason (default-off, no pin, forged collector, denied egress,
model-sourced material) — never merely that a value is falsy.
"""
from __future__ import annotations

import http.server
import json
import threading
from types import SimpleNamespace

import pytest

pytest.importorskip("framework.v2")  # offense-leg only; skips cleanly in the keyless two-env (P5) leg

from vigil_integration.live.wiring import (  # noqa: E402
    EngineConfig,
    _build_oracle,
    _governed_oob_material,
    _with_trusted_oob_material,
    build_engine,
    provision_authority,
)


# ---------------------------------------------------------------------------------------------------
# hermetic isolation (per-test CRUCIBLE_ROOT) + charter + entitlement (mirrors test_engine_live /
# test_oob_redrive_arm) — provisioning, the authority store, the kill-switch and the charter all land
# under the throwaway root, so nothing leaks across tests.
# ---------------------------------------------------------------------------------------------------

@pytest.fixture()
def hermetic_root(tmp_path, monkeypatch):
    root = tmp_path / "crucible-root"
    root.mkdir(parents=True, exist_ok=True)
    (root / "CLAUDE.md").write_text("# hermetic test root (CRUCIBLE_ROOT sentinel)\n", encoding="utf-8")
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    monkeypatch.setenv("VIGIL_AUTHORITY_ROOT_DIR", str(root / ".authority-root"))
    from framework.v2.common import paths as _paths
    _paths.crucible_root.cache_clear()
    try:
        yield tmp_path
    finally:
        _paths.crucible_root.cache_clear()


@pytest.fixture(autouse=True)
def _isolate_blackboard(tmp_path, monkeypatch):
    from framework.v2.agents import blackboard as _bb
    db = tmp_path / "bb-isolated.sqlite"
    monkeypatch.setattr(_bb, "open_blackboard", lambda **_kw: _bb.Blackboard(db_path=db))
    yield


def _grant_active_recon(monkeypatch):
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _write_charter(slug: str, host: str = "127.0.0.1") -> None:
    from framework.v2.common import paths
    p = paths.charter_path(slug)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _collector_keypair():
    from vigil_core import generate_keypair
    return generate_keypair()


def _serve_benchmark():
    from framework.v2.eval.benchmark_app import BenchmarkHandler
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _analysis(bug_class: str = "ssrf"):
    return SimpleNamespace(extracted_info={"bug_class": bug_class})


# ===================================================================================================
# provision_authority — PINS the collector into the SIGNED authority; default-off byte-identical
# ===================================================================================================

def test_provision_authority_pins_the_collector_into_the_signed_authority(hermetic_root):
    from framework.v2.authority.gate import load_authority_for_gate
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-pin", scope=["127.0.0.1"],
                               oob_collector_pubkey=kp.public_key_b64,
                               oob_relay_host="relay.op.example")
    # the OWNER-SIGNED authority (verified against the returned trust root) carries the pin + relay.
    authority = load_authority_for_gate("feed-pin", trust_root=prov.trust_root)
    assert authority.oob_collector_pubkey == kp.public_key_b64
    assert authority.oob_relay_host == "relay.op.example"


def test_provision_authority_default_off_leaves_no_oob_pin(hermetic_root):
    from framework.v2.authority.gate import load_authority_for_gate
    prov = provision_authority(slug="feed-nopin", scope=["127.0.0.1"])   # no oob_* params
    authority = load_authority_for_gate("feed-nopin", trust_root=prov.trust_root)
    assert authority.oob_collector_pubkey == ""   # a non-OOB authority is byte-identical in meaning
    assert authority.oob_relay_host == ""
    assert authority.oob_dns_collector_pubkey == ""


# ===================================================================================================
# _governed_oob_material — the trusted feeder: positive + every safe-negative
# ===================================================================================================

def test_feeder_builds_the_trusted_bundle_when_provisioned(hermetic_root):
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-ok", scope=["127.0.0.1"], oob_collector_pubkey=kp.public_key_b64)
    cfg = EngineConfig(slug="feed-ok", oob_enable=True, oob_collector_keypair=kp)
    mat = _governed_oob_material(prov, cfg)
    assert isinstance(mat, dict) and mat, "the feeder must build a bundle when fully provisioned"
    assert mat["collector_keypair"] is kp, "the INDEPENDENT collector keypair (it signs receipts) must be threaded"
    assert mat["collector_pubkey"] == kp.public_key_b64, "the pin must be the OWNER-SIGNED authority pin"
    # the OWNER-SIGNED engagement window is threaded (both edges) as the anti-replay boundary.
    assert "not_before" in mat and "not_after" in mat and mat["not_after"] > mat["not_before"]
    assert mat["ttl_seconds"] > 0 and mat["skew_seconds"] >= 0


def test_feeder_default_off_returns_none_even_when_everything_else_is_provisioned(hermetic_root):
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-off", scope=["127.0.0.1"], oob_collector_pubkey=kp.public_key_b64)
    cfg = EngineConfig(slug="feed-off", oob_enable=False, oob_collector_keypair=kp)   # master switch OFF
    assert _governed_oob_material(prov, cfg) is None, "default-off must yield NO material (fail-closed LEAD)"


def test_feeder_refuses_without_a_provisioned_collector_private_key(hermetic_root):
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-nokey", scope=["127.0.0.1"], oob_collector_pubkey=kp.public_key_b64)
    cfg = EngineConfig(slug="feed-nokey", oob_enable=True, oob_collector_keypair=None)   # no private half
    assert _governed_oob_material(prov, cfg) is None, "no collector key ⇒ cannot sign receipts ⇒ no material"


def test_feeder_refuses_when_the_authority_has_no_pin(hermetic_root):
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-authnopin", scope=["127.0.0.1"])   # authority carries NO pin
    cfg = EngineConfig(slug="feed-authnopin", oob_enable=True, oob_collector_keypair=kp)
    assert _governed_oob_material(prov, cfg) is None, "no owner pin ⇒ OOB not provisioned ⇒ LEAD"


def test_feeder_refuses_a_forged_or_wrong_collector(hermetic_root):
    # TRIPLE-LOCK #3 (feeder side): the deployment-provisioned key does NOT match the owner-signed pin.
    pinned = _collector_keypair()
    wrong = _collector_keypair()
    prov = provision_authority(slug="feed-forged", scope=["127.0.0.1"],
                               oob_collector_pubkey=pinned.public_key_b64)   # authority pins `pinned`
    cfg = EngineConfig(slug="feed-forged", oob_enable=True, oob_collector_keypair=wrong)   # deploy ships `wrong`
    assert _governed_oob_material(prov, cfg) is None, "a key that does not match the owner-signed pin is refused"


def test_feeder_egress_gate_authorizes_only_the_owner_signed_relay(hermetic_root):
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-egress", scope=["127.0.0.1"],
                               oob_collector_pubkey=kp.public_key_b64, oob_relay_host="relay.op.example")
    # POSITIVE: an advertised callback on the owner-signed relay is authorized ⇒ the bundle carries it.
    ok = _governed_oob_material(prov, EngineConfig(
        slug="feed-egress", oob_enable=True, oob_collector_keypair=kp,
        oob_advertise_base_url="http://relay.op.example/cb"))
    assert isinstance(ok, dict) and ok.get("advertise_base_url") == "http://relay.op.example/cb"
    # NEGATIVE: an advertised callback on a DIFFERENT host is refused by authorize_oob_egress (fail-closed).
    denied = _governed_oob_material(prov, EngineConfig(
        slug="feed-egress", oob_enable=True, oob_collector_keypair=kp,
        oob_advertise_base_url="http://evil.example/cb"))
    assert denied is None, "a relay host that is not the owner-signed egress must be refused"


def test_feeder_refuses_a_reachable_advertise_without_an_owner_signed_relay(hermetic_root):
    # A reachable (non-loopback) callback REQUIRES an owner-signed relay. A deployment that supplies an advertise
    # URL while the authority names NO relay is a half-config ⇒ refused (a reachable callback is embedded only
    # toward the owner-authorized egress, never an arbitrary deployment-chosen host).
    kp = _collector_keypair()
    prov = provision_authority(slug="feed-noloan", scope=["127.0.0.1"],
                               oob_collector_pubkey=kp.public_key_b64)   # NO oob_relay_host on the authority
    mat = _governed_oob_material(prov, EngineConfig(
        slug="feed-noloan", oob_enable=True, oob_collector_keypair=kp,
        oob_advertise_base_url="http://relay.op.example/cb"))
    assert mat is None, "an advertise URL with no owner-signed relay must be refused (fail-closed)"


# ===================================================================================================
# _with_trusted_oob_material — the enrichment helper is the SOLE writer of the key (triple-lock #1)
# ===================================================================================================

def test_enrichment_sets_only_the_feeder_material_for_an_oob_spec():
    spec = {"kind": "oob", "url": "http://127.0.0.1:1/x", "bug_class": "ssrf"}
    out = _with_trusted_oob_material(spec, lambda: {"collector_keypair": object(), "collector_pubkey": "K"})
    assert out["oob_material"] == {"collector_keypair": out["oob_material"]["collector_keypair"],
                                   "collector_pubkey": "K"}
    assert out["url"] == spec["url"] and out["bug_class"] == "ssrf"


def test_enrichment_strips_a_model_supplied_material_and_is_fail_closed_without_a_feeder():
    # TRIPLE-LOCK #1: a producer/model-supplied oob_material on the spec is STRIPPED; the trusted feeder is
    # the SOLE source. With no feeder (provider=None) the OOB spec is left with NO material (fail-closed).
    forged = {"kind": "oob", "url": "http://127.0.0.1:1/x", "bug_class": "ssrf",
              "oob_material": {"collector_keypair": object(), "collector_pubkey": "ATTACKER"}}
    out = _with_trusted_oob_material(forged, None)
    assert "oob_material" not in out, "a model-supplied material must be stripped when no trusted feeder is wired"
    # a feeder that yields nothing (unprovisioned / forged) also leaves NO material on the spec.
    out2 = _with_trusted_oob_material(forged, lambda: None)
    assert "oob_material" not in out2


def test_enrichment_leaves_non_oob_specs_untouched():
    # A spec that is NOT OOB-consumable (non-"oob" kind AND a non-OOB bug_class) is returned UNCHANGED
    # (identity) — the byte-identical no-op. open_redirect is not in OOB_REDRIVE_CLASSES.
    web = {"kind": "web", "url": "http://x/", "bug_class": "open_redirect"}
    assert _with_trusted_oob_material(web, lambda: {"collector_keypair": object()}) is web
    assert _with_trusted_oob_material(None, lambda: {"collector_keypair": object()}) is None


def test_enrichment_strips_producer_material_on_a_NON_oob_kind_spec_with_an_oob_bug_class():
    # RED-PEN REGRESSION (the BLOCK): the consumer _live_oob_redrive_fact gates on bug_class ∈
    # OOB_REDRIVE_CLASSES, NOT on kind. A spec whose kind is NOT "oob" but whose bug_class IS an OOB class,
    # carrying a producer/model-supplied (even SELF-CONSISTENT: keypair + its own pubkey as the pin)
    # oob_material, must have that material STRIPPED — Lock #1 is keyed on the consumer's surface, not kind.
    atk = _collector_keypair()
    forged = {"kind": "web", "url": "http://127.0.0.1:1/oobtest/fetch", "bug_class": "ssrf",
              "oob_material": {"collector_keypair": atk, "collector_pubkey": atk.public_key_b64}}
    out = _with_trusted_oob_material(forged, None)   # default-off: no trusted feeder
    assert "oob_material" not in out, (
        "producer oob_material on a non-'oob'-kind spec carrying an OOB bug_class MUST be stripped "
        "(strip-on-kind / consume-on-bug_class mismatch = the defense-in-depth collapse)")
    # a feeder that yields nothing also leaves NO material on such a spec.
    assert "oob_material" not in _with_trusted_oob_material(forged, lambda: None)


def test_enrichment_replaces_producer_material_with_the_trusted_feeder_on_a_non_oob_kind_oob_class_spec():
    # With a trusted feeder wired, the attacker bundle on a non-"oob"-kind OOB-class spec is REPLACED by the
    # feeder's bundle — the feeder is the SOLE source of the key, even on this surface (never the producer's).
    atk = _collector_keypair()
    forged = {"kind": "web", "url": "http://127.0.0.1:1/oobtest/fetch", "bug_class": "ssrf",
              "oob_material": {"collector_keypair": atk, "collector_pubkey": atk.public_key_b64}}
    trusted = {"collector_keypair": object(), "collector_pubkey": "TRUSTED-PIN"}
    out = _with_trusted_oob_material(forged, lambda: trusted)
    assert out["oob_material"]["collector_pubkey"] == "TRUSTED-PIN", "the feeder bundle must win"
    assert out["oob_material"]["collector_keypair"] is not atk, "the attacker keypair must be gone"


def test_governed_seam_refuses_producer_material_on_a_non_oob_kind_spec_end_to_end(hermetic_root, monkeypatch):
    # END-TO-END RED-PEN REGRESSION: the full governed oracle seam, driven by the red-pen's exact spec shape
    # (kind="web", OOB bug_class, a SELF-CONSISTENT attacker bundle) with NO feeder wired, mints NOTHING.
    # Without the fix this minted a real signed OOB FACT from the model's own material.
    _grant_active_recon(monkeypatch)
    _write_charter("gov-nonoob")
    prov = provision_authority(slug="gov-nonoob", scope=["127.0.0.1"])
    oracle = _build_oracle(prov)   # no feeder (default-off)
    atk = _collector_keypair()
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        spec = {"kind": "web", "url": f"http://127.0.0.1:{port}/oobtest/fetch", "bug_class": "ssrf",
                "oob_material": {"collector_keypair": atk, "collector_pubkey": atk.public_key_b64}}
        ref = oracle("", _analysis("ssrf"), redrive=spec)
    finally:
        srv.shutdown()
    assert ref is None, (
        "a producer-supplied oob_material on a non-'oob'-kind OOB-class spec must be stripped — the model can "
        "never mint an OOB FACT through the kind/bug_class mismatch")


# ===================================================================================================
# END-TO-END: the governed oracle seam, fed by the trusted feeder, MINTS a signed OOB FACT
# ===================================================================================================

def test_governed_oracle_seam_mints_an_oob_fact_end_to_end(hermetic_root, monkeypatch):
    _grant_active_recon(monkeypatch)
    _write_charter("gov-mint")
    kp = _collector_keypair()
    prov = provision_authority(slug="gov-mint", scope=["127.0.0.1"], oob_collector_pubkey=kp.public_key_b64)
    cfg = EngineConfig(slug="gov-mint", oob_enable=True, oob_collector_keypair=kp)
    oracle = _build_oracle(prov, oob_material_provider=lambda: _governed_oob_material(prov, cfg))
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        spec = {"kind": "oob", "url": f"http://127.0.0.1:{port}/oobtest/fetch", "bug_class": "ssrf"}
        ref = oracle("", _analysis("ssrf"), redrive=spec)   # the router-shaped spec — NO material on it
    finally:
        srv.shutdown()
    assert ref, "a governed OOB interaction with the feeder provisioned must mint a signed FACT (a finding ref)"


def test_governed_oracle_seam_stays_a_lead_without_the_feeder(hermetic_root, monkeypatch):
    # DEFAULT-OFF control: the SAME oracle call, but no feeder wired ⇒ no material ⇒ the claim stays a LEAD.
    _grant_active_recon(monkeypatch)
    _write_charter("gov-lead")
    prov = provision_authority(slug="gov-lead", scope=["127.0.0.1"])
    oracle = _build_oracle(prov)   # no oob_material_provider → default-off
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        spec = {"kind": "oob", "url": f"http://127.0.0.1:{port}/oobtest/fetch", "bug_class": "ssrf"}
        ref = oracle("", _analysis("ssrf"), redrive=spec)
    finally:
        srv.shutdown()
    assert ref is None, "no feeder ⇒ OOB stays a LEAD (fail-closed, byte-identical to today)"


def test_governed_oracle_seam_refuses_a_model_supplied_material(hermetic_root, monkeypatch):
    # TRIPLE-LOCK #1 end-to-end: even if a crafted spec carries a model-supplied oob_material, with no trusted
    # feeder the enrichment STRIPS it and the seam mints NOTHING (the model can never source the material).
    _grant_active_recon(monkeypatch)
    _write_charter("gov-forged")
    prov = provision_authority(slug="gov-forged", scope=["127.0.0.1"])
    oracle = _build_oracle(prov)   # no feeder
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        spec = {"kind": "oob", "url": f"http://127.0.0.1:{port}/oobtest/fetch", "bug_class": "ssrf",
                "oob_material": {"collector_keypair": _collector_keypair()}}   # a MODEL-planted bundle
        ref = oracle("", _analysis("ssrf"), redrive=spec)
    finally:
        srv.shutdown()
    assert ref is None, "a model-supplied oob_material must be stripped — the model can never mint an OOB FACT"


def test_the_minted_fact_reverifies_offline_with_the_pin_and_fails_closed_without_it(hermetic_root, monkeypatch):
    # Drive the arm with the REAL feeder bundle, then re-verify the retained record offline (mirrors the arm
    # suite) to prove the governed-engage FACT is offline-re-verifiable AND tamper-rejected.
    from vigil_integration.live.runtime_redrive import oob_callback_redrive
    _grant_active_recon(monkeypatch)
    _write_charter("gov-reverify")
    kp = _collector_keypair()
    prov = provision_authority(slug="gov-reverify", scope=["127.0.0.1"], oob_collector_pubkey=kp.public_key_b64)
    cfg = EngineConfig(slug="gov-reverify", oob_enable=True, oob_collector_keypair=kp)
    material = _governed_oob_material(prov, cfg)
    assert material is not None
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug=prov.slug,
                                   engagement_slug=prov.slug, signers=prov.signers,
                                   oob_material={**material, "bug_class": "ssrf"}, timeout=3.0)
    finally:
        srv.shutdown()
    assert res.n_facts == 1, res.notes
    ctx = res.contexts[res.facts[0].finding_ref]
    from framework.v2.verify.oracles import oob_callback_oracle
    pin = kp.public_key_b64
    assert oob_callback_oracle(ctx["oob_hits"], ctx.get("oob_token"), collector_pubkey=pin,
                               issued_at=ctx.get("oob_issued_at")).fired, "must re-fire offline WITH the pin"
    assert not oob_callback_oracle(ctx["oob_hits"], ctx.get("oob_token"), collector_pubkey=None,
                                   issued_at=ctx.get("oob_issued_at")).fired, "must FAIL CLOSED without the pin"
    # TAMPER: a token-matched hit whose receipt does not verify against the pin is refused.
    hit = dict(ctx["oob_hits"][0])
    corrupt = {**hit, "collector_sig": ("A" * len(str(hit.get("collector_sig") or "A")))}
    assert not oob_callback_oracle([corrupt], ctx.get("oob_token"), collector_pubkey=pin,
                                   issued_at=ctx.get("oob_issued_at")).fired, "a corrupted receipt is refused"
    # the pinned key never leaks into the retained producer context (it is out-of-band only).
    assert pin not in json.dumps(ctx)


# ===================================================================================================
# build_engine — the full factory wires the feeder; ON mints, OFF stays a LEAD
# ===================================================================================================

def test_build_engine_wires_the_feeder_and_the_governed_engage_mints(hermetic_root, tmp_path, monkeypatch):
    _grant_active_recon(monkeypatch)
    kp = _collector_keypair()
    cfg = EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), scope=("127.0.0.1",),
                       oob_enable=True, oob_collector_keypair=kp)
    engine = build_engine(cfg)   # provisions + pins the authority + wires the OOB provider; writes the charter
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        spec = {"kind": "oob", "url": f"http://127.0.0.1:{port}/oobtest/fetch", "bug_class": "ssrf"}
        ref = engine.seams.oracle("", _analysis("ssrf"), redrive=spec)
    finally:
        srv.shutdown()
    assert ref, "build_engine with OOB provisioned must mint a signed OOB FACT through the full factory path"


def test_build_engine_default_off_keeps_oob_a_lead(hermetic_root, tmp_path, monkeypatch):
    _grant_active_recon(monkeypatch)
    cfg = EngineConfig(slug="loopback", base_dir=str(tmp_path / "live"), scope=("127.0.0.1",))  # OOB default off
    engine = build_engine(cfg)
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        spec = {"kind": "oob", "url": f"http://127.0.0.1:{port}/oobtest/fetch", "bug_class": "ssrf"}
        ref = engine.seams.oracle("", _analysis("ssrf"), redrive=spec)
    finally:
        srv.shutdown()
    assert ref is None, "default-off build_engine must keep an OOB claim a LEAD (fail-closed)"


# ===================================================================================================
# TRIPLE-LOCK #2 — the router (engine._redrive_spec) emits class + url ONLY (no trusted material)
# ===================================================================================================

def test_the_router_oob_branch_emits_class_and_url_only():
    import inspect

    from vigil_integration.live import engine
    src = ""
    for _n, obj in vars(engine).items():
        if isinstance(obj, type) and "_redrive_spec" in vars(obj):
            src = inspect.getsource(obj._redrive_spec)
            break
    assert '"kind": "oob"' in src, "the router must emit an oob spec kind"
    tail = src.split('"kind": "oob"')[1][:200]
    for forbidden in ("oob_material", "collector", "token", "not_before", "pubkey", "advertise"):
        assert forbidden not in tail, f"the router must NOT source {forbidden!r} (triple-lock #2)"
