"""APEX PR-2 — blind SSTI out-of-band confirmation, the ONE genuinely-new OOB class.

Blind SSTI (a template/EL construct that EVALUATES server-side and forces an out-of-band fetch, with no
readable response byte) reuses the already-built VF-2b signed-collector machinery with NO oracle change — the
class-agnostic ``oob_callback_oracle`` fires on a token-matched, independent-collector-receipt-verified
interaction inside the owner-signed window. This suite proves the WIRING + the honest fact-capability:

  * ``blind_ssti`` is EFFECTIVE as an out-of-band class ONLY when ``VIGIL_APEX_OOB`` is on (default-off,
    byte-identical: the frozen ``OOB_REDRIVE_CLASSES`` constant is untouched);
  * its ``BUG_CLASS_ORACLES`` row is PERMANENT ``(OOB_CALLBACK,)`` (so an offline re-verify is stable,
    flag-independent) and the in-corpus ``ssti`` (reflected) row is UNCHANGED;
  * the runner-crafted probes embed VIGIL's per-finding callback in a per-engine construct;
  * the dedicated ``oob_callback.ssti`` evidence branch is registered, fact_capable, NOT clean_capable;
  * END-TO-END against a REAL loopback target: a VULNERABLE evaluate-and-fetch route mints a SIGNED FACT that
    re-verifies offline WITH the pin and FAILS CLOSED without it; the MANDATORY same-shape negative control —
    a template-REFLECTING-but-non-executing twin — stays a LEAD, and a forged-token twin stays a LEAD;
  * the triple-lock holds for blind_ssti (forged collector key refused; flag-off fail-closed LEAD).

The loopback target is the benchmark app's blind-OOB model: ``/oobtest/fetch`` (VULNERABLE: extracts and
fetches the embedded loopback callback — models a server that EVALUATED the construct and fetched), its
same-shape twin ``/oobtest/reflect`` (echoes but NEVER fetches), and ``/oobtest/forge`` (wrong token). No
network leaves loopback.
"""
from __future__ import annotations

import http.server
import json
import threading

import pytest

pytest.importorskip("framework.v2")  # offense-leg only; skips cleanly in the keyless two-env (P5) leg

from vigil_integration.live.runtime_redrive import (  # noqa: E402
    OOB_REDRIVE_CLASSES,
    _oob_branch_for,
    _oob_probe_requests,
    oob_callback_redrive,
    oob_redrive_classes,
)


# --------------------------------------------------------------------------------------------------- fixtures
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


@pytest.fixture()
def apex_on(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_OOB", "1")
    yield


def _collector_keypair():
    from vigil_core import generate_keypair
    return generate_keypair()


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


def _serve_benchmark():
    from framework.v2.eval.benchmark_app import BenchmarkHandler
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _provisioned_material(slug: str):
    """A verified owner-signed authority pinning the collector + the trusted feeder bundle (APEX flag assumed
    set by the caller). Returns (prov, kp, material)."""
    from vigil_integration.live.wiring import EngineConfig, _governed_oob_material, provision_authority
    kp = _collector_keypair()
    prov = provision_authority(slug=slug, scope=["127.0.0.1"], oob_collector_pubkey=kp.public_key_b64)
    cfg = EngineConfig(slug=slug, oob_enable=True, oob_collector_keypair=kp)
    material = _governed_oob_material(prov, cfg)
    assert material is not None, "the feeder must build the trusted bundle when fully provisioned"
    return prov, kp, material


# ----------------------------------------------------------------- the class vocabulary + flag (default-off)
def test_blind_ssti_effective_only_when_the_flag_is_on(monkeypatch):
    # The frozen constant is UNTOUCHED (an identity other code + test_oob_redrive_arm pins), so default-off is
    # byte-identical; blind_ssti is appended to the EFFECTIVE set only when VIGIL_APEX_OOB is affirmative.
    assert set(OOB_REDRIVE_CLASSES) == {"ssrf", "blind_xxe", "xxe", "rce", "command_injection",
                                        "deserialization", "oob_sqli"}, "the frozen base set must not change"
    monkeypatch.delenv("VIGIL_APEX_OOB", raising=False)
    assert oob_redrive_classes() == OOB_REDRIVE_CLASSES, "flag OFF ⇒ effective set is byte-identical to base"
    assert "blind_ssti" not in oob_redrive_classes()
    monkeypatch.setenv("VIGIL_APEX_OOB", "1")
    assert "blind_ssti" in oob_redrive_classes()
    # every base class is still present when on (additive, never a substitution).
    assert set(OOB_REDRIVE_CLASSES).issubset(set(oob_redrive_classes()))


def test_blind_ssti_row_is_permanent_and_routes_to_oob_callback_only():
    # PERMANENT (flag-independent) so an offline re-verify of a minted FACT is stable regardless of the flag.
    from framework.v2.verify.models import OracleKind
    from framework.v2.verify.verifier import BUG_CLASS_ORACLES, known_bug_classes
    assert BUG_CLASS_ORACLES["blind_ssti"] == (OracleKind.OOB_CALLBACK,)
    assert "blind_ssti" in known_bug_classes()
    # the in-corpus reflected-SSTI row is UNTOUCHED (no OOB_CALLBACK added ⇒ `make gate` byte-identical).
    assert BUG_CLASS_ORACLES["ssti"] == (OracleKind.EVALUATION, OracleKind.SIDE_EFFECT,
                                         OracleKind.DIFFERENTIAL_RESPONSE)


def test_blind_ssti_admits_through_its_own_branch_others_unchanged():
    assert _oob_branch_for("blind_ssti") == "oob_callback.ssti"
    for other in OOB_REDRIVE_CLASSES:
        assert _oob_branch_for(other) == "oob_callback.collector_receipt", other


def test_the_blind_ssti_branch_is_registered_fact_capable_not_clean_capable():
    from pathlib import Path

    from vigil_integration.live.verdict import admit
    reg = Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "evidence-branches.json"
    row = {b["id"]: b for b in json.loads(reg.read_text())["branches"]}["oob_callback.ssti"]
    assert row["fact_capable"] is True
    assert row["clean_capable"] is False, "an OOB non-fire is not a sound CLEAN (positive-only channel)"
    assert row["oracle_version"] == "oob_callback"
    v = admit("oob_callback.ssti", fired=True, conclusive=True,
              observed={"channel_established": True, "body_semantically_available": True,
                        "gate_authorized": True})
    assert v.verdict.value == "FACT"
    # a non-firing is INCONCLUSIVE, never CLEAN (positive-only).
    v2 = admit("oob_callback.ssti", fired=False, conclusive=True,
               observed={"channel_established": True, "gate_authorized": True})
    assert v2.verdict.value == "INCONCLUSIVE"


def test_blind_ssti_probes_embed_the_callback_in_a_per_engine_construct():
    from urllib.parse import unquote

    from framework.v2.scanner.insertion import HttpRequest
    cb = "http://127.0.0.1:5555/" + "ab" * 16
    probes = _oob_probe_requests(HttpRequest, "blind_ssti", "http://127.0.0.1:9/render", cb)
    assert probes, "blind_ssti must produce runner-crafted probes"
    # the value is percent-encoded into the query; decode before asserting the callback rode intact.
    decoded = [unquote(p.url) for p in probes]
    assert all(cb in u for u in decoded), "every probe must embed VIGIL's per-finding callback verbatim"
    # the construct set spans multiple engines (not a single payload), and no probe is the raw callback alone.
    assert any("popen" in u or "Runtime" in u or "system" in u for u in decoded)


# -------------------------------------------------------------------------------- END-TO-END: mint / twins
def test_blind_ssti_mints_a_signed_fact_against_a_vulnerable_target(hermetic_root, apex_on, monkeypatch):
    _grant_active_recon(monkeypatch)
    _write_charter("ssti-mint")
    prov, kp, material = _provisioned_material("ssti-mint")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug=prov.slug,
                                   engagement_slug=prov.slug, signers=prov.signers,
                                   oob_material={**material, "bug_class": "blind_ssti"}, timeout=4.0)
    finally:
        srv.shutdown()
    assert res.n_facts == 1, res.notes
    fact = res.facts[0]
    assert fact.is_fact
    # the FACT admitted through the DEDICATED blind-SSTI branch, not the shared collector_receipt one.
    assert any(b == "oob_callback.ssti" and verdict == "FACT"
               for (b, verdict, _reason) in res.admissions), res.admissions


def test_blind_ssti_same_shape_reflecting_twin_stays_a_lead(hermetic_root, apex_on, monkeypatch):
    # THE MANDATORY SAME-SHAPE NEGATIVE CONTROL. /oobtest/reflect ECHOES the construct (reflects the template)
    # but NEVER fetches — no out-of-band interaction, so the oracle never fires and blind_ssti stays a LEAD.
    _grant_active_recon(monkeypatch)
    _write_charter("ssti-reflect")
    prov, kp, material = _provisioned_material("ssti-reflect")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/reflect", slug=prov.slug,
                                   engagement_slug=prov.slug, signers=prov.signers,
                                   oob_material={**material, "bug_class": "blind_ssti"}, timeout=3.0)
    finally:
        srv.shutdown()
    assert res.n_facts == 0, "a reflecting-but-non-executing twin must NEVER mint a FACT (same-shape control)"
    assert res.inconclusive, "no callback ⇒ INCONCLUSIVE/LEAD, never CLEAN"


def test_blind_ssti_forged_token_twin_stays_a_lead(hermetic_root, apex_on, monkeypatch):
    # /oobtest/forge fetches with a FIXED forged token (not the per-finding one) ⇒ no token-match ⇒ no FACT.
    _grant_active_recon(monkeypatch)
    _write_charter("ssti-forge")
    prov, kp, material = _provisioned_material("ssti-forge")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/forge", slug=prov.slug,
                                   engagement_slug=prov.slug, signers=prov.signers,
                                   oob_material={**material, "bug_class": "blind_ssti"}, timeout=3.0)
    finally:
        srv.shutdown()
    assert res.n_facts == 0, "a wrong/forged token can never mint a blind_ssti FACT"


def test_blind_ssti_oracle_refuses_a_wrong_token_hit_directly():
    # The class-agnostic oracle fires ONLY for a hit carrying the REGISTERED per-finding token. Hand it a
    # REAL signed hit under a DIFFERENT token (bypassing the receiver's per-token bucketing + the redrive's
    # upstream filter) and it must still refuse — the token match is the oracle's own guard, not only an
    # upstream convenience.
    import time

    from framework.v2.verify.oob import OOBHit, sign_oob_receipt
    from framework.v2.verify.oracles import oob_callback_oracle
    kp = _collector_keypair()
    now = time.time()
    hit = OOBHit(token="dead" * 8, method="GET", path="/" + "dead" * 8, received_at=now)
    hit.collector_sig = sign_oob_receipt(kp.private_key_b64, hit)   # a genuine receipt — just the wrong token
    sig = oob_callback_oracle([hit], expected_token="cafe" * 8, collector_pubkey=kp.public_key_b64,
                              issued_at=now)
    assert not sig.fired, "a hit whose token != the registered one must never fire (the oracle's token match)"


def test_blind_ssti_fact_reverifies_offline_with_pin_and_fails_closed_without(hermetic_root, apex_on, monkeypatch):
    _grant_active_recon(monkeypatch)
    _write_charter("ssti-reverify")
    prov, kp, material = _provisioned_material("ssti-reverify")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug=prov.slug,
                                   engagement_slug=prov.slug, signers=prov.signers,
                                   oob_material={**material, "bug_class": "blind_ssti"}, timeout=4.0)
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
    # a token-matched hit whose receipt is corrupted does not verify against the pin.
    corrupt = {**dict(ctx["oob_hits"][0]),
               "collector_sig": "A" * len(str(dict(ctx["oob_hits"][0]).get("collector_sig") or "A"))}
    assert not oob_callback_oracle([corrupt], ctx.get("oob_token"), collector_pubkey=pin,
                                   issued_at=ctx.get("oob_issued_at")).fired, "a corrupted receipt is refused"
    # the pinned key is OUT-OF-BAND only — it never leaks into the retained producer context.
    assert pin not in json.dumps(ctx)


# -------------------------------------------------------------------------- default-off + triple-lock #3
def test_blind_ssti_flag_off_the_governed_seam_refuses_it_as_a_non_oob_class(hermetic_root, monkeypatch):
    # With VIGIL_APEX_OOB OFF, blind_ssti is NOT an out-of-band re-drive class: oob_callback_redrive refuses it
    # before any traffic (byte-identical to a build without APEX OOB) ⇒ fail-closed LEAD.
    monkeypatch.delenv("VIGIL_APEX_OOB", raising=False)
    _grant_active_recon(monkeypatch)
    _write_charter("ssti-off")
    # Provision with the flag momentarily on so the trusted bundle builds, then turn it OFF for the re-drive.
    monkeypatch.setenv("VIGIL_APEX_OOB", "1")
    prov, kp, material = _provisioned_material("ssti-off")
    monkeypatch.delenv("VIGIL_APEX_OOB", raising=False)
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug=prov.slug,
                                   engagement_slug=prov.slug, signers=prov.signers,
                                   oob_material={**material, "bug_class": "blind_ssti"}, timeout=3.0)
    finally:
        srv.shutdown()
    assert res.n_facts == 0, "flag-off ⇒ blind_ssti is not an OOB class ⇒ no FACT (fail-closed LEAD)"
    assert any("not an OOB re-drive class" in n for n in res.notes), res.notes


def test_blind_ssti_forged_collector_key_is_refused(hermetic_root, apex_on, monkeypatch):
    # TRIPLE-LOCK #3 for blind_ssti: a collector keypair that does NOT match the owner-signed pin yields NO
    # trusted material from the feeder, so the re-drive refuses (no material, no FACT).
    from vigil_integration.live.wiring import EngineConfig, _governed_oob_material, provision_authority
    _grant_active_recon(monkeypatch)
    _write_charter("ssti-forgedkey")
    pinned = _collector_keypair()
    wrong = _collector_keypair()
    prov = provision_authority(slug="ssti-forgedkey", scope=["127.0.0.1"],
                               oob_collector_pubkey=pinned.public_key_b64)
    cfg = EngineConfig(slug="ssti-forgedkey", oob_enable=True, oob_collector_keypair=wrong)
    assert _governed_oob_material(prov, cfg) is None, "a key that does not match the owner-signed pin is refused"
