"""M-11 — the OOB-CALLBACK re-drive arm (``oob_callback_redrive``) that FEEDS ``oob_callback_oracle``.

Every control here drives a REAL loopback origin through the REAL gated send against VIGIL's OWN loopback
collector, and asserts POSITIVELY what the arm did — the examined surface, the minted/withheld FACT, the
specific refusal note — never merely that a result is falsy, so stubbing the arm to ``return None`` fails
these. VIGIL mints its OWN per-finding secret callback token, embeds it in a class-shaped probe, and the
deterministic oracle adjudicates a token-matched + independent-collector-receipt-verified interaction over
VIGIL's OWN capture (the VIGIL-native "achieved-effect", never a metasploit/sqlmap tool byte).

EMBEDDED CONTROLS:
  * POSITIVE — a VULNERABLE route that EXECUTES the embedded loopback callback (ssrf/xxe/oob_sqli/rce/…) ⇒
    ONE signed FACT that RE-VERIFIES OFFLINE with the out-of-band pin AND FAILS CLOSED without it;
  * SAFE TWIN 1 — a route that REFLECTS the token but never fetches ⇒ no interaction ⇒ no FACT (INCONCLUSIVE);
  * SAFE TWIN 2 — a route that calls back with a WRONG/FORGED token ⇒ no token-match ⇒ no FACT;
  * ORACLE CONTROLS — a wrong-token hit and a corrupted-receipt hit are refused by the oracle;
  * DNS-ONLY — a resolution-only interaction (no HTTP fetch) is INCONCLUSIVE, never a FACT;
  * REFUSAL — no trusted collector material ⇒ a recorded refusal and NO traffic (no material, no FACT);
  * the LLM-claim seam / router is fail-closed WITHOUT trusted material on the trusted spec.
"""
from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path

import pytest

pytest.importorskip("framework.v2")  # offense-leg only; skips cleanly in the keyless two-env leg


# ---------------------------------------------------------------------------------------------------
# gate isolation + charter (mirrors test_credential_acceptance_arm)
# ---------------------------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path: Path, host: str, slug: str = "alpha") -> None:
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n"
        f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _signers():
    from vigil_core import generate_keypair
    kp = generate_keypair()
    return [("gov0", kp.private_key_b64)]


def _collector_keypair():
    from vigil_core import generate_keypair
    return generate_keypair()


# ---------------------------------------------------------------------------------------------------
# the shipped benchmark app's planted /oobtest scenario + its safe twins
# ---------------------------------------------------------------------------------------------------

def _serve_benchmark():
    from framework.v2.eval.benchmark_app import BenchmarkHandler
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _drive(monkeypatch, tmp_path, path, bug_class, *, material=None, timeout=3.0):
    """Drive the REAL arm against the REAL benchmark /oobtest scenario; returns (result, base, port)."""
    from vigil_integration.live.runtime_redrive import oob_callback_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    mat = {"collector_keypair": _collector_keypair()} if material is None else material
    mat = {**mat, "bug_class": bug_class}
    try:
        res = oob_callback_redrive(f"{base}{path}", slug="alpha", engagement_slug="alpha",
                                   signers=_signers(), oob_material=mat, timeout=timeout)
        return res, base, port
    finally:
        srv.shutdown()


# ===================================================================================================
# POSITIVE: a target that EXECUTES the embedded callback mints exactly one FACT
# ===================================================================================================

def test_ssrf_that_executes_the_callback_mints_one_fact(monkeypatch, tmp_path):
    res, _b, _p = _drive(monkeypatch, tmp_path, "/oobtest/fetch", "ssrf")
    assert res.surfaces.get("ssrf"), "the arm examined NO surface — it was stubbed, not run"
    assert res.n_facts == 1, f"expected exactly one OOB FACT, got {res.n_facts}; notes={res.notes}"
    assert res.facts[0].is_fact
    from vigil_integration.live.runtime_redrive import _OOB_BRANCH
    assert any(v == "FACT" and b == _OOB_BRANCH for (b, v, _r) in res.admissions), res.admissions
    assert res.family_verdict("ssrf") == "FACT"


@pytest.mark.parametrize("path,bug_class", [
    ("/oobtest/fetch", "oob_sqli"),
    ("/oobtest/fetch", "rce"),
    ("/oobtest/fetch", "command_injection"),
    ("/oobtest/fetch", "xxe"),
    ("/oobtest/fetch", "blind_xxe"),
    ("/oobtest/fetch", "deserialization"),
])
def test_each_oob_class_mints_a_fact_against_the_vulnerable_route(monkeypatch, tmp_path, path, bug_class):
    res, _b, _p = _drive(monkeypatch, tmp_path, path, bug_class)
    assert res.n_facts == 1, f"{bug_class}: expected one OOB FACT, got {res.n_facts}; notes={res.notes}"
    assert res.family_verdict(bug_class) == "FACT"


def test_the_minted_fact_re_verifies_offline_with_the_pin_and_fails_closed_without_it(monkeypatch, tmp_path):
    mat = {"collector_keypair": _collector_keypair()}
    res, _b, _p = _drive(monkeypatch, tmp_path, "/oobtest/fetch", "ssrf", material=mat)
    assert res.n_facts == 1, res.notes
    ctx = res.contexts[res.facts[0].finding_ref]
    pin = mat["collector_keypair"].public_key_b64
    from framework.v2.verify.oracles import oob_callback_oracle
    # WITH the OUT-OF-BAND pin (from the signed authority) → the retained record re-fires offline.
    again = oob_callback_oracle(ctx["oob_hits"], ctx.get("oob_token"), collector_pubkey=pin,
                                issued_at=ctx.get("oob_issued_at"))
    assert again.fired, "the retained record did not re-fire the oracle offline WITH the pin"
    # WITHOUT the pin → a receipt-bearing hit FAILS CLOSED (no pin to verify), never a silent token-only fire.
    nopin = oob_callback_oracle(ctx["oob_hits"], ctx.get("oob_token"), collector_pubkey=None,
                                issued_at=ctx.get("oob_issued_at"))
    assert not nopin.fired, "a receipt-bearing OOB FACT must FAIL CLOSED offline without the pinned key"


def test_the_pinned_collector_key_is_not_in_the_retained_context(monkeypatch, tmp_path):
    mat = {"collector_keypair": _collector_keypair()}
    res, _b, _p = _drive(monkeypatch, tmp_path, "/oobtest/fetch", "ssrf", material=mat)
    assert res.n_facts == 1, res.notes
    blob = json.dumps(res.contexts[res.facts[0].finding_ref])
    assert mat["collector_keypair"].public_key_b64 not in blob, (
        "the pinned collector key LEAKED into the producer context — it must be out-of-band only")
    assert mat["collector_keypair"].private_key_b64 not in blob


# ===================================================================================================
# SAFE TWINS: the arm must NEVER flag these
# ===================================================================================================

def test_a_reflected_but_unexecuted_token_mints_nothing(monkeypatch, tmp_path):
    # SAFE TWIN 1 — the route ECHOES the callback but never fetches it: no out-of-band interaction occurs.
    res, _b, _p = _drive(monkeypatch, tmp_path, "/oobtest/reflect", "ssrf", timeout=1.5)
    assert res.surfaces.get("ssrf"), "the arm must still RUN (examine the surface) and conclude INCONCLUSIVE"
    assert res.n_facts == 0, f"a reflected-not-executed token must mint NOTHING, got {res.n_facts}"
    assert any("no token-matched" in n for n in res.notes), res.notes
    assert res.family_verdict("ssrf") != "FACT"


def test_a_forged_token_callback_mints_nothing(monkeypatch, tmp_path):
    # SAFE TWIN 2 — the route calls back with a FIXED FORGED token, not the per-finding registered one.
    res, _b, _p = _drive(monkeypatch, tmp_path, "/oobtest/forge", "ssrf", timeout=1.5)
    assert res.surfaces.get("ssrf"), "the arm must still RUN and conclude INCONCLUSIVE"
    assert res.n_facts == 0, f"a forged-token callback must mint NOTHING, got {res.n_facts}"
    assert res.family_verdict("ssrf") != "FACT"


# ===================================================================================================
# ORACLE-LEVEL CONTROLS: a wrong token / a corrupted receipt are refused (over a GENUINE minted record)
# ===================================================================================================

def test_oracle_refuses_a_wrong_token_and_a_corrupted_receipt(monkeypatch, tmp_path):
    mat = {"collector_keypair": _collector_keypair()}
    res, _b, _p = _drive(monkeypatch, tmp_path, "/oobtest/fetch", "ssrf", material=mat)
    assert res.n_facts == 1, res.notes
    ctx = res.contexts[res.facts[0].finding_ref]
    pin = mat["collector_keypair"].public_key_b64
    from framework.v2.verify.oracles import oob_callback_oracle
    hit = dict(ctx["oob_hits"][0])
    # a hit that carries a DIFFERENT token than the registered one is not a callback for THIS finding.
    wrong = {**hit, "token": "deadbeef" * 4}
    assert not oob_callback_oracle([wrong], ctx.get("oob_token"), collector_pubkey=pin,
                                   issued_at=ctx.get("oob_issued_at")).fired
    # a token-matched hit whose collector receipt does NOT verify against the pin is refused (SIGNATURE_INVALID).
    corrupt = {**hit, "collector_sig": ("A" * len(str(hit.get("collector_sig") or "A")))}
    assert not oob_callback_oracle([corrupt], ctx.get("oob_token"), collector_pubkey=pin,
                                   issued_at=ctx.get("oob_issued_at")).fired


def test_a_dns_only_interaction_is_inconclusive_never_a_fact(monkeypatch, tmp_path):
    # Force the collector to report ONLY a DNS-method interaction (resolution reached us, no HTTP fetch). The
    # HTTP-collector arm must treat that as INCONCLUSIVE — a strictly weaker claim it does not mint.
    from vigil_integration.live import runtime_redrive as rr
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve_benchmark()
    port = srv.server_address[1]

    def _dns_only(_receiver, token, _deadline):
        class _H:
            def __init__(self, tok):
                self.token = tok
                self.method = "DNS"
                self.path = f"/{tok}"
                self.client_ip = "127.0.0.1"
                self.received_at = 0.0
                self.collector_sig = ""
        return [_H(token)]

    monkeypatch.setattr(rr, "_oob_poll_matched", _dns_only)
    try:
        res = rr.oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug="alpha",
                                      engagement_slug="alpha", signers=_signers(),
                                      oob_material={"collector_keypair": _collector_keypair(), "bug_class": "ssrf"},
                                      timeout=2.0)
    finally:
        srv.shutdown()
    assert res.n_facts == 0, "a DNS-only interaction must NOT mint a FACT"
    assert any("DNS-resolution" in n for n in res.notes), res.notes


# ===================================================================================================
# REFUSALS: fail-closed before any traffic without the trusted collector material
# ===================================================================================================

def test_refuses_without_trusted_material(monkeypatch, tmp_path):
    from vigil_integration.live.runtime_redrive import oob_callback_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = oob_callback_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug="alpha",
                                   engagement_slug="alpha", signers=_signers(),
                                   oob_material={"bug_class": "ssrf"}, timeout=2.0)   # NO collector_keypair
    finally:
        srv.shutdown()
    assert res.n_facts == 0
    assert not res.surfaces.get("ssrf"), "a no-material refusal must happen BEFORE any traffic (no surface)"
    assert any("no trusted OOB collector material" in n for n in res.notes), res.notes


def test_the_generic_runtime_redrive_delegation_is_inert_without_material(monkeypatch, tmp_path):
    from vigil_integration.live.runtime_redrive import runtime_redrive
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    srv = _serve_benchmark()
    port = srv.server_address[1]
    try:
        res = runtime_redrive(f"http://127.0.0.1:{port}/oobtest/fetch", slug="alpha", engagement_slug="alpha",
                              signers=_signers(), claimed_class="ssrf")
    finally:
        srv.shutdown()
    assert res.bug_class == "ssrf"
    assert res.n_facts == 0
    assert any("no trusted OOB collector material" in n for n in res.notes), res.notes


# ===================================================================================================
# REGISTRATION + ADMISSION: the branch is registered FACT-capable and demotion/minting is correct
# ===================================================================================================

def test_the_branch_is_registered_fact_capable_and_dispatched():
    from vigil_integration.live.runtime_redrive import OOB_REDRIVE_CLASSES, _OOB_BRANCH
    from vigil_integration.live.tool_manifest import load_branch_registry
    from vigil_integration.live.verdict import admit

    assert set(OOB_REDRIVE_CLASSES) == {"ssrf", "blind_xxe", "xxe", "rce", "command_injection",
                                        "deserialization", "oob_sqli"}
    reg = {b["id"]: b for b in load_branch_registry(
        Path(__file__).resolve().parents[2] / "docs" / "capability-matrix" / "evidence-branches.json")}
    row = reg[_OOB_BRANCH]
    assert row["fact_capable"] is True
    assert row["clean_capable"] is False, "an OOB non-fire is not a sound CLEAN (positive-only channel)"
    assert row["oracle_version"] == "oob_callback"

    v_fact = admit(_OOB_BRANCH, fired=True, conclusive=True,
                   observed={"channel_established": True, "body_semantically_available": True,
                             "gate_authorized": True})
    assert v_fact.verdict.value == "FACT"
    v_non = admit(_OOB_BRANCH, fired=False, conclusive=False,
                  observed={"channel_established": True, "body_semantically_available": True,
                            "gate_authorized": True})
    assert v_non.verdict.value == "INCONCLUSIVE"


def test_the_oob_classes_stay_lead_only_in_the_redrive_branch_fallback():
    # the LEAD-fallback _redrive_branch_for MUST omit the oob classes: an OOB claim with no trusted material
    # has no registered branch there and stays a LEAD (never routed to a FACT-capable admit).
    from vigil_integration.live.wiring import _redrive_branch_for
    for c in ("ssrf", "blind_xxe", "xxe", "rce", "command_injection", "deserialization", "oob_sqli"):
        assert _redrive_branch_for(c) is None, f"{c} must NOT map to a FACT branch in the LEAD fallback"


# ===================================================================================================
# SEAM / ROUTER: the trusted material never comes from the model
# ===================================================================================================

def test_the_live_seam_is_fail_closed_without_trusted_material():
    from vigil_integration.live.wiring import _live_oob_redrive_fact

    class _Prov:
        slug = "alpha"
        signers = _signers()

    # a spec with NO oob_material (the LLM-claim path) ⇒ None (LEAD, fail-closed)
    spec = {"kind": "oob", "url": "http://127.0.0.1:1/x", "bug_class": "ssrf"}
    assert _live_oob_redrive_fact(_Prov(), {"bug_class": "ssrf"}, spec) is None
    # a wrong-class spec ⇒ None
    assert _live_oob_redrive_fact(_Prov(), {}, {"url": "http://x/", "oob_material": {"collector_keypair": object()},
                                                "bug_class": "xss"}) is None
    # no redrive spec at all ⇒ None
    assert _live_oob_redrive_fact(_Prov(), {}, None) is None


def test_the_redrive_spec_router_never_sources_material_from_the_model():
    import inspect

    from vigil_integration.live import engine
    src = ""
    for _n, obj in vars(engine).items():
        if isinstance(obj, type) and "_redrive_spec" in vars(obj):
            src = inspect.getsource(obj._redrive_spec)
            break
    assert '"kind": "oob"' in src, "the router must emit an oob spec kind"
    # the oob branch of the router returns only class+url (no material/token/pin/window sourced here)
    tail = src.split('"kind": "oob"')[1][:200]
    for forbidden in ("oob_material", "collector", "token", "not_before", "pubkey"):
        assert forbidden not in tail, f"the router must NOT source {forbidden!r} (triple-lock: no trusted material)"


# ===================================================================================================
# STRIX RAIL: the OOB arm is on the rail + screened in by the sink, and is LEAD-only (a report carries
# no trusted collector material, so it can never mint from the Strix narrative)
# ===================================================================================================

def test_the_oob_arm_is_on_the_strix_rail_and_is_lead_only(monkeypatch, tmp_path):
    from vigil_integration.proof import run, sink

    classifiers = {c for c, _d, _n in run._REDRIVE_ARMS}
    assert run._oob_redrive_class in classifiers, "the OOB arm is not on the Strix re-drive rail"
    for classify, _drive, requires_no_capture in run._REDRIVE_ARMS:
        if classify is run._oob_redrive_class:
            assert requires_no_capture is True, "a capture-bearing report must stay on the executor path"
    # the sink screens an OOB-class report in (and a non-OOB report out)
    assert sink._oob_redrivable({"bug_class": "ssrf"}) is True
    assert sink._oob_redrivable({"cwe": "CWE-918"}) is True
    assert sink._oob_redrivable({"bug_class": "deserialization"}) is True
    assert sink._oob_redrivable({"bug_class": "xss"}) is False

    # LEAD-ONLY: the Strix driver consults the governed arm WITHOUT trusted collector material (a report
    # carries none) ⇒ the arm refuses ⇒ no FACT. The Strix report's narrative is NEVER proof.
    _grant_active_recon(monkeypatch)
    _charter(tmp_path, "127.0.0.1")
    report = {"bug_class": "ssrf", "endpoint": "http://127.0.0.1:9/x"}
    res = run._oob_redrive(report, "ssrf", run_dir=str(tmp_path), signers=_signers(), engagement_slug="alpha")
    assert not getattr(res, "is_fact", False), "a Strix OOB report must NEVER mint a FACT (LEAD-only rail)"
