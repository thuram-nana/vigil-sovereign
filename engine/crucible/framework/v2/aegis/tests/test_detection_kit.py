"""AEGIS AS-10c (detection-content KIT — supply-chain packaging attestation over CRS + Sigma) — deterministic,
offline acceptance tests.

AS-10c is the SUPPLY-CHAIN gate for a SHIPPABLE detection kit: the CRS-derived + Sigma-derived rules a tenant pushes
to customers (the ``pushed-rules`` bundle). It composes, by relative import, three merged slices and re-implements
none of them: the AS-7a §7 licence gate (is the DISTRIBUTION bundle licence-admitted?), the AS-7b CRS corpus pin +
address-free normalize/admit primitives, and the AS-17a Sigma rules (identity + deployability). It mints a Sigma
corpus pin in AS-7b's AS-28 style and BINDS both corpus pins + the licence-ledger digest + the kit identity into one
``kit_digest`` seal. ``admissible = licensed AND crs_pinned AND sigma_pinned``; a kit hit's refs are admitted as
LEADS only over an admissible kit, else DROPPED (fail closed). It is not a detector, so DoD-1's "detector near-zero-
FP" is N/A — substituted by attestation-correctness vs a hand-computed expectation + a byte-identity negative
control. The DoD points, mapped to the sections below:

  (1) e2e behavioral — a configured gateway with the flag ON (and a kit) surfaces the attestation on the AS-5c probe
      snapshot, computed from the shipped §7 ledger + the two corpus pins, end-to-end through the gateway.
  (2) gate-invariance — importing aegis leaves verify.verifier._ALL_ORACLES at exactly 15 (AS-10c adds NO
      OracleKind); detection_kit.py (and coraza_source / license_gate / defender.sigma, through it) is NOT import-
      reachable from aegis/__init__ or framework.v2.__main__; gateway.KIT_ENV is in lockstep.
  (3) FATAL-2 — detection_kit.py imports ONLY the stdlib (reaching the AS-7a license_gate, the AS-7b coraza_source,
      and the AS-17a defender.sigma by RELATIVE import); never sigil/governor/strix/apps/vigil_core/pydantic/yaml.
  (4) determinism — identical corpora + ledger yield a byte-identical Sigma pin, kit digest and summary; no wall-
      clock, no RNG.
  (5) default-OFF + byte-identity — VIGIL_AEGIS_KIT off (or NO kit configured) => NO meter active, nothing computed,
      and the probe snapshot is byte-identical (no kit keys); the flag is strict/fail-closed.
  (6) correctness + negative controls — the Sigma pin and the kit digest match a hand-computed digest; licensed /
      crs_pinned / sigma_pinned / admissible track the §7 ledger + the corpora content; a drifted CRS corpus, a
      drifted Sigma corpus, a removed §7 record and a policy-denied distribution licence are each DETECTED and drop
      admission; from_rules packs ONLY DEPLOYABLE rules; admit is ADDRESS-FREE, bounded/sorted/de-duplicated, and an
      attestation is NOT a block/verdict (it never acts).
  (7) read-only — AS-10c NEVER mutates the injected ledger or the corpora, and NEVER drives an admit/shed/allow/block
      decision; only a fired oracle blocks; a kit rule_ref is a LEAD.

Everything is a pure function of its inputs; no real secret and no network beyond the loopback gateway/upstream.
"""
from __future__ import annotations

import ast
import hashlib
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from framework.v2.aegis import detection_kit as K
from framework.v2.aegis.coraza_source import CorazaCorpus
from framework.v2.aegis.detection_kit import (
    KIT_ENV,
    PUSHED_CRS_ARTEFACT,
    PUSHED_SIGMA_ARTEFACT,
    DetectionKit,
    DetectionKitAttestation,
    DetectionKitMeter,
    SigmaCorpus,
    admit_kit_leads,
    kit_digest,
    kit_enabled,
    sigma_corpus_pin,
)
from framework.v2.aegis.license_gate import LicenseRecord, load_ledger
from framework.v2.aegis.license_policy import UseMode
from framework.v2.defender.sigma import parse_sigma_rule


def _crs(rule_ids=("942100", "941110", "932160"), *, version="4.3.0", paranoia=1, expected_pin=None):
    return CorazaCorpus.build(version=version, paranoia=paranoia, rule_ids=rule_ids, expected_pin=expected_pin)


def _sigma(rule_ids=("win_proc_a", "net_conn_b"), *, version="2024.11", author="SigmaHQ contributors",
           license="DRL-1.1", nondeployable=0, expected_pin=None):
    return SigmaCorpus.build(version=version, author=author, license=license, rule_ids=rule_ids,
                             nondeployable=nondeployable, expected_pin=expected_pin)


def _kit(*, crs=None, sigma=None, name=K.KIT_NAME):
    return DetectionKit.build(crs=crs if crs is not None else _crs(),
                              sigma=sigma if sigma is not None else _sigma(), name=name)


def _shipped_ledger():
    return load_ledger()


# ==================================================================================================
# (6) Sigma corpus pin correctness — matches a hand-computed digest; order/dup invariant; moves on content change.
# ==================================================================================================
def test_sigma_corpus_pin_matches_a_hand_computed_canonical_digest():
    ids = ["net_conn_b", "win_proc_a", "win_proc_a"]  # unsorted + a duplicate
    payload = {"artefact": PUSHED_SIGMA_ARTEFACT, "version": "2024.11", "author": "SigmaHQ contributors",
               "license": "DRL-1.1", "rule_ids": ["net_conn_b", "win_proc_a"]}  # normalized: sorted + de-duplicated
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert sigma_corpus_pin("2024.11", "SigmaHQ contributors", "DRL-1.1", ids) == expect


def test_sigma_corpus_pin_is_order_and_duplicate_invariant():
    a = sigma_corpus_pin("v", "au", "DRL-1.1", ["r3", "r1", "r2"])
    b = sigma_corpus_pin("v", "au", "DRL-1.1", ["r2", "r3", "r1", "r3"])  # reordered + duplicated
    assert a == b


def test_sigma_corpus_pin_moves_when_content_version_author_or_licence_changes():
    base = sigma_corpus_pin("v", "au", "DRL-1.1", ["r1", "r2"])
    assert base != sigma_corpus_pin("v", "au", "DRL-1.1", ["r1", "r2", "r3"])   # rule added
    assert base != sigma_corpus_pin("v", "au", "DRL-1.1", ["r1"])               # rule removed
    assert base != sigma_corpus_pin("v2", "au", "DRL-1.1", ["r1", "r2"])        # version bump
    assert base != sigma_corpus_pin("v", "other", "DRL-1.1", ["r1", "r2"])      # author change (attribution)
    assert base != sigma_corpus_pin("v", "au", "Apache-2.0", ["r1", "r2"])      # licence change


def test_sigma_corpus_build_normalizes_rule_ids_and_self_pins():
    corp = _sigma(rule_ids=["r2", "r1", "r2", "bad id!"])
    assert corp.rule_ids == ("badid", "r1", "r2")                               # scrubbed, de-duplicated, sorted
    assert corp.pinned is True and corp.pin == corp.expected_pin                # self-consistent by default


# ==================================================================================================
# (6) kit digest — binds both corpus pins + the licence-ledger digest + the kit identity; moves on any change.
# ==================================================================================================
def _kit_identity(crs: CorazaCorpus, sigma: SigmaCorpus):
    return (
        {"artefact": "coreruleset-crs-4x", "version": crs.version, "paranoia": crs.paranoia, "rules": len(crs.rule_ids)},
        {"artefact": PUSHED_SIGMA_ARTEFACT, "version": sigma.version, "author": sigma.author,
         "license": sigma.license, "rules": len(sigma.rule_ids)},
    )


def test_kit_digest_matches_a_hand_computed_canonical_seal():
    crs, sigma = _crs(), _sigma()
    crs_id, sigma_id = _kit_identity(crs, sigma)
    payload = {"kit": K.KIT_NAME,
               "crs": {**crs_id, "digest": crs.pin},
               "sigma": {**sigma_id, "digest": sigma.pin},
               "ledger_digest": "LD"}
    expect = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    got = kit_digest(name=K.KIT_NAME, crs_digest=crs.pin, sigma_digest=sigma.pin, ledger_digest="LD",
                     crs=crs_id, sigma=sigma_id)
    assert got == expect


def test_kit_digest_moves_when_either_corpus_the_ledger_or_the_identity_moves():
    crs, sigma = _crs(), _sigma()
    crs_id, sigma_id = _kit_identity(crs, sigma)
    base = kit_digest(name=K.KIT_NAME, crs_digest=crs.pin, sigma_digest=sigma.pin, ledger_digest="LD",
                      crs=crs_id, sigma=sigma_id)
    assert base != kit_digest(name=K.KIT_NAME, crs_digest="deadbeef", sigma_digest=sigma.pin, ledger_digest="LD",
                              crs=crs_id, sigma=sigma_id)                         # CRS pin moved
    assert base != kit_digest(name=K.KIT_NAME, crs_digest=crs.pin, sigma_digest="deadbeef", ledger_digest="LD",
                              crs=crs_id, sigma=sigma_id)                         # Sigma pin moved
    assert base != kit_digest(name=K.KIT_NAME, crs_digest=crs.pin, sigma_digest=sigma.pin, ledger_digest="LD2",
                              crs=crs_id, sigma=sigma_id)                         # licence posture moved
    assert base != kit_digest(name="other-kit", crs_digest=crs.pin, sigma_digest=sigma.pin, ledger_digest="LD",
                              crs=crs_id, sigma=sigma_id)                         # kit identity moved


# ==================================================================================================
# (6) licensed / crs_pinned / sigma_pinned / admissible — track the §7 ledger + the corpora content.
# ==================================================================================================
def test_attestation_over_the_shipped_ledger_is_admissible():
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    assert att.licensed is True and att.crs_pinned is True and att.sigma_pinned is True and att.admissible is True
    assert att.crs_rules == 3 and att.sigma_rules == 2 and att.blocking == 0 and att.advisories >= 2
    assert len(att.kit_digest) == 64 and len(att.crs_digest) == 64 and len(att.sigma_digest) == 64
    assert att.sigma_author == "SigmaHQ contributors" and att.sigma_license == "DRL-1.1"


def test_a_drifted_crs_corpus_is_detected_and_blocks_admission():
    kit = _kit(crs=_crs(rule_ids=["942100"], expected_pin="deadbeef" * 8))
    att = DetectionKitMeter(kit, ledger=_shipped_ledger()).summary()
    assert att.licensed is True and att.crs_pinned is False and att.admissible is False


def test_a_drifted_sigma_corpus_is_detected_and_blocks_admission():
    kit = _kit(sigma=_sigma(rule_ids=["r1"], expected_pin="00" * 32))
    att = DetectionKitMeter(kit, ledger=_shipped_ledger()).summary()
    assert att.licensed is True and att.sigma_pinned is False and att.admissible is False


def test_a_missing_distribution_licence_record_is_detected_and_blocks_admission():
    """Drop the pushed-sigma-rules §7 record -> the AS-7a gate fails closed (missing_ledger_record) -> licensed=False
    -> NOT admissible, even though both corpora are self-consistently pinned."""
    ledger = [r for r in _shipped_ledger() if r.artefact != PUSHED_SIGMA_ARTEFACT]
    att = DetectionKitMeter(_kit(), ledger=ledger).summary()
    assert att.licensed is False and att.crs_pinned is True and att.sigma_pinned is True
    assert att.admissible is False and att.blocking >= 1


def test_a_policy_denied_distribution_licence_is_detected():
    """A Sigma rule set ledgered under a DENIED distribution licence (e.g. SSPL) fails the §7 policy -> licensed
    False -> not admissible. Models an unacceptable third-party rule-content licence shipped in the kit."""
    ledger = [r for r in _shipped_ledger() if r.artefact != PUSHED_SIGMA_ARTEFACT]
    ledger.append(LicenseRecord(artefact=PUSHED_SIGMA_ARTEFACT, component_kind="rule", license="SSPL-1.0",
                                use_mode=UseMode.DISTRIBUTION))
    att = DetectionKitMeter(_kit(), ledger=ledger).summary()
    assert att.licensed is False and att.admissible is False and att.blocking >= 1


# ==================================================================================================
# (6) from_rules — packs ONLY DEPLOYABLE AS-17a rules; counts the rest; derives attribution; reaches AS-17a.
# ==================================================================================================
def _rule(rid, *, author="SigmaHQ contributors", license="DRL-1.1", image="*cmd.exe"):
    doc = {"title": rid, "id": rid, "logsource": {"category": "process_creation"},
           "detection": {"sel": {"Image": image}, "condition": "sel"}, "level": "high"}
    if author:
        doc["author"] = author
    if license:
        doc["license"] = license
    return parse_sigma_rule(doc)


def test_from_rules_packs_only_deployable_rules_and_counts_the_rest():
    good1 = _rule("r-good-1")
    good2 = _rule("r-good-2")
    no_author = _rule("r-no-author", author="")                 # non-deployable: missing attribution
    assert good1.deployable and not no_author.deployable
    corp = SigmaCorpus.from_rules([good1, no_author, good2], version="2024.11")
    assert corp.rule_ids == ("r-good-1", "r-good-2")            # only deployable, normalized
    assert corp.nondeployable == 1
    assert corp.author == "SigmaHQ contributors" and corp.license == "DRL-1.1"  # derived from the rules
    assert corp.pinned is True


def test_from_rules_tolerates_non_rule_objects_and_explicit_attribution_override():
    corp = SigmaCorpus.from_rules([_rule("r1"), object(), None], version="v",  # type: ignore[list-item]
                                  author="Vendor X", license="Apache-2.0")
    assert corp.rule_ids == ("r1",) and corp.nondeployable == 2
    assert corp.author == "Vendor X" and corp.license == "Apache-2.0"           # explicit override wins


# ==================================================================================================
# (6)/(7) admit gate — refs admitted as leads ONLY over an admissible kit; never a block; address-free.
# ==================================================================================================
def test_admit_passes_refs_over_an_admissible_kit():
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    assert admit_kit_leads(["win_proc_a", "942100", "942100"], att) == ("942100", "win_proc_a")  # normalized


def test_admit_drops_refs_over_an_inadmissible_kit_fail_closed():
    kit = _kit(sigma=_sigma(rule_ids=["r1"], expected_pin="11" * 32))
    att = DetectionKitMeter(kit, ledger=_shipped_ledger()).summary()
    assert att.admissible is False
    assert admit_kit_leads(["r1", "942100"], att) == ()                        # unverified content raises NO belief


def test_admit_bounds_and_normalizes():
    from framework.v2.aegis import coraza_source as C
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    many = [str(900000 + i) for i in range(C._MAX_RULE_REFS + 20)]
    out = admit_kit_leads(many, att)
    assert len(out) == C._MAX_RULE_REFS and list(out) == sorted(out)           # bounded + sorted


def test_admit_scrubs_smuggled_request_bytes_to_safe_bounded_tokens():
    """A caller-supplied ref that carries request bytes (a URI, an injection payload, a matched-data string) is
    SCRUBBED to the safe CRS/Sigma rule-id charset and length-bounded — never surfaced verbatim."""
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    out = admit_kit_leads(["942100", "/admin?q=' OR 1=1", "Matched Data: SECRET-TOKEN in ARGS:q", "<script>"], att)
    blob = json.dumps(out)
    for leak in ("/admin?q=", "' OR 1=1", "Matched Data:", " in ARGS", "<script>"):
        assert leak not in blob                                                # raw request bytes never surface verbatim
    import re
    for tok in out:
        assert re.fullmatch(r"[0-9A-Za-z:_.-]{1,20}", tok), tok               # only scrubbed, bounded tokens


def test_admit_over_a_coraza_audit_event_never_leaks_address_or_matched_data():
    """The field-level address-free guarantee, REUSED from AS-7b: when a caller normalizes a real Coraza audit record
    with AS-7b's ``normalize_rule_refs`` and feeds the typed refs to the kit admit gate, the client address, the
    request URI and the matched ``data`` fields NEVER reach the lead surface (normalize reads only rule ids)."""
    from framework.v2.aegis.coraza_source import normalize_rule_refs
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    event = {
        "clientIp": "203.0.113.9",
        "uri": "/admin?q=' OR 1=1",
        "messages": [
            {"id": "942100", "data": "Matched Data: SECRET-TOKEN found in ARGS:q", "message": "SQLi"},
            {"ruleId": "941110", "data": "203.0.113.9 <script>"},
        ],
    }
    out = admit_kit_leads(normalize_rule_refs(event), att)
    assert out == ("941110", "942100")
    blob = json.dumps(out)
    for leak in ("203.0.113.9", "SECRET-TOKEN", "OR 1=1", "/admin", "script"):
        assert leak not in blob


def test_an_attestation_is_a_measurement_never_a_block_or_verdict():
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    blob = json.dumps(att.to_dict())
    assert "certificate" not in blob and "verdict" not in blob and "decision" not in blob and "action" not in blob


# ==================================================================================================
# (4) determinism — identical corpora + ledger yield a byte-identical pin, kit digest and summary.
# ==================================================================================================
def test_identical_inputs_yield_a_byte_identical_summary():
    ledger = _shipped_ledger()
    kit = _kit()

    def _run() -> str:
        return json.dumps(DetectionKitMeter(kit, ledger=ledger).summary().to_dict(), sort_keys=True)

    assert _run() == _run()


def test_summary_is_a_pure_typed_dataclass():
    att = DetectionKitMeter(_kit(), ledger=_shipped_ledger()).summary()
    assert isinstance(att, DetectionKitAttestation)
    assert att.crs_digest == _crs().pin and att.sigma_digest == _sigma().pin


# ==================================================================================================
# (7) READ-ONLY — the meter never mutates the injected ledger or the corpora.
# ==================================================================================================
def test_meter_never_mutates_the_injected_ledger_or_corpora():
    ledger = _shipped_ledger()
    before = [r.model_dump() for r in ledger]
    crs, sigma = _crs(), _sigma()
    before_crs = (crs.version, crs.paranoia, crs.rule_ids, crs.expected_pin)
    before_sigma = (sigma.version, sigma.author, sigma.license, sigma.rule_ids, sigma.expected_pin)
    meter = DetectionKitMeter(DetectionKit.build(crs=crs, sigma=sigma), ledger=ledger)
    for _ in range(50):
        meter.snapshot()
    assert [r.model_dump() for r in ledger] == before                         # ledger untouched
    assert (crs.version, crs.paranoia, crs.rule_ids, crs.expected_pin) == before_crs
    assert (sigma.version, sigma.author, sigma.license, sigma.rule_ids, sigma.expected_pin) == before_sigma


# ==================================================================================================
# (5) default-OFF + fail-closed flag parse.
# ==================================================================================================
def test_kit_env_flag_is_strict_fail_closed(monkeypatch):
    monkeypatch.delenv(KIT_ENV, raising=False)
    assert kit_enabled() is False
    for on in ("1", "true", "YES", "on", " On "):
        monkeypatch.setenv(KIT_ENV, on)
        assert kit_enabled() is True, on
    for off in ("0", "false", "", "nope", "2", "enable"):
        monkeypatch.setenv(KIT_ENV, off)
        assert kit_enabled() is False, off


# ==================================================================================================
# (2) gate-invariance — AS-10c adds NO OracleKind; detection_kit.py off the __init__/__main__ import path.
# ==================================================================================================
def test_importing_aegis_leaves_all_oracles_frozen_at_15():
    import framework.v2.aegis  # noqa: F401
    from framework.v2.verify import verifier as V
    assert len(V._ALL_ORACLES) == 15                                          # an attestation is a measurement, not an oracle


def test_detection_kit_not_import_reachable_from_init_or_main():
    root = Path(__file__).resolve().parents[4]                                # repo .../engine/crucible
    code = (
        "import sys;"
        "import framework.v2.aegis;"
        "import framework.v2.__main__;"
        "assert 'framework.v2.aegis.detection_kit' not in sys.modules, "
        "'detection_kit.py must be OFF the __init__/__main__ import path (make-gate byte-identity)';"
        "assert 'framework.v2.aegis.coraza_source' not in sys.modules, "
        "'coraza_source.py must stay OFF the import path (detection_kit must not drag it on eagerly)';"
        "assert 'framework.v2.aegis.license_gate' not in sys.modules, "
        "'license_gate.py must stay OFF the import path';"
        "assert 'framework.v2.defender.sigma' not in sys.modules, "
        "'defender.sigma (AS-17a) must stay OFF the import path (detection_kit must not drag it on eagerly)';"
        "print('OK')"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(root.parents[1] / "packages/core/vigil_core"),
                                         env.get("PYTHONPATH", "")])
    out = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env,
                         capture_output=True, text=True)
    assert out.returncode == 0, f"detection_kit reachable from init/main:\n{out.stdout}\n{out.stderr}"


def test_gateway_kit_env_in_lockstep_with_module():
    from framework.v2.aegis import gateway as G
    assert G.KIT_ENV == KIT_ENV == "VIGIL_AEGIS_KIT"


# ==================================================================================================
# (3) FATAL-2 — detection_kit.py imports ONLY the stdlib (reaching its deps by RELATIVE import).
# ==================================================================================================
def test_detection_kit_imports_only_stdlib_and_reaches_deps_by_relative_import():
    src = Path(K.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:            # absolute imports only
            roots.add((node.module or "").split(".")[0])
    for forbidden in ("sigil", "governor", "strix", "apps", "vigil_core", "pydantic", "yaml"):
        assert forbidden not in roots, f"detection_kit must never import {forbidden!r} (FATAL-2)"
    allowed = {"__future__", "hashlib", "json", "os", "dataclasses", "typing"}
    assert roots <= allowed, f"unexpected absolute import roots in detection_kit.py: {sorted(roots - allowed)}"
    # AS-7a (license_gate / license_policy), AS-7b (coraza_source) and AS-17a (defender.sigma) are reached by
    # RELATIVE import only (never an absolute framework.* root).
    rel = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level >= 1}
    assert "coraza_source" in rel, "detection_kit must reach the AS-7b CRS primitives by relative import"
    assert "license_gate" in rel, "detection_kit must reach the AS-7a licence gate by relative import"
    assert "defender.sigma" in rel, "detection_kit must reach the AS-17a Sigma rules by relative import"


# ==================================================================================================
# (1)/(5) gateway integration — end-to-end through the live gateway over real loopback sockets.
# ==================================================================================================
class _Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def _reply(self):
        body = b"UPSTREAM-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Upstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _run_gateway(upstream_port: int, *, detection_kit=None):
    from framework.v2.aegis.gateway import serve_gateway
    from framework.v2.aegis.models import AegisConfig
    cfg = AegisConfig(deployment_secret="k", mode="observe")
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}", config=cfg, host="127.0.0.1", port=0,
                       detection_kit=detection_kit)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _get(port: int, path: str):
    try:
        r = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)   # noqa: S310
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_gateway_kit_off_builds_no_meter_and_probe_is_byte_identical(upstream, monkeypatch):
    """DEFAULT-OFF byte-identity: VIGIL_AEGIS_KIT unset (kit configured) => NO active meter, the data path still
    forwards, and the probe snapshot carries NO kit keys."""
    monkeypatch.delenv(KIT_ENV, raising=False)
    gw, port = _run_gateway(upstream, detection_kit=_kit())
    try:
        assert gw.settings.kit_meter is None
        assert gw.settings.kit_active is False
        assert [_get(port, "/x")[0] for _ in range(3)] == [200] * 3            # data path byte-identical
        snap = gw.settings._probe_snapshot()
        assert "kit" not in snap and "kit_active" not in snap
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_kit_on_but_no_kit_is_inert(upstream, monkeypatch):
    """No kit configured => inert (mirrors AS-7b's no-corpus case): no meter, no probe keys."""
    monkeypatch.setenv(KIT_ENV, "1")
    gw, port = _run_gateway(upstream, detection_kit=None)
    try:
        assert gw.settings.kit_meter is None and gw.settings.kit_active is False
        assert "kit" not in gw.settings._probe_snapshot()
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_kit_on_surfaces_the_attestation_on_the_probe_snapshot(upstream, monkeypatch):
    """Flag ON + a kit => the probe snapshot surfaces the supply-chain attestation computed from the shipped §7
    ledger + the two corpus pins, metadata-only (counts + digests, never request bytes)."""
    monkeypatch.setenv(KIT_ENV, "1")
    gw, port = _run_gateway(upstream, detection_kit=_kit())
    try:
        assert gw.settings.kit_meter is not None and gw.settings.kit_active is True
        for _ in range(3):
            assert _get(port, "/x")[0] == 200                                 # data path forwards unchanged
        snap = gw.settings._probe_snapshot()
        assert snap["kit_active"] is True
        a = snap["kit"]
        assert a["licensed"] is True and a["crs_pinned"] is True and a["sigma_pinned"] is True
        assert a["admissible"] is True and a["crs_rules"] == 3 and a["sigma_rules"] == 2
        assert len(a["kit_digest"]) == 64 and len(a["crs_digest"]) == 64 and len(a["sigma_digest"]) == 64
        assert "127.0.0.1" not in json.dumps(snap)                            # NO raw caller/upstream address leaks
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_kit_flip_off_at_runtime_stops_surfacing_the_attestation(upstream, monkeypatch):
    """Flipping VIGIL_AEGIS_KIT OFF at runtime makes the attestation go inert live, so the probe answer drops the
    kit keys again."""
    monkeypatch.setenv(KIT_ENV, "1")
    gw, port = _run_gateway(upstream, detection_kit=_kit())
    try:
        _get(port, "/x")
        assert "kit" in gw.settings._probe_snapshot()
        monkeypatch.setenv(KIT_ENV, "0")
        assert gw.settings.kit_active is False
        assert "kit" not in gw.settings._probe_snapshot()
        monkeypatch.setenv(KIT_ENV, "1")
        assert "kit" in gw.settings._probe_snapshot()                         # restored -> surfaced again
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_probe_without_kit_is_byte_identical_whether_flag_on_or_off(upstream, monkeypatch):
    """The strongest OFF-invariance: with NO kit configured, the probe snapshot is byte-identical whether the flag is
    on or off (AS-10c never touches the data path or the probe without its configured dependency)."""
    gw, port = _run_gateway(upstream, detection_kit=None)
    try:
        monkeypatch.delenv(KIT_ENV, raising=False)
        off = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        monkeypatch.setenv(KIT_ENV, "1")
        on = json.dumps(gw.settings._probe_snapshot(), sort_keys=True)
        assert off == on
    finally:
        gw.shutdown(); gw.server_close()


def test_gateway_kit_coexists_byte_identically_with_coraza_off(upstream, monkeypatch):
    """AS-10c is independent of the AS-7b coraza surface: with the kit flag ON (kit configured) but coraza OFF (no
    corpus), the probe carries the kit attestation and NO coraza keys — the two measurers do not interfere."""
    monkeypatch.setenv(KIT_ENV, "1")
    monkeypatch.delenv("VIGIL_AEGIS_CORAZA", raising=False)
    gw, port = _run_gateway(upstream, detection_kit=_kit())
    try:
        snap = gw.settings._probe_snapshot()
        assert "kit" in snap and "coraza" not in snap
    finally:
        gw.shutdown(); gw.server_close()
