"""VF-1a — the `vigil remediate --prove` native verb: the four-state LIVE remediation proof, end-to-end.

This drives ``_cmd_remediate`` (via the real argparse) against the SAME genuine stdlib loopback target pattern
as test_live_adapter.py, over a PROVENANCE-GROUNDED finding rebuilt from the engagement's OWN signed spine +
its retained re-verifiable proof material (the original firing oracle_context = the positive control). It
produces every state by toggling the server / target:

  * PATCHED server  → REMEDIATED, and the written prove-certificate independently verifies (exit 0).
  * VULNERABLE server → STILL_VULNERABLE (the live oracle fires over FRESH evidence).
  * out-of-scope --target-base-url → REFUSED (the charter scope gate refuses; testing must not begin).
  * missing --prove → a non-zero, honest refusal (downgrade resistance — no silent weaker mode).

Gating mirrors test_live_adapter: a hermetic signed charter (127.0.0.1 in scope) + framework path helpers
pointed at a tmp tree admit the loopback fetch. Needs framework (reverify + translator + HttpExecutor) →
PYTHONPATH=integration:engine/crucible:gateway.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify.confirmation", reason="CRUCIBLE (offense) not importable here")

from framework.v2.common import paths as _paths  # noqa: E402

from vigil_integration.cli import build_parser  # noqa: E402
from vigil_integration.remediation.prove_driver import verify_prove_certificate  # noqa: E402

SLUG = "remediate-cli"
FACT_REF = "f-errsqli"
BUG = "error_based_sqli"
_ORIG_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near '' at line 1"


# --------------------------------------------------------------------------------------------------------
# The retained ORIGINAL firing oracle_context (the positive control) + the reconstructable exploit request.
# --------------------------------------------------------------------------------------------------------
def _error_context(body: bytes) -> dict:
    from framework.v2.evidence.poc import CapturedExchange
    from framework.v2.verify.poc_translate import context_from_exchanges
    ex = CapturedExchange(channel="error_signature", role="mutated", response_bytes_ref="resp")
    ctx = context_from_exchanges([ex], bug_class=BUG, resolve=lambda _r: body)
    assert ctx is not None
    return ctx.model_dump(mode="json")


# --------------------------------------------------------------------------------------------------------
# A genuine loopback HTTP target (stdlib only — mirrors test_live_adapter's _Handler/_Server).
# --------------------------------------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler contract
        srv = self.server
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        exploit_present = any(v for v in q.get("q", []))
        nonce = (q.get("rc") or [""])[0]
        if (not srv.patched) and exploit_present:
            body = "HTTP 500 Internal Server Error\nYou have an error in your SQL syntax near '' at line 1\n"
        else:
            body = '{"results": [], "ok": true}\n'
        if nonce:
            body += f"\n<!-- vigil-echo:{nonce} -->\n"
        raw = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(*, patched: bool) -> _Server:
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.patched = patched  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --------------------------------------------------------------------------------------------------------
# hermetic CRUCIBLE paths — a signed charter so the HttpExecutor scope gate ADMITS loopback (127.0.0.1).
# --------------------------------------------------------------------------------------------------------
_CHARTER = """\
# Engagement charter — `{slug}`

**Status:** Final

## 1. Operator attestation

Signed: `tester`     Date: `2026-05-04`

## 2. In-scope systems

| Host / Surface | Notes | Auth |
|----------------|-------|------|
| `127.0.0.1` | Loopback test app | Yes |

## 3. Out of scope

- Anything not listed above.

## 7. Posture

- [x] **TEST**
- [ ] **AUDIT**
- [ ] **EMULATE**
"""


def _seed_spine(base: Path) -> None:
    """Write a real {SLUG}.spine under `base` holding ONE confirmed fact (the STABLE spine key
    finding_from_spine will re-load). Mirrors test_trusted_finding._seed_spine."""
    from vigil_core.vault import Vault

    from vigil_integration.agent.state import AgentState, Finding
    from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from vigil_integration.live.spine_vigilcore import VigilCoreSpine
    base.mkdir(parents=True, exist_ok=True)
    kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=Vault(base / "vault"))
    spine = VigilCoreSpine(kp, str(base / f"{SLUG}.spine"))
    st = AgentState(engagement_slug=SLUG, iteration=1)
    st.record_fact(Finding(ref=FACT_REF, bug_class=BUG, title="error-based SQLi", severity="high"),
                   evidence_ref="cert:evi-errsqli")
    spine.write_state(st, seq=1)


def _write_reverifiable(base: Path) -> None:
    """Persist the run's reverifiable.json: ONE entry whose oracle_context is the retained ORIGINAL firing
    bytes (the positive control) and which carries the reconstructable exploit request (payload_param /
    request_payload) + the confirmed channel + insertion point. This is the SAME plain-dict shape the live
    proof pipeline persists (proof.run._persist_reverifiable)."""
    octx = _error_context(_ORIG_SQL_ERROR)
    octx["payload_param"] = "q"                 # the named insertion point (rides on the certificate)
    octx["request_payload"] = "x' OR '1'='1"    # the retained decoded exploit value
    entry = {
        "check_id": FACT_REF,
        "bug_class": BUG,
        "channel": "error_signature",
        "insertion_point": "/search",           # the reconstructable endpoint (path-like)
        "confirmed_by": "error_signature",
        "confidence": 0.9,
        "action_id": "poc-errsqli",
        "oracle_context": octx,
    }
    proofs = base / "proofs"
    proofs.mkdir(parents=True, exist_ok=True)
    (proofs / "reverifiable.json").write_text(
        json.dumps({"active_findings": [entry]}, sort_keys=True), encoding="utf-8")


@pytest.fixture()
def gated_home(tmp_path, monkeypatch):
    """A ready engagement home: hermetic signed charter (127.0.0.1 in scope), a seeded signed spine with one
    confirmed fact, and the retained reverifiable proof material. Returns the base dir the CLI reads/writes."""
    targets = tmp_path / "targets"
    (targets / SLUG).mkdir(parents=True)
    (targets / SLUG / "charter.md").write_text(_CHARTER.format(slug=SLUG), encoding="utf-8")
    authdir = tmp_path / "authority"
    authdir.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    monkeypatch.setattr(_paths, "authority_path", lambda s: authdir / f"{s}.authority.json")
    base = tmp_path / "home"
    _seed_spine(base)
    _write_reverifiable(base)
    return base


def _remediate(argv, capsys):
    args = build_parser().parse_args(["remediate", *argv])
    rc = args.func(args)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


# ============================ the four states, live ============================
def test_patched_target_is_remediated_and_cert_verifies(gated_home, capsys):
    srv = _start(patched=True)
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        rc, out, err = _remediate(
            ["--prove", "--from-spine", SLUG, "--base-dir", str(gated_home),
             "--target-base-url", base_url], capsys)
    finally:
        srv.shutdown(); srv.server_close()
    assert rc == 0, (rc, out, err)
    assert "STATE             : REMEDIATED" in out
    assert "re-verify         : OK" in out
    # the cert was written and independently re-verifies (cross-bound + embedded re-executes).
    cert_path = gated_home / "proofs" / f"remediation-prove-{FACT_REF}.json"
    assert cert_path.is_file()
    cert = json.loads(cert_path.read_text(encoding="utf-8"))
    # the signer key_id → pubkey is the provisioned STABLE governance key persisted under --base-dir.
    key_id = cert["signer"]["key_id"]
    from vigil_integration.live.governance_identity import (
        DEFAULT_GOVERNANCE_KEY_FILE, load_or_create_governance_keypair)
    from vigil_core.vault import Vault
    kp = load_or_create_governance_keypair(
        path=str(gated_home / DEFAULT_GOVERNANCE_KEY_FILE), vault=Vault(gated_home / "vault"))
    ok, reason = verify_prove_certificate(cert, signer_pubkeys={key_id: kp.public_key_b64})
    assert ok, reason
    assert cert["state"] == "REMEDIATED" and cert["evidence"]["embedded_remediation_cert"] is not None


def test_vulnerable_target_is_still_vulnerable(gated_home, capsys):
    srv = _start(patched=False)
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        rc, out, err = _remediate(
            ["--prove", "--from-spine", SLUG, "--base-dir", str(gated_home),
             "--target-base-url", base_url], capsys)
    finally:
        srv.shutdown(); srv.server_close()
    assert rc != 0, (rc, out, err)
    assert "STATE             : STILL_VULNERABLE" in out
    assert "oracle_fired" in out or "reason_code       : oracle_fired_over_fresh_evidence" in out


def test_out_of_scope_target_is_refused(gated_home, capsys):
    # A target host NOT in the signed charter scope: the executor's scope gate refuses BEFORE any I/O, so the
    # identity sample cannot be taken — testing must not begin → REFUSED (fail-closed).
    rc, out, err = _remediate(
        ["--prove", "--from-spine", SLUG, "--base-dir", str(gated_home),
         "--target-base-url", "http://out-of-scope.example/"], capsys)
    assert rc != 0, (rc, out, err)
    assert "STATE             : REFUSED" in out


def test_missing_prove_flag_refuses_honestly(gated_home, capsys):
    # Downgrade resistance: without --prove there is no weaker mode — refuse non-zero with an honest message.
    rc, out, err = _remediate(
        ["--from-spine", SLUG, "--base-dir", str(gated_home),
         "--target-base-url", "http://127.0.0.1:1/"], capsys)
    assert rc != 0
    assert "only --prove mode is supported" in err
    # nothing "fixed" was printed
    assert "REMEDIATED" not in out


def test_no_source_is_refused(gated_home, capsys):
    # mirrors `vigil patch`: EXACTLY ONE trusted finding source; a raw-JSON finding is never accepted.
    rc, out, err = _remediate(["--prove", "--target-base-url", "http://127.0.0.1:1/"], capsys)
    assert rc != 0
    assert "EXACTLY ONE trusted finding source" in err


def test_insufficient_retained_data_errors_honestly(gated_home, capsys):
    # Strip the retained exploit value from the reverifiable entry: the exploit request cannot be honestly
    # reconstructed → an honest error, no fabrication (fail-closed).
    rev = gated_home / "proofs" / "reverifiable.json"
    doc = json.loads(rev.read_text(encoding="utf-8"))
    doc["active_findings"][0]["oracle_context"].pop("request_payload", None)
    rev.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    rc, out, err = _remediate(
        ["--prove", "--from-spine", SLUG, "--base-dir", str(gated_home),
         "--target-base-url", "http://127.0.0.1:1/"], capsys)
    assert rc != 0
    assert "insufficient to reconstruct the exploit request" in err


# ============================ BLOCK regression: never substitute another finding's positive control ==========
def test_match_entry_refuses_a_mismatched_sole_entry():
    # the single-entry fallback must NEVER override a KNOWN finding ref (else finding A's REMEDIATED could be
    # minted from finding B's retained control). A known ref + a sole entry with a different check_id → None.
    from vigil_integration.cli import _match_reverifiable_entry
    entries = [{"check_id": "f-OTHER", "oracle_context": {"error_observed": "x"}}]
    assert _match_reverifiable_entry(entries, "f-errsqli", "") is None          # ref known via finding.ref
    assert _match_reverifiable_entry(entries, "", "f-errsqli") is None          # ref known via --finding-ref
    assert _match_reverifiable_entry(entries, "f-OTHER", "") == entries[0]      # an exact match is admitted
    assert _match_reverifiable_entry(entries, "", "") == entries[0]             # no ref known → sole-entry ok


def test_empty_ref_finding_is_refused(tmp_path, monkeypatch, capsys):
    # A confirmed fact with an EMPTY ref is un-addressable: `want` would be empty and the sole-entry fallback
    # could substitute another finding's control. The CLI must refuse before that (the enforced invariant that
    # makes _match_reverifiable_entry's docstring true), minting nothing.
    from vigil_core.vault import Vault
    from vigil_integration.agent.state import AgentState, Finding
    from vigil_integration.live.spine_identity import DEFAULT_SPINE_KEY_FILE, load_or_create_spine_keypair
    from vigil_integration.live.spine_vigilcore import VigilCoreSpine
    targets = tmp_path / "targets"; (targets / SLUG).mkdir(parents=True)
    (targets / SLUG / "charter.md").write_text(_CHARTER.format(slug=SLUG), encoding="utf-8")
    authdir = tmp_path / "authority"; authdir.mkdir()
    monkeypatch.setattr(_paths, "target_dir", lambda s: targets / s)
    monkeypatch.setattr(_paths, "charter_path", lambda s: targets / s / "charter.md")
    monkeypatch.setattr(_paths, "killswitch_path", lambda s: targets / s / ".halt")
    monkeypatch.setattr(_paths, "authority_path", lambda s: authdir / f"{s}.authority.json")
    base = tmp_path / "home"; base.mkdir(parents=True)
    kp = load_or_create_spine_keypair(path=str(base / DEFAULT_SPINE_KEY_FILE), vault=Vault(base / "vault"))
    spine = VigilCoreSpine(kp, str(base / f"{SLUG}.spine"))
    st = AgentState(engagement_slug=SLUG, iteration=1)
    st.record_fact(Finding(ref="", bug_class=BUG, title="empty-ref fact", severity="high"),
                   evidence_ref="cert:evi-x")   # a signed fact with NO addressable ref
    spine.write_state(st, seq=1)
    _write_reverifiable(base)
    doc = json.loads((base / "proofs" / "reverifiable.json").read_text(encoding="utf-8"))
    doc["active_findings"][0]["check_id"] = "f-A-DIFFERENT-FINDING"   # sole entry belongs to ANOTHER finding
    (base / "proofs" / "reverifiable.json").write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    rc, out, err = _remediate(
        ["--prove", "--from-spine", SLUG, "--base-dir", str(base), "--target-base-url", "http://127.0.0.1:1/"],
        capsys)
    assert rc != 0, (rc, out, err)
    assert "no addressable ref" in err and "REMEDIATED" not in out


def test_cross_finding_control_is_refused_end_to_end(gated_home, capsys):
    # The spine's confirmed fact is FACT_REF, but the SOLE reverifiable entry belongs to a DIFFERENT finding.
    # The CLI must REFUSE (no retained material for THIS finding) and mint NOTHING — not a false REMEDIATED
    # from another finding's positive control + exploit.
    rev = gated_home / "proofs" / "reverifiable.json"
    doc = json.loads(rev.read_text(encoding="utf-8"))
    doc["active_findings"][0]["check_id"] = "f-DIFFERENT-FINDING"
    rev.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    srv = _start(patched=True)
    base_url = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        rc, out, err = _remediate(
            ["--prove", "--from-spine", SLUG, "--finding-ref", FACT_REF, "--base-dir", str(gated_home),
             "--target-base-url", base_url], capsys)
    finally:
        srv.shutdown(); srv.server_close()
    assert rc != 0, (rc, out, err)
    assert "no retained re-verifiable proof material" in err
    assert "REMEDIATED" not in out
    assert not (gated_home / "proofs" / f"remediation-prove-{FACT_REF}.json").is_file()
