"""
Wave-A2 — the retained re-verifiable ``oracle_context`` must not store captured secrets / raw response
bytes in PLAINTEXT at rest, WITHOUT breaking offline re-verification.

Two arms retain secret-bearing material in a re-verifiable context, and both fields are LOAD-BEARING
(the deterministic oracle re-fires over them), so they are SEALED (crypto-shredding), not blind-redacted:

  * exposure secret-signature — ``observed_evidence.{secret_value, secret_assignment, body}``.
  * error-signature          — ``error_observed`` / ``error_control`` (raw response bytes).

These tests PROVE, over a really-produced ``reverifiable.json``:
  1. the plaintext secret is NOT present at rest (sealed);
  2. ``framework.v2 verify`` still re-fires the certificate offline IN-ENGAGEMENT (the local DEK);
  3. a tamper of the sealed context is rejected (fail-closed);
  4. after the DEK is crypto-shredded, verify no longer re-fires (the correct post-erasure state);
  5. a NON-secret context is left byte-identical (no seal, no ``sealed_engagement`` stamp);
  6. the client bundle still exports + re-verifies (export unseals in-engagement).

The per-test keystore is isolated by ``conftest._isolate_evidence_keys_dir``.
"""

from __future__ import annotations

import http.server
import json
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")


# ---------------------------------------------------------------------------------------------------
# isolation + charter + signers (mirrors test_runtime_redrive_soundness / test_strix_errsig_redrive)
# ---------------------------------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _grant(monkeypatch: pytest.MonkeyPatch) -> None:
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


# a leaked credential distinctive enough to grep for anywhere in the at-rest JSON.
_SECRET = "S3cr3t-Real-Prod-Key-WAVEA2"
_ENV_REAL = f"APP_ENV=production\nDB_PASSWORD={_SECRET}\nJWT_SECRET=lab-decoy\n"
_SPA_SHELL = "<!doctype html><html><body><div id=app></div></body></html>"


class _EnvApp(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = _ENV_REAL if urlsplit(self.path).path == "/.env" else _SPA_SHELL
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        return


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _produce_exposure_reverifiable(monkeypatch, tmp_path: Path, slug: str = "alpha") -> Path:
    """Drive the REAL exposure arm against a loopback .env leak and persist via the ANCHORED proof-path
    function (``_persist_runtime_reverifiable``). Returns the reverifiable.json path."""
    from vigil_integration.live.runtime_redrive import runtime_redrive
    from vigil_integration.proof.run import _persist_runtime_reverifiable, PROOFS_SUBDIR, REVERIFIABLE_NAME
    _grant(monkeypatch)
    _charter(tmp_path, "127.0.0.1", slug)
    srv = _serve(_EnvApp)
    port = srv.server_address[1]
    try:
        res = runtime_redrive(f"http://127.0.0.1:{port}/", slug=slug, engagement_slug=slug,
                              signers=_signers(), claimed_class="exposure")
    finally:
        srv.shutdown()
    assert res.n_facts == 1, f"the exposure arm did not mint a FACT; notes={res.notes!r}"
    run_dir = tmp_path / "run"
    (run_dir).mkdir(parents=True, exist_ok=True)
    _persist_runtime_reverifiable(run_dir, res, slug)
    return run_dir / PROOFS_SUBDIR / REVERIFIABLE_NAME


# ===================================================================================================
# exposure secret-signature — the secret_value / secret_assignment / body triple
# ===================================================================================================

def test_exposure_secret_is_sealed_at_rest_but_reverifies_in_engagement(monkeypatch, tmp_path):
    from framework.v2.verify import reverify
    rv = _produce_exposure_reverifiable(monkeypatch, tmp_path)
    txt = rv.read_text(encoding="utf-8")

    # (1) at rest: NO plaintext secret, and the three secret fields are sealed evs1: tokens.
    assert _SECRET not in txt, "the leaked credential is stored in PLAINTEXT at rest"
    doc = json.loads(txt)
    oe = doc["active_findings"][0]["oracle_context"]["observed_evidence"]
    for f in ("secret_value", "secret_assignment", "body"):
        assert str(oe[f]).startswith("evs1:"), f"{f} was not sealed"
    assert doc["active_findings"][0]["sealed_engagement"] == "alpha"

    # (2) offline verify re-fires IN-ENGAGEMENT (the DEK is present) — the acceptance test.
    assert reverify.main([str(rv)]) == 0, "sealed context must still re-fire offline in-engagement"


def test_exposure_tamper_of_sealed_context_is_rejected(monkeypatch, tmp_path):
    from framework.v2.verify import reverify
    rv = _produce_exposure_reverifiable(monkeypatch, tmp_path)
    doc = json.loads(rv.read_text(encoding="utf-8"))

    # flip a byte inside the sealed secret_value token → AEAD auth fails → fail-closed.
    tok = doc["active_findings"][0]["oracle_context"]["observed_evidence"]["secret_value"]
    doc["active_findings"][0]["oracle_context"]["observed_evidence"]["secret_value"] = tok[:-6] + "AAAAAA"
    tp = tmp_path / "tampered-sealed.json"
    tp.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tp)]) != 0, "a tampered sealed context must not re-verify"

    # substitute a DIFFERENT plaintext value for the sealed token (strip the seal) → oracle refuses too.
    doc2 = json.loads(rv.read_text(encoding="utf-8"))
    doc2["active_findings"][0]["oracle_context"]["observed_evidence"]["secret_value"] = "totally-different-value"
    tp2 = tmp_path / "tampered-plain.json"
    tp2.write_text(json.dumps(doc2), encoding="utf-8")
    assert reverify.main([str(tp2)]) != 0, "a substituted value must not re-verify"


def test_exposure_after_cryptoshred_the_context_no_longer_reverifies(monkeypatch, tmp_path):
    from framework.v2.common.crypto_shred import EvidenceKeyring
    from framework.v2.verify import reverify
    rv = _produce_exposure_reverifiable(monkeypatch, tmp_path)
    assert reverify.main([str(rv)]) == 0                      # recoverable before erasure

    EvidenceKeyring().shred("alpha")                          # destroy the DEK (right-to-erasure)
    assert reverify.main([str(rv)]) != 0, "after crypto-shred the sealed evidence must be unrecoverable"


# ===================================================================================================
# error-signature — raw response bytes (via the production proof mint / capture path)
# ===================================================================================================

_ERR_SECRET = "SECRET-DUMP-rowdata-XYZ789"


def _mint_errsig_reverifiable(tmp_path: Path, slug: str = "acme") -> Path:
    """Mint a real error-based-sqli FACT whose observed body carries a distinctive secret, via the
    production proof mint (executor-capture path → ``_persist_reverifiable``)."""
    from vigil_integration.proof.run import build_report_mint, PROOFS_SUBDIR, REVERIFIABLE_NAME
    try:
        from vigil_integration.proof.sink import CAPTURE_KEY
    except Exception:  # pragma: no cover
        CAPTURE_KEY = "__capture__"
    run_dir = tmp_path / "errrun"
    run_dir.mkdir(parents=True, exist_ok=True)
    mint = build_report_mint(run_dir=run_dir, signers=_signers(), engagement_slug=slug)
    report = {
        "id": "errsqli-a2", "bug_class": "error_based_sqli", "poc_script_code": "print('benign')",
        CAPTURE_KEY: {
            "exchanges": [
                {"channel": "error_signature", "role": "mutated", "response_bytes_ref": "resp",
                 "request_bytes_ref": "req", "bug_class": "error_based_sqli", "observed_scheme": "http"},
                {"channel": "error_signature", "role": "control", "response_bytes_ref": "cresp",
                 "bug_class": "error_based_sqli", "observed_scheme": "http"},
            ],
            "blobs": {
                "resp": (f"You have an error in your SQL syntax; check the manual near "
                         f"'{_ERR_SECRET}'").encode("utf-8"),
                "req": b"q=1'",
                "cresp": b"OK, clean row rendered",
            },
        },
    }
    mr = mint(report)
    assert mr is not None and getattr(mr, "is_fact", False), f"expected a signed errsig FACT; got {mr}"
    return run_dir, run_dir / PROOFS_SUBDIR / REVERIFIABLE_NAME


def test_errsig_raw_bytes_sealed_at_rest_but_reverify_and_bundle_still_work(tmp_path):
    from framework.v2.verify import reverify
    from vigil_integration.proof.bundle import export_bundle
    run_dir, rv = _mint_errsig_reverifiable(tmp_path)
    txt = rv.read_text(encoding="utf-8")

    # (1) at rest: the raw-response secret is sealed, not plaintext.
    assert _ERR_SECRET not in txt, "raw error_observed bytes stored in PLAINTEXT at rest"
    doc = json.loads(txt)
    oc = doc["active_findings"][0]["oracle_context"]
    assert str(oc["error_observed"]).startswith("evs1:"), "error_observed not sealed"
    assert doc["active_findings"][0]["sealed_engagement"] == "acme"

    # (2) offline verify re-fires in-engagement.
    assert reverify.main([str(rv)]) == 0

    # (3) the client bundle exports (unseals in-engagement) and its shipped report carries PLAINTEXT
    #     evidence a recipient can re-fire (a deliberate disclosure), while the run file stays sealed.
    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run_dir, out_dir=out, engagement_slug="acme")
    assert res["ok"], res
    shipped = json.loads((out / "reverifiable.json").read_text(encoding="utf-8"))
    assert _ERR_SECRET in json.dumps(shipped), "the client bundle must carry the evidence it re-fires over"
    assert reverify.main([str(out / "reverifiable.json")]) == 0, "shipped bundle must re-fire for a recipient"

    # (4) but the RUN's own reverifiable.json is still sealed at rest.
    assert _ERR_SECRET not in rv.read_text(encoding="utf-8")


def test_errsig_tamper_rejected(tmp_path):
    from framework.v2.verify import reverify
    _run_dir, rv = _mint_errsig_reverifiable(tmp_path)
    doc = json.loads(rv.read_text(encoding="utf-8"))
    tok = doc["active_findings"][0]["oracle_context"]["error_observed"]
    doc["active_findings"][0]["oracle_context"]["error_observed"] = tok[:-6] + "BBBBBB"
    tp = tmp_path / "tampered.json"
    tp.write_text(json.dumps(doc), encoding="utf-8")
    assert reverify.main([str(tp)]) != 0


# ===================================================================================================
# remediation loop (PCR): it re-fires the positive control via reverify_context (NOT reverify_finding),
# so the remediation consumers must unseal BEFORE the re-fire. This is the red-pen BLOCKER.
# ===================================================================================================

def _errsig_entry(tmp_path: Path) -> dict:
    from vigil_integration.proof.run import read_reverifiable
    run_dir, _rv = _mint_errsig_reverifiable(tmp_path)
    entries = read_reverifiable(run_dir).get("active_findings", [])
    assert entries, "the mint must persist a re-verifiable entry"
    return entries[0]


def test_remediation_positive_control_refires_over_a_sealed_context(tmp_path):
    """The prove_driver positive control (`_fires` -> reverify_context) and the cli extraction helper.
    Pins the BLOCKER: a SEALED context does NOT re-fire via reverify_context; after the remediation
    consumer unseals it in-engagement, the positive control RE-FIRES."""
    from vigil_integration.remediation.prove_driver import _fires
    from vigil_integration.cli import _unseal_entry_context_or_none
    entry = _errsig_entry(tmp_path)
    bug_class = entry["bug_class"]
    assert entry.get("sealed_engagement") == "acme"

    # (1) the exact bug: the SEALED retained context does NOT re-fire the positive control.
    assert _fires(dict(entry["oracle_context"]), bug_class, "rem") is False

    # (2) the fix: the remediation consumer unseals in-engagement (DEK present) -> the control RE-FIRES.
    unsealed = _unseal_entry_context_or_none(entry)
    assert unsealed is not None
    assert "sealed_engagement" not in unsealed, "the unsealed entry must be an honest plaintext entry"
    assert _fires(dict(unsealed["oracle_context"]), bug_class, "rem") is True


def test_remediation_control_fail_closes_after_cryptoshred(tmp_path):
    """After the DEK is crypto-shredded the remediation consumer cannot recover the positive control:
    the unseal helper returns None (so the cli's 'no retained firing oracle_context' refusal fires)."""
    from framework.v2.common.crypto_shred import EvidenceKeyring
    from vigil_integration.cli import _unseal_entry_context_or_none
    entry = _errsig_entry(tmp_path)
    assert _unseal_entry_context_or_none(entry) is not None      # recoverable before erasure

    EvidenceKeyring().shred("acme")
    assert _unseal_entry_context_or_none(entry) is None, "a crypto-shredded control must fail closed"


def test_audit_package_unseals_and_stays_verifiable(tmp_path):
    """`evidence build_audit_package` over a SEALED proof-path entry unseals in-engagement so the minted
    cert binds plaintext and the shipped package re-verifies + reproduces; the plaintext lands only in the
    deliberately-disclosed package, not the run's sealed reverifiable.json."""
    from framework.v2.evidence.audit_package import build_audit_package
    from framework.v2.evidence.certify import verify_certificate
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.proof.run import read_reverifiable
    run_dir, _rv = _mint_errsig_reverifiable(tmp_path)
    entry = read_reverifiable(run_dir).get("active_findings", [])[0]
    assert str(entry["oracle_context"]["error_observed"]).startswith("evs1:")   # sealed input

    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    res = build_audit_package(tmp_path / "pkg", findings=[entry], signers=signers, trust_root=tr,
                              engagement_slug="acme")
    assert res.get("ok"), res
    shipped = json.loads((tmp_path / "pkg" / "reverifiable.json").read_text(encoding="utf-8"))
    sf = shipped["active_findings"][0]
    # the shipped (disclosed) context is PLAINTEXT and re-fireable; the cert binds it.
    assert not str(sf["oracle_context"]["error_observed"]).startswith("evs1:")
    ctxs = json.loads((tmp_path / "pkg" / "contexts.json").read_text(encoding="utf-8"))
    ref, ctx = next(iter(ctxs.items()))
    certs = json.loads((tmp_path / "pkg" / "evidence-bundle.json").read_text(encoding="utf-8"))["certificates"]
    from framework.v2.evidence.models import SignedEvidence
    sc = SignedEvidence.model_validate(certs[0])
    assert verify_certificate(sc, oracle_context=ctx, trust_root=tr).ok is True   # BINDING + reproduction hold


# ===================================================================================================
# byte-identity: a NON-secret context is never sealed and never stamped
# ===================================================================================================

def test_non_secret_context_is_left_byte_identical(tmp_path):
    """A context that carries no secret marker (no secret_value, no error_observed) must be returned
    UNCHANGED by the seal helper — no seal, no sealed_engagement stamp — so every boolean/timing/xss/
    web-differential retained context stays byte-identical at rest."""
    from framework.v2.common.context_sealing import context_carries_secret, seal_oracle_context
    ctx = {"bug_class": "boolean_sqli",
           "probe_rounds": [{"payload": "a", "truth": True}],
           "observed_evidence": {"status": 200, "body": "just a normal page, no credential"}}
    assert context_carries_secret(ctx) is False
    out = seal_oracle_context(ctx, "alpha")
    assert out is ctx, "a non-secret context must be returned unchanged (identity)"


def test_seal_unseal_roundtrip_is_byte_identical(tmp_path):
    """Sealing then unsealing returns the EXACT original plaintext (AES-GCM), so the pure oracle re-fires
    byte-identically; and the input is never mutated."""
    import copy
    from framework.v2.common.context_sealing import (
        context_carries_secret, seal_oracle_context, unseal_oracle_context)
    ctx = {"bug_class": "exposure",
           "observed_evidence": {"status": 200, "control_body": "spa shell",
                                 "body": f"DB_PASSWORD={_SECRET}\n",
                                 "secret_assignment": f"DB_PASSWORD={_SECRET}",
                                 "secret_value": _SECRET},
           "predicate": {"all": []}}
    original = copy.deepcopy(ctx)
    assert context_carries_secret(ctx) is True
    sealed = seal_oracle_context(ctx, "alpha")
    assert ctx == original, "seal must not mutate its input"
    assert _SECRET not in json.dumps(sealed)
    assert sealed["observed_evidence"]["control_body"] == "spa shell", "the benign control is not sealed"
    unsealed = unseal_oracle_context(sealed, "alpha")
    assert unsealed == original, "unseal must recover the exact original plaintext"
