"""Lane C / C3 — verifier supply-chain provenance drift guard.

The three STANDALONE, zero-VIGIL verifiers are the trusted computing base a third party runs to re-check a
finding with nothing of VIGIL installed. Their integrity must be confirmable out-of-band. This guard keeps
the signed provenance, the committed transparency record, the `SECURITY.md` pins, and the shipped verifier
bytes in LOCK-STEP:

  * every pinned sha256 (in the provenance `subject` list) equals the LIVE sha256 of the shipped verifier
    file — change a verifier without re-minting and the build goes red (the drift guard the task asks for);
  * the transparency record and the `SECURITY.md` out-of-band table carry the SAME pins and the SAME
    trust-root fingerprint — update one channel and not another and the build goes red;
  * the three verifiers are the exact set claimed, and the provenance names its honest boundary (NOT an
    external certification, NO hardware root) — so the certifiable-ready claim can never silently inflate.

STDLIB ONLY. The required `the briefing explains every agent and capability` CI job runs `pytest docs/tests`
with only pytest installed, so this guard uses `hashlib` + `json` + `pathlib` + `re` and imports no trust
domain. The cryptographic signature leg (framework / cryptography) is a SEPARATE, import-skipped test.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SUPPLY = REPO / "docs" / "supply-chain"
PROVENANCE = SUPPLY / "verifier-provenance.json"
SIG = SUPPLY / "verifier-provenance.sig.json"
FINGERPRINT = SUPPLY / "verifier-provenance.fingerprint.txt"
TRANSPARENCY = SUPPLY / "verifier-transparency.jsonl"
SECURITY = REPO / "SECURITY.md"

# The three standalone verifiers whose bytes the provenance pins — the zero-VIGIL trusted computing base.
VERIFIERS = (
    "docs/proof-carrying-finding/verify_pcf.py",
    "docs/proof-carrying-finding/verify_vf.py",
    "engine/crucible/framework/v2/evidence/audit_offline_verifier.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _live_digests() -> dict[str, str]:
    return {rel: _sha256(REPO / rel) for rel in VERIFIERS}


def test_artifacts_present() -> None:
    for p in (PROVENANCE, SIG, FINGERPRINT, TRANSPARENCY):
        assert p.exists(), f"missing C3 artifact: {p}"


def test_provenance_subjects_match_shipped_files() -> None:
    """THE drift guard: every pinned sha256 equals the live hash of the shipped verifier file."""
    statement = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    pinned = {s["name"]: s["digest"]["sha256"] for s in statement["subject"]}
    live = _live_digests()
    assert pinned == live, (
        "verifier drift: provenance pins do not match the shipped verifier bytes — re-run "
        "`python3 -m framework.v2.eval.verifier_provenance mint`.\n"
        f"pinned={pinned}\nlive={live}")


def test_provenance_pins_exactly_the_three_verifiers() -> None:
    statement = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    names = sorted(s["name"] for s in statement["subject"])
    assert names == sorted(VERIFIERS)
    # every subject carries a 64-hex sha256
    for s in statement["subject"]:
        assert re.fullmatch(r"[0-9a-f]{64}", s["digest"]["sha256"]), s


def test_transparency_record_matches_pins_and_fingerprint() -> None:
    fp = FINGERPRINT.read_text(encoding="utf-8").strip()
    live = _live_digests()
    rows = [json.loads(line) for line in TRANSPARENCY.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_path = {r["path"]: r for r in rows}
    assert set(by_path) == set(VERIFIERS), "transparency record must cover exactly the three verifiers"
    for rel, r in by_path.items():
        assert r["sha256"] == live[rel], f"transparency pin drift for {rel}"
        assert r["trust_root_fingerprint"] == fp, f"transparency fingerprint drift for {rel}"
        assert r["record"] == "vigil-verifier-pin/1"


def test_security_md_publishes_the_same_pins_out_of_band() -> None:
    """The out-of-band channel: SECURITY.md must carry the SAME trust-root fingerprint and the SAME verifier
    hashes. A reviewer trusts this channel over the signature file, so it must never drift from the pins."""
    text = SECURITY.read_text(encoding="utf-8")
    fp = FINGERPRINT.read_text(encoding="utf-8").strip()
    assert fp in text, "SECURITY.md must publish the trust-root fingerprint out of band"
    live = _live_digests()
    for rel, digest in live.items():
        assert digest in text, f"SECURITY.md must publish the pinned sha256 for {rel} (out-of-band channel)"


def test_fingerprint_matches_embedded_trust_root() -> None:
    """The .fingerprint.txt pin must be the sha256 over the canonical authorizer set embedded in the sig —
    re-derived here with stdlib (sorted authorizers, compact separators, sorted keys), so the out-of-band
    pin can never silently diverge from the trust root the signature actually binds to."""
    sig = json.loads(SIG.read_text(encoding="utf-8"))
    fp = FINGERPRINT.read_text(encoding="utf-8").strip()
    authorizers = sorted(sig["trust_root"]["authorizers"], key=lambda a: a["key_id"])
    body = json.dumps(authorizers, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expect = "sha256:" + hashlib.sha256(body).hexdigest()
    assert fp == expect, f"fingerprint {fp} != re-derived {expect}"


def test_honest_boundary_is_named_not_hidden() -> None:
    """The certifiable-ready claim must name its irreducible boundary: NOT an external certification, a
    FIXTURE signing key by default, NO hardware root. A missing boundary would be a silent overclaim."""
    statement = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    boundary = statement["predicate"]["irreducible_boundary"]
    assert set(boundary) >= {"not_an_external_certification", "fixture_signing_key", "no_hardware_root"}
    blob = json.dumps(boundary).lower()
    assert "not" in blob and "certif" in blob


# --- cryptographic signature leg (framework / cryptography) — import-skipped in the minimal CI job --------
def test_provenance_signature_verifies_offline() -> None:
    pytest.importorskip("cryptography")
    vp = pytest.importorskip("framework.v2.eval.verifier_provenance")
    res = vp.verify_offline()
    assert res["present"] and res["offline_ok"], res
    assert res["framework_verify"] and res["standalone_verify_vf_threshold"]
    assert res["pins_match_shipped_files"] and not res["drift"]
