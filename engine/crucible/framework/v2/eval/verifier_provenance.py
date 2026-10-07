"""verifier_provenance — Lane C / C3: SLSA-style signed provenance + a PINNED content hash for each of
the three STANDALONE, zero-VIGIL verifiers.

The whole value of proof-carrying findings is that a third party who trusts and runs NOTHING of VIGIL
can re-check a finding with three files and the Python standard library (+ one Ed25519 lib):

  * ``docs/proof-carrying-finding/verify_pcf.py``        — the positive PCF v0.1 reference verifier
  * ``docs/proof-carrying-finding/verify_vf.py``         — the Verifiable-Fact lifecycle + re-execution
  * ``engine/crucible/framework/v2/evidence/audit_offline_verifier.py`` — the external-audit-package verifier

But a third party who downloads those three files has no way, today, to confirm they are the EXACT bytes
VIGIL's maintainers audited — a tampered verifier could pass a forged bundle. This module closes that gap:
it emits an in-toto / SLSA-provenance statement whose ``subject`` list PINS the sha256 of each verifier,
m-of-n Ed25519 signs it over canonical bytes, and publishes the signing trust-root fingerprint OUT OF BAND
(``SECURITY.md`` + the committed transparency record ``docs/supply-chain/verifier-transparency.jsonl``). A
drift test (``docs/tests/test_verifier_provenance.py``) re-hashes the shipped verifier files and fails CI
if any pinned hash no longer matches — so a verifier can never be changed without the provenance changing
with it, and a forged verifier can never masquerade as the audited one.

HONESTY BAR (Lane C). This is a CERTIFIABLE-READY artifact, not an external certification. The signing key
is a DETERMINISTIC FIXTURE key derived at runtime from a committed PUBLIC seed (no private key in the repo),
so the whole run is byte-stable and re-runnable in CI with nothing provisioned — it signs a SELF-attestation
of the verifier bytes, NOT a governance statement. A PUBLISHED provenance re-runs this with the operator's
real governance key (``--signing-key``; FATAL-2 — keys are passed in, never provisioned here), yielding the
same provenance CONTENT under the operator's trust root. What this proves is integrity + origin-under-the-
pinned-root of the verifier bytes; it does not, and cannot, assert that an external body certified them.

The provenance and this generator import framework freely (they are engine-side tooling) — the INVARIANT is
only that the three VERIFIERS stay zero-VIGIL, which this file never edits and the drift test re-confirms by
hashing them verbatim.

Deterministic: no wallclock, no RNG. The statement is a pure function of the verifier bytes + committed spec
references, so ``mint`` is idempotent and the committed artifacts are reproducible.

Usage::

    python3 -m framework.v2.eval.verifier_provenance mint     # (re)mint + sign the provenance (writes)
    python3 -m framework.v2.eval.verifier_provenance verify    # offline-verify the committed provenance
    python3 -m framework.v2.eval.verifier_provenance check     # verify-only, no write (CI / determinism)

Exit 0 iff SOUND; 2 otherwise.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from .conformance_run import _load_module, fixture_keypair

_REPO_ROOT = Path(__file__).resolve().parents[5]
_PCF_DIR = _REPO_ROOT / "docs" / "proof-carrying-finding"
_VERIFY_VF = _PCF_DIR / "verify_vf.py"
_SUPPLY_DIR = _REPO_ROOT / "docs" / "supply-chain"
_PROVENANCE = _SUPPLY_DIR / "verifier-provenance.json"
_TRANSPARENCY = _SUPPLY_DIR / "verifier-transparency.jsonl"
_SECURITY_MD = _REPO_ROOT / "SECURITY.md"

_SCHEMA_STATEMENT = "https://in-toto.io/Statement/v1"
_SCHEMA_PREDICATE = "https://slsa.dev/provenance/v1"

_FIXTURE_KEY_ID = "verifier-provenance-fixture"

# The three standalone verifiers, by their repo-relative POSIX path (the identity a third party downloads
# and runs). Each is PINNED by sha256 in the provenance subject list. Ordered + the role each one plays.
_VERIFIERS: tuple[tuple[str, str], ...] = (
    ("docs/proof-carrying-finding/verify_pcf.py",
     "PCF v0.1 reference verifier — authenticity (m-of-n Ed25519) + binding + faithful projection + "
     "the out-of-band trust-root pin, over a proof bundle / certificate."),
    ("docs/proof-carrying-finding/verify_vf.py",
     "Verifiable-Fact lifecycle verifier — prove-certificate authenticity, attestation series, witnessed "
     "time bound, AND zero-VIGIL RE-EXECUTION of the pure oracle bodies (verdict re-derivation)."),
    ("engine/crucible/framework/v2/evidence/audit_offline_verifier.py",
     "External-audit-package re-verifier (shipped verbatim as verify_offline.py) — authenticity + binding "
     "+ artifact integrity + chain/anti-suppression + the out-of-band trust-root pin."),
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verifier_digests() -> list[dict[str, str]]:
    """The pinned content hash of each of the three standalone verifiers, as it is on disk NOW."""
    out: list[dict[str, str]] = []
    for rel, role in _VERIFIERS:
        p = _REPO_ROOT / rel
        out.append({"path": rel, "sha256": _sha256_file(p), "role": role})
    return out


def _irreducible_boundary() -> dict[str, Any]:
    """The honest residual, named — never faked as reproduced. This file proves the verifier BYTES are the
    audited ones (integrity + origin under the pinned root). It does NOT, and structurally cannot, assert
    an external certification, a hardware root of trust, or that the signing key is anything but the
    deterministic fixture until an operator re-signs with a governance key."""
    return {
        "not_an_external_certification": (
            "This is certifiable-READY provenance (integrity + origin of the verifier bytes under a "
            "pinned trust root). It is NOT a Common-Criteria / FedRAMP / third-party certification; that "
            "requires an external accredited body (see docs/limitations LIMIT-external-audit-team)."),
        "fixture_signing_key": (
            "The default signing key is a deterministic, committed-public-seed FIXTURE key (non-governance), "
            "so CI is byte-stable with nothing provisioned. Published provenance re-signs with the operator's "
            "governance key (--signing-key; FATAL-2)."),
        "no_hardware_root": (
            "Origin is anchored to an out-of-band-pinned Ed25519 trust root, NOT to a hardware root of trust "
            "(TEE) — see docs/limitations LIMIT-attest-tee-hardware."),
    }


def build_provenance() -> dict[str, Any]:
    """Build the deterministic in-toto/SLSA-provenance statement pinning the three verifiers. Pure function
    of the verifier bytes + committed spec references — no wallclock, no RNG."""
    subjects = [
        {"name": d["path"], "digest": {"sha256": d["sha256"]}}
        for d in verifier_digests()
    ]
    roles = {d["path"]: d["role"] for d in verifier_digests()}
    return {
        "_type": _SCHEMA_STATEMENT,
        "predicateType": _SCHEMA_PREDICATE,
        "subject": sorted(subjects, key=lambda s: s["name"]),
        "predicate": {
            "buildDefinition": {
                "buildType": "https://vigil.dev/provenance/zero-vigil-verifier/1",
                "externalParameters": {
                    "attests": (
                        "The sha256 of each subject is the EXACT, audited content of that standalone, "
                        "zero-VIGIL verifier. A third party re-hashes the file they downloaded and compares "
                        "it to the pinned subject digest; a mismatch means the file is not the audited one."),
                    "zero_vigil_property": (
                        "Each subject imports NO framework/vigil/crucible/strix/gateway code — it runs with "
                        "the Python standard library and one Ed25519 library (cryptography). This provenance "
                        "file does NOT relax that; the drift test re-confirms it by AST over the import graph."),
                    "verifier_roles": roles,
                },
                "resolvedDependencies": [
                    {"uri": "docs/proof-carrying-finding/SPEC.md",
                     "annotations": {"role": "PCF v0.1 wire spec the verifiers re-implement"}},
                    {"uri": "docs/proof-carrying-finding/PROTOCOL.md",
                     "annotations": {"role": "Verifiable-Fact lifecycle protocol"}},
                    {"uri": "SECURITY.md",
                     "annotations": {"role": "out-of-band publication of the trust-root fingerprint + pins"}},
                    {"uri": "docs/supply-chain/verifier-transparency.jsonl",
                     "annotations": {"role": "durable committed transparency record of the pins"}},
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://vigil.dev/eval/verifier_provenance",
                    "note": ("deterministic: the statement is a pure function of the verifier bytes + "
                             "committed spec references; mint is idempotent and byte-reproducible."),
                },
            },
            "irreducible_boundary": _irreducible_boundary(),
        },
    }


def _write_json(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_transparency(digests: list[dict[str, str]], fingerprint: str) -> None:
    """The durable OUT-OF-BAND transparency record: one append-only JSONL line per verifier, binding its
    path + sha256 to the signing trust-root fingerprint. Deterministic (sorted, no wallclock); committed so
    a reader has a second, independent channel for the pins besides SECURITY.md."""
    lines = []
    for d in sorted(digests, key=lambda x: x["path"]):
        lines.append(json.dumps({
            "record": "vigil-verifier-pin/1",
            "path": d["path"],
            "sha256": d["sha256"],
            "trust_root_fingerprint": fingerprint,
        }, sort_keys=True))
    _TRANSPARENCY.parent.mkdir(parents=True, exist_ok=True)
    _TRANSPARENCY.write_text("\n".join(lines) + "\n", encoding="utf-8")


def mint(*, signing_key_b64: str | None = None, key_id: str | None = None) -> dict[str, Any]:
    """Mint + sign the provenance and write all committed artifacts. Reuses the benchmark_run signing path
    (m-of-n Ed25519 over canonical bytes), which also writes ``.sig.json`` + ``.fingerprint.txt``."""
    from framework.v2.eval.benchmark_run import _scorecard_fingerprint, sign_scorecard

    if signing_key_b64 is None:
        pub_b64, signing_key_b64 = fixture_keypair()
        key_id = _FIXTURE_KEY_ID
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = base64.b64decode(signing_key_b64)
        pub = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        pub_b64 = base64.b64encode(pub).decode("ascii")
        key_id = key_id or "operator"

    statement = build_provenance()
    _write_json(_PROVENANCE, statement)
    authorizers = [{"key_id": key_id, "public_key_b64": pub_b64}]
    sign_scorecard(_PROVENANCE, signers=[(key_id, signing_key_b64)], authorizers=authorizers, threshold=1)
    fingerprint = _scorecard_fingerprint(authorizers)
    _write_transparency(verifier_digests(), fingerprint)
    return {"statement": statement, "fingerprint": fingerprint, "key_id": key_id}


def verify_offline() -> dict[str, Any]:
    """Re-verify the committed provenance OFFLINE three ways and re-derive the pin drift check:
      1. the framework ``verify_scorecard`` (digest + m-of-n + out-of-band pin),
      2. the zero-VIGIL ``verify_vf.verify_threshold`` over the SAME canonical bytes (no framework),
      3. the pinned subject hashes equal the live sha256 of the shipped verifier files (drift → NOT SOUND).
    """
    from framework.v2.eval.benchmark_run import verify_scorecard

    if not _PROVENANCE.exists():
        return {"present": False, "offline_ok": False}
    sig = json.loads(_PROVENANCE.with_suffix(".sig.json").read_text(encoding="utf-8"))
    pin = _PROVENANCE.with_suffix(".fingerprint.txt").read_text(encoding="utf-8").strip()
    fw_ok = verify_scorecard(_PROVENANCE, sig, trust_root_fingerprint=pin, expected_threshold=1)

    vf = _load_module("verify_vf_prov", _VERIFY_VF)
    body = vf.canonical_json(json.loads(_PROVENANCE.read_text(encoding="utf-8")))
    standalone_ok, _valid, _reason = vf.verify_threshold(body, sig["signatures"], sig["trust_root"])

    statement = json.loads(_PROVENANCE.read_text(encoding="utf-8"))
    pinned = {s["name"]: s["digest"]["sha256"] for s in statement["subject"]}
    live = {d["path"]: d["sha256"] for d in verifier_digests()}
    drift = sorted(p for p in pinned if pinned.get(p) != live.get(p))
    no_drift = (pinned == live)

    return {
        "present": True,
        "framework_verify": bool(fw_ok),
        "standalone_verify_vf_threshold": bool(standalone_ok),
        "pins_match_shipped_files": bool(no_drift),
        "drift": drift,
        "offline_ok": bool(fw_ok and standalone_ok and no_drift),
    }


def _cmd_mint(args: argparse.Namespace) -> int:
    out = mint(signing_key_b64=args.signing_key or None, key_id=args.key_id or None)
    print(f"minted verifier provenance over {len(out['statement']['subject'])} verifiers -> {_PROVENANCE}")
    print(f"trust-root fingerprint (pinned out of band): {out['fingerprint']}")
    res = verify_offline()
    print(f"offline verify: {res}")
    return 0 if res["offline_ok"] else 2


def _cmd_verify(args: argparse.Namespace) -> int:
    res = verify_offline()
    print(f"verifier provenance offline verify: {res}")
    return 0 if res["offline_ok"] else 2


def _cmd_check(args: argparse.Namespace) -> int:
    return _cmd_verify(args)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verifier_provenance", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint", help="(re)mint + sign the provenance (writes committed artifacts)")
    m.add_argument("--signing-key", default="", help="operator governance private key (b64); FATAL-2 passed in")
    m.add_argument("--key-id", default="", help="operator key id")
    m.set_defaults(fn=_cmd_mint)
    v = sub.add_parser("verify", help="offline-verify the committed provenance")
    v.set_defaults(fn=_cmd_verify)
    c = sub.add_parser("check", help="verify-only (CI / determinism)")
    c.set_defaults(fn=_cmd_check)
    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
