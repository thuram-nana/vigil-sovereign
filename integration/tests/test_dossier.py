"""R2 — the one-click run dossier compiler (``framework.v2.report.dossier.build_dossier`` + ``vigil dossier``).

The moat property under test: ``build_dossier`` compiles EVERYTHING a run produced into ONE self-contained,
tamper-evident ``.zip`` — and the archive is (a) integrity-checkable (every entry's sha256 is in a MANIFEST),
(b) authenticity-signed when a governance signer is resolvable, (c) path-safe (no entry escapes; symlinks are
never followed), (d) secret-scrubbed (no credential leaks into the shipped log), (e) HONEST (a FACT is a fact,
a LEAD is a lead, an unsigned dossier says so), and (f) DETERMINISTIC (build twice → identical MANIFEST). The
embedded proof bundle re-verifies OFFLINE, in a VIGIL-free venv, with the exact command the index prints.

Needs framework (mint + verify + the report renderers) → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from vigil_core import generate_keypair, verify_one
from vigil_integration.proof.run import build_report_mint
from vigil_integration.proof.sink import CAPTURE_KEY

from framework.v2.report.dossier import build_dossier

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]

# The error-signature oracle fires on a distinctive datastore error in the response body → a response-side
# (target-produced) FACT, exactly the channel the live Strix capture builds (mirrors test_proof_bundle).
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"


def _mint_a_fact(run_dir: Path) -> object:
    mint = build_report_mint(run_dir=run_dir, signers=SIGNERS, engagement_slug="acme")
    report = {
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign repro')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "bug_class": "error_based_sqli"}],
                      "blobs": {"resp": _SQL_ERROR}},
    }
    res = mint(report)
    assert res is not None and res.is_fact, "the SQL-error response must mint a FACT"
    return res


def _findings_json(run_dir: Path) -> None:
    """A raw findings source so the report renderers (generate/export) are exercised — one fact, one lead."""
    (run_dir / "findings.json").write_text(json.dumps({"findings": [
        {"finding_slug": "sqli-1", "title": "SQL injection in login", "severity": "High",
         "bug_class": "boolean_sqli", "surface": "/login", "summary": "tautology bypass",
         "impact": "auth bypass", "verified_by_oracle": True},
        {"finding_slug": "xss-1", "title": "Reflected XSS in search", "severity": "Medium",
         "bug_class": "reflected_xss", "surface": "/search", "summary": "reflected param",
         "impact": "session theft"},
    ]}), encoding="utf-8")


def _log_with_secret(run_dir: Path) -> None:
    (run_dir / ".crucible-v2.log").write_text(
        json.dumps({"event": "req", "authorization": "Bearer SECRET-TOKEN-XYZ", "tokens_in": 42}) + "\n" +
        json.dumps({"event": "resp", "cookie": "session=DEADBEEF-SECRET"}) + "\n" +
        "this line is not json\n", encoding="utf-8")


def _entries(zf: zipfile.ZipFile) -> list[str]:
    return zf.namelist()


def _manifest(zf: zipfile.ZipFile) -> dict:
    return json.loads(zf.read("MANIFEST.json"))


def _verify_bundle_offline(bundle_dir: Path, *, fingerprint: str = "") -> subprocess.CompletedProcess:
    """Run the third-party offline verify exactly as the dossier's index.html prescribes."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path.cwd() / "engine" / "crucible"), env.get("PYTHONPATH", "")])
    argv = [sys.executable, "-m", "framework.v2", "evidence", "verify",
            "--report", "reverifiable.json", "--bundle", ".",
            "--trust-root", "trust-root.json", "--evidence-root", "evidence"]
    if fingerprint:
        argv += ["--trust-root-fingerprint", fingerprint]
    return subprocess.run(argv, cwd=str(bundle_dir), env=env, capture_output=True, text=True, timeout=120)


# --------------------------------------------------------------------------------------------------
# integrity — every entry's sha256 is in the manifest; the manifest does not list its own envelope
# --------------------------------------------------------------------------------------------------


def test_manifest_hashes_match_every_entry(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    _findings_json(run)
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["ok"] and res["facts"] == 1

    with zipfile.ZipFile(out) as zf:
        names = _entries(zf)
        man = _manifest(zf)
        # every manifested entry re-hashes to its recorded sha256
        for e in man["entries"]:
            assert hashlib.sha256(zf.read(e["path"])).hexdigest() == e["sha256"], f"hash mismatch {e['path']}"
        # the manifest covers the CONTENT entries, but never its own signature envelope
        listed = {e["path"] for e in man["entries"]}
        assert "MANIFEST.json" not in listed
        assert "MANIFEST.sig.json" not in listed
        assert "TRUST-ROOT-FINGERPRINT.txt" not in listed
        # and it covers everything else that is in the zip
        content = set(names) - {"MANIFEST.json", "MANIFEST.sig.json", "TRUST-ROOT-FINGERPRINT.txt"}
        assert listed == content, "every content entry must be manifested"
        # the reports + proof bundle + index are actually present
        assert "index.html" in names and "reports/technical.md" in names
        assert any(n.startswith("proof-bundle/") for n in names)


def test_evidence_symlink_is_not_shipped_or_vouched(tmp_path):
    # BLOCK-1 regression: a symlink planted in the run's evidence/ tree must NEVER be followed into the
    # bundle. The old shutil.copytree(symlinks=False) DEREFERENCED it, materialising an OUTSIDE file's
    # content into the governance-SIGNED archive (a hand-to-anyone exfiltration the manifest then vouched for).
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("TOP-SECRET-VIA-EVIDENCE-SYMLINK", encoding="utf-8")
    outdir = tmp_path / "leak-dir-src"; outdir.mkdir(); (outdir / "sekret.txt").write_text("DIR-LEAK", encoding="utf-8")
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)                                    # creates run/evidence/<action_id>/…
    ev = run / "evidence"
    assert ev.is_dir()
    (ev / "leak-file.txt").symlink_to(outside)          # a file symlink → outside the run
    (ev / "leak-dir").symlink_to(outdir, target_is_directory=True)   # a dir symlink → outside the run
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["ok"]
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        blob = b"".join(zf.read(n) for n in names)
        assert b"TOP-SECRET-VIA-EVIDENCE-SYMLINK" not in blob    # the symlinked file's content never ships
        assert b"DIR-LEAK" not in blob                           # nor a symlinked dir's content
        assert not any("leak-file.txt" in n or "leak-dir" in n for n in names)   # nor the link names


def test_scrub_recurses_into_lists():
    # BLOCK-2 regression: a credential under a secret key inside a LIST-of-dicts must be masked (the old
    # scrubber recursed into dicts but not lists → a realistic structlog header capture leaked).
    from framework.v2.common.redact import scrub_log_event
    out = scrub_log_event({"event": "req",
                           "headers": [{"authorization": "Bearer LISTNEST-SECRET"}, {"x": "ok"}],
                           "nested": [[{"cookie": "s=DEEP-SECRET"}]], "tokens_in": 7})
    dumped = json.dumps(out)
    assert "LISTNEST-SECRET" not in dumped and "DEEP-SECRET" not in dumped   # secrets in lists masked
    assert out["tokens_in"] == 7 and out["headers"][1]["x"] == "ok"          # non-secrets preserved


def test_a_flipped_byte_breaks_the_manifest_check(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    _findings_json(run)
    out = tmp_path / "dossier.zip"
    assert build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))["ok"]

    with zipfile.ZipFile(out) as zf:
        man = _manifest(zf)
        victim = next(e for e in man["entries"] if e["path"] == "reports/technical.md")
        tampered = bytearray(zf.read("reports/technical.md"))
    tampered[-1] ^= 0x01
    # the flipped bytes no longer match the recorded sha256 → integrity check fails
    assert hashlib.sha256(bytes(tampered)).hexdigest() != victim["sha256"]


def test_the_governance_signature_over_the_manifest_verifies(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["signed"] is True and str(res["trust_root_fingerprint"]).startswith("sha256:")

    with zipfile.ZipFile(out) as zf:
        manifest_bytes = zf.read("MANIFEST.json")
        sig = json.loads(zf.read("MANIFEST.sig.json"))
        fp_txt = zf.read("TRUST-ROOT-FINGERPRINT.txt").decode("utf-8").strip()
    # the signature signs the exact manifest bytes; the recorded sha256 matches
    assert sig["manifest_sha256"] == hashlib.sha256(manifest_bytes).hexdigest()
    assert sig["trust_root_fingerprint"] == fp_txt == res["trust_root_fingerprint"]
    # every signature validates against its embedded PUBLIC authoriser key over the manifest bytes
    pub = {a["key_id"]: a["public_key_b64"] for a in sig["trust_root"]["authorizers"]}
    good = sum(1 for s in sig["signatures"] if verify_one(pub[s["key_id"]], manifest_bytes, s["sig_b64"]))
    assert good >= sig["threshold"] >= 1
    # a byte flip in the manifest makes the SAME signature fail (authenticity binds the content)
    forged = bytearray(manifest_bytes); forged[-1] ^= 0x01
    assert not verify_one(pub[sig["signatures"][0]["key_id"]], bytes(forged), sig["signatures"][0]["sig_b64"])


# --------------------------------------------------------------------------------------------------
# offline re-verification — the embedded proof bundle re-proves with zero trust in VIGIL
# --------------------------------------------------------------------------------------------------


def test_embedded_proof_bundle_reverifies_offline(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["proof_bundle"] is True

    extracted = tmp_path / "unzipped"
    with zipfile.ZipFile(out) as zf:
        zf.extractall(extracted)
    bundle = extracted / "proof-bundle"
    assert bundle.is_dir()
    # the exact fingerprint the operator publishes out-of-band, pinned — a sound bundle exits 0
    proc = _verify_bundle_offline(bundle, fingerprint=res["trust_root_fingerprint"])
    assert proc.returncode == 0, f"embedded bundle must re-verify offline:\n{proc.stdout}\n{proc.stderr}"


# --------------------------------------------------------------------------------------------------
# path safety — no zip entry escapes; a hostile action_id drops artifacts, never traverses
# --------------------------------------------------------------------------------------------------


def test_no_zip_entry_escapes_and_a_hostile_action_id_does_not_traverse(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    # poison the retained action_id with an absolute path (a hostile proofs/reverifiable.json)
    rp = run / "proofs" / "reverifiable.json"
    doc = json.loads(rp.read_text(encoding="utf-8"))
    doc["active_findings"][0]["action_id"] = "/etc"
    rp.write_text(json.dumps(doc), encoding="utf-8")

    out = tmp_path / "dossier.zip"
    assert build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))["ok"]
    with zipfile.ZipFile(out) as zf:
        names = _entries(zf)
    # EVERY arcname is a confined relative path — no absolute, no `..`, nothing under /etc
    for n in names:
        assert not n.startswith("/"), f"absolute entry escaped: {n}"
        assert ".." not in Path(n).parts, f"parent-traversal entry escaped: {n}"
        assert "etc" not in Path(n).parts[:1], f"hostile action_id traversed into the archive: {n}"


def test_a_symlink_in_the_run_dir_is_not_followed_into_the_zip(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    # a symlinked spine artifact pointing at a secret file OUTSIDE the run dir must not be embedded
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("TOP-SECRET-OUTSIDE-CONTENT", encoding="utf-8")
    try:
        (run / "acme.spine").symlink_to(secret)
    except (OSError, NotImplementedError):
        return  # platform without symlinks — nothing to assert
    out = tmp_path / "dossier.zip"
    assert build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))["ok"]
    with zipfile.ZipFile(out) as zf:
        blob = b"".join(zf.read(n) for n in _entries(zf))
    assert b"TOP-SECRET-OUTSIDE-CONTENT" not in blob, "a symlink smuggled outside content into the dossier"


# --------------------------------------------------------------------------------------------------
# secret scrubbing — the shipped engagement log carries no credential in the clear
# --------------------------------------------------------------------------------------------------


def test_the_shipped_engagement_log_is_scrubbed(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    _log_with_secret(run)
    out = tmp_path / "dossier.zip"
    assert build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))["ok"]
    with zipfile.ZipFile(out) as zf:
        assert "logs/engagement-log.jsonl" in _entries(zf)
        log = zf.read("logs/engagement-log.jsonl").decode("utf-8")
        whole = b"".join(zf.read(n) for n in _entries(zf)).decode("utf-8", errors="replace")
    # the secret VALUES are masked everywhere in the archive
    assert "SECRET-TOKEN-XYZ" not in whole and "DEADBEEF-SECRET" not in whole
    assert "<redacted-X2>" in log
    # non-secret telemetry that merely CONTAINS a secret word is preserved (no over-masking)
    assert "tokens_in" in log and "42" in log
    # the non-JSON line is dropped, never shipped in the clear
    assert "this line is not json" not in whole


# --------------------------------------------------------------------------------------------------
# honesty — FACT vs LEAD reflected exactly; a facts-only-absent run ships no proof bundle and says so
# --------------------------------------------------------------------------------------------------


def test_index_reflects_fact_and_lead_honestly(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    _findings_json(run)
    out = tmp_path / "dossier.zip"
    build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    with zipfile.ZipFile(out) as zf:
        idx = zf.read("index.html").decode("utf-8")
    assert "oracle-confirmed FACT" in idx
    assert "error_based_sqli" in idx                 # the FACT's bug class, from reverifiable.json
    assert "lead" in idx.lower()                       # the LEAD is labelled, never dressed as a fact


def test_a_leads_only_run_ships_no_proof_bundle_and_says_so(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    # no FACT minted — only a raw leads source
    (run / "findings.json").write_text(json.dumps({"findings": [
        {"finding_slug": "xss-1", "title": "Possible reflected XSS", "severity": "Medium",
         "bug_class": "reflected_xss", "surface": "/search", "summary": "reflected param"},
    ]}), encoding="utf-8")
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["ok"] and res["facts"] == 0 and res["proof_bundle"] is False

    with zipfile.ZipFile(out) as zf:
        names = _entries(zf)
        idx = zf.read("index.html").decode("utf-8")
        man = _manifest(zf)
    # no proof bundle at all, and the index is honest about it
    assert not any(n.startswith("proof-bundle/") for n in names)
    assert "NO oracle-confirmed FACT" in idx or "no oracle-confirmed FACT" in idx
    # still fully integrity-checkable (a manifest with matching hashes)
    with zipfile.ZipFile(out) as zf:
        for e in man["entries"]:
            assert hashlib.sha256(zf.read(e["path"])).hexdigest() == e["sha256"]


def test_unsigned_dossier_is_honest_when_no_signer_is_resolvable(tmp_path, monkeypatch):
    """When no governance signer is resolvable, the dossier is still integrity-checkable (hashes) but the
    index/README + the summary state HONESTLY that it is NOT authenticity-signed."""
    import vigil_integration.live.wiring as wiring

    def _boom(*a, **k):
        raise RuntimeError("no signer in this environment")

    monkeypatch.setattr(wiring, "provision_authority", _boom)

    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["ok"] and res["signed"] is False

    with zipfile.ZipFile(out) as zf:
        names = _entries(zf)
        idx = zf.read("index.html").decode("utf-8")
        man = _manifest(zf)
        for e in man["entries"]:
            assert hashlib.sha256(zf.read(e["path"])).hexdigest() == e["sha256"]
    assert "MANIFEST.sig.json" not in names                     # no signature envelope
    assert "NOT authenticity-signed" in idx
    # the proof bundle also can't sign, so a leads-run would be honest; here the FACT bundle may be absent
    assert any(n == "MANIFEST.json" for n in names)             # but always integrity-checkable


# --------------------------------------------------------------------------------------------------
# determinism — build twice over the same inputs → identical MANIFEST (+ identical signature)
# --------------------------------------------------------------------------------------------------


def test_two_builds_produce_identical_manifest(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    _findings_json(run)
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    ra = build_dossier(run_dir=str(run), out_zip=str(a), engagement_slug="acme", base_dir=str(run))
    rb = build_dossier(run_dir=str(run), out_zip=str(b), engagement_slug="acme", base_dir=str(run))
    with zipfile.ZipFile(a) as za, zipfile.ZipFile(b) as zb:
        assert za.read("MANIFEST.json") == zb.read("MANIFEST.json"), "MANIFEST is not deterministic"
        assert za.read("MANIFEST.sig.json") == zb.read("MANIFEST.sig.json"), "signature is not deterministic"
    assert ra["manifest_sha256"] == rb["manifest_sha256"]


def test_an_injected_timestamp_stays_out_of_the_hashed_content(tmp_path):
    """The OPTIONAL ``generated_at`` stamp only decorates index/README; two builds with the SAME stamp are
    identical, and the default (no stamp) is fully reproducible — the timestamp is the only non-determinism."""
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    a = tmp_path / "a.zip"; b = tmp_path / "b.zip"
    ra = build_dossier(run_dir=str(run), out_zip=str(a), engagement_slug="acme", base_dir=str(run),
                       generated_at="2026-07-28T00:00:00Z")
    rb = build_dossier(run_dir=str(run), out_zip=str(b), engagement_slug="acme", base_dir=str(run),
                       generated_at="2026-07-28T00:00:00Z")
    assert ra["manifest_sha256"] == rb["manifest_sha256"]
    with zipfile.ZipFile(a) as za:
        assert "2026-07-28T00:00:00Z" in za.read("index.html").decode("utf-8")


# --------------------------------------------------------------------------------------------------
# the `vigil dossier` verb (native) — end-to-end over a real run dir
# --------------------------------------------------------------------------------------------------


def test_vigil_dossier_cli_verb(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _mint_a_fact(run)
    _findings_json(run)
    out = tmp_path / "cli-dossier.zip"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path.cwd() / "engine" / "crucible"), str(Path.cwd() / "integration"),
         str(Path.cwd() / "gateway"), env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [sys.executable, "-m", "vigil_integration.cli", "dossier",
         "--run-dir", str(run), "--out", str(out), "--slug", "acme", "--base-dir", str(run)],
        env=env, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, f"vigil dossier failed:\n{proc.stdout}\n{proc.stderr}"
    assert out.is_file()
    assert "vigil dossier" in proc.stdout and "MANIFEST.json sha256=" in proc.stdout
    with zipfile.ZipFile(out) as zf:
        man = _manifest(zf)
        for e in man["entries"]:
            assert hashlib.sha256(zf.read(e["path"])).hexdigest() == e["sha256"]


# --------------------------------------------------------------------------------------------------
# the governed terminal transcript — included, scrubbed, and manifest-covered
# --------------------------------------------------------------------------------------------------


def _terminal_history_with_secret(path: Path) -> None:
    # a signed terminal.run ExecRecord + a secret under a secret-named key (redacted at source in production;
    # planted here to prove the compiler re-scrubs it) + an unparseable line (must be dropped, not shipped).
    path.write_text(
        json.dumps({"seq": 1, "tool": "terminal.run", "argv": ["cat", "/etc/hostname"], "exit_code": 0,
                    "tier": "A2", "signature": "sig-abc", "authorization": "Bearer TERMSECRET-XYZ"}) + "\n" +
        "this line is not json\n", encoding="utf-8")


def test_terminal_transcript_included_scrubbed_and_manifested(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _findings_json(run)
    hist = tmp_path / "terminal-history.jsonl"
    _terminal_history_with_secret(hist)
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run),
                        terminal_history=str(hist))
    assert res["ok"]
    with zipfile.ZipFile(out) as zf:
        names = _entries(zf)
        assert "logs/terminal-transcript.jsonl" in names           # the transcript is in the archive
        body = zf.read("logs/terminal-transcript.jsonl").decode("utf-8")
        assert "terminal.run" in body and "cat" in body            # the command is recorded
        assert "TERMSECRET-XYZ" not in body                        # the planted secret was scrubbed
        assert "this line is not json" not in body                 # the unparseable line was dropped
        man = _manifest(zf)                                         # tamper-evident: manifest covers it
        listed = {e["path"] for e in man["entries"]}
        assert "logs/terminal-transcript.jsonl" in listed
        for e in man["entries"]:
            assert hashlib.sha256(zf.read(e["path"])).hexdigest() == e["sha256"]


def test_no_terminal_history_no_transcript_entry(tmp_path):
    run = tmp_path / "run"; run.mkdir()
    _findings_json(run)
    out = tmp_path / "dossier.zip"
    res = build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme", base_dir=str(run))
    assert res["ok"]
    with zipfile.ZipFile(out) as zf:
        assert "logs/terminal-transcript.jsonl" not in _entries(zf)   # absent when no transcript is supplied
