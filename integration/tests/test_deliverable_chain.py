"""W16-7 — the deliverable chain, end to end.

Traces an engagement to its final deliverable (the dossier ZIP) and pins every link the issue found broken:

  * AC2 — a PRODUCTION run writes ``findings.json`` (``console.actions._write_findings_json``), and the three
    human reports + SARIF render FROM it (raw ``report.json`` alone cannot be rendered — see
    ``report/tests/test_adapt``). A pre-fix tree has no such function, so the test fails there.
  * AC3 — the console writes ``<run>/reverifiable.json`` (top-level, via ``--reverifiable-out``) and
    ``export_bundle`` reads it (via ``read_reverifiable``): the two conventions now meet. Asserted by WRITING
    with the console convention and READING with the exporter.
  * AC4 — a bundle is signed with a STABLE trust root pinned to the install (``base_dir``): two runs of one
    install share a root, and a bundle from a DIFFERENT install does not verify against the pinned root —
    proving the signature establishes ORIGIN, not just integrity (negative control).
  * AC5 — the signed certificate STORED at mint time is byte-identical to what the download returns (no
    re-mint); a cert signed under a different key is NOT reused (the authenticity gate is not a no-op).
  * The full chain: a loopback-style run → ``build_dossier`` → a ZIP carrying the reports, SARIF, the raw
    HTTP evidence (AC1), and the offline-verifiable proof bundle.

Framework-dependent (mint + certify + build_dossier), so this runs in the OFFENSE leg only — it is
``--ignore``d in the sovereign leg and listed in the offense leg of ``.github/workflows/ci.yml`` (the
``test_ci_framework_tests_run_in_offense_leg`` guard enforces both).
Run: ``PYTHONPATH=integration:engine/crucible:gateway python -m pytest integration/tests/test_deliverable_chain.py``
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from framework.v2.report import dossier as dossier_mod
from framework.v2.report.adapt import adapt_scan_export
from framework.v2.report.generate import ReportMeta, generate_reports
from vigil_integration.live.wiring import provision_authority
from vigil_integration.proof.bundle import export_bundle
from vigil_integration.proof.run import build_report_mint, read_reverifiable
from vigil_integration.proof.sink import CAPTURE_KEY

# Import the console actions LAZILY inside the tests that need it — the module is framework-side and this file
# already loads framework, but keeping it local mirrors the repo's function-local framework-import discipline.

_FIXTURES = (Path(__file__).resolve().parents[2]
             / "engine" / "crucible" / "framework" / "v2" / "report" / "tests" / "fixtures")

# The error-signature oracle fires on a datastore error in the response body → a response-side FACT, exactly
# the channel a live capture builds. Reused, verbatim, from the C1 proof-bundle test recipe.
_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"


def _mint_a_fact(run_dir: Path, signers, *, slug: str = "acme") -> object:
    mint = build_report_mint(run_dir=run_dir, signers=signers, engagement_slug=slug)
    report = {
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign repro')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "request_bytes_ref": "req",
                                     "bug_class": "error_based_sqli"}],
                      "blobs": {"resp": _SQL_ERROR,
                                "req": b"GET /items?id=1%27 HTTP/1.1\r\nHost: t\r\n\r\n"}},
    }
    res = mint(report)
    assert res is not None and res.is_fact, "the SQL-error response must mint a FACT"
    return res


def _verify(bundle: Path, *, fingerprint: str = "") -> subprocess.CompletedProcess:
    """Third-party OFFLINE verify, exactly as the README prescribes (optionally with a pinned trust root)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(Path.cwd() / "engine" / "crucible"), env.get("PYTHONPATH", "")])
    argv = [sys.executable, "-m", "framework.v2", "evidence", "verify",
            "--report", "reverifiable.json", "--bundle", ".",
            "--trust-root", "trust-root.json", "--evidence-root", "evidence"]
    if fingerprint:
        argv += ["--trust-root-fingerprint", fingerprint]
    return subprocess.run(argv, cwd=str(bundle), env=env, capture_output=True, text=True, timeout=120)


# ==================================================================================================
# AC2 — a production run writes findings.json, and the reports + SARIF render from it
# ==================================================================================================


def test_production_findings_json_is_renderer_shape_and_drives_the_reports(tmp_path):
    from framework.v2.console import actions

    run = tmp_path / "run"
    run.mkdir()
    (run / "report.json").write_text((_FIXTURES / "stored-report.json").read_text(encoding="utf-8"),
                                     encoding="utf-8")
    (run / "reverifiable.json").write_text((_FIXTURES / "stored-reverifiable.json").read_text(encoding="utf-8"),
                                           encoding="utf-8")

    # the PRODUCTION scan-completion path writes findings.json (no such function on a pre-fix tree).
    assert actions._write_findings_json(run) is True
    fj = run / "findings.json"
    assert fj.is_file(), "a production run must leave findings.json behind"
    findings = json.loads(fj.read_text(encoding="utf-8"))["findings"]
    assert findings, "findings.json must carry the renderer-shape finding set"

    # it is TRULY renderer-shape: the renderers ACCEPT it. The raw report.json does NOT (that is the whole
    # reason report.adapt exists — see report/tests/test_adapt), so this is a real behavioural assertion.
    docs = generate_reports(findings, ReportMeta(target="t"))
    assert set(docs) == {"executive", "technical", "remediation-roadmap"}
    assert all(body.strip() for body in docs.values())

    # and a dossier whose ONLY finding source is findings.json (report.json removed) still renders all three
    # human reports + SARIF from it.
    (run / "report.json").unlink()
    out = tmp_path / "d.zip"
    res = dossier_mod.build_dossier(run_dir=run, out_zip=out, engagement_slug="acme",
                                    base_dir=str(tmp_path / "install"))
    assert res["ok"], res
    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
    for n in ("reports/executive.md", "reports/technical.md", "reports/remediation-roadmap.md",
              "appendix/report.sarif"):
        assert n in names, f"the deliverable must render {n} from findings.json"


def test_write_findings_json_is_fail_closed_and_not_a_no_op(tmp_path):
    """Negative control: the gate is not a no-op — a missing or malformed source writes NOTHING."""
    from framework.v2.console import actions

    run = tmp_path / "run"
    run.mkdir()
    assert actions._write_findings_json(run) is False           # no report.json
    assert not (run / "findings.json").exists()

    (run / "report.json").write_text("{ this is not json", encoding="utf-8")
    assert actions._write_findings_json(run) is False           # malformed report.json
    assert not (run / "findings.json").exists()

    # a well-formed export with an empty findings list also declines (nothing to render).
    (run / "report.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    assert actions._write_findings_json(run) is False
    assert not (run / "findings.json").exists()


# ==================================================================================================
# AC3 — the console's top-level reverifiable.json convention is read by the exporter
# ==================================================================================================


def test_console_convention_reverifiable_is_read_by_export_bundle(tmp_path):
    """WRITE with one convention (the console's top-level ``<run>/reverifiable.json``), READ with the other
    (``export_bundle`` → ``read_reverifiable``). Before W16-7 these never met and a plain scan exported ZERO
    certificates."""
    base = str(tmp_path / "install")
    prov = provision_authority(slug="acme", scope=["127.0.0.1"], base_dir=base)
    run = tmp_path / "run"
    run.mkdir()
    _mint_a_fact(run, prov.signers)

    # relocate the retained proof to the CONSOLE convention: top-level reverifiable.json, and remove the
    # studio's proofs/ copy — so ONLY the console's convention is present.
    proofs = run / "proofs" / "reverifiable.json"
    doc = json.loads(proofs.read_text(encoding="utf-8"))
    (run / "reverifiable.json").write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    proofs.unlink()

    # the exporter's reader finds it under the console convention ...
    assert read_reverifiable(run)["active_findings"], "read_reverifiable must read the top-level convention"
    # ... and a bundle exports from it.
    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run, out_dir=out, engagement_slug="acme", base_dir=base)
    assert res["ok"] and res["certificates"] == 1
    assert (out / "reverifiable.json").is_file() and (out / "evidence-bundle.json").is_file()

    # negative control: with NEITHER convention present there is nothing to export (the exporter refuses).
    empty = tmp_path / "empty"
    (empty / "proofs").mkdir(parents=True)
    none = export_bundle(run_dir=empty, out_dir=tmp_path / "b2", engagement_slug="acme")
    assert none["ok"] is False and "no proven findings" in none["error"]


# ==================================================================================================
# AC4 — the signature establishes ORIGIN: a stable per-install trust root, pinned out of band
# ==================================================================================================


def test_signature_establishes_origin_not_just_integrity(tmp_path):
    # install A — one stable governance key under base_dir A
    base_a = str(tmp_path / "installA")
    prov_a = provision_authority(slug="acme", scope=["127.0.0.1"], base_dir=base_a)
    run_a = tmp_path / "runA"
    run_a.mkdir()
    _mint_a_fact(run_a, prov_a.signers)
    out_a = tmp_path / "bundleA"
    res_a = export_bundle(run_dir=run_a, out_dir=out_a, engagement_slug="acme", base_dir=base_a)
    fp_a = res_a["trust_root_fingerprint"]
    assert fp_a.startswith("sha256:")

    # STABLE: a SECOND run under the SAME install yields the SAME trust-root fingerprint (one root per
    # install — the property the console's --base-dir pin buys). Before the fix each run minted a fresh key.
    run_a2 = tmp_path / "runA2"
    run_a2.mkdir()
    _mint_a_fact(run_a2, prov_a.signers)
    res_a2 = export_bundle(run_dir=run_a2, out_dir=tmp_path / "bundleA2", engagement_slug="acme",
                           base_dir=base_a)
    assert res_a2["trust_root_fingerprint"] == fp_a

    # install B — a DIFFERENT base_dir → a DIFFERENT governance key → a DIFFERENT trust root
    base_b = str(tmp_path / "installB")
    prov_b = provision_authority(slug="acme", scope=["127.0.0.1"], base_dir=base_b)
    run_b = tmp_path / "runB"
    run_b.mkdir()
    _mint_a_fact(run_b, prov_b.signers)
    out_b = tmp_path / "bundleB"
    res_b = export_bundle(run_dir=run_b, out_dir=out_b, engagement_slug="acme", base_dir=base_b)
    assert res_b["trust_root_fingerprint"] != fp_a

    # bundle A verifies against install A's PINNED fingerprint ...
    assert _verify(out_a, fingerprint=fp_a).returncode == 0
    # ... and bundle B, from a DIFFERENT install, does NOT verify against install A's pinned root.
    proc = _verify(out_b, fingerprint=fp_a)
    assert proc.returncode != 0
    assert "MISMATCH" in (proc.stdout + proc.stderr)


# ==================================================================================================
# AC5 — the certificate stored at mint time is byte-identical to what the download returns
# ==================================================================================================


def test_stored_certificate_is_byte_identical_to_the_download(tmp_path):
    base = str(tmp_path / "install")
    prov = provision_authority(slug="acme", scope=["127.0.0.1"], base_dir=base)
    run = tmp_path / "run"
    run.mkdir()
    _mint_a_fact(run, prov.signers)

    # the mint STORED the signed certificate (a pre-fix tree stores none → this assertion fails there).
    stored = json.loads((run / "proofs" / "reverifiable.json").read_text(encoding="utf-8"))["active_findings"]
    assert len(stored) == 1
    stored_cert = stored[0].get("signed_certificate")
    assert stored_cert is not None, "the mint must STORE the signed certificate at mint time"

    # export under the SAME governance key — the download RETURNS the stored cert, byte-identical (no re-mint).
    out = tmp_path / "bundle"
    res = export_bundle(run_dir=run, out_dir=out, engagement_slug="acme", base_dir=base)
    assert res["ok"] and res["certificates"] == 1
    downloaded = json.loads((out / "evidence-bundle.json").read_text(encoding="utf-8"))["certificates"][0]
    assert json.dumps(downloaded, sort_keys=True) == json.dumps(stored_cert, sort_keys=True), (
        "the downloaded certificate must be byte-identical to the one stored at mint time")
    # and it still verifies offline.
    assert _verify(out, fingerprint=res["trust_root_fingerprint"]).returncode == 0


def test_a_cert_signed_under_a_different_key_is_re_minted_not_reused(tmp_path):
    """Negative control for the reuse gate: a stored cert that is NOT authentic against the bundle's own
    trust root (signed under another install's key) is re-minted, never smuggled in. So the byte-identical
    reuse of the test above is a genuine authenticity match, not an unconditional passthrough."""
    base_a = str(tmp_path / "installA")
    prov_a = provision_authority(slug="acme", scope=["127.0.0.1"], base_dir=base_a)
    run = tmp_path / "run"
    run.mkdir()
    _mint_a_fact(run, prov_a.signers)   # the stored cert is signed by install A's key
    stored_cert = json.loads(
        (run / "proofs" / "reverifiable.json").read_text(encoding="utf-8")
    )["active_findings"][0]["signed_certificate"]
    assert stored_cert is not None

    # export under a DIFFERENT install → the A-signed stored cert fails authenticity → it is re-minted under B.
    out_b = tmp_path / "bundleB"
    res = export_bundle(run_dir=run, out_dir=out_b, engagement_slug="acme", base_dir=str(tmp_path / "installB"))
    assert res["ok"] and res["certificates"] == 1
    downloaded = json.loads((out_b / "evidence-bundle.json").read_text(encoding="utf-8"))["certificates"][0]
    assert json.dumps(downloaded, sort_keys=True) != json.dumps(stored_cert, sort_keys=True), (
        "a cert signed under a different key must NOT be reused (re-minted under the bundle's own key)")
    # the re-minted bundle still verifies against its OWN pinned root.
    assert _verify(out_b, fingerprint=res["trust_root_fingerprint"]).returncode == 0


# ==================================================================================================
# The full chain — a loopback-style run produces a dossier carrying every link (AC1 end to end)
# ==================================================================================================


def test_full_deliverable_chain_produces_a_dossier_with_every_link(tmp_path):
    from framework.v2.console import actions

    base = str(tmp_path / "install")
    prov = provision_authority(slug="acme", scope=["127.0.0.1"], base_dir=base)

    run = tmp_path / "run"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps({"slug": "acme"}), encoding="utf-8")
    # a finished loopback scan's stored export drives the reports ...
    (run / "report.json").write_text((_FIXTURES / "stored-report.json").read_text(encoding="utf-8"),
                                     encoding="utf-8")
    # ... an oracle-confirmed FACT (minted under the install's key) drives the proof bundle ...
    _mint_a_fact(run, prov.signers)
    # ... and the gated executor's raw HTTP capture is on disk (nothing read this before W16-7).
    aid = "act-0001"
    ev = run / "evidence" / aid
    ev.mkdir(parents=True)
    (ev / "request.http").write_text("GET /search?q=test%27 HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n\r\n",
                                     encoding="utf-8")
    (ev / "response.http").write_text("HTTP/1.1 500 Server Error\r\nContent-Type: text/html\r\n\r\n",
                                      encoding="utf-8")
    (ev / "response.body").write_bytes(b"You have an error in your SQL syntax near ''' at line 1")

    # the production scan-completion path leaves findings.json behind (AC2).
    assert actions._write_findings_json(run) is True

    # BUILD THE DELIVERABLE.
    out = tmp_path / "dossier.zip"
    res = dossier_mod.build_dossier(run_dir=run, out_zip=out, engagement_slug="acme", base_dir=base)
    assert res["ok"], res

    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
        index = z.read("index.html").decode("utf-8")

    # (a) the three human reports + SARIF, rendered from findings.json
    for n in ("reports/executive.md", "reports/technical.md", "reports/remediation-roadmap.md",
              "appendix/report.sarif", "appendix/report.json"):
        assert n in names, f"missing deliverable link {n}"
    # (b) AC1 — the raw HTTP evidence is IN the deliverable and named in the readable index
    for name in ("request.http", "response.http", "response.body"):
        assert f"http-evidence/{aid}/{name}" in names, f"missing http-evidence/{aid}/{name}"
    assert "Raw HTTP evidence" in index
    with zipfile.ZipFile(out) as z:
        assert b"error in your SQL syntax" in z.read(f"http-evidence/{aid}/response.body")
    # (c) the offline-verifiable proof bundle
    assert "proof-bundle/reverifiable.json" in names
    assert "proof-bundle/evidence-bundle.json" in names
    # (d) signed with a STABLE, origin-pinnable trust root
    assert res.get("signed") is True
    assert str(res.get("trust_root_fingerprint", "")).startswith("sha256:")
