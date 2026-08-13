"""
The dossier's plain-English case file — completeness, honesty, and the label's confinement.

The proof layer of a dossier was already sound; what a non-specialist could read was one machine
format. These tests pin the properties the case file has to hold for the people it is written for
— a regulator, an auditor, a government official — and, just as importantly, the properties that
stop it saying something untrue.

Each honesty test is paired with a MUTATION CONTROL: a variant that removes the thing being
asserted and checks the assertion then fails. Without that pairing a test like "the archive never
claims an embedded bundle when there is none" passes just as happily against a document that says
nothing at all, and proves nothing.

Needs framework + integration → run with PYTHONPATH=integration:engine/crucible:gateway.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

import pytest

# Assembling a case file needs the offense engine (the report renderers and the dossier compiler both live
# there), so skip in the deliberately framework-free sovereign leg — the same convention the sibling
# producer tests use. This file is wired into the framework-on-path CI invocation, where it really runs.
pytest.importorskip("framework.v2.report.case_file")

from vigil_core import generate_keypair
from vigil_integration.proof.run import build_report_mint
from vigil_integration.proof.sink import CAPTURE_KEY

from framework.v2.report import dossier as D
from framework.v2.report.case_file import CASE_FILE_NAMES, START_HERE

SIGNER = generate_keypair()
SIGNERS = [("root0", SIGNER.private_key_b64)]

_SQL_ERROR = b"HTTP/1.1 500\r\n\r\nYou have an error in your SQL syntax near ''' at line 1"

_FIXTURES = Path(__file__).parents[1] / "engine/crucible/framework/v2/report/tests/fixtures"
if not _FIXTURES.is_dir():                       # running from the repo root
    _FIXTURES = Path("engine/crucible/framework/v2/report/tests/fixtures").resolve()


def _mint_a_fact(run_dir: Path) -> None:
    mint = build_report_mint(run_dir=run_dir, signers=SIGNERS, engagement_slug="acme")
    res = mint({
        "id": "errsqli-001", "bug_class": "error_based_sqli", "poc_script_code": "print('benign')",
        CAPTURE_KEY: {"exchanges": [{"channel": "error_signature", "role": "mutated",
                                     "response_bytes_ref": "resp", "bug_class": "error_based_sqli"}],
                      "blobs": {"resp": _SQL_ERROR}},
    })
    assert res is not None and res.is_fact


def _stored_run(tmp_path: Path, *, meta: dict | None = None) -> Path:
    """A run directory holding the REAL stored artefacts of a finished web scan."""
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    (run / "report.json").write_bytes((_FIXTURES / "stored-report.json").read_bytes())
    (run / "reverifiable.json").write_bytes((_FIXTURES / "stored-reverifiable.json").read_bytes())
    (run / "meta.json").write_text(json.dumps(meta or {
        "target": "http://127.0.0.1:18080/search?q=test",
        "cmd": ["/py", "-m", "framework.v2", "scan", "http://127.0.0.1:18080/search?q=test",
                "--max-pages", "40", "--no-oob", "--targeted"],
        "status": "done", "rc": 0, "finished": 1785338410.645,
    }), encoding="utf-8")
    return run


def _build(run: Path, out: Path, **kw) -> tuple[dict, dict[str, str]]:
    """Build and return ``(summary, {arcname: text})``."""
    res = D.build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme",
                          base_dir=str(run), **kw)
    assert res["ok"], res
    texts: dict[str, str] = {}
    with zipfile.ZipFile(out) as zf:
        for name in zf.namelist():
            texts[name] = zf.read(name).decode("utf-8", errors="replace")
    return (res, texts)


# --------------------------------------------------------------------------------------------------
# completeness — every promised document, and every file accounted for
# --------------------------------------------------------------------------------------------------


def test_every_promised_document_is_present(tmp_path: Path) -> None:
    res, texts = _build(_stored_run(tmp_path), tmp_path / "d.zip")
    for name in CASE_FILE_NAMES:
        assert name in texts, f"{name} missing from the archive"
        assert texts[name].strip(), f"{name} is empty"
    assert "appendix/report.json" in texts and "appendix/report.sarif" in texts
    assert "reports/technical.md" in texts, "the engineering reports must still ship"


def test_start_here_accounts_for_every_file_in_the_archive(tmp_path: Path) -> None:
    """The owner's "nothing ever missed out" requirement, enforced. A recipient must not find a
    file in the archive that the front page never mentions."""
    res, texts = _build(_stored_run(tmp_path), tmp_path / "d.zip")
    page = texts[START_HERE]
    unexplained = [name for name in texts if name not in page]
    assert not unexplained, f"START-HERE does not account for: {unexplained}"


def test_start_here_accounts_for_the_proof_bundle_and_the_signature_envelope(tmp_path: Path) -> None:
    """A mutation control for the test above: the inventory must be built from the REAL entry list,
    not a fixed list of names that happens to cover the common case."""
    run = _stored_run(tmp_path)
    _mint_a_fact(run)                       # adds proof-bundle/ + evidence/ entries
    res, texts = _build(run, tmp_path / "d.zip")
    page = texts[START_HERE]
    assert res["proof_bundle"] is True
    assert any(n.startswith("proof-bundle/evidence/") for n in texts)
    for name in texts:
        assert name in page, f"{name} is in the archive but not on the START-HERE page"
    assert "MANIFEST.sig.json" in page and "TRUST-ROOT-FINGERPRINT.txt" in page


# --------------------------------------------------------------------------------------------------
# the label — presentation only; it must not touch the proof layer
# --------------------------------------------------------------------------------------------------


def test_the_label_appears_but_never_reaches_the_proof_layer(tmp_path: Path) -> None:
    run = _stored_run(tmp_path)
    _mint_a_fact(run)
    label_a = "Ministry of Health — Q3 external review"
    label_b = "Acme Corp — pre-launch assurance"
    res_a, a = _build(run, tmp_path / "a.zip", label=label_a)
    res_b, b = _build(run, tmp_path / "b.zip", label=label_b)

    # it is shown to the reader, in both the front page and the summary
    assert label_a in a[START_HERE] and label_a in a["01-executive-summary.md"]
    assert label_b in b[START_HERE] and label_b in b["01-executive-summary.md"]
    assert res_a["label"] == label_a and res_b["label"] == label_b

    # and it changes NOTHING in the proof layer
    proof_entries = sorted(n for n in a if n.startswith("proof-bundle/"))
    assert proof_entries, "this run must produce a proof bundle for the test to mean anything"
    for name in proof_entries:
        assert a[name] == b[name], f"the label altered proof-bundle content: {name}"
    assert label_a not in json.dumps(a), "the label must not appear inside the proof bundle"

    # the machine identity of the engagement is untouched
    for texts in (a, b):
        assert json.loads(texts["MANIFEST.json"])["engagement_slug"] == "acme"


def test_the_proof_bundle_verifies_under_either_label(tmp_path: Path) -> None:
    """The property that actually matters: a relabelled dossier is still independently verifiable."""
    import os
    import subprocess
    import sys

    run = _stored_run(tmp_path)
    _mint_a_fact(run)
    for i, label in enumerate(("Ministry of Health — Q3 external review", "Another Client Ltd")):
        out = tmp_path / f"lab{i}.zip"
        res = D.build_dossier(run_dir=str(run), out_zip=str(out), engagement_slug="acme",
                              base_dir=str(run), label=label)
        extracted = tmp_path / f"x{i}"
        with zipfile.ZipFile(out) as zf:
            zf.extractall(extracted)
        bundle = extracted / "proof-bundle"
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(Path.cwd() / "engine" / "crucible"), env.get("PYTHONPATH", "")])
        proc = subprocess.run(
            [sys.executable, "-m", "framework.v2", "evidence", "verify",
             "--report", "reverifiable.json", "--bundle", ".", "--trust-root", "trust-root.json",
             "--evidence-root", "evidence",
             "--trust-root-fingerprint", res["trust_root_fingerprint"]],
            cwd=str(bundle), env=env, capture_output=True, text=True, timeout=180)
        assert proc.returncode == 0, f"label {label!r} broke verification:\n{proc.stdout}{proc.stderr}"


# --------------------------------------------------------------------------------------------------
# no self-contradiction — the defect that lived in signed bytes
# --------------------------------------------------------------------------------------------------


def _claims_an_embedded_bundle(text: str) -> bool:
    """Does this document tell the reader an offline proof bundle travels with the archive?"""
    lowered = text.lower()
    return ("re-verifiable\noffline from the embedded proof bundle" in lowered
            or "re-verifiable offline from the embedded proof bundle" in lowered
            or "embedded proof bundle" in lowered and "no offline proof bundle" not in lowered)


def test_no_document_claims_a_proof_bundle_when_none_is_embedded(tmp_path, monkeypatch) -> None:
    """A run WITH facts but WITHOUT a bundle must not promise one. This is the case the old gate
    got wrong: it keyed the promise on the fact count, so index.html advertised an embedded bundle
    that README, in the same archive, said was absent."""
    monkeypatch.setattr(D, "_build_proof_bundle",
                        lambda *a, **k: ({}, {"ok": False, "note": "no signer in this environment"}))
    run = _stored_run(tmp_path)
    res, texts = _build(run, tmp_path / "d.zip")

    assert res["facts"] > 0, "the run must still HAVE facts, or the test is vacuous"
    assert res["proof_bundle"] is False
    assert not any(n.startswith("proof-bundle/") for n in texts)

    for name, body in texts.items():
        if name.endswith((".md", ".html")):
            assert not _claims_an_embedded_bundle(body), f"{name} promises a bundle that is absent"
    # and it says so positively, rather than merely staying silent
    assert "NO offline proof bundle is embedded" in texts["index.html"]
    assert "No evidence bundle is included" in texts["07-verify-it-yourself.md"]


def test_mutation_control_the_claim_is_made_when_a_bundle_IS_embedded(tmp_path) -> None:
    """The control for the test above. If this fails, the detector matches nothing and the
    no-false-claim test proves nothing."""
    run = _stored_run(tmp_path)
    _mint_a_fact(run)
    res, texts = _build(run, tmp_path / "d.zip")
    assert res["proof_bundle"] is True
    assert _claims_an_embedded_bundle(texts["index.html"]), (
        "with a bundle present the index must claim it — otherwise the absence test is vacuous")


def test_no_document_points_at_a_file_the_archive_does_not_contain(tmp_path, monkeypatch) -> None:
    """Every cross-reference is checked against the real entry list. A pointer to a missing file is
    a defect the reader discovers, and it devalues every other statement in the pack."""
    # force the markdown renderers to fail, so the reports/ documents are absent
    monkeypatch.setattr(D, "generate_reports",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("renderer down")))
    run = _stored_run(tmp_path)
    res, texts = _build(run, tmp_path / "d.zip")
    assert "reports/technical.md" not in texts, "the renderers must really have failed"

    referenced = set()
    for name, body in texts.items():
        if name.endswith((".md", ".html")):
            referenced |= set(re.findall(r"(?:reports|appendix|logs|spine|proof-bundle)/[\w.\-/]+",
                                         body))
    missing = {r for r in referenced if r not in texts}
    assert not missing, f"documents point at files that are not in the archive: {missing}"


# --------------------------------------------------------------------------------------------------
# honesty — absence of a record is never rendered as absence of a problem
# --------------------------------------------------------------------------------------------------


def test_a_cloud_run_says_its_sections_cannot_be_produced(tmp_path: Path) -> None:
    """A cloud posture assessment records no findings today. The case file must say so explicitly
    and must NOT present an empty findings list as an examination that found nothing."""
    run = tmp_path / "cloudrun"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps({
        "target": "acme-prod-account", "slug": "acme", "mode": "cloud", "provider": "aws",
        "sensor": "cloud_import", "status": "done", "finished": 1785338410.0,
        "cmd": ["/py", "-m", "framework.v2", "engage", "acme", "--fuse-only", "--spine"],
    }), encoding="utf-8")
    res, texts = _build(run, tmp_path / "cloud.zip")

    findings = texts["03-findings.md"]
    assert "does not currently record" in findings
    assert "not as a finding that nothing is wrong" in findings
    assert "Nothing was proven in this examination" not in findings, (
        "an unrecorded section must not be phrased as a clean result")

    # the subject is described in cloud vocabulary, never as a web address
    page = texts[START_HERE]
    assert "Cloud account examined" in page and "acme-prod-account" in page
    assert "Web address examined" not in page
    assert "cloud posture assessment" in page
    assert "which regions were covered" in page, "unrecorded aspects must be stated"


def test_mutation_control_a_web_run_does_report_a_real_result(tmp_path: Path) -> None:
    """The control: when a findings record IS present, the wording must be the real-result wording,
    not the cannot-be-produced wording."""
    res, texts = _build(_stored_run(tmp_path), tmp_path / "d.zip")
    findings = texts["03-findings.md"]
    assert "does not currently record" not in findings
    assert "Web address examined" in texts[START_HERE]


def test_a_codebase_run_distinguishes_missing_from_never_recorded(tmp_path: Path) -> None:
    """A source-code review records proofs but no findings list. The two absences have different
    causes and the documents must not blur them."""
    run = tmp_path / "coderun"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps({
        "mode": "codebase", "target": "/srv/payments-api", "slug": "payments-api",
        "objective": "review the payment flow", "status": "done", "finished": 1785338410.0,
        "cmd": ["strix", "--non-interactive", "--target", "/srv/payments-api"],
    }), encoding="utf-8")
    res, texts = _build(run, tmp_path / "code.zip")

    page = texts[START_HERE]
    assert "Codebase examined" in page and "/srv/payments-api" in page
    assert "payments-api" in page, "the repository name must be surfaced"
    assert "which files were read" in page
    approach = texts["02-approach-and-scope.md"]
    # a type that DOES record proofs but has none reports an incomplete record, not a policy gap
    assert "source-code review" in approach
    assert "cannot observe how the running service is configured" in approach


def test_the_catalogue_never_infers_examined_from_an_absent_finding(tmp_path: Path) -> None:
    res, texts = _build(_stored_run(tmp_path), tmp_path / "d.zip")
    cat = texts["05-what-was-looked-for.md"]
    assert "Not recorded whether examined" in cat
    assert "examined and found clean" in cat, "the missing state must be named and explained"
    assert "It is not a clean result" in cat
    # the confirmed categories really are the proven ones (the status appears both in the
    # recorded-categories table and again in the full catalogue, so count rows via the export)

    export = json.loads(texts["appendix/catalogue.json"])
    assert export["counts"]["confirmed"] == 2
    assert export["counts"]["total"] > 50, "the catalogue must come from the real registry"
    assert all(c["status"] in ("confirmed", "reported", "not_recorded")
               for c in export["categories"]), "no 'clean' state may exist"


def test_a_finding_separates_the_general_category_from_what_was_proved(tmp_path: Path) -> None:
    """A reader must never conclude the category's worst case was demonstrated on their system."""
    res, texts = _build(_stored_run(tmp_path), tmp_path / "d.zip")
    findings = texts["03-findings.md"]
    assert "**What this kind of weakness can lead to, in general.**" in findings
    assert "The paragraph above describes the CATEGORY" in findings
    assert "**What was established on this system.**" in findings
    assert "**What this does NOT prove.**" in findings
    assert "no data was extracted, no account was taken over" in findings
    # the category is named in the engine's own vocabulary so it can be cross-referenced
    assert "**Category:** `boolean_sqli`" in findings
    # ... and the engine's own recorded title is preserved alongside the readable one
    assert "boolean_sqli confirmed at q" in findings
    assert "Database injection (SQL injection) in the 'q' parameter" in findings


# --------------------------------------------------------------------------------------------------
# timestamps + the archive stays tamper-evident
# --------------------------------------------------------------------------------------------------


def test_timestamps_render_in_a_human_format_with_a_timezone(tmp_path: Path) -> None:
    res, texts = _build(_stored_run(tmp_path), tmp_path / "d.zip",
                        generated_at="2026-08-12T18:00:00Z")
    for name in (START_HERE, "01-executive-summary.md"):
        assert "29 July 2026 at 15:20:10 UTC" in texts[name], f"{name} lacks the engagement time"
        assert "12 August 2026 at 18:00:00 UTC" in texts[name], f"{name} lacks the build time"
    assert "2026-08-12T18:00:00Z" not in texts["01-executive-summary.md"], (
        "the raw machine stamp should be rendered, not printed")


def test_an_unrecorded_timestamp_says_so_rather_than_being_invented(tmp_path: Path) -> None:
    run = _stored_run(tmp_path, meta={"target": "http://x/", "status": "done"})
    res, texts = _build(run, tmp_path / "d.zip")
    summary = texts["01-executive-summary.md"]
    assert "**Examination started:** not recorded" in summary
    assert "**Examination finished:** not recorded" in summary
    assert "genuinely did not record it" in summary


def test_the_case_file_documents_are_covered_by_the_manifest(tmp_path: Path) -> None:
    """The case file is evidence like everything else: altering it must be detectable."""
    out = tmp_path / "d.zip"
    res, texts = _build(_stored_run(tmp_path), out, label="Ministry of Health")
    manifest = json.loads(texts["MANIFEST.json"])
    listed = {e["path"]: e["sha256"] for e in manifest["entries"]}
    with zipfile.ZipFile(out) as zf:
        for name in CASE_FILE_NAMES:
            assert name in listed, f"{name} is not covered by the MANIFEST"
            assert hashlib.sha256(zf.read(name)).hexdigest() == listed[name]
    assert res["signed"] is True


def test_two_builds_with_the_same_inputs_are_identical(tmp_path: Path) -> None:
    run = _stored_run(tmp_path)
    common = dict(run_dir=str(run), engagement_slug="acme", base_dir=str(run),
                  label="Same Label", generated_at="2026-08-12T18:00:00Z")
    a = D.build_dossier(out_zip=str(tmp_path / "a.zip"), **common)
    b = D.build_dossier(out_zip=str(tmp_path / "b.zip"), **common)
    assert a["manifest_sha256"] == b["manifest_sha256"], "the case file broke determinism"


@pytest.mark.parametrize("mode", ["aegis", "suite", "tool", "k8s", "infra"])
def test_every_operation_type_produces_an_honest_pack(tmp_path: Path, mode: str) -> None:
    """No operation type may crash the builder or silently render an empty pack as a clean one."""
    run = tmp_path / f"run-{mode}"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps({
        "mode": mode, "target": f"subject-for-{mode}", "slug": "acme", "status": "done",
        "finished": 1785338410.0, "cmd": ["/py", "-m", "framework.v2", "engage", "acme"],
    }), encoding="utf-8")
    res, texts = _build(run, tmp_path / f"{mode}.zip")
    for name in CASE_FILE_NAMES:
        assert name in texts and texts[name].strip()
    assert f"subject-for-{mode}" in texts[START_HERE]
    assert "does not currently record" in texts["03-findings.md"]
    assert "Nothing was proven in this examination" not in texts["03-findings.md"]
