"""PR-G (Area 6) — the shareable REPORT export (``ui/report_export``) and its PDF seam (``ui/report_pdf``).

Load-bearing invariants (each mutation-verified — the named test reds when its guard is broken):
  * DETERMINISTIC: the same spine and ``now`` give byte-identical HTML (test_the_html_report_is_deterministic).
  * REDACTION ALLOWLIST: report claims, the artifact manifest, the internal slug and any other cert field never reach
    the document; the offline verify command and the proof fingerprint do (test_only_allowlisted_fields_reach_the_report).
  * INERT: every value is escaped; no script, no form, no external reference, a default-src 'none' CSP
    (test_the_report_is_inert_html).
  * TENANT-SCOPED: org B's report never carries org A's finding (test_another_tenants_finding_is_never_in_the_report).
  * PREVIEW LOCK: a trial-preview org is refused — the full report is what its first purchase unlocks
    (test_a_trial_preview_org_is_refused_the_full_report).
  * SIGNED-ONLY plain language + honest absence (test_plain_language_and_fix_come_only_from_the_signed_block).
  * FOLD-CACHE IDENTITY: flipping the presentation flag between two reads of one spine under the fold cache gives each
    read exactly the uncached report for its own value — never the signed fix after the flag went off, never a report
    missing it after the flag came back on (test_the_presentation_flag_flips_between_two_reads_under_the_fold_cache).
  * PDF SEAM FAIL-CLOSED: no renderer -> refused; a renderer inside the venv, writable by others, failing, hanging,
    oversized or not producing a PDF -> refused; secrets never reach its environment (the test_pdf_* tests).
  * GATING: flag off -> refused + cockpit 404; only view_assessments; rate-limited (test_flag_off_..., test_roles_...,
    test_exports_are_rate_limited).
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui import report_export as rx
from sigil.ui import report_pdf as rp
from sigil.ui.provision import ProvisionDenied, ProvisionRateLimited
from test_compliance_rollup import _area6_env  # noqa: F401  (autouse: every Area-6 flag starts unset)
from test_compliance_rollup import _finding, _member, _prov, _prove, _store

T = 1_800_000_000.0
_REPO = Path(__file__).resolve().parents[3]


def _org_with_findings(*, title="Finding <b>one</b>", presentation=None, extra=None):
    store = _store()
    p = _prov(store, ensure_owner_keypair(), now=T)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", "operator", it, name="Acme <Corp> & Sons")
    slug = _prove(store, "acme", "acme.example", it)
    extra = extra or {}
    _finding(store, slug, "f1", bug_class="sqli", severity="critical", title=title, presentation=presentation,
             how_to_verify="vigil verify --ref f1", oracle_context_digest="sha256:" + "a" * 64,
             report_claims=[{"sentence": "S-RC-f1"}], artifact_manifest={"x": "S-AM-f1"}, **extra)
    _finding(store, slug, "f2", bug_class="open_redirect", severity="medium", how_to_verify="vigil verify --ref f2")
    return store, p, slug


# ---- the HTML document -------------------------------------------------------------------------------------------
def test_the_html_report_is_deterministic():
    store, _p, _s = _org_with_findings()
    a = rx.build_report(store, "acme", now=T, org_name="Acme")
    b = rx.build_report(store, "acme", now=T, org_name="Acme")
    assert a["html"] == b["html"] and a["sha256"] == b["sha256"] and a["fingerprint"] == b["fingerprint"]
    later = rx.build_report(store, "acme", now=T + 86400.0, org_name="Acme")
    assert later["html"] != a["html"] and later["fingerprint"] != a["fingerprint"]   # the time stamp is in it
    assert a["filename"] == "vigil-report-acme-20270115.html" and a["content_type"] == "text/html; charset=utf-8"
    assert a["bytes"] == len(a["html"].encode("utf-8")) and a["findings_total"] == 2


def test_only_allowlisted_fields_reach_the_report():
    store, _p, slug = _org_with_findings(extra={"internal_note": "S-INTERNAL", "proof_bytes": "S-PROOF"})
    doc = rx.build_report(store, "acme", now=T)["html"]
    for leak in ("S-RC-f1", "S-AM-f1", "S-INTERNAL", "S-PROOF", slug):
        assert leak not in doc, leak
    assert "vigil verify --ref f1" in doc and "sha256:" + "a" * 64 in doc        # verify-it-yourself is in
    model = rx.report_model(store, "acme", now=T)
    for f in model["findings"]:
        assert set(f) <= set(rx.REPORT_FIELDS), set(f) - set(rx.REPORT_FIELDS)


def test_the_report_is_inert_html():
    store, _p, _s = _org_with_findings(title='<script>alert(1)</script>" onload="x')
    doc = rx.build_report(store, "acme", now=T, org_name="Acme <Corp> & Sons")["html"]
    assert "<script" not in doc.lower() and "onload=\"x" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;&quot; onload=&quot;x" in doc
    assert "Acme &lt;Corp&gt; &amp; Sons" in doc
    assert re.search(r'Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
                     r'img-src data:"', doc)
    assert not re.search(r"(?i)<form|<iframe|<object|<embed|<link|@import|javascript:", doc)
    for m in re.finditer(r'(?i)\b(?:src|href)\s*=\s*"([^"]*)"', doc):
        assert m.group(1).startswith("data:image/svg+xml;base64,"), m.group(1)[:40]
    assert not re.search(r"(?i)url\(", doc)


def test_the_report_carries_the_summary_roadmap_standards_and_verify_sections():
    store, _p, _s = _org_with_findings()
    model = rx.report_model(store, "acme", now=T)
    doc = rx.render_html(model)
    from sigil.ui import compliance_view as cv
    from sigil.ui import finding_presentation as fpres
    assert model["posture_score"] == fpres.posture_score([{"bug_class": "sqli", "severity": "critical"},
                                                          {"bug_class": "open_redirect", "severity": "medium"}])
    assert [x["finding_ref"] for x in model["fix_first"]] == ["f1", "f2"]               # worst first
    for section in ('id="summary"', 'id="findings"', 'id="roadmap"', 'id="standards"', 'id="verify"'):
        assert section in doc, section
    assert cv.STATEMENT.replace("'", "&#x27;") in doc
    assert "A03:2021" in doc and "Injection" in doc                                      # implicated controls named
    assert "not a compliance attestation" in doc and "not a certified rating" in doc


_SIGNED = {"schema": 1, "plain_impact": {"what": "An attacker can read your database.",
                                         "category_consequence": "Data theft.", "established": "The query ran."},
           "remediation": "Use parameterised queries.", "standards": {"controls": {"owasp": "A03:2021"}}}


def test_plain_language_and_fix_come_only_from_the_signed_block(monkeypatch):
    monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1")
    store, _p, _s = _org_with_findings(presentation=_SIGNED)
    doc = rx.build_report(store, "acme", now=T)["html"]
    assert "An attacker can read your database." in doc and "Use parameterised queries." in doc
    # f2 has no signed block: no fix is invented for it — the report says so
    assert doc.count("carries no signed fix guidance") == 1
    monkeypatch.delenv("VIGIL_APEX_PRESENTATION")
    off = rx.build_report(store, "acme", now=T)["html"]                                  # presentation flag off
    assert "Use parameterised queries." not in off and off.count("carries no signed fix guidance") == 2


@pytest.mark.parametrize("first", [True, False], ids=["on-then-off", "off-then-on"])
def test_the_presentation_flag_flips_between_two_reads_under_the_fold_cache(monkeypatch, first):
    """REGRESSION (the "fold cache ON" CI leg). The assessments fold index projected each finding under the value the
    presentation flag had when the index was BUILT, and its cache identity left the flag out: after a flag-ON read the
    flag-OFF report still carried the signed fix ("Use parameterised queries.") — and a flag-ON read after a flag-OFF
    one lost it. Run here with the fold cache forced ON (so every CI leg runs it), starting from each value: every
    cached read equals the UNCACHED report for its own flag value, a second read under the same value reuses the
    index entry (the cache still caches), and each entry was built under its read's own value."""
    from sigil.spine import fold_cache
    from sigil.ui import assessments as am
    store, _p, _s = _org_with_findings(presentation=_SIGNED)

    def report(present: bool, *, cached: bool) -> str:
        monkeypatch.setenv("VIGIL_APEX_PRESENTATION", "1" if present else "")
        monkeypatch.setenv("VIGIL_FOLD_CACHE_ENABLED", "1" if cached else "")
        return rx.build_report(store, "acme", now=T)["html"]

    truth = {present: report(present, cached=False) for present in (False, True)}   # the uncached scan, per value
    assert "Use parameterised queries." in truth[True] and truth[True].count("carries no signed fix guidance") == 1
    assert "Use parameterised queries." not in truth[False]
    assert truth[False].count("carries no signed fix guidance") == 2
    fold_cache.clear_all()
    built = []
    for present in (first, not first, first, not first):   # ON -> OFF: a stale index LEAKS the fix; OFF -> ON: LOSES it
        assert report(present, cached=True) == truth[present], f"flag {'ON' if present else 'OFF'}"
        (entry,) = am._ASSESSMENTS_FOLD._entries.values()                            # the cached path answered
        assert report(present, cached=True) == truth[present]
        (again,) = am._ASSESSMENTS_FOLD._entries.values()
        assert again is entry                                                        # ... and reused its entry
        built.append((present, entry))
    for present, entry in built:                        # each entry was built under its own read's flag value
        assert entry.key[-2:] == ("presentation", present) and entry.state.presentation == present


def test_another_tenants_finding_is_never_in_the_report():
    store, p, _s = _org_with_findings(title="ACME-ONLY SECRET")
    it = iter(range(20_000, 30_000))
    _member(p.orgs, "globex", "bob", "operator", it)
    _prove(store, "globex", "globex.example", it)
    b = rx.build_report(store, "globex", now=T)
    assert b["findings_total"] == 0 and "ACME-ONLY" not in b["html"] and "acme.example" not in b["html"]
    assert "No proven findings in this workspace" in b["html"]


def test_retest_fixed_findings_leave_the_roadmap(monkeypatch):
    from test_compliance_rollup import _retest
    store, _p, slug = _org_with_findings()
    _retest(store, slug, "f2", "fixed")
    model = rx.report_model(store, "acme", now=T, retests=True)
    assert [x["finding_ref"] for x in model["fix_first"]] == ["f1"]
    doc = rx.render_html(model)
    assert "Retested: the proof no longer works on this host." in doc


# ---- the provisioner: gating, roles, preview, rate limit ---------------------------------------------------------
def test_flag_off_the_export_is_absent_everywhere(monkeypatch):
    from sigil.ui.server import Handler
    _store_, p, _s = _org_with_findings()
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_report_export("alice", "acme")
    h = Handler.__new__(Handler)
    for action in ("report_export", "report_export_pdf"):
        assert h._provision_dispatch(p, action, "alice", {"org_id": "acme"}) is None        # -> 404
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    out = h._provision_dispatch(p, "report_export", "alice", {"org_id": "acme"})
    assert out["format"] == "html" and out["html"].startswith("<!doctype html>")


@pytest.mark.parametrize("role,ok", [("operator", True), ("org_admin", False), ("analyst", False)])
def test_roles_that_cannot_read_assessments_are_refused(monkeypatch, role, ok):
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    store = _store()
    p = _prov(store, ensure_owner_keypair(), now=T)
    it = iter(range(1, 10_000))
    _member(p.orgs, "acme", "alice", role, it)
    _finding(store, _prove(store, "acme", "acme.example", it), "f1", bug_class="sqli", severity="critical")
    if ok:
        assert p.customer_report_export("alice", "acme")["findings_total"] == 1
    else:
        with pytest.raises(ProvisionDenied, match="view_assessments"):
            p.customer_report_export("alice", "acme")


def test_a_trial_preview_org_is_refused_the_full_report(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    monkeypatch.setenv("VIGIL_TRIAL_PREVIEW_ENABLED", "1")
    _store_, p, _s = _org_with_findings()
    p.wallet.grant("acme", 100, "trial", entry_id="trial-preview:acme", issued_at=50.0)
    with pytest.raises(ProvisionDenied, match="unlocks with your first purchase"):
        p.customer_report_export("alice", "acme")
    from sigil.governor.report_unlock import ReportUnlockRegistry
    ReportUnlockRegistry(p.store).unlock("acme", "topup", source_ref="evt_1", issued_at=60.0)
    assert p.customer_report_export("alice", "acme")["findings_total"] == 2          # unlocked: the full report


def test_exports_are_rate_limited(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    _store_, p, _s = _org_with_findings()
    for _ in range(p._REPORT_MAX):
        p.customer_report_export("alice", "acme")
    with pytest.raises(ProvisionRateLimited):
        p.customer_report_export("alice", "acme")


def test_an_unknown_format_is_refused(monkeypatch):
    from sigil.ui.provision import ProvisionError
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    _store_, p, _s = _org_with_findings()
    with pytest.raises(ProvisionError, match="unknown report format"):
        p.customer_report_export("alice", "acme", fmt="docx")


# ---- the PDF seam --------------------------------------------------------------------------------------------------
def _renderer(tmp_path: Path, body: str, *, mode: int = 0o700) -> str:
    """A fake renderer OUTSIDE the venv: a /bin/sh script with ``body``."""
    path = tmp_path / "render-pdf"
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(mode)
    return str(path)


def _good(tmp_path: Path) -> str:
    """A renderer that writes a (minimal) PDF carrying the first bytes of its stdin and its whole environment, so the
    tests can read both back."""
    return _renderer(tmp_path, "\n".join([
        'head -c 15 > "$TMPDIR/in"',
        "cat <<'PDFHEAD'", "%PDF-1.4", "PDFHEAD",
        'cat "$TMPDIR/in"', "env | sort",
        "cat <<'PDFTAIL'", "trailer << >>", "%%EOF", "PDFTAIL"]))


def test_pdf_refuses_while_no_renderer_is_provisioned(monkeypatch):
    with pytest.raises(rp.ReportPdfUnavailable, match="not set up"):
        rp.render_pdf("<!doctype html>")
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    _store_, p, _s = _org_with_findings()
    with pytest.raises(ProvisionDenied, match="PDF export is not set up"):
        p.customer_report_export("alice", "acme", fmt="pdf")


def test_pdf_through_a_provisioned_renderer(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    monkeypatch.setenv("VIGIL_REPORT_PDF_RENDERER", _good(tmp_path))
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "sk_test_" + "MUSTNOTLEAK")
    monkeypatch.setenv("SIGIL_OWNER_SECRET_PROBE", "MUSTNOTLEAK2")
    _store_, p, _s = _org_with_findings()
    out = p.customer_report_export("alice", "acme", fmt="pdf")
    pdf = base64.b64decode(out["pdf_b64"])
    assert pdf.startswith(b"%PDF-") and b"%%EOF" in pdf[-64:]
    assert out["format"] == "pdf" and out["content_type"] == "application/pdf"
    assert out["filename"] == "vigil-report-acme-20270115.pdf" and out["bytes"] == len(pdf)
    assert b"<!doctype html>" in pdf                                   # the renderer got the report on stdin
    assert b"MUSTNOTLEAK" not in pdf and b"VIGIL_" not in pdf          # a minimal env: no secret reaches it
    assert b"PATH=/usr/local/bin:/usr/bin:/bin" in pdf


@pytest.mark.parametrize("case", ["relative", "missing", "not_executable", "world_writable", "group_writable"])
def test_pdf_refuses_a_renderer_that_fails_a_check(monkeypatch, tmp_path, case):
    path = _good(tmp_path)
    if case == "relative":
        path = "render-pdf"
    elif case == "missing":
        path = str(tmp_path / "nope")
    elif case == "not_executable":
        os.chmod(path, 0o600)
    elif case == "world_writable":
        os.chmod(path, 0o707)
    elif case == "group_writable":
        os.chmod(path, 0o770)
    monkeypatch.setenv("VIGIL_REPORT_PDF_RENDERER", path)
    with pytest.raises(rp.ReportPdfUnavailable):
        rp.render_pdf("<!doctype html>")


def test_pdf_refuses_a_renderer_inside_the_customer_venv(monkeypatch, tmp_path):
    path = _good(tmp_path)
    monkeypatch.setenv("VIGIL_REPORT_PDF_RENDERER", path)
    assert rp.render_pdf("<!doctype html>").startswith(b"%PDF-")       # control: outside the venv it renders
    monkeypatch.setattr(sys, "prefix", str(tmp_path))                  # ... and the same file INSIDE the venv
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    with pytest.raises(rp.ReportPdfUnavailable, match="outside the customer environment"):
        rp.render_pdf("<!doctype html>")


@pytest.mark.parametrize("body,why", [
    ('cat >/dev/null; exit 7', "failed"),
    ('cat >/dev/null; echo "not a pdf at all"', "not a PDF"),
    ('cat >/dev/null', "empty or oversized"),
    ('cat >/dev/null; echo "%PDF-1.4 no trailer"', "not a PDF"),
])
def test_pdf_refuses_a_failed_or_non_pdf_render(monkeypatch, tmp_path, body, why):
    monkeypatch.setenv("VIGIL_REPORT_PDF_RENDERER", _renderer(tmp_path, body))
    with pytest.raises(rp.ReportPdfUnavailable, match=why):
        rp.render_pdf("<!doctype html>")


def test_pdf_refuses_an_oversized_document(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_REPORT_PDF_RENDERER", _good(tmp_path))
    with pytest.raises(rp.ReportPdfUnavailable, match="empty or oversized"):
        rp.render_pdf("<!doctype html>", max_bytes=16)


def test_pdf_kills_a_hung_renderer_and_its_children(monkeypatch, tmp_path):
    marker = tmp_path / "child.pid"
    monkeypatch.setenv("VIGIL_REPORT_PDF_RENDERER",
                       _renderer(tmp_path, f'sleep 30 & echo $! > "{marker}"; sleep 30'))
    t0 = time.monotonic()
    with pytest.raises(rp.ReportPdfUnavailable, match="took too long"):
        rp.render_pdf("<!doctype html>", timeout_s=0.5)
    assert time.monotonic() - t0 < 10
    child = int(marker.read_text().strip())
    for _ in range(50):                                                # the whole process group was killed
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("the renderer's child process outlived the timeout")


def test_the_reference_renderer_refuses_cleanly_without_its_library():
    """tools/report_pdf/render_pdf.py runs OUTSIDE every VIGIL venv; where its library is absent it exits 3 and writes
    nothing to stdout (never a partial PDF)."""
    script = _REPO / "tools" / "report_pdf" / "render_pdf.py"
    assert os.access(script, os.X_OK)
    r = subprocess.run([sys.executable, "-I", str(script)], input=b"<!doctype html><p>x</p>", capture_output=True,
                       timeout=60)
    try:
        import weasyprint  # noqa: F401
    except Exception:  # noqa: BLE001 — the expected case in the sovereign venv
        assert r.returncode == 3 and r.stdout == b"" and b"weasyprint is not installed" in r.stderr
    else:  # pragma: no cover - only where the library happens to be installed
        assert r.returncode == 0 and r.stdout.startswith(b"%PDF-")


def _reference_renderer():
    """tools/report_pdf/render_pdf.py loaded as a module (it imports its library only inside main())."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("vigil_render_pdf", _REPO / "tools" / "report_pdf" / "render_pdf.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_reference_renderer_fetches_nothing_but_the_reports_own_inline_image():
    """The renderer's url_fetcher decodes the report's inline wordmark and REFUSES every other URL — no network, no
    file read, whatever a document under it names."""
    mod = _reference_renderer()
    logo = rx._wordmark_uri()
    assert logo.startswith("data:image/svg+xml;base64,")
    got = mod.no_fetch(logo)
    assert got["mime_type"] == "image/svg+xml" and got["string"] == rx._WORDMARK.read_bytes()
    for url in ("https://example.com/x.png", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
                "/etc/passwd", "report.css", "ftp://x/y", "data:text/html;base64,PHA+eDwvcD4=",
                "data:image/svg+xml,<svg/>", "data:image/png;base64,***", "DATA:image/png;base64,AAAA",
                " data:image/png;base64,AAAA"):
        with pytest.raises(ValueError):
            mod.no_fetch(url)
    with pytest.raises(ValueError, match="oversized"):
        mod.no_fetch("data:image/png;base64," + base64.b64encode(b"\0" * (mod._MAX_DATA_BYTES + 1)).decode())


def test_the_pdf_hop_outwaits_the_render():
    from sigil.ui import custui
    assert custui._SLOW_HOP_TIMEOUTS_S["report_export_pdf"] > rp.RENDER_TIMEOUT_S + 5.0
    # the edge's drain deadline (sized against the units' TimeoutStopSec) is not raised by PR-G's hops
    assert custui._SLOW_HOP_TIMEOUTS_S["report_export_pdf"] <= 60.0


def test_report_json_round_trips(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_PDF_REPORT", "1")
    _store_, p, _s = _org_with_findings()
    out = p.customer_report_export("alice", "acme")
    assert json.loads(json.dumps(out)) == out                       # the hop carries it as JSON, losslessly


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
